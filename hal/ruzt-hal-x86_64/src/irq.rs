//! IRQ delivery through the I/O APIC or cascaded 8259A PICs.

use ruzt_hal::irq::{IrqController, IrqNumber};
use spin::{Mutex, Once};

use crate::{
    apic::{Input, IoApic, Ipi, LocalApic},
    pci::{Msi, Msix},
    pic,
    vtd::InterruptTable,
};

/// The existing ISA logical interrupt namespace.
pub const ISA_IRQ_COUNT: usize = 16;
/// Beginning of the logical IRQ vector range in the x86 IDT.
pub const VECTOR_BASE: u8 = 0x20;
/// Logical IRQs occupy the vectors below the 0x80 syscall gate.
pub const IRQ_COUNT: usize = (0x80 - VECTOR_BASE) as usize;
/// ISA timer interrupt.
pub const TIMER: usize = 0;
/// ISA keyboard interrupt.
pub const KEYBOARD: usize = 1;
/// The legacy PIC cascade. This logical number is reserved.
pub const CASCADE: usize = 2;

struct ApicRoutes {
    local: LocalApic,
    inputs: [Option<Input>; ISA_IRQ_COUNT],
    extended: Mutex<[Option<ExtendedRoute>; IRQ_COUNT - ISA_IRQ_COUNT]>,
    remapping: Option<IoApicRemapping>,
}

/// A VT-d table and the exact requester ID of each firmware-mapped I/O APIC.
pub struct IoApicRemapping {
    /// A pinned table ready to be programmed.
    pub table: &'static InterruptTable,
    /// Requester IDs indexed by verified I/O APIC ID.
    pub sources: &'static [Option<u16>; 256],
}

impl IoApicRemapping {
    fn stage(&self, input: Input, line: u8, destination: u8) {
        let source = self.sources[usize::from(input.controller_id())]
            .expect("validate all I/O APIC requester IDs before enabling remapping");
        self.table.stage(
            line,
            source,
            VECTOR_BASE + line,
            destination,
            input.level_triggered(),
        );
    }
}

#[derive(Clone, Copy)]
enum ExtendedInput {
    Gsi { gsi: u32, input: Input },
    Message(Message),
}

#[derive(Clone, Copy)]
enum Message {
    Msi(Msi),
    Msix(Msix),
}

impl Message {
    fn function(self) -> u16 {
        match self {
            Self::Msi(msi) => msi.function(),
            Self::Msix(msix) => msix.function(),
        }
    }

    fn conflicts(self, other: Self) -> bool {
        self.function() == other.function()
            && match (self, other) {
                (Self::Msix(a), Self::Msix(b)) => a.vector() == b.vector(),
                _ => true,
            }
    }

    fn program(self, address: u32, first: bool) -> bool {
        match self {
            Self::Msi(msi) => msi.program(address),
            Self::Msix(msix) => (!first || msix.start()) && msix.program(address),
        }
    }

    fn set_enabled(self, enabled: bool) -> bool {
        match self {
            Self::Msi(msi) => msi.set_enabled(enabled),
            Self::Msix(msix) => msix.set_enabled(enabled),
        }
    }

    fn finish(self, last: bool) -> bool {
        match self {
            Self::Msi(msi) => msi.restore_intx(),
            Self::Msix(msix) => !last || msix.finish(),
        }
    }
}

impl ExtendedInput {
    fn same_source(self, other: Self) -> bool {
        match (self, other) {
            (Self::Gsi { gsi: a, .. }, Self::Gsi { gsi: b, .. }) => a == b,
            (Self::Message(a), Self::Message(b)) => a.conflicts(b),
            _ => false,
        }
    }

    fn idle(self) -> bool {
        match self {
            Self::Gsi { input, .. } => input.delivery_idle(),
            // Messages enter retirement only after masking the endpoint.
            Self::Message(_) => true,
        }
    }

    fn is_function(self, function: u16) -> bool {
        matches!(self, Self::Message(message) if message.function() == function)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Lease {
    Live,
    Retired,
    Quarantined,
}

#[derive(Clone, Copy)]
struct ExtendedRoute {
    source: ExtendedInput,
    lease: Lease,
}

/// Why an extended I/O APIC line could not be reserved.
#[derive(Debug, PartialEq, Eq)]
pub enum ReserveError {
    /// The required interrupt backend is inactive.
    Unavailable,
    /// This GSI is claimed or its previous delivery is still draining.
    Occupied,
    /// All extended IRQ vectors are in use or draining.
    NoVector,
    /// The remapper failed to synchronize its table.
    RemappingFailed,
    /// The PCI endpoint did not accept the requested interrupt state.
    DeviceFailed,
    /// The local APIC still has an interrupt from an earlier binding.
    PendingDelivery,
}

static APIC: Once<ApicRoutes> = Once::new();
static REMOTE_VECTOR_PROBE: Once<fn(u8) -> bool> = Once::new();

/// Install the transport for a synchronous boot-CPU LAPIC query.
///
/// The callback runs with interrupts disabled and must sample the vector
/// on the CPU that receives device interrupts. It must not take route locks.
pub fn install_vector_probe(remote: fn(u8) -> bool) {
    REMOTE_VECTOR_PROBE.call_once(|| remote);
}

/// Read the device-target LAPIC only if this is the boot CPU.
///
/// # Safety
/// Interrupts must be disabled in the negotiated APIC mode.
pub unsafe fn local_boot_vector_idle(vector: u8) -> Option<bool> {
    let local = &APIC.get()?.local;
    (local.current_id() == local.id()).then(|| local.vector_idle(vector))
}

/// Report whether a vector in the boot CPU's LAPIC is neither pending nor active.
///
/// # Safety
/// Call in the negotiated APIC mode with interrupts disabled and serialized
/// against other remote vector queries. The route and source must stay masked
/// and drained for the duration of a reclamation check.
pub unsafe fn boot_vector_idle(vector: u8) -> bool {
    // SAFETY: The caller disabled interrupts and uses the configured LAPIC.
    unsafe { local_boot_vector_idle(vector) }
        .or_else(|| REMOTE_VECTOR_PROBE.get().map(|probe| probe(vector)))
        .unwrap_or(false)
}

/// Send a physical unicast interrupt from the current CPU.
///
/// # Safety
/// The current CPU uses the negotiated APIC mode and owns its local ICR
/// with interrupts disabled. The target state must match the command.
pub unsafe fn send_ipi(destination: u8, message: Ipi) -> bool {
    APIC.get().is_some_and(|routes| routes.local.send_ipi(destination, message))
}

/// Report the ID of the current CPU's local APIC.
///
/// # Safety
/// The current CPU must use the negotiated APIC mode, if initialized.
pub unsafe fn current_apic_id() -> Option<u8> {
    APIC.get().map(|routes| routes.local.current_id())
}

/// Acknowledge an IPI on the receiving CPU and return its APIC ID.
///
/// # Safety
/// A fixed IPI is in service and this CPU uses the kernel's negotiated APIC mode.
pub unsafe fn finish_ipi() -> Option<u8> {
    let local = &APIC.get()?.local;
    let id = local.current_id();
    local.end_of_interrupt();
    Some(id)
}

/// Install a validated APIC configuration and route the PIT and keyboard.
///
/// # Safety
/// Call once with interrupts disabled on the boot CPU, after installing IDT
/// gates for the IRQ range and LAPIC spurious vector. All controller windows
/// must stay mapped uncached, and inputs must refer to unique pins on those
/// controllers. If firmware advertises compatible PICs, set `mask_pics`.
/// A remapping configuration must cover every supplied controller.
pub unsafe fn install_apic(
    local: LocalApic,
    controllers: impl IntoIterator<Item = IoApic>,
    inputs: [Option<Input>; ISA_IRQ_COUNT],
    mask_pics: bool,
    remapping: Option<IoApicRemapping>,
) {
    let routes = APIC.call_once(|| {
        for controller in controllers {
            controller.mask_all();
        }
        for (line, input) in inputs.iter().enumerate() {
            if let Some(input) = input {
                let line = line as u8;
                let index = remapping.as_ref().map(|mapping| {
                    mapping.stage(*input, line, local.id());
                    line
                });
                input.configure(VECTOR_BASE + line, local.id(), index);
            }
        }
        if mask_pics {
            pic::mask_all();
        }
        local.enable();
        if let Some(mapping) = &remapping {
            // A failed command can leave the hardware between modes. With
            // the inputs masked, halt before allowing any ambiguous delivery.
            mapping
                .table
                .activate()
                .expect("enable VT-d interrupt remapping");
        }
        ApicRoutes {
            local,
            inputs,
            extended: Mutex::new([None; IRQ_COUNT - ISA_IRQ_COUNT]),
            remapping,
        }
    });
    for line in [TIMER, KEYBOARD] {
        if let Some(input) = routes.inputs[line] {
            input.set_enabled(true);
        }
    }
}

/// Whether this ISA line is a routable device interrupt in the active backend.
pub fn is_device_irq(line: u32) -> bool {
    let line = line as usize;
    line > TIMER
        && line < ISA_IRQ_COUNT
        && line != CASCADE
        && APIC
            .get()
            .is_none_or(|routes| routes.inputs[line].is_some())
}

/// Reserve an extended GSI and assign it a masked interrupt vector.
///
/// # Safety
/// Serialize route transactions and disable local interrupts. The input must
/// designate this GSI's unique controller pin, outside the ISA and NMI routes.
pub unsafe fn reserve_gsi(gsi: u32, input: Input) -> Result<u32, ReserveError> {
    reserve_extended(ExtendedInput::Gsi { gsi, input })
}

/// Reserve one source-validated message interrupt for an exclusive endpoint.
///
/// # Safety
/// Serialize route transactions and disable local interrupts. The device lease must
/// remain exclusive until the IRQ is retired, and the active remapper must
/// cover the endpoint's exact requester ID.
pub unsafe fn reserve_msi(msi: Msi) -> Result<u32, ReserveError> {
    reserve_extended(ExtendedInput::Message(Message::Msi(msi)))
}

/// Reserve one independently maskable MSI-X vector.
///
/// # Safety
/// Serialize route transactions and disable local interrupts, holding the exclusive
/// covered endpoint lease. All table and pending-bit pages must be private.
pub unsafe fn reserve_msix(msix: Msix) -> Result<u32, ReserveError> {
    reserve_extended(ExtendedInput::Message(Message::Msix(msix)))
}

fn reserve_extended(source: ExtendedInput) -> Result<u32, ReserveError> {
    let routes = APIC.get().ok_or(ReserveError::Unavailable)?;
    if matches!(source, ExtendedInput::Message(_)) && routes.remapping.is_none() {
        return Err(ReserveError::Unavailable);
    }
    let mut extended = routes.extended.lock();
    let mut first = true;
    for (index, slot) in extended.iter_mut().enumerate() {
        if let Some(old) = slot {
            // Drain deliveries issued before masking before reusing a vector
            // for another input or reprogramming the retired pin.
            if old.lease == Lease::Retired && old.source.idle() {
                if let Some(mapping) = &routes.remapping {
                    mapping
                        .table
                        .retire(extended_line(index))
                        .map_err(|_| ReserveError::RemappingFailed)?;
                }
                // Interrupt-cache invalidation drains the remapper before
                // checking the receiving CPU for the previous delivery.
                let vector = VECTOR_BASE + extended_line(index);
                // SAFETY: The caller serialized this route update with IF clear.
                if old.source.idle() && unsafe { boot_vector_idle(vector) } {
                    *slot = None;
                    continue;
                }
            }
            if old.source.same_source(source) {
                return Err(ReserveError::Occupied);
            }
            if let ExtendedInput::Message(message) = source {
                if old.lease != Lease::Retired && old.source.is_function(message.function()) {
                    if old.lease == Lease::Quarantined {
                        return Err(ReserveError::Occupied);
                    }
                    first = false;
                }
            }
        }
    }
    if let ExtendedInput::Message(Message::Msix(msix)) = source {
        if first && !msix.initially_disabled() {
            return Err(ReserveError::DeviceFailed);
        }
    }
    let (index, slot) = extended
        .iter_mut()
        .enumerate()
        .find(|(_, slot)| slot.is_none())
        .ok_or(ReserveError::NoVector)?;
    let line = extended_line(index);
    let remap_index = if let Some(mapping) = &routes.remapping {
        match source {
            ExtendedInput::Gsi { input, .. } => mapping.stage(input, line, routes.local.id()),
            ExtendedInput::Message(message) => mapping.table.stage(
                line,
                message.function(),
                VECTOR_BASE + line,
                routes.local.id(),
                false,
            ),
        }
        if mapping.table.sync().is_err() {
            *slot = Some(ExtendedRoute {
                source,
                lease: Lease::Quarantined,
            });
            return Err(ReserveError::RemappingFailed);
        }
        Some(line)
    } else {
        None
    };
    match source {
        ExtendedInput::Gsi { input, .. } => {
            input.configure(VECTOR_BASE + line, routes.local.id(), remap_index);
        }
        ExtendedInput::Message(message) => {
            // VT-d §5.1.5.2. SHV=1 with a zero subhandle selects this IRTE.
            let address = 0xfee0_0018 | (u32::from(line) << 5);
            if !message.program(address, first) {
                let lease = if stop_message(routes, message, line, first) {
                    Lease::Retired
                } else {
                    Lease::Quarantined
                };
                *slot = Some(ExtendedRoute { source, lease });
                return Err(ReserveError::DeviceFailed);
            }
        }
    }
    *slot = Some(ExtendedRoute {
        source,
        lease: Lease::Live,
    });
    Ok(u32::from(line))
}

/// Mask a released route. On failure the caller must keep its PCI lease pinned.
pub fn release_extended(line: u32) -> bool {
    let Some((routes, index)) = extended_index(line) else {
        return true;
    };
    let mut extended = routes.extended.lock();
    let Some(route) = extended[index] else {
        return true;
    };
    let stopped = match route.source {
        ExtendedInput::Gsi { input, .. } => {
            input.set_enabled(false);
            true
        }
        ExtendedInput::Message(message) => {
            let last = !extended.iter().enumerate().any(|(other, route)| {
                other != index
                    && route.is_some_and(|route| {
                        route.lease != Lease::Retired
                            && route.source.is_function(message.function())
                    })
            });
            stop_message(routes, message, line as u8, last)
        }
    };
    let lease = if stopped {
        Lease::Retired
    } else {
        Lease::Quarantined
    };
    extended[index] = Some(ExtendedRoute { lease, ..route });
    stopped
}

fn stop_message(routes: &ApicRoutes, message: Message, line: u8, last: bool) -> bool {
    let disabled = message.set_enabled(false);
    let table = routes.remapping.as_ref().expect("MSI uses remapping").table;
    // Attempt to block the IRTE even if the endpoint did not confirm masking.
    let drained = table.retire(line).is_ok();
    disabled && drained && message.finish(last)
}

/// Whether this logical line carries PCI interrupt messages.
pub fn is_message_irq(line: u32) -> bool {
    extended_index(line).is_some_and(|(routes, index)| {
        routes.extended.lock()[index]
            .is_some_and(|route| matches!(route.source, ExtendedInput::Message(_)))
    })
}

fn extended_index(line: u32) -> Option<(&'static ApicRoutes, usize)> {
    let index = (line as usize).checked_sub(ISA_IRQ_COUNT)?;
    (line < IRQ_COUNT as u32).then_some((APIC.get()?, index))
}

fn extended_line(index: usize) -> u8 {
    (ISA_IRQ_COUNT + index) as u8
}

/// Consume an 8259A spurious delivery if the legacy PIC is in use.
pub fn dismiss_spurious(line: u8) -> bool {
    APIC.get().is_none() && pic::dismiss_spurious(line)
}

/// x86_64 interrupt controller for the boot CPU.
pub struct X86_64IrqController;

impl IrqController for X86_64IrqController {
    fn enable(irq: IrqNumber) {
        let _ = set_enabled(irq.0, true);
    }

    fn disable(irq: IrqNumber) {
        let _ = set_enabled(irq.0, false);
    }

    fn route(_irq: IrqNumber, _cpu: u32) {
        // Both backends deliver to the bootstrap CPU.
    }

    fn end_of_interrupt(irq: IrqNumber) {
        if irq.0 < IRQ_COUNT as u32 {
            match APIC.get() {
                Some(routes) => routes.local.end_of_interrupt(),
                None if irq.0 < ISA_IRQ_COUNT as u32 => pic::send_eoi(irq.0 as u8),
                None => {}
            }
        }
    }
}

/// Change a route's delivery state and report any hardware failure.
pub fn set_enabled(line: u32, enabled: bool) -> Result<(), ReserveError> {
    match APIC.get() {
        Some(routes) => {
            let line = line as usize;
            if let Some(index) = line.checked_sub(ISA_IRQ_COUNT) {
                let mut extended = routes.extended.lock();
                let Some(Some(route)) = extended.get_mut(index) else {
                    return Ok(());
                };
                if route.lease != Lease::Live {
                    return Err(ReserveError::Unavailable);
                }
                match route.source {
                    ExtendedInput::Gsi { input, .. } => input.set_enabled(enabled),
                    ExtendedInput::Message(message) => {
                        let table = routes.remapping.as_ref().expect("MSI uses remapping").table;
                        if enabled {
                            // Complete old messages before allowing a new binding.
                            table.sync().map_err(|_| ReserveError::RemappingFailed)?;
                            // SAFETY: Capability IRQ transitions run inside the
                            // kernel's serialized entry with interrupts disabled.
                            if !unsafe { boot_vector_idle(VECTOR_BASE + line as u8) } {
                                return Err(ReserveError::PendingDelivery);
                            }
                        }
                        if !message.set_enabled(enabled) {
                            route.lease = Lease::Quarantined;
                            let _ = table.retire(line as u8);
                            return Err(ReserveError::DeviceFailed);
                        }
                    }
                };
            } else if let Some(input) = routes.inputs[line] {
                input.set_enabled(enabled);
            }
        }
        None => pic::set_enabled(line, enabled),
    }
    Ok(())
}
