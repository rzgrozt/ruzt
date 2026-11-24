//! IRQ delivery through the I/O APIC or cascaded 8259A PICs.

use ruzt_hal::irq::{IrqController, IrqNumber};
use spin::{Mutex, Once};

use crate::{
    apic::{Input, IoApic, LocalApic},
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
    extended: Mutex<[Option<GsiInput>; IRQ_COUNT - ISA_IRQ_COUNT]>,
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
struct GsiInput {
    gsi: u32,
    input: Input,
    retired: bool,
}

/// Why an extended I/O APIC line could not be reserved.
#[derive(Debug, PartialEq, Eq)]
pub enum ReserveError {
    /// The I/O APIC backend is inactive.
    Unavailable,
    /// This GSI is claimed or its previous delivery is still draining.
    Occupied,
    /// All extended IRQ vectors are in use or draining.
    NoVector,
    /// The remapper failed to synchronize its table.
    RemappingFailed,
}

static APIC: Once<ApicRoutes> = Once::new();

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
/// Call on the boot CPU with local interrupts disabled. The input must
/// designate this GSI's unique controller pin, outside the ISA and NMI routes.
pub unsafe fn reserve_gsi(gsi: u32, input: Input) -> Result<u32, ReserveError> {
    let routes = APIC.get().ok_or(ReserveError::Unavailable)?;
    let mut extended = routes.extended.lock();
    for (index, slot) in extended.iter_mut().enumerate() {
        if let Some(old) = slot {
            // Drain deliveries issued before masking before reusing a vector
            // for another input or reprogramming the retired pin.
            if old.retired && old.input.delivery_idle() {
                if let Some(mapping) = &routes.remapping {
                    mapping
                        .table
                        .retire(extended_line(index))
                        .map_err(|_| ReserveError::RemappingFailed)?;
                }
                // Interrupt-cache invalidation drains the remapper before
                // checking the receiving CPU for the previous delivery.
                if old.input.delivery_idle()
                    && routes.local.vector_idle(VECTOR_BASE + extended_line(index))
                {
                    *slot = None;
                    continue;
                }
            }
            if old.gsi == gsi {
                return Err(ReserveError::Occupied);
            }
        }
    }
    let (index, slot) = extended
        .iter_mut()
        .enumerate()
        .find(|(_, slot)| slot.is_none())
        .ok_or(ReserveError::NoVector)?;
    let line = extended_line(index);
    let remap_index = if let Some(mapping) = &routes.remapping {
        mapping.stage(input, line, routes.local.id());
        if mapping.table.sync().is_err() {
            *slot = Some(GsiInput {
                gsi,
                input,
                retired: true,
            });
            return Err(ReserveError::RemappingFailed);
        }
        Some(line)
    } else {
        None
    };
    input.configure(VECTOR_BASE + line, routes.local.id(), remap_index);
    *slot = Some(GsiInput {
        gsi,
        input,
        retired: false,
    });
    Ok(u32::from(line))
}

/// Mask a released extended route and retire its vector.
pub fn release_gsi(line: u32) {
    if let Some(index) = (line as usize).checked_sub(ISA_IRQ_COUNT) {
        if let Some(routes) = APIC.get() {
            if let Some(Some(route)) = routes.extended.lock().get_mut(index) {
                route.input.set_enabled(false);
                route.retired = true;
            }
        }
    }
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
        set_enabled(irq.0, true);
    }

    fn disable(irq: IrqNumber) {
        set_enabled(irq.0, false);
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

fn set_enabled(line: u32, enabled: bool) {
    match APIC.get() {
        Some(routes) => {
            let line = line as usize;
            if let Some(index) = line.checked_sub(ISA_IRQ_COUNT) {
                if let Some(Some(route)) = routes.extended.lock().get(index) {
                    if !route.retired {
                        route.input.set_enabled(enabled);
                    }
                }
            } else if let Some(input) = routes.inputs[line] {
                input.set_enabled(enabled);
            }
        }
        None => pic::set_enabled(line, enabled),
    }
}
