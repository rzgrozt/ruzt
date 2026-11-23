//! IRQ delivery through the I/O APIC or cascaded 8259A PICs.

use ruzt_hal::irq::{IrqController, IrqNumber};
use spin::Once;

use crate::{
    apic::{Input, IoApic, LocalApic},
    pic,
};

/// The existing ISA logical interrupt namespace.
pub const IRQ_COUNT: usize = 16;
/// Beginning of the logical IRQ vector range in the x86 IDT.
pub const VECTOR_BASE: u8 = 0x20;
/// ISA timer interrupt.
pub const TIMER: usize = 0;
/// ISA keyboard interrupt.
pub const KEYBOARD: usize = 1;
/// The legacy PIC cascade. This logical number is reserved.
pub const CASCADE: usize = 2;

struct ApicRoutes {
    local: LocalApic,
    inputs: [Option<Input>; IRQ_COUNT],
}

static APIC: Once<ApicRoutes> = Once::new();

/// Install a validated APIC configuration and route the PIT and keyboard.
///
/// # Safety
/// Call once with interrupts disabled on the boot CPU, after installing IDT
/// gates for the IRQ range and LAPIC spurious vector. All controller windows
/// must stay mapped uncached, and inputs must refer to unique pins on those
/// controllers. If firmware advertises compatible PICs, set `mask_pics`.
pub unsafe fn install_apic(
    local: LocalApic,
    controllers: impl IntoIterator<Item = IoApic>,
    inputs: [Option<Input>; IRQ_COUNT],
    mask_pics: bool,
) {
    let routes = APIC.call_once(|| {
        for controller in controllers {
            controller.mask_all();
        }
        for (line, input) in inputs.iter().enumerate() {
            if let Some(input) = input {
                input.configure(VECTOR_BASE + line as u8, local.id());
            }
        }
        if mask_pics {
            pic::mask_all();
        }
        local.enable();
        ApicRoutes { local, inputs }
    });
    for line in [TIMER, KEYBOARD] {
        if let Some(input) = routes.inputs[line] {
            input.set_enabled(true);
        }
    }
}

/// Whether this line is a routable device interrupt in the active backend.
pub fn is_device_irq(line: u32) -> bool {
    let line = line as usize;
    line > TIMER
        && line < IRQ_COUNT
        && line != CASCADE
        && APIC
            .get()
            .is_none_or(|routes| routes.inputs[line].is_some())
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
                None => pic::send_eoi(irq.0 as u8),
            }
        }
    }
}

fn set_enabled(line: u32, enabled: bool) {
    match APIC.get() {
        Some(routes) => {
            if let Some(Some(input)) = routes.inputs.get(line as usize) {
                input.set_enabled(enabled);
            }
        }
        None => pic::set_enabled(line, enabled),
    }
}
