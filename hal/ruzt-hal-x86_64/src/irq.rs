//! 8259A PIC-based interrupt controller for x86_64.

use ruzt_hal::irq::{IrqController, IrqNumber};

/// x86_64 interrupt controller backed by the cascaded 8259A PIC.
pub struct X86_64IrqController;

impl IrqController for X86_64IrqController {
    fn enable(irq: IrqNumber) {
        crate::pic::set_enabled(irq.0, true);
    }

    fn disable(irq: IrqNumber) {
        crate::pic::set_enabled(irq.0, false);
    }

    fn route(_irq: IrqNumber, _cpu: u32) {
        // The PIC has a single CPU delivery path.
    }

    fn end_of_interrupt(irq: IrqNumber) {
        if irq.0 < crate::pic::IRQ_COUNT as u32 {
            crate::pic::send_eoi(irq.0 as u8);
        }
    }
}
