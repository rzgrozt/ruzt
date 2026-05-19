//! GICv3 interrupt controller stubs for aarch64.

use ruzt_hal::irq::{IrqController, IrqNumber};

/// aarch64 interrupt controller (GICv3 — stub until Phase 6).
pub struct AArch64IrqController;

impl IrqController for AArch64IrqController {
    fn enable(_irq: IrqNumber) {
        todo!("GICv3 distributor: set enable bit for SPI/PPI. Phase 6.");
    }

    fn disable(_irq: IrqNumber) {
        todo!("GICv3 distributor: clear enable bit for SPI/PPI. Phase 6.");
    }

    fn route(_irq: IrqNumber, _cpu: u32) {
        todo!("GICv3: set affinity routing. Phase 6.");
    }

    fn end_of_interrupt(_irq: IrqNumber) {
        todo!("GICv3: write to ICC_EOIR1_EL1. Phase 6.");
    }
}
