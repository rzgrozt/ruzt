//! Stub interrupt controller for x86_64.

use ruzt_hal::irq::{IrqController, IrqNumber};

/// x86_64 interrupt controller (stub — APIC implementation pending scheduler task).
pub struct X86_64IrqController;

impl IrqController for X86_64IrqController {
    fn enable(_irq: IrqNumber) {
        todo!("APIC enable IRQ")
    }
    fn disable(_irq: IrqNumber) {
        todo!("APIC disable IRQ")
    }
    fn route(_irq: IrqNumber, _cpu: u32) {
        todo!("APIC route IRQ")
    }
    fn end_of_interrupt(_irq: IrqNumber) {
        todo!("APIC EOI")
    }
}
