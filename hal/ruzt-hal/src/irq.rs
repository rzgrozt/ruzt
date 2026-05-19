//! Interrupt controller abstraction.
//!
//! SOURCE: Design Report §8 — IrqController trait

/// A logical interrupt request line number, arch-independent.
// SOURCE: Design Report §7.3 — "The kernel exposes a logical IrqNumber;
//   the HAL maps it to APIC vectors on x86_64 or GIC interrupt IDs on aarch64."
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IrqNumber(pub u32);

/// Controls the platform interrupt controller (APIC on x86_64, GIC on aarch64).
// SOURCE: Design Report §8 — IrqController trait skeleton
pub trait IrqController {
    /// Unmask the given IRQ line so interrupts can be received.
    fn enable(irq: IrqNumber);
    /// Mask the given IRQ line.
    fn disable(irq: IrqNumber);
    /// Route an IRQ to the specified CPU.
    fn route(irq: IrqNumber, cpu: u32);
    /// Signal end-of-interrupt to the controller (must be called in every handler).
    fn end_of_interrupt(irq: IrqNumber);
}
