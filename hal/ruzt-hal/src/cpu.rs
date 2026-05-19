//! CPU operations and interrupt control.
//!
//! SOURCE: Design Report §8 — CpuOps trait

/// RAII guard that re-enables interrupts when dropped.
///
/// Implementations must store the prior interrupt flag and restore it on drop.
#[allow(drop_bounds)]
pub trait InterruptGuard: Drop {}

/// Architecture-generic CPU operations.
// SOURCE: Design Report §8 — CpuOps trait skeleton
pub trait CpuOps {
    /// The guard type returned by [`disable_interrupts`](CpuOps::disable_interrupts).
    type Guard: InterruptGuard;

    /// Return the logical CPU identifier for the current core.
    fn cpu_id() -> u32;
    /// Halt the CPU until the next interrupt (power-saving idle).
    fn cpu_idle();
    /// Enable interrupts unconditionally.
    ///
    /// # Safety
    /// Must only be called from a context where interrupts are safe to receive.
    fn enable_interrupts();
    /// Disable interrupts and return a guard that re-enables them on drop.
    fn disable_interrupts() -> Self::Guard;
}
