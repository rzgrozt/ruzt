//! aarch64 [`CpuOps`] and [`InterruptGuard`] implementation.

use ruzt_hal::cpu::{CpuOps, InterruptGuard};

/// Stores the prior interrupt-enable flag and restores it on drop.
pub struct AArch64InterruptGuard {
    were_enabled: bool,
}

impl Drop for AArch64InterruptGuard {
    fn drop(&mut self) {
        if self.were_enabled {
            unsafe { core::arch::asm!("msr daifclr, #2"); }
        }
    }
}

impl InterruptGuard for AArch64InterruptGuard {}

/// Check whether interrupts are currently enabled.
fn interrupts_enabled() -> bool {
    let daif: u64;
    unsafe { core::arch::asm!("mrs {}, daif", out(reg) daif); }
    (daif & (1 << 7)) == 0
}

/// aarch64 implementation of [`CpuOps`].
pub struct AArch64Cpu;

impl CpuOps for AArch64Cpu {
    type Guard = AArch64InterruptGuard;

    fn cpu_id() -> u32 {
        let mpidr: u64;
        unsafe { core::arch::asm!("mrs {}, mpidr_el1", out(reg) mpidr); }
        (mpidr & 0xFF) as u32
    }

    fn cpu_idle() {
        unsafe { core::arch::asm!("wfi"); }
    }

    fn enable_interrupts() {
        unsafe { core::arch::asm!("msr daifclr, #2"); }
    }

    fn disable_interrupts() -> Self::Guard {
        let were_enabled = interrupts_enabled();
        unsafe { core::arch::asm!("msr daifset, #2"); }
        AArch64InterruptGuard { were_enabled }
    }
}
