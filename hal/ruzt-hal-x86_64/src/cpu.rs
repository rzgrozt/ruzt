//! x86_64 [`CpuOps`] and [`InterruptGuard`] implementation.

use ruzt_hal::cpu::{CpuOps, InterruptGuard};
use x86_64::instructions::interrupts;

/// Stores the prior interrupt-enable flag and restores it on drop.
pub struct X86_64InterruptGuard {
    if_enabled: bool,
}

impl Drop for X86_64InterruptGuard {
    fn drop(&mut self) {
        if self.if_enabled {
            interrupts::enable();
        }
    }
}

impl InterruptGuard for X86_64InterruptGuard {}

/// x86_64 implementation of [`CpuOps`].
pub struct X86_64Cpu;

impl CpuOps for X86_64Cpu {
    type Guard = X86_64InterruptGuard;

    fn cpu_id() -> u32 {
        // SAFETY: [Category 13 - Library contract] CPUID leaf 1 is defined on
        // every x86_64 CPU, so executing this intrinsic has a valid leaf.
        let cpuid = unsafe { core::arch::x86_64::__cpuid(1) };
        // APIC ID is in EBX[31:24].
        (cpuid.ebx >> 24) as u32
    }

    fn cpu_idle() {
        // `hlt` is safe in x86_64 crate 0.15.
        x86_64::instructions::hlt();
    }

    fn enable_interrupts() {
        interrupts::enable();
    }

    fn disable_interrupts() -> Self::Guard {
        let if_enabled = interrupts::are_enabled();
        interrupts::disable();
        X86_64InterruptGuard { if_enabled }
    }
}

/// Trigger QEMU isa-debug-exit shutdown.
///
/// This function never returns.
pub fn qemu_shutdown() -> ! {
    // SAFETY: I/O port 0xf4 is the QEMU isa-debug-exit device.
    // Writing 0x10 triggers a clean shutdown in QEMU test mode.
    unsafe {
        x86_64::instructions::port::PortWriteOnly::new(0xf4).write(0x10u32);
    }
    loop {
        x86_64::instructions::hlt();
    }
}
