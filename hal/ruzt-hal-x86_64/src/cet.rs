//! x86 control-flow enforcement setup.

use x86_64::registers::{
    control::{Cr4, Cr4Flags},
    model_specific::Msr,
};

const IA32_U_CET: u32 = 0x6a0;
const IA32_S_CET: u32 = 0x6a2;
const END_BRANCH_ENABLED: u64 = 1 << 2;

/// Enable supervisor indirect branch tracking on the calling CPU.
///
/// # Safety
/// Run with interrupts disabled and the kernel IDT installed. If the image is
/// instrumented, every tracked indirect kernel target must start with ENDBR64.
pub unsafe fn enable_kernel_ibt(instrumented: bool) -> bool {
    let supported = core::arch::x86_64::__cpuid(0).eax >= 7
        && (core::arch::x86_64::__cpuid_count(7, 0).edx & (1 << 20)) != 0;
    if !instrumented || !supported {
        return false;
    }
    // SAFETY: CPUID enumerates CET IBT and the kernel installed its #CP gate.
    unsafe {
        Msr::new(IA32_U_CET).write(0);
        Msr::new(IA32_S_CET).write(END_BRANCH_ENABLED);
        Cr4::update(|flags| flags.insert(Cr4Flags::CONTROL_FLOW_ENFORCEMENT));
    }
    Cr4::read().contains(Cr4Flags::CONTROL_FLOW_ENFORCEMENT)
        // SAFETY: The same CPUID check authorizes reading the enabled MSR.
        && unsafe { Msr::new(IA32_S_CET).read() } & END_BRANCH_ENABLED != 0
}
