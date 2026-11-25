//! x86 control-flow enforcement setup.

use x86_64::registers::{
    control::{Cr4, Cr4Flags},
    model_specific::Msr,
};

const IA32_U_CET: u32 = 0x6a0;
const IA32_S_CET: u32 = 0x6a2;
const IA32_PL3_SSP: u32 = 0x6a7;
const SHADOW_STACK_ENABLED: u64 = 1;
const END_BRANCH_ENABLED: u64 = 1 << 2;

/// Active supervisor IBT and availability of user shadow stacks on one CPU.
pub struct Features {
    /// Supervisor indirect branch tracking is active.
    pub supervisor_ibt: bool,
    /// This CPU can run user threads with shadow stacks.
    pub user_shadow_stack: bool,
}

/// Set up the supported control-flow enforcement features on the calling CPU.
///
/// # Safety
/// Run with interrupts disabled and the kernel IDT installed. If the image is
/// instrumented, every tracked indirect kernel target must start with ENDBR64.
pub unsafe fn init(instrumented: bool) -> Features {
    let mut active = Features {
        supervisor_ibt: false,
        user_shadow_stack: false,
    };
    if core::arch::x86_64::__cpuid(0).eax < 7 {
        return active;
    }
    let cpuid = core::arch::x86_64::__cpuid_count(7, 0);
    let ibt = instrumented && cpuid.edx & (1 << 20) != 0;
    let shstk = cpuid.ecx & (1 << 7) != 0;
    if !ibt && !shstk {
        return active;
    }
    let supervisor = if ibt { END_BRANCH_ENABLED } else { 0 };
    // SAFETY: CPUID enumerates CET and the kernel installed its #CP gate.
    // Keep user CET off until the scheduler prepares that thread's SSP.
    let supervisor = unsafe {
        Msr::new(IA32_U_CET).write(0);
        Msr::new(IA32_S_CET).write(supervisor);
        Cr4::update(|flags| flags.insert(Cr4Flags::CONTROL_FLOW_ENFORCEMENT));
        Msr::new(IA32_S_CET).read()
    };
    if Cr4::read().contains(Cr4Flags::CONTROL_FLOW_ENFORCEMENT) {
        active.supervisor_ibt = supervisor & END_BRANCH_ENABLED != 0;
        active.user_shadow_stack = shstk;
    }
    active
}

/// Read the shadow-stack pointer saved by a user-to-kernel transition.
///
/// # Safety
/// User shadow stacks must be active on this CPU and this thread must still
/// own the saved ring-3 state. Call before handling a trap that can schedule.
pub unsafe fn saved_user_ssp() -> u64 {
    // SAFETY: The caller has established MSR support and current ownership.
    unsafe { Msr::new(IA32_PL3_SSP).read() }
}

/// Install the incoming user shadow-stack pointer before IRET.
///
/// # Safety
/// Run with interrupts disabled on a CPU set up with shadow-stack support.
/// The incoming thread must own the canonical, aligned shadow-stack pointer.
pub unsafe fn restore_user_ssp(ssp: u64) {
    // SAFETY: CPU support and SSP validity are the caller's responsibility.
    unsafe {
        Msr::new(IA32_PL3_SSP).write(ssp);
        Msr::new(IA32_U_CET).write(SHADOW_STACK_ENABLED);
    }
}
