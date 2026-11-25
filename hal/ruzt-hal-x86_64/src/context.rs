//! x86_64 context switch.

use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};

/// The x87, MMX, and SSE state of one thread.
#[repr(C, align(16))]
pub struct FpState([u8; 512]);

impl Default for FpState {
    fn default() -> Self {
        // Intel SDM Vol. 1, FXSAVE/FXRSTOR layout and reset state.
        // The x87 tag word is empty, and the SSE registers are zero.
        let mut bytes = [0; 512];
        bytes[..2].copy_from_slice(&0x037fu16.to_le_bytes());
        bytes[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
        Self(bytes)
    }
}

/// Enable the register state supported by the context switch.
///
/// # Safety
/// Call once on every CPU before running user code or switching threads.
/// Kernel code must use the soft-float target, including interrupt handlers.
pub unsafe fn init_fp() {
    // SAFETY: At boot no thread owns the CPU's floating-point state. FXSAVE
    // is available on x86_64. Keep extended state and user TLS base writes
    // disabled until the scheduler can preserve them.
    unsafe {
        Cr4::update(|flags| {
            flags.insert(Cr4Flags::OSFXSR | Cr4Flags::OSXMMEXCPT_ENABLE);
            flags.remove(Cr4Flags::OSXSAVE | Cr4Flags::FSGSBASE);
        });
        Cr0::update(|flags| {
            flags.insert(Cr0Flags::MONITOR_COPROCESSOR | Cr0Flags::NUMERIC_ERROR);
            flags.remove(Cr0Flags::EMULATE_COPROCESSOR | Cr0Flags::TASK_SWITCHED);
        });
    }
}

/// Read the active page-table root and its CR3 flags.
pub fn current_cr3() -> u64 {
    let (frame, flags) = x86_64::registers::control::Cr3::read_raw();
    frame.start_address().as_u64() | u64::from(flags)
}

/// Set up a fresh kernel stack so that the first context switch into it
/// "returns" into `entry`.
///
/// The initial stack frame contains dummy callee-saved registers and the
/// thread entry point as the return address. After it is popped, the entry
/// function sees the System V ABI's eight-byte stack bias.
/// See [AMD64 psABI §3.2.2](https://gitlab.com/x86-psABIs/x86-64-ABI).
///
/// # Safety
/// `stack` must be at least 79 bytes long and must remain valid and
/// exclusively owned by the thread until the thread exits.
pub unsafe fn init_stack(stack: &mut [u8], entry: fn() -> !) -> u64 {
    assert!(
        stack.len() >= 79,
        "stack too small (need at least 79 bytes)"
    );
    let top = stack.as_mut_ptr() as u64 + stack.len() as u64;
    let aligned_top = top & !0xF;
    let rsp = aligned_top - 64;

    let slots = rsp as *mut u64;
    // SAFETY: [Categories 1/3/6/10 - Aliasing, dangling, alignment, bounds]
    // `&mut stack` is exclusive, `rsp` is 16-byte aligned, and the 79-byte
    // minimum leaves all seven u64 slots and the return bias inside the stack.
    let frame = unsafe { core::slice::from_raw_parts_mut(slots, 7) };
    frame.fill(0);
    frame[6] = entry as usize as u64;
    rsp
}

/// Perform a context switch.
///
/// Saves the current stack and floating-point state and restores the next
/// thread's address space, stack, and registers. Calls `finish` on the new
/// stack after the outgoing context and address space are no longer active.
///
/// # Safety
/// - `old_rsp` must point to a valid, writable `u64`.
/// - `new_rsp` must point to a frame from [`init_stack`] or a previous switch,
///   with sufficient writable stack below it to call `finish`.
/// - `new_cr3` must be valid and map the kernel and both kernel stacks.
/// - `old_fp` and `new_fp` must point to distinct, aligned kernel-owned
///   states mapped in both address spaces. Call [`init_fp`] before switching.
/// - Interrupts must be disabled by the caller.
/// - The current thread's stack must remain live until `finish` is entered.
/// - `finish` must return with interrupts still disabled. It may publish the
///   saved context or release its scheduler lock, so `switch` does not access
///   the outgoing context after the call.
#[unsafe(naked)]
pub unsafe extern "C" fn switch(
    _old_rsp: *mut u64,
    _new_rsp: u64,
    _new_cr3: u64,
    _old_fp: *mut FpState,
    _new_fp: *const FpState,
    _finish: extern "C" fn(),
) {
    // SAFETY: [Categories 3/6/10/13 - Dangling, alignment, bounds, library
    // contract] The caller provides writable `rdi`, a frame-aligned `rsi`
    // created by `init_stack` or `switch`, and disabled interrupts. Each push,
    // pop, and the final return stays within those live kernel stacks.
    core::arch::naked_asm!(
        "endbr64",
        "push rbp",
        "push rbx",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov [rdi], rsp",
        "fxsave64 [rcx]",
        "mov rax, cr3",
        "cmp rax, rdx",
        "je 2f",
        "mov cr3, rdx",
        "2:",
        "fxrstor64 [r8]",
        "mov rsp, rsi",
        // The saved and initial frames have different stack alignment.
        // Keep the exact frame pointer in a callee-saved register until the
        // callback returns, then restore the incoming thread's registers.
        "mov r12, rsp",
        "and rsp, -16",
        "call r9",
        "mov rsp, r12",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbx",
        "pop rbp",
        "ret",
    );
}

#[cfg(test)]
mod tests {
    fn entry() -> ! {
        panic!("test entry should never run")
    }

    #[test]
    fn initial_context_has_system_v_entry_alignment() {
        let mut stack = [0u8; 79];
        // SAFETY: The frame is built and inspected in this stack allocation.
        let rsp = unsafe { super::init_stack(&mut stack, entry) };
        assert_eq!((rsp + 7 * size_of::<u64>() as u64) % 16, 8);
    }
}
