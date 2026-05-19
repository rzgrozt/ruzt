//! x86_64 context switch.

/// Set up a fresh kernel stack so that the first context switch into it
/// "returns" into `entry`.
///
/// The initial stack frame contains dummy callee-saved registers and the
/// thread entry point as the return address. The resulting `rsp` is
/// 16-byte aligned so the x86_64 ABI is satisfied when the thread function
/// starts executing.
///
/// # Safety
/// `stack` must be at least 64 bytes long and must remain valid and
/// exclusively owned by the thread until the thread exits.
pub unsafe fn init_stack(stack: &mut [u8], entry: fn() -> !) -> u64 {
    assert!(stack.len() >= 64, "stack too small (need at least 64 bytes)");
    let top = stack.as_mut_ptr() as u64 + stack.len() as u64;
    let aligned_top = top & !0xF;
    let rsp = aligned_top - 56;

    let slots = rsp as *mut u64;
    // Safety: `rsp` points into `stack`, which is valid for at least 56 bytes.
    unsafe {
        slots.offset(0).write(0);
        slots.offset(1).write(0);
        slots.offset(2).write(0);
        slots.offset(3).write(0);
        slots.offset(4).write(0);
        slots.offset(5).write(0);
        slots.offset(6).write(entry as usize as u64);
    }
    rsp
}

/// Perform a context switch.
///
/// Saves the current thread's callee-saved registers, stores the current
/// stack pointer in `*old_rsp`, loads `new_rsp`, restores the new thread's
/// callee-saved registers, and returns into the new thread.
///
/// # Safety
/// - `old_rsp` must point to a valid, writable `u64`.
/// - `new_rsp` must be a valid stack pointer initialised by [`init_stack`].
/// - Interrupts must be disabled by the caller.
/// - This function never returns to its caller.
#[unsafe(naked)]
pub unsafe extern "C" fn switch(_old_rsp: *mut u64, _new_rsp: u64) {
    // SAFETY: `rdi` (first arg) holds `old_rsp`, a valid writable pointer
    // into the current thread's Thread struct. `rsi` (second arg) holds
    // `new_rsp`, a valid stack pointer set up by `init_stack` or a previous
    // `switch`. Interrupts are disabled by the caller.
    core::arch::naked_asm!(
        "push rbp",
        "push rbx",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov [rdi], rsp",
        "mov rsp, rsi",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbx",
        "pop rbp",
        "ret",
    );
}
