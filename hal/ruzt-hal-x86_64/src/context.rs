//! x86_64 context switch.

use crate::gdt::{USER_CODE_SELECTOR, USER_DATA_SELECTOR};

/// Set up a fresh kernel stack so that the first context switch into it
/// "returns" into `entry`.
///
/// The initial stack frame contains dummy callee-saved registers and the
/// thread entry point as the return address. The resulting `rsp` is
/// 16-byte aligned so the x86_64 ABI is satisfied when the thread function
/// starts executing.
///
/// # Safety
/// `stack` must be at least 71 bytes long and must remain valid and
/// exclusively owned by the thread until the thread exits.
pub unsafe fn init_stack(stack: &mut [u8], entry: fn() -> !) -> u64 {
    assert!(stack.len() >= 71, "stack too small (need at least 71 bytes)");
    let top = stack.as_mut_ptr() as u64 + stack.len() as u64;
    let aligned_top = top & !0xF;
    let rsp = aligned_top - 56;

    let slots = rsp as *mut u64;
    // SAFETY: [Categories 1/3/6/10 - Aliasing, dangling, alignment, bounds]
    // `&mut stack` is exclusive, `rsp` is 8-byte aligned, and the 71-byte
    // minimum leaves all seven u64 slots inside the allocation after aligning.
    let frame = unsafe { core::slice::from_raw_parts_mut(slots, 7) };
    frame.fill(0);
    frame[6] = entry as usize as u64;
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
    // SAFETY: [Categories 3/6/10/13 - Dangling, alignment, bounds, library
    // contract] The caller provides writable `rdi`, a frame-aligned `rsi`
    // created by `init_stack` or `switch`, and disabled interrupts. Each push,
    // pop, and the final return stays within those live kernel stacks.
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

/// Enter ring 3 for the first time through an `iretq` frame.
///
/// The System V inputs are `rdi = user_rip`, `rsi = user_rsp`, and
/// `rdx = user_cr3`. The transition starts userspace with interrupts enabled
/// and all general-purpose registers except RSP cleared.
///
/// # Safety
///
/// [`crate::gdt::init`] must have loaded the expected selectors and a valid
/// TSS RSP0. `user_rip` and `user_rsp` must be canonical and mapped in
/// `user_cr3` as user-executable and user-writable respectively. `user_cr3`
/// must be a valid aligned PML4 root for the current paging mode and must map
/// the current transition code and stack, plus the kernel higher half,
/// GDT, IDT, TSS, and trap stack until `iretq` completes. Fault and NMI entry
/// must be valid throughout the transition because `cli` masks only ordinary
/// interrupts. This function must be called from CPL0 and never returns.
#[unsafe(naked)]
pub unsafe extern "C" fn enter_user(_user_rip: u64, _user_rsp: u64, _user_cr3: u64) -> ! {
    // SAFETY: [Categories 5/13 - Invalid machine state and library contract]
    // The caller contract proves every selector, canonical address, CR3 root,
    // and transient kernel mapping consumed by this privileged sequence. The
    // fixed RFLAGS value exposes only bit 1 and IF, with IOPL, NT, and DF clear.
    core::arch::naked_asm!(
        "cli",
        "push {user_data}",
        "push rsi",
        "push 0x202",
        "push {user_code}",
        "push rdi",
        "mov cr3, rdx",
        "mov ax, {user_data}",
        "mov ds, ax",
        "mov es, ax",
        "mov fs, ax",
        "mov gs, ax",
        "xor eax, eax",
        "xor ebx, ebx",
        "xor ecx, ecx",
        "xor edx, edx",
        "xor esi, esi",
        "xor edi, edi",
        "xor ebp, ebp",
        "xor r8d, r8d",
        "xor r9d, r9d",
        "xor r10d, r10d",
        "xor r11d, r11d",
        "xor r12d, r12d",
        "xor r13d, r13d",
        "xor r14d, r14d",
        "xor r15d, r15d",
        "iretq",
        user_code = const USER_CODE_SELECTOR,
        user_data = const USER_DATA_SELECTOR,
    );
}
