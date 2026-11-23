#![allow(unsafe_code)]

use core::arch::asm;

use ruzt_abi::{ErrorCode, SyscallNumber};

/// Enter the kernel with one register-encoded system call.
///
/// # Safety
///
/// The caller must ensure that pointer-valued arguments identify memory valid
/// for the access implied by `number`, and that execution is in Ruzt ring
/// 3 with interrupt vector `0x80` installed as the syscall entry point.
#[inline]
pub unsafe fn syscall(
    number: SyscallNumber,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> u64 {
    let mut rax = number as u64;

    // SAFETY: [Category 13 - Library contract] The caller supplies arguments
    // satisfying the documented syscall contract. Each operand is assigned to
    // its ABI register, and the Ruzt kernel returns through the same frame.
    unsafe {
        asm!(
            "int 0x80",
            inout("rax") rax,
            in("rdi") arg0,
            in("rsi") arg1,
            in("rdx") arg2,
            in("r10") arg3,
            in("r8") arg4,
            in("r9") arg5,
            options(nostack, preserves_flags),
        );
    }

    rax
}

#[inline]
pub fn debug_putchar(byte: u8) {
    // SAFETY: [Category 13 - Library contract] `DebugPutChar` accepts one byte
    // by value and dereferences no user pointers; every remaining argument is
    // zero, so this call satisfies the operation-specific kernel contract.
    let _ = unsafe {
        syscall(
            SyscallNumber::DebugPutChar,
            u64::from(byte),
            0,
            0,
            0,
            0,
            0,
        )
    };
}

/// Read the current monotonic time in nanoseconds since boot.
pub fn monotonic_ns() -> Result<u64, ErrorCode> {
    let mut timestamp = 0u64;
    // SAFETY: The timestamp is exclusively writable for the entire call.
    let status = unsafe {
        syscall(
            SyscallNumber::MonotonicTime,
            (&raw mut timestamp) as u64,
            0,
            0,
            0,
            0,
            0,
        )
    };
    ErrorCode::from_u64(status)?;
    Ok(timestamp)
}

/// Sleep until an absolute deadline on the monotonic clock.
pub fn sleep_until(deadline_ns: u64) -> Result<(), ErrorCode> {
    // SAFETY: An empty wait list requires no input or output buffers.
    let status = unsafe { syscall(SyscallNumber::WaitAnyUntil, 0, 0, 0, 0, 0, deadline_ns) };
    match ErrorCode::from_u64(status) {
        Err(ErrorCode::TimedOut) => Ok(()),
        other => other,
    }
}

/// Terminate the calling user task.
pub fn exit(status: u32) -> ! {
    // SAFETY: Exit takes a scalar status and has no memory operands.
    let _ = unsafe { syscall(SyscallNumber::Exit, u64::from(status), 0, 0, 0, 0, 0) };
    loop {
        core::hint::spin_loop();
    }
}
