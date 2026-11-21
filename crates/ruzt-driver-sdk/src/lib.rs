//! User-space wrappers for capability-gated device access.

#![no_std]

use ruzt_abi::{CapOp, ErrorCode, FramebufferInfo, SyscallNumber};
use ruzt_runtime::syscall::syscall;

/// Sleep until an interrupt is pending, then consume the notification.
pub fn wait_irq(cap: u64) -> Result<(), ErrorCode> {
    // SAFETY: This operation has no memory operands.
    let status = unsafe { syscall(SyscallNumber::Invoke, cap, CapOp::Wait as u64, 0, 0, 0, 0) };
    ErrorCode::from_u64(status)
}

/// Read one byte from the I/O port designated by the capability.
pub fn read_port_u8(cap: u64) -> Result<u8, ErrorCode> {
    let mut byte = 0u8;
    // SAFETY: The kernel has exclusive write access to this byte until the
    // synchronous operation returns.
    let status = unsafe {
        syscall(
            SyscallNumber::Invoke,
            cap,
            CapOp::ReadPort8 as u64,
            &mut byte as *mut u8 as u64,
            0,
            0,
            0,
        )
    };
    ErrorCode::from_u64(status)?;
    Ok(byte)
}

/// Return the address and layout of the framebuffer mapped for this capability.
pub fn framebuffer_info(cap: u64) -> Result<FramebufferInfo, ErrorCode> {
    let mut info = FramebufferInfo::default();
    // SAFETY: The kernel can write this full record before returning, and all
    // bit patterns of the record's integer fields are valid.
    let status = unsafe {
        syscall(
            SyscallNumber::Invoke,
            cap,
            CapOp::FramebufferInfo as u64,
            &mut info as *mut FramebufferInfo as u64,
            0,
            0,
            0,
        )
    };
    ErrorCode::from_u64(status)?;
    Ok(info)
}
