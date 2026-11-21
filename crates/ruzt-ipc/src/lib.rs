#![no_std]
#![deny(unsafe_code)]

use ruzt_abi::{CapOp, CapRights, ErrorCode, IpcMessage, SyscallNumber};

pub fn send(endpoint_cptr: u64, message: &IpcMessage) -> Result<(), ErrorCode> {
    let return_value = {
        #[allow(unsafe_code)]
        // SAFETY: [Category 13 - Library contract] The immutable borrow keeps
        // the complete message readable for the synchronous `Send` operation.
        unsafe {
            ruzt_runtime::syscall::syscall(
                SyscallNumber::Invoke,
                endpoint_cptr,
                CapOp::Send as u64,
                message as *const IpcMessage as u64,
                0,
                0,
                0,
            )
        }
    };

    ErrorCode::from_u64(return_value)
}

pub fn recv(endpoint_cptr: u64, message: &mut IpcMessage) -> Result<(), ErrorCode> {
    let return_value = {
        #[allow(unsafe_code)]
        // SAFETY: [Categories 1 and 13 - aliasing and library contract] The
        // exclusive borrow keeps the complete message uniquely writable for
        // the synchronous `Recv` operation and prevents aliasing accesses.
        unsafe {
            ruzt_runtime::syscall::syscall(
                SyscallNumber::Invoke,
                endpoint_cptr,
                CapOp::Recv as u64,
                message as *mut IpcMessage as u64,
                0,
                0,
                0,
            )
        }
    };

    ErrorCode::from_u64(return_value)
}

/// Derive a capability in an empty slot of the caller's capability space.
pub fn mint(source: u64, destination: u64, rights: CapRights, badge: u64) -> Result<(), ErrorCode> {
    control(
        source,
        CapOp::Mint,
        destination,
        u64::from(rights.bits()),
        badge,
    )
}

/// Move a capability to an empty slot in the same capability space.
pub fn move_cap(source: u64, destination: u64) -> Result<(), ErrorCode> {
    control(source, CapOp::Move, destination, 0, 0)
}

/// Delete the capability in this slot.
pub fn delete(cptr: u64) -> Result<(), ErrorCode> {
    control(cptr, CapOp::Delete, 0, 0, 0)
}

/// Revoke all descendants while keeping the invoked capability.
pub fn revoke(cptr: u64) -> Result<(), ErrorCode> {
    control(cptr, CapOp::Revoke, 0, 0, 0)
}

#[allow(unsafe_code)]
fn control(cptr: u64, op: CapOp, arg2: u64, arg3: u64, arg4: u64) -> Result<(), ErrorCode> {
    // SAFETY: These capability-space operations take scalar arguments only.
    let status = unsafe {
        ruzt_runtime::syscall::syscall(SyscallNumber::Invoke, cptr, op as u64, arg2, arg3, arg4, 0)
    };
    ErrorCode::from_u64(status)
}
