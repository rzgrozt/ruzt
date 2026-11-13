#![no_std]
#![deny(unsafe_code)]

use ruzt_abi::{CapOp, ErrorCode, IpcMessage, SyscallNumber};

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
