//! Syscall subsystem — entry, dispatch, and user memory helpers.

#![allow(unsafe_code)]

pub mod invoke;
pub mod user_mem;

use ruzt_abi::{ErrorCode, SyscallArgs, SyscallNumber};

/// Initialise the syscall entry point.
///
/// Called once after IDT initialisation, before any user thread exists.
pub fn init() {
    // For Phase 2.3 the syscall entry is via int 0x80, registered in the
    // IDT by exceptions::init_idt(). No MSR setup required.
    crate::serial_println!("syscall entry initialised.");
}

/// Central syscall dispatch function.
///
/// Called from the interrupt handler with the register state of the caller.
/// Returns the value to be written back into `rax`.
#[inline(never)]
pub(crate) extern "C" fn syscall_dispatch(args: &SyscallArgs, caller_cs: u64) -> u64 {
    let from_user = caller_cs & 3 == 3;
    match SyscallNumber::from(args.number) {
        // The shared kernel CSpace serves only the internal IPC self-test.
        SyscallNumber::Invoke if from_user => crate::ipc::bootstrap::invoke(args)
            .map_or_else(ErrorCode::as_u64, |()| ErrorCode::Ok.as_u64()),
        SyscallNumber::Invoke => invoke::invoke(args),
        SyscallNumber::DebugPutChar => {
            crate::serial::SERIAL1.lock().send(args.arg0 as u8);
            ErrorCode::Ok.as_u64()
        }
        SyscallNumber::NotImplemented | SyscallNumber::_Reply | SyscallNumber::_Yield => {
            ErrorCode::NotImplemented.as_u64()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscall_dispatch_not_implemented() {
        let args = SyscallArgs {
            number: 999,
            arg0: 0,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        };
        let ret = syscall_dispatch(&args, 0);
        assert_eq!(ret, ErrorCode::NotImplemented.as_u64());
    }

    #[test]
    fn user_invoke_cannot_access_kernel_cspace() {
        let args = SyscallArgs {
            number: SyscallNumber::Invoke as u64,
            arg0: 0,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        };
        assert_eq!(
            syscall_dispatch(&args, 0x1b),
            ErrorCode::InvalidCap.as_u64()
        );
    }
}
