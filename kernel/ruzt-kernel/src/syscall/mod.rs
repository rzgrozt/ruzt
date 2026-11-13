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
#[no_mangle]
pub extern "C" fn syscall_dispatch(args: &SyscallArgs) -> u64 {
    match SyscallNumber::from(args.number) {
        SyscallNumber::Invoke => invoke::invoke(args),
        SyscallNumber::DebugPutChar => {
            let byte = args.arg0 as u8;
            crate::serial::SERIAL1.lock().send(byte);
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
        let ret = syscall_dispatch(&args);
        assert_eq!(ret, ErrorCode::NotImplemented.as_u64());
    }

    #[test]
    fn user_entry_state_round_trips_when_process_sets_initial_context() {
        // Given: a validated initial user machine state.
        // When: process creation publishes the three entry registers.
        set_user_entry(0x400000, 0x8000fff8, 0x12345000);
        let entry = user_entry();
        // Then: ring-3 handoff observes the exact values together.
        assert_eq!(entry.rip, 0x400000);
        assert_eq!(entry.rsp, 0x8000fff8);
        assert_eq!(entry.cr3, 0x12345000);
    }
}
