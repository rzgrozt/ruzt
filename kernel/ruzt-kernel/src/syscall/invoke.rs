//! Invoke dispatcher — routes capability operations to their handlers.

use ruzt_abi::{ErrorCode as AbiErrorCode, SyscallArgs};
use ruzt_cap::CapType;

use crate::cap::ops::{CapOp, cap_delete, cap_mint, cap_move, cap_retype};

/// The `invoke` syscall handler.
///
/// Reads the capability pointer from the current thread's CSpace, decodes the
/// operation, and dispatches to the appropriate handler.
pub fn invoke(args: &SyscallArgs) -> u64 {
    crate::serial_println!("invoke: cptr={} op={}", args.arg0, args.arg1);
    let cptr = args.arg0;
    let op = CapOp::from(args.arg1, args);
    crate::serial_println!("invoke: op={:?}", op);

    let slot = {
        let mut guard = crate::cap::cspace::kernel_cspace();
        let cspace = guard.as_mut().expect("kernel cspace not initialised");
        match cspace.lookup(cptr) {
            Ok(s) => *s,
            Err(e) => return e.as_u64(),
        }
    };
    crate::serial_println!("invoke: cap_type={:?}", slot.cap_type);

    match op {
        CapOp::Delete { cptr } => {
            let mut guard = crate::cap::cspace::kernel_cspace();
            let cspace = guard.as_mut().expect("kernel cspace not initialised");
            match cap_delete(cspace, cptr) {
                Ok(()) => AbiErrorCode::Ok.as_u64(),
                Err(e) => e.as_u64(),
            }
        }
        CapOp::Retype { src_cptr, dest_cptr, new_type } => {
            let mut guard = crate::cap::cspace::kernel_cspace();
            let cspace = guard.as_mut().expect("kernel cspace not initialised");
            match cap_retype(cspace, src_cptr, dest_cptr, new_type) {
                Ok(()) => AbiErrorCode::Ok.as_u64(),
                Err(e) => e.as_u64(),
            }
        }
        CapOp::Mint { src_cptr, dest_cptr, new_rights, badge } => {
            let mut guard = crate::cap::cspace::kernel_cspace();
            let cspace = guard.as_mut().expect("kernel cspace not initialised");
            match cap_mint(cspace, src_cptr, dest_cptr, new_rights, badge) {
                Ok(()) => AbiErrorCode::Ok.as_u64(),
                Err(e) => e.as_u64(),
            }
        }
        CapOp::Move { src_cptr, dest_cptr } => {
            let mut guard = crate::cap::cspace::kernel_cspace();
            let cspace = guard.as_mut().expect("kernel cspace not initialised");
            match cap_move(cspace, src_cptr, dest_cptr) {
                Ok(()) => AbiErrorCode::Ok.as_u64(),
                Err(e) => e.as_u64(),
            }
        }
        CapOp::Send => {
            match slot.cap_type {
                CapType::Endpoint(id) => crate::ipc::endpoint_send(id, args),
                _ => AbiErrorCode::InvalidCap.as_u64(),
            }
        }
        CapOp::Recv => {
            match slot.cap_type {
                CapType::Endpoint(id) => crate::ipc::endpoint_recv(id, args),
                _ => AbiErrorCode::InvalidCap.as_u64(),
            }
        }
        CapOp::Signal => {
            match slot.cap_type {
                CapType::Notification(id) => crate::ipc::notification_signal(id),
                _ => AbiErrorCode::InvalidCap.as_u64(),
            }
        }
        CapOp::Wait => {
            match slot.cap_type {
                CapType::Notification(id) => crate::ipc::notification_wait(id),
                _ => AbiErrorCode::InvalidCap.as_u64(),
            }
        }
    }
}
