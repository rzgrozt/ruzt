//! Rendezvous IPC primitives — synchronous endpoint send/recv and
//! notification signal/wait.

use ruzt_abi::{ErrorCode, IpcMessage, SyscallArgs};
use ruzt_cap::{EndpointId, NotificationId};

use crate::cap::object::{KObjectId, KernelObject};
use crate::sched;
use crate::syscall::user_mem;

/// Send a message through an endpoint.
///
/// Synchronous rendezvous: if a receiver is already blocked, the message is
/// copied directly and the receiver is unblocked. Otherwise the sender blocks.
pub fn endpoint_send(endpoint_id: EndpointId, args: &SyscallArgs) -> u64 {
    crate::serial_println!("endpoint_send: id={} arg2={:x}", endpoint_id.0, args.arg2);
    let user_ptr = args.arg2;
    let mut msg = IpcMessage {
        label: 0,
        length: 0,
        cap_count: 0,
        flags: 0,
        data: [0; 56],
        caps: [ruzt_abi::CapTransferSlot {
            cptr: 0,
            rights: ruzt_abi::CapRights::empty(),
            badge: 0,
        }; 4],
    };
    if let Err(e) = user_mem::copy_from_user(user_ptr, &mut msg.data) {
        return e.as_u64();
    }
    msg.label = args.arg3;
    msg.length = args.arg4 as u16;

    let id = KObjectId(endpoint_id.0);
    let obj = match crate::cap::object::get(id) {
        Some(o) => o,
        None => return ErrorCode::InvalidCap.as_u64(),
    };

    match obj {
        KernelObject::Endpoint { blocked_receiver, .. } => {
            if let Some(receiver_id) = blocked_receiver {
                // Direct rendezvous: copy message to receiver and unblock.
                crate::sched::set_thread_message(receiver_id, msg);
                crate::sched::unblock(receiver_id);
                crate::cap::object::clear_blocked_receiver(id);
                ErrorCode::Ok.as_u64()
            } else {
                // No receiver waiting: block the sender.
                let sender_id = crate::sched::current_thread_id();
                crate::sched::set_thread_message(sender_id, msg);
                crate::cap::object::set_blocked_sender(id, sender_id);
                crate::sched::block_current(sched::ThreadState::BlockedSend(id));
                ErrorCode::Ok.as_u64()
            }
        }
        _ => ErrorCode::InvalidCap.as_u64(),
    }
}

/// Receive a message through an endpoint.
///
/// Synchronous rendezvous: if a sender is already blocked, the message is
/// copied directly and the sender is unblocked. Otherwise the receiver blocks.
pub fn endpoint_recv(endpoint_id: EndpointId, args: &SyscallArgs) -> u64 {
    crate::serial_println!("endpoint_recv: id={} arg2={:x}", endpoint_id.0, args.arg2);
    let user_ptr = args.arg2;
    let id = KObjectId(endpoint_id.0);
    let obj = match crate::cap::object::get(id) {
        Some(o) => o,
        None => return ErrorCode::InvalidCap.as_u64(),
    };

    match obj {
        KernelObject::Endpoint { blocked_sender, .. } => {
            crate::serial_println!("endpoint_recv: blocked_sender={:?}", blocked_sender);
            if let Some(sender_id) = blocked_sender {
                // Direct rendezvous: sender already blocked, copy its message.
                if let Some(msg) = crate::sched::take_thread_message(sender_id) {
                    if let Err(e) = user_mem::copy_to_user(&msg.data, user_ptr) {
                        return e.as_u64();
                    }
                }
                crate::sched::unblock(sender_id);
                crate::cap::object::clear_blocked_sender(id);
                ErrorCode::Ok.as_u64()
            } else {
                // No sender waiting: block the receiver.
                let receiver_id = crate::sched::current_thread_id();
                crate::cap::object::set_blocked_receiver(id, receiver_id);
                crate::sched::block_current(sched::ThreadState::BlockedRecv(id));
                // When we return, the sender has delivered the message.
                if let Some(msg) = crate::sched::take_current_message() {
                    if let Err(e) = user_mem::copy_to_user(&msg.data, user_ptr) {
                        return e.as_u64();
                    }
                }
                ErrorCode::Ok.as_u64()
            }
        }
        _ => ErrorCode::InvalidCap.as_u64(),
    }
}

/// Signal a notification object.
///
/// Never blocks. If a thread is waiting, it is unblocked.
pub fn notification_signal(notification_id: NotificationId) -> u64 {
    let id = KObjectId(notification_id.0);
    let obj = match crate::cap::object::get(id) {
        Some(o) => o,
        None => return ErrorCode::InvalidCap.as_u64(),
    };

    match obj {
        KernelObject::Notification { blocked_waiter, .. } => {
            if let Some(waiter_id) = blocked_waiter {
                crate::sched::unblock(waiter_id);
                crate::cap::object::clear_blocked_waiter(id);
            }
            crate::cap::object::set_notification_state(id, true);
            ErrorCode::Ok.as_u64()
        }
        _ => ErrorCode::InvalidCap.as_u64(),
    }
}

/// Wait on a notification object.
///
/// If the notification is already signalled, clears it and returns immediately.
/// Otherwise blocks the caller until a signal arrives.
pub fn notification_wait(notification_id: NotificationId) -> u64 {
    let id = KObjectId(notification_id.0);
    let obj = match crate::cap::object::get(id) {
        Some(o) => o,
        None => return ErrorCode::InvalidCap.as_u64(),
    };

    match obj {
        KernelObject::Notification { state, .. } => {
            if state {
                crate::cap::object::set_notification_state(id, false);
                ErrorCode::Ok.as_u64()
            } else {
                let waiter_id = crate::sched::current_thread_id();
                crate::cap::object::set_blocked_waiter(id, waiter_id);
                crate::sched::block_current(sched::ThreadState::BlockedWait(id));
                crate::cap::object::set_notification_state(id, false);
                ErrorCode::Ok.as_u64()
            }
        }
        _ => ErrorCode::InvalidCap.as_u64(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruzt_abi::{SyscallArgs, IpcMessage};
    use ruzt_cap::EndpointId;

    #[test]
    fn endpoint_send_recv_round_trip() {
        crate::cap::object::init();
        crate::sched::init();

        let id = crate::cap::object::allocate(ruzt_cap::CapType::Endpoint(EndpointId(0))).unwrap();

        let msg = IpcMessage {
            label: 42,
            length: 5,
            cap_count: 0,
            flags: 0,
            data: {
                let mut d = [0u8; 56];
                d[..5].copy_from_slice(b"hello");
                d
            },
            caps: [ruzt_abi::CapTransferSlot {
                cptr: 0,
                rights: ruzt_abi::CapRights::empty(),
                badge: 0,
            }; 4],
        };

        let args_send = SyscallArgs {
            number: 0,
            arg0: 0,
            arg1: 0,
            arg2: &msg.data as *const _ as u64,
            arg3: 42,
            arg4: 5,
            arg5: 0,
        };

        let ret = endpoint_send(EndpointId(id.0), &args_send);
        assert_eq!(ret, ruzt_abi::ErrorCode::Ok.as_u64());

        let mut buf = [0u8; 56];
        let args_recv = SyscallArgs {
            number: 0,
            arg0: 0,
            arg1: 1,
            arg2: &mut buf as *mut _ as u64,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        };

        let ret = endpoint_recv(EndpointId(id.0), &args_recv);
        assert_eq!(ret, ruzt_abi::ErrorCode::Ok.as_u64());
        assert_eq!(&buf[..5], b"hello");
    }

    #[test]
    fn notification_signal_wait() {
        crate::cap::object::init();
        let id = crate::cap::object::allocate(ruzt_cap::CapType::Notification(ruzt_cap::NotificationId(0))).unwrap();

        let ret = notification_signal(ruzt_cap::NotificationId(id.0));
        assert_eq!(ret, ruzt_abi::ErrorCode::Ok.as_u64());

        let ret = notification_wait(ruzt_cap::NotificationId(id.0));
        assert_eq!(ret, ruzt_abi::ErrorCode::Ok.as_u64());
    }
}
