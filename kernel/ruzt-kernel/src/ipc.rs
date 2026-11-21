//! Blocking endpoint rendezvous and one-bit notifications.

pub(crate) mod bootstrap;

use ruzt_abi::{ErrorCode, IpcMessage, SyscallArgs};
use ruzt_cap::{EndpointId, NotificationId};

use crate::cap::object::{self, KObjectId, KernelObject};
use crate::sched::{self, ThreadState};
use crate::syscall::user_mem;

fn check_endpoint(endpoint: EndpointId) -> Result<KObjectId, ErrorCode> {
    let id = KObjectId(endpoint.0);
    match object::get(id) {
        Some(KernelObject::Endpoint) => Ok(id),
        _ => Err(ErrorCode::InvalidCap),
    }
}

pub(crate) fn send_message(endpoint: EndpointId, message: IpcMessage) -> Result<(), ErrorCode> {
    let id = check_endpoint(endpoint)?;
    // The IPC interrupt gate keeps this lookup and the subsequent scheduler
    // transition atomic on the boot CPU.
    if let Some(receiver) = sched::first_waiter(ThreadState::BlockedRecv(id)) {
        sched::set_thread_message(receiver, message);
        sched::unblock(receiver);
    } else {
        sched::set_thread_message(sched::current_thread_id(), message);
        sched::block_current(ThreadState::BlockedSend(id));
    }
    Ok(())
}

pub(crate) fn receive_message(endpoint: EndpointId) -> Result<IpcMessage, ErrorCode> {
    let id = check_endpoint(endpoint)?;
    if let Some(sender) = sched::first_waiter(ThreadState::BlockedSend(id)) {
        let message = sched::take_thread_message(sender).ok_or(ErrorCode::BadMessage)?;
        sched::unblock(sender);
        Ok(message)
    } else {
        sched::block_current(ThreadState::BlockedRecv(id));
        sched::take_current_message().ok_or(ErrorCode::BadMessage)
    }
}

/// Send through the endpoint used by the kernel-only IPC diagnostic.
pub fn endpoint_send(endpoint: EndpointId, args: &SyscallArgs) -> u64 {
    let mut message = IpcMessage::default();
    if args.arg4 > message.data.len() as u64 {
        return ErrorCode::BadMessage.as_u64();
    }
    message.label = args.arg3;
    message.length = args.arg4 as u16;
    let payload = &mut message.data[..usize::from(message.length)];
    user_mem::copy_from_user(args.arg2, payload)
        .and_then(|()| send_message(endpoint, message))
        .map_or_else(ErrorCode::as_u64, |()| ErrorCode::Ok.as_u64())
}

/// Receive through the endpoint used by the kernel-only IPC diagnostic.
pub fn endpoint_recv(endpoint: EndpointId, args: &SyscallArgs) -> u64 {
    receive_message(endpoint)
        .and_then(|message| user_mem::copy_to_user(&message.data, args.arg2))
        .map_or_else(ErrorCode::as_u64, |()| ErrorCode::Ok.as_u64())
}

/// Signal the first waiter or record a pending notification.
pub fn notification_signal(notification: NotificationId) -> u64 {
    let id = KObjectId(notification.0);
    if !matches!(object::get(id), Some(KernelObject::Notification { .. })) {
        return ErrorCode::InvalidCap.as_u64();
    }
    if let Some(waiter) = sched::first_waiter(ThreadState::BlockedWait(id)) {
        sched::unblock(waiter);
    } else {
        object::set_notification_state(id, true);
    }
    ErrorCode::Ok.as_u64()
}

/// Consume a pending notification or block until another thread signals it.
pub fn notification_wait(notification: NotificationId) -> u64 {
    let id = KObjectId(notification.0);
    match object::get(id) {
        Some(KernelObject::Notification { state: true }) => {
            object::set_notification_state(id, false)
        }
        Some(KernelObject::Notification { state: false }) => {
            sched::block_current(ThreadState::BlockedWait(id));
        }
        _ => return ErrorCode::InvalidCap.as_u64(),
    }
    ErrorCode::Ok.as_u64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notification_signal_wait() {
        let _state = crate::isolated_kernel_state();
        let id = object::allocate(ruzt_cap::CapType::Notification(NotificationId(0))).unwrap();

        assert_eq!(
            notification_signal(NotificationId(id.0)),
            ErrorCode::Ok.as_u64()
        );
        assert_eq!(
            notification_wait(NotificationId(id.0)),
            ErrorCode::Ok.as_u64()
        );
        assert_eq!(
            object::get(id),
            Some(KernelObject::Notification { state: false })
        );
    }
}
