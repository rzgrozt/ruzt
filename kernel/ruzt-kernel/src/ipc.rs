//! Blocking endpoint rendezvous and one-bit notifications.

pub(crate) mod wait;

use ruzt_abi::{ErrorCode, IpcMessage, SyscallArgs, IPC_CAP_SLOTS};
use ruzt_cap::{EndpointId, NotificationId};

use crate::cap::cspace::{CSpace, CapGrant, CapabilityId};
use crate::cap::object::{self, KObjectId, KernelObject};
use crate::sched::{self, ThreadState};
use crate::syscall::user_mem;
use crate::transaction::Transaction;

#[derive(Clone, Copy, Default)]
pub(crate) struct ReceiveSlots {
    pub first: u64,
    pub capacity: usize,
    pub cnode: Option<KObjectId>,
}

pub(crate) struct Packet {
    pub message: IpcMessage,
    pub grants: [Option<CapGrant>; IPC_CAP_SLOTS],
}

impl Packet {
    pub(crate) fn inline(message: IpcMessage) -> Self {
        Self {
            message,
            grants: [None; IPC_CAP_SLOTS],
        }
    }

    pub(crate) fn deliver(
        mut self,
        slots: ReceiveSlots,
        space: Option<&mut CSpace>,
    ) -> Result<IpcMessage, ErrorCode> {
        let count = usize::from(self.message.cap_count);
        if count == 0 {
            return Ok(self.message);
        }
        if count > slots.capacity || count > IPC_CAP_SLOTS {
            return Err(ErrorCode::BadMessage);
        }
        let space = space.ok_or(ErrorCode::InvalidCap)?;
        space.accept_grants(slots.first, slots.cnode, &self.grants[..count])?;
        for (index, cap) in self.message.caps[..count].iter_mut().enumerate() {
            cap.cptr = slots.first + index as u64;
        }
        Ok(self.message)
    }
}

fn check_endpoint(id: KObjectId) -> Result<(), ErrorCode> {
    match object::get(id) {
        Some(KernelObject::Endpoint { closed: false }) => Ok(()),
        Some(KernelObject::Endpoint { closed: true }) => Err(ErrorCode::NotFound),
        _ => Err(ErrorCode::InvalidCap),
    }
}

pub(crate) fn send_packet(
    transaction: &mut Transaction,
    endpoint: EndpointId,
    authority: Option<CapabilityId>,
    packet: Packet,
) -> Result<(), ErrorCode> {
    let id = KObjectId(endpoint.0);
    check_endpoint(id)?;
    if let Some(receiver) = sched::first_waiter(ThreadState::BlockedRecv(id)) {
        sched::deliver_to_waiter(receiver, packet)
    } else {
        sched::set_thread_message(sched::current_thread_id(), packet);
        sched::block_with_authority(
            transaction,
            ThreadState::BlockedSend(id),
            authority,
            ReceiveSlots::default(),
        );
        sched::check_ipc_completion()
    }
}

pub(crate) fn receive_packet(
    transaction: &mut Transaction,
    endpoint: EndpointId,
    authority: Option<CapabilityId>,
    slots: ReceiveSlots,
) -> Result<IpcMessage, ErrorCode> {
    let id = KObjectId(endpoint.0);
    if let Some(message) = poll_packet(id, slots)? {
        Ok(message)
    } else {
        sched::block_with_authority(transaction, ThreadState::BlockedRecv(id), authority, slots);
        sched::check_ipc_completion()?;
        sched::take_current_message()
            .map(|packet| packet.message)
            .ok_or(ErrorCode::BadMessage)
    }
}

fn poll_packet(id: KObjectId, slots: ReceiveSlots) -> Result<Option<IpcMessage>, ErrorCode> {
    check_endpoint(id)?;
    sched::first_waiter(ThreadState::BlockedSend(id))
        .map(|sender| {
            let result = sched::take_thread_message(sender)
                .ok_or(ErrorCode::BadMessage)
                .and_then(|packet| {
                    if packet.message.cap_count == 0 {
                        Ok(packet.message)
                    } else {
                        sched::with_current_user(|user| {
                            packet.deliver(slots, Some(&mut user.cspace))
                        })
                        .ok_or(ErrorCode::InvalidCap)?
                    }
                });
            sched::complete_ipc(sender, result.as_ref().err().copied());
            result
        })
        .transpose()
}

pub(crate) fn close_endpoint(_transaction: &Transaction, endpoint: EndpointId) {
    let id = KObjectId(endpoint.0);
    object::close_endpoint(id);
    sched::cancel_endpoint_waiters(id);
}

/// Send through the endpoint used by the kernel-only IPC diagnostic.
pub(crate) fn endpoint_send(transaction: &mut Transaction, endpoint: EndpointId, args: &SyscallArgs) -> u64 {
    let mut message = IpcMessage::default();
    if args.arg4 > message.data.len() as u64 {
        return ErrorCode::BadMessage.as_u64();
    }
    message.label = args.arg3;
    message.length = args.arg4 as u16;
    let payload = &mut message.data[..usize::from(message.length)];
    user_mem::copy_from_user(args.arg2, payload)
        .and_then(|()| send_packet(transaction, endpoint, None, Packet::inline(message)))
        .map_or_else(ErrorCode::as_u64, |()| ErrorCode::Ok.as_u64())
}

/// Receive through the endpoint used by the kernel-only IPC diagnostic.
pub(crate) fn endpoint_recv(transaction: &mut Transaction, endpoint: EndpointId, args: &SyscallArgs) -> u64 {
    receive_packet(transaction, endpoint, None, ReceiveSlots::default())
        .and_then(|message| user_mem::copy_to_user(&message.data, args.arg2))
        .map_or_else(ErrorCode::as_u64, |()| ErrorCode::Ok.as_u64())
}

/// Signal the first waiter or record a pending notification.
pub(crate) fn notification_signal(_transaction: &Transaction, notification: NotificationId) -> u64 {
    let id = KObjectId(notification.0);
    if !matches!(object::get(id), Some(KernelObject::Notification { .. })) {
        return ErrorCode::InvalidCap.as_u64();
    }
    if let Some(waiter) = sched::first_waiter(ThreadState::BlockedWait(id)) {
        sched::unblock(waiter);
    } else {
        object::set_notification_state(id, true);
        sched::wake_wait_any(wait::Target::Notification(id));
    }
    ErrorCode::Ok.as_u64()
}

/// Consume a pending notification or block until another thread signals it.
pub(crate) fn wait_notification(
    transaction: &mut Transaction,
    notification: NotificationId,
    authority: Option<CapabilityId>,
) -> Result<(), ErrorCode> {
    let id = KObjectId(notification.0);
    if !take_notification(id)? {
        sched::block_with_authority(
            transaction,
            ThreadState::BlockedWait(id),
            authority,
            ReceiveSlots::default(),
        );
        sched::check_ipc_completion()?;
    }
    Ok(())
}

fn take_notification(id: KObjectId) -> Result<bool, ErrorCode> {
    let Some(KernelObject::Notification { state }) = object::get(id) else {
        return Err(ErrorCode::InvalidCap);
    };
    if state {
        object::set_notification_state(id, false);
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_endpoint_stays_closed_with_a_live_handle() {
        let _state = crate::isolated_kernel_state();
        let mut transaction = crate::transaction::enter();
        let cap_type = ruzt_cap::CapType::Endpoint(EndpointId(0));
        let old = object::allocate(cap_type).unwrap();
        let endpoint = EndpointId(old.0);

        close_endpoint(&transaction, endpoint);
        let new = object::allocate(cap_type).unwrap();
        assert_ne!(old, new);
        assert_eq!(
            send_packet(&mut transaction, endpoint, None, Packet::inline(IpcMessage::default())),
            Err(ErrorCode::NotFound)
        );
        assert_eq!(receive_packet(&mut transaction, endpoint, None, ReceiveSlots::default()), Err(ErrorCode::NotFound));
    }

    #[test]
    fn notification_signal_wait() {
        let _state = crate::isolated_kernel_state();
        let mut transaction = crate::transaction::enter();
        let id = object::allocate(ruzt_cap::CapType::Notification(NotificationId(0))).unwrap();

        assert_eq!(
            notification_signal(&transaction, NotificationId(id.0)),
            ErrorCode::Ok.as_u64()
        );
        assert_eq!(
            wait_notification(&mut transaction, NotificationId(id.0), None),
            Ok(())
        );
        assert_eq!(
            object::get(id),
            Some(KernelObject::Notification { state: false })
        );
    }
}
