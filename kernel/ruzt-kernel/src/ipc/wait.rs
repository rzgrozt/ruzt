//! Wait for one incoming message, notification, IRQ, or process exit.

use ruzt_abi::{
    ErrorCode, WaitEvent, MAX_WAIT_SOURCES, WAIT_ENDPOINT_CLOSED, WAIT_IRQ, WAIT_MESSAGE,
    WAIT_NOTIFICATION, WAIT_PROCESS_EXITED,
};
use ruzt_cap::{CapRights, CapSlot, CapType};
use ruzt_hal::time::Timer;
use ruzt_hal_x86_64::time::X86_64Timer;

use super::{poll_packet, take_notification, ReceiveSlots};
use crate::cap::cspace::CapabilityPath;
use crate::cap::object::{self, KObjectId, KernelObject};
use crate::{keyboard, sched};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Target {
    Endpoint(KObjectId),
    Notification(KObjectId),
    Irq(u32),
    Process(KObjectId),
}

#[derive(Clone, Copy)]
pub(crate) struct Source {
    pub target: Target,
    pub authority: CapabilityPath,
}

pub(crate) type Sources = [Option<Source>; MAX_WAIT_SOURCES];

impl Source {
    pub(crate) fn new(
        authority: CapabilityPath,
        slot: CapSlot,
        thread: sched::ThreadId,
    ) -> Result<Self, ErrorCode> {
        let target = match slot.cap_type {
            CapType::Endpoint(id) => Target::Endpoint(KObjectId(id.0)),
            CapType::Notification(id) => Target::Notification(KObjectId(id.0)),
            CapType::Process(id) => Target::Process(KObjectId(id.0)),
            CapType::Irq {
                irq_num: keyboard::IRQ,
            } if keyboard::is_user_driver(thread) => Target::Irq(keyboard::IRQ),
            _ => return Err(ErrorCode::InvalidCap),
        };
        if !slot.rights.contains(CapRights::READ) {
            return Err(ErrorCode::CapRightsViolation);
        }
        Ok(Self { target, authority })
    }
}

/// Called with interrupts disabled. Readiness, consumption, and wait
/// registration are atomic with respect to event producers on this CPU.
pub(crate) fn wait_any(
    sources: &Sources,
    slots: ReceiveSlots,
    deadline: Option<u64>,
) -> Result<WaitEvent, ErrorCode> {
    loop {
        if sources
            .iter()
            .flatten()
            .any(|entry| !entry.authority.is_live())
        {
            return Err(ErrorCode::InvalidCap);
        }
        for (index, entry) in sources.iter().enumerate() {
            let Some(entry) = entry else { continue };
            if let Some(mut event) = poll(entry.target, slots)? {
                event.index = index as u64;
                return Ok(event);
            }
        }
        if deadline.is_some_and(|deadline| deadline <= X86_64Timer::now_monotonic_ns()) {
            return Err(ErrorCode::TimedOut);
        }
        if sources
            .iter()
            .flatten()
            .any(|entry| entry.target == Target::Irq(keyboard::IRQ))
        {
            keyboard::trace_wait();
        }
        sched::block_wait_any(sources, deadline);
        sched::check_ipc_completion()?;
    }
}

fn poll(target: Target, slots: ReceiveSlots) -> Result<Option<WaitEvent>, ErrorCode> {
    let mut event = WaitEvent::default();
    event.kind = match target {
        Target::Endpoint(id) => match poll_packet(id, slots) {
            Ok(Some(message)) => {
                event.message = message;
                WAIT_MESSAGE
            }
            Ok(None) => return Ok(None),
            Err(ErrorCode::NotFound) => WAIT_ENDPOINT_CLOSED,
            Err(error) => return Err(error),
        },
        Target::Notification(id) if take_notification(id)? => WAIT_NOTIFICATION,
        Target::Irq(_) if keyboard::take_irq() => WAIT_IRQ,
        Target::Process(id) => match object::get(id) {
            Some(KernelObject::Process { status: Some(_) }) => WAIT_PROCESS_EXITED,
            Some(KernelObject::Process { status: None }) => return Ok(None),
            _ => return Err(ErrorCode::InvalidCap),
        },
        _ => return Ok(None),
    };
    Ok(Some(event))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::cspace::CSpace;
    use ruzt_cap::NotificationId;

    #[test]
    fn simultaneous_notifications_are_selected_in_order_and_consumed_once() {
        let _state = crate::isolated_kernel_state();
        let mut space = CSpace::new(1);
        let mut sources = Sources::default();
        let mut ids = [KObjectId(0); 2];
        for (index, id) in ids.iter_mut().enumerate() {
            *id = object::allocate(CapType::Notification(NotificationId(0))).unwrap();
            space
                .insert(
                    index as u64,
                    CapSlot {
                        cap_type: CapType::Notification(NotificationId(id.0)),
                        rights: CapRights::READ,
                        badge: 0,
                    },
                )
                .unwrap();
            let (authority, slot) = space.lookup_path(index as u64).unwrap();
            sources[index] = Some(Source::new(authority, slot, 0).unwrap());
        }
        for id in ids.into_iter().rev() {
            object::set_notification_state(id, true);
        }
        for expected in 0..2 {
            let event = wait_any(&sources, ReceiveSlots::default(), Some(0)).unwrap();
            assert_eq!((event.index, event.kind), (expected, WAIT_NOTIFICATION));
        }
        for id in ids {
            assert!(!take_notification(id).unwrap());
        }
        assert_eq!(
            wait_any(&sources, ReceiveSlots::default(), Some(0)),
            Err(ErrorCode::TimedOut)
        );
    }
}
