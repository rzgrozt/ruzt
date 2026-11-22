//! Round-robin scheduler.

use crate::cap::cspace::{self, CapabilityId};
use crate::cap::object::KObjectId;
use crate::ipc::{Packet, ReceiveSlots};
use crate::process::UserProcess;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use ruzt_abi::{ErrorCode, ProcessStatus};
use ruzt_hal_x86_64::context::FpState;
use spin::Mutex;

/// Opaque handle for a scheduler thread.
pub type ThreadId = usize;

/// Thread scheduling state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadState {
    /// Thread is runnable and may be scheduled.
    Runnable,
    /// Thread is blocked waiting to send on an endpoint.
    BlockedSend(KObjectId),
    /// Thread is blocked waiting to receive on an endpoint.
    BlockedRecv(KObjectId),
    /// Thread is blocked waiting on a notification.
    BlockedWait(KObjectId),
    /// Thread is waiting for a process to exit and be reaped.
    BlockedProcess(KObjectId),
    /// A user driver is blocked waiting for a device interrupt.
    BlockedIrq(u32),
    /// The task has terminated and will never run again.
    Exited,
}

/// Per-thread state.
struct Thread {
    /// Owned kernel stack (64 KiB).  `None` for the idle thread.
    stack: Option<alloc::boxed::Box<[u8]>>,
    /// Saved stack pointer from the last context switch.
    rsp: u64,
    /// Saved architectural floating-point context.
    fp: FpState,
    /// Current scheduling state.
    state: ThreadState,
    /// IPC message buffer for rendezvous delivery.
    message: Option<Packet>,
    receive_slots: ReceiveSlots,
    wait_capability: Option<CapabilityId>,
    /// A failure delivered instead of a message when an endpoint closes.
    ipc_error: Option<ErrorCode>,
    /// Address space and capabilities of a user-mode thread.
    user: Option<UserProcess>,
}

/// Scheduler state.
#[allow(clippy::vec_box)]
struct Scheduler {
    threads: Vec<alloc::boxed::Box<Thread>>,
    run_queue: VecDeque<ThreadId>,
    wait_queue: VecDeque<ThreadId>,
    current: ThreadId,
    kernel_cr3: u64,
    retired: Option<(ThreadId, ProcessStatus)>,
}

impl Scheduler {
    fn mark_blocked(&mut self, id: ThreadId, reason: ThreadState) {
        self.run_queue.retain(|&thread| thread != id);
        self.threads[id].state = reason;
        self.wait_queue.push_back(id);
    }

    fn mark_runnable(&mut self, id: ThreadId) {
        if !matches!(
            self.threads[id].state,
            ThreadState::Runnable | ThreadState::Exited
        ) {
            self.wait_queue.retain(|&thread| thread != id);
            self.threads[id].state = ThreadState::Runnable;
            self.threads[id].wait_capability = None;
            self.threads[id].receive_slots = ReceiveSlots::default();
            self.run_queue.push_back(id);
        }
    }
    fn finish_waiters(&mut self, error: Option<ErrorCode>, matches: impl Fn(&Thread) -> bool) {
        loop {
            let waiter = self
                .wait_queue
                .iter()
                .copied()
                .find(|&id| matches(&self.threads[id]));
            let Some(id) = waiter else { break };
            self.threads[id].ipc_error = error;
            self.threads[id].message = None;
            self.mark_runnable(id);
        }
    }
}

static SCHEDULER: Mutex<Option<Scheduler>> = Mutex::new(None);

/// Set by the timer ISR when a tick has occurred.
static NEED_SWITCH: AtomicBool = AtomicBool::new(false);

/// Set by the timer ISR to request a context switch.
pub fn request_switch() {
    NEED_SWITCH.store(true, Ordering::Relaxed);
}

/// Check whether the timer ISR has requested a context switch.
pub fn should_switch() -> bool {
    NEED_SWITCH.swap(false, Ordering::Relaxed)
}

/// Initialise the scheduler, registering the current execution context as the
/// idle thread (thread 0).
pub fn init() {
    #[cfg(not(test))]
    let kernel_cr3 = ruzt_hal_x86_64::context::current_cr3();
    #[cfg(test)]
    let kernel_cr3 = 0;
    let mut guard = SCHEDULER.lock();
    let mut sched = Scheduler {
        threads: Vec::with_capacity(16),
        run_queue: VecDeque::new(),
        wait_queue: VecDeque::new(),
        current: 0,
        kernel_cr3,
        retired: None,
    };
    sched.threads.push(alloc::boxed::Box::new(Thread {
        stack: None,
        rsp: 0,
        fp: FpState::default(),
        state: ThreadState::Runnable,
        message: None,
        receive_slots: ReceiveSlots::default(),
        wait_capability: None,
        ipc_error: None,
        user: None,
    }));
    *guard = Some(sched);
}

/// Block the current thread with the given reason and yield immediately.
///
/// Must be called with interrupts disabled.
pub fn block_current(reason: ThreadState) {
    block_with_authority(reason, None, ReceiveSlots::default());
}

pub(crate) fn block_with_authority(
    reason: ThreadState,
    capability: Option<CapabilityId>,
    slots: ReceiveSlots,
) {
    #[cfg(feature = "qemu-smoke-test")]
    crate::serial_println!(
        "block_current: thread={} reason={:?}",
        current_thread_id(),
        reason
    );
    let mut guard = SCHEDULER.lock();
    let sched = guard.as_mut().expect("scheduler not initialised");
    let current_id = sched.current;

    // Remove current from run queue.
    assert_ne!(current_id, 0, "the idle thread cannot block");
    sched.threads[current_id].wait_capability = capability;
    sched.threads[current_id].receive_slots = slots;
    sched.mark_blocked(current_id, reason);

    // Switch to next runnable thread.
    let next_id = sched.run_queue.front().copied().unwrap_or(0);
    switch_to(guard, next_id);
}

/// Unblock a thread and return it to the run queue.
pub fn unblock(thread_id: ThreadId) {
    let mut guard = SCHEDULER.lock();
    let sched = guard.as_mut().expect("scheduler not initialised");
    sched.mark_runnable(thread_id);
}

pub(crate) fn first_waiter(reason: ThreadState) -> Option<ThreadId> {
    let guard = SCHEDULER.lock();
    let sched = guard.as_ref().expect("scheduler not initialised");
    sched
        .wait_queue
        .iter()
        .copied()
        .find(|&id| sched.threads[id].state == reason)
}

pub(crate) fn cancel_endpoint_waiters(endpoint: KObjectId) {
    let mut guard = SCHEDULER.lock();
    let sched = guard.as_mut().expect("scheduler not initialised");
    sched.finish_waiters(Some(ErrorCode::NotFound), |thread| {
        matches!(
            thread.state,
            ThreadState::BlockedSend(object) | ThreadState::BlockedRecv(object)
                if object == endpoint
        )
    });
}

pub(crate) fn apply_capability_removals() {
    let mut guard = SCHEDULER.lock();
    let Some(sched) = guard.as_mut() else { return };
    for thread in &mut sched.threads {
        if let Some(user) = &mut thread.user {
            user.unmap_revoked_frames();
        }
    }
    sched.finish_waiters(Some(ErrorCode::InvalidCap), |thread| {
        thread
            .wait_capability
            .is_some_and(|id| !cspace::is_live(id))
    });
}

pub(crate) fn wake_process_waiters(process: KObjectId) {
    let mut guard = SCHEDULER.lock();
    let sched = guard.as_mut().expect("scheduler not initialised");
    sched.finish_waiters(None, |thread| {
        thread.state == ThreadState::BlockedProcess(process)
    });
}

pub(crate) fn complete_ipc(id: ThreadId, error: Option<ErrorCode>) {
    let mut guard = SCHEDULER.lock();
    let sched = guard.as_mut().expect("scheduler not initialised");
    sched.threads[id].ipc_error = error;
    sched.mark_runnable(id);
}

pub(crate) fn deliver_to_waiter(id: ThreadId, packet: Packet) -> Result<(), ErrorCode> {
    let mut guard = SCHEDULER.lock();
    let sched = guard.as_mut().expect("scheduler not initialised");
    let receiver = &mut sched.threads[id];
    let result = packet.deliver(
        receiver.receive_slots,
        receiver.user.as_mut().map(|p| &mut p.cspace),
    );
    let status = match result {
        Ok(message) => {
            receiver.message = Some(Packet::inline(message));
            Ok(())
        }
        Err(error) => {
            receiver.ipc_error = Some(error);
            Err(error)
        }
    };
    sched.mark_runnable(id);
    status
}

pub(crate) fn check_ipc_completion() -> Result<(), ErrorCode> {
    let mut guard = SCHEDULER.lock();
    let sched = guard.as_mut().expect("scheduler not initialised");
    sched.threads[sched.current]
        .ipc_error
        .take()
        .map_or(Ok(()), Err)
}

pub(crate) fn wake_irq(thread_id: ThreadId, irq: u32) {
    let mut guard = SCHEDULER.lock();
    let sched = guard.as_mut().expect("scheduler not initialised");
    if sched.threads[thread_id].state == ThreadState::BlockedIrq(irq) {
        sched.mark_runnable(thread_id);
        request_switch();
    }
}

pub(crate) fn with_current_user<T>(f: impl FnOnce(&mut UserProcess) -> T) -> Option<T> {
    let mut guard = SCHEDULER.lock();
    let sched = guard.as_mut()?;
    sched.threads[sched.current].user.as_mut().map(f)
}

/// Leave the dying task on its own stack until the idle thread can reap it.
/// Called from a syscall or user fault with interrupts disabled.
pub(crate) fn retire_current_user(status: ProcessStatus) -> ! {
    let mut guard = SCHEDULER.lock();
    let sched = guard.as_mut().expect("scheduler not initialised");
    let id = sched.current;
    assert!(sched.threads[id].user.is_some());
    assert!(sched.retired.is_none());
    sched.run_queue.retain(|&thread| thread != id);
    sched.threads[id].state = ThreadState::Exited;
    sched.retired = Some((id, status));
    request_switch();
    switch_to(guard, 0);
    unreachable!("exited thread resumed");
}

pub(crate) fn reap_retired_user() {
    let (mut user, stack, status) = {
        let mut guard = SCHEDULER.lock();
        let sched = guard.as_mut().expect("scheduler not initialised");
        let Some((id, status)) = sched.retired.take() else {
            return;
        };
        assert_eq!(sched.current, 0);
        let retired = &mut sched.threads[id];
        retired.fp = FpState::default();
        (
            retired.user.take().expect("retired user task"),
            retired.stack.take(),
            status,
        )
    };
    #[allow(unsafe_code)]
    // SAFETY: Idle is running on its boot stack with interrupts disabled.
    // Restore RSP0 before releasing the task's former privilege stack.
    unsafe {
        ruzt_hal_x86_64::gdt::use_boot_trap_stack()
    };
    let name = user.name;
    let publisher = user.exit_publisher.take();
    drop(user);
    drop(stack);
    crate::serial_println!("reaped user process {name}");
    if let Some(publisher) = publisher {
        publisher.publish(status);
    }
}

/// Return the current thread's ID.
pub fn current_thread_id() -> ThreadId {
    let guard = SCHEDULER.lock();
    let sched = guard.as_ref().expect("scheduler not initialised");
    sched.current
}

/// Return a copy of the current thread's message buffer, clearing it.
pub(crate) fn take_current_message() -> Option<Packet> {
    let mut guard = SCHEDULER.lock();
    let sched = guard.as_mut().expect("scheduler not initialised");
    let current_id = sched.current;
    sched.threads[current_id].message.take()
}

/// Store a message into the given thread's buffer.
pub(crate) fn set_thread_message(thread_id: ThreadId, msg: Packet) {
    let mut guard = SCHEDULER.lock();
    let sched = guard.as_mut().expect("scheduler not initialised");
    sched.threads[thread_id].message = Some(msg);
}

/// Take a message from the given thread's buffer, clearing it.
pub(crate) fn take_thread_message(thread_id: ThreadId) -> Option<Packet> {
    let mut guard = SCHEDULER.lock();
    let sched = guard.as_mut().expect("scheduler not initialised");
    sched.threads[thread_id].message.take()
}

/// Spawn a new kernel thread that starts executing `f`.
///
/// Allocates a 64 KiB stack, sets up an initial frame, and pushes the thread
/// onto the run queue.
pub fn spawn(f: fn() -> !) -> ThreadId {
    spawn_thread(f, None).expect("allocate kernel thread")
}

pub(crate) fn spawn_user(user: UserProcess, entry: fn() -> !) -> Result<ThreadId, ErrorCode> {
    spawn_thread(entry, Some(user))
}

fn spawn_thread(f: fn() -> !, user: Option<UserProcess>) -> Result<ThreadId, ErrorCode> {
    const STACK_SIZE: usize = 64 * 1024;
    let mut stack = Vec::new();
    stack
        .try_reserve_exact(STACK_SIZE)
        .map_err(|_| ErrorCode::NoMemory)?;
    stack.resize(STACK_SIZE, 0u8);
    let mut stack = stack.into_boxed_slice();
    #[allow(unsafe_code)]
    // SAFETY: The new 64 KiB stack is exclusively owned by this thread.
    let rsp = unsafe { ruzt_hal_x86_64::context::init_stack(&mut stack, f) };

    let mut guard = SCHEDULER.lock();
    let sched = guard.as_mut().expect("scheduler not initialised");
    sched
        .run_queue
        .try_reserve(1)
        .map_err(|_| ErrorCode::NoMemory)?;
    let thread = Thread {
        stack: Some(stack),
        rsp,
        fp: FpState::default(),
        state: ThreadState::Runnable,
        message: None,
        receive_slots: ReceiveSlots::default(),
        wait_capability: None,
        ipc_error: None,
        user,
    };
    let id = if let Some(index) = sched.threads.iter().position(|thread| {
        thread.state == ThreadState::Exited && thread.stack.is_none() && thread.user.is_none()
    }) {
        // The idle thread already reaped this slot. Only the independently
        // generation-qualified process capability escapes the scheduler.
        *sched.threads[index] = thread;
        index
    } else {
        let index = sched.threads.len();
        sched
            .threads
            .try_reserve(1)
            .map_err(|_| ErrorCode::NoMemory)?;
        let thread = alloc::boxed::Box::try_new(thread).map_err(|_| ErrorCode::NoMemory)?;
        sched.threads.push(thread);
        index
    };
    sched.run_queue.push_back(id);

    Ok(id)
}

/// Rotate the run queue and, if a different thread should run, perform the
/// context switch.
///
/// Must be called with interrupts disabled to prevent re-entrancy.
pub fn yield_thread() {
    let mut guard = SCHEDULER.lock();
    let sched = guard.as_mut().expect("scheduler not initialised");

    let current_id = sched.current;

    // Idle stays outside the run queue and runs only when no task is ready.
    if sched.run_queue.front() == Some(&current_id) {
        sched.run_queue.rotate_left(1);
    }
    let next_id = sched.run_queue.front().copied().unwrap_or(0);

    if next_id != current_id {
        switch_to(guard, next_id);
    }
}

#[allow(unsafe_code)]
fn switch_to(mut guard: spin::MutexGuard<'_, Option<Scheduler>>, next_id: ThreadId) {
    let sched = guard.as_mut().expect("scheduler not initialised");
    let current = &mut sched.threads[sched.current];
    let old_rsp = &mut current.rsp as *mut u64;
    let old_fp = &mut current.fp as *mut FpState;
    let next = &sched.threads[next_id];
    let new_rsp = next.rsp;
    let new_fp = &next.fp as *const FpState;
    let new_cr3 = if let Some(user) = &next.user {
        let stack = next
            .stack
            .as_ref()
            .expect("user thread needs a kernel stack");
        let stack_top = (stack.as_ptr() as u64 + stack.len() as u64) & !0xF;
        // SAFETY: Interrupts are disabled, and this owned kernel stack lies in
        // the common supervisor mapping of every supported page-table root.
        unsafe { ruzt_hal_x86_64::gdt::set_trap_stack(stack_top) };
        user.root().base.as_u64()
    } else {
        sched.kernel_cr3
    };
    sched.current = next_id;
    drop(guard);
    // SAFETY: Both thread records are pinned in separate boxes, and the boot
    // kernel heap, the switch code, and both stacks are mapped in both roots.
    unsafe { ruzt_hal_x86_64::context::switch(old_rsp, new_rsp, new_cr3, old_fp, new_fp) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduler_init_creates_idle_thread() {
        let _state = crate::isolated_kernel_state();
        let id = current_thread_id();
        assert_eq!(id, 0);
    }

    #[test]
    fn thread_slot_is_reused_after_its_stack_is_released() {
        let _state = crate::isolated_kernel_state();
        fn entry() -> ! {
            panic!("host tests do not switch stacks")
        }
        let retired = spawn(entry);
        {
            let mut guard = SCHEDULER.lock();
            let sched = guard.as_mut().unwrap();
            sched.run_queue.clear();
            sched.threads[retired].state = ThreadState::Exited;
        }
        let live = spawn(entry);
        assert_ne!(live, retired);
        {
            let mut guard = SCHEDULER.lock();
            let sched = guard.as_mut().unwrap();
            sched.threads[retired].stack = None;
        }
        assert_eq!(spawn(entry), retired);
        let guard = SCHEDULER.lock();
        let sched = guard.as_ref().unwrap();
        assert_eq!(sched.run_queue, [live, retired]);
        assert_eq!(sched.threads.len(), 3);
    }

    #[test]
    fn endpoint_waiters_are_selected_in_block_order() {
        let _state = crate::isolated_kernel_state();
        fn entry() -> ! {
            panic!("host tests do not switch stacks")
        }
        let earlier_spawned = spawn(entry);
        let later_spawned = spawn(entry);
        let unrelated = spawn(entry);
        let reason = ThreadState::BlockedSend(KObjectId(0));

        {
            let mut guard = SCHEDULER.lock();
            let sched = guard.as_mut().unwrap();
            sched.mark_blocked(unrelated, ThreadState::BlockedRecv(KObjectId(1)));
            sched.mark_blocked(later_spawned, reason);
            sched.mark_blocked(earlier_spawned, reason);
        }

        assert_eq!(first_waiter(reason), Some(later_spawned));
        unblock(later_spawned);
        unblock(later_spawned);
        assert_eq!(first_waiter(reason), Some(earlier_spawned));
        unblock(earlier_spawned);
        assert_eq!(first_waiter(reason), None);
        let guard = SCHEDULER.lock();
        let sched = guard.as_ref().unwrap();
        assert_eq!(sched.run_queue, [later_spawned, earlier_spawned]);
        assert_eq!(sched.wait_queue, [unrelated]);
    }

    #[test]
    fn revocation_wakes_only_waiters_that_lost_their_authority() {
        use crate::cap::{cspace::CSpace, object};
        use ruzt_cap::{CapRights, CapSlot, CapType, NotificationId};

        let _state = crate::isolated_kernel_state();
        let id = object::allocate(CapType::Notification(NotificationId(0))).unwrap();
        let mut caps = CSpace::new(2);
        caps.insert(
            0,
            CapSlot {
                cap_type: CapType::Notification(NotificationId(id.0)),
                rights: CapRights::new(),
                badge: 0,
            },
        )
        .unwrap();
        let surviving_cap = caps.capability_id(0).unwrap();
        caps.derive(surviving_cap, 1, CapRights::READ, 0).unwrap();
        let revoked_cap = caps.capability_id(1).unwrap();
        fn entry() -> ! {
            panic!("host tests do not switch stacks")
        }
        let survivor = spawn(entry);
        let revoked = spawn(entry);
        {
            let mut guard = SCHEDULER.lock();
            let scheduler = guard.as_mut().unwrap();
            scheduler.threads[survivor].wait_capability = Some(surviving_cap);
            scheduler.threads[revoked].wait_capability = Some(revoked_cap);
            scheduler.mark_blocked(survivor, ThreadState::BlockedWait(id));
            scheduler.mark_blocked(revoked, ThreadState::BlockedWait(id));
        }
        caps.revoke(0).unwrap();
        apply_capability_removals();
        let guard = SCHEDULER.lock();
        let scheduler = guard.as_ref().unwrap();
        assert_eq!(
            scheduler.threads[survivor].state,
            ThreadState::BlockedWait(id)
        );
        assert_eq!(scheduler.threads[revoked].state, ThreadState::Runnable);
        assert_eq!(
            scheduler.threads[revoked].ipc_error,
            Some(ErrorCode::InvalidCap)
        );
    }

    #[test]
    fn exit_status_wakes_every_observer_and_persists_while_the_cap_is_live() {
        use crate::cap::object::{self, ProcessExitPublisher};
        use ruzt_cap::{CapRights, CapSlot, CapType};

        let _state = crate::isolated_kernel_state();
        let (process, publisher) = ProcessExitPublisher::new().unwrap();
        let id = KObjectId(process.0);
        let mut caps = cspace::CSpace::new(2);
        caps.insert(
            0,
            CapSlot {
                cap_type: CapType::Process(process),
                rights: CapRights::READ,
                badge: 0,
            },
        )
        .unwrap();
        let observer = Some(caps.capability_id(0).unwrap());
        assert_eq!(
            crate::process::wait_for_status(process, observer, true),
            Err(ErrorCode::WouldBlock)
        );
        fn entry() -> ! {
            panic!("host tests do not switch stacks")
        }
        let first = spawn(entry);
        let second = spawn(entry);
        let unrelated = spawn(entry);
        {
            let mut guard = SCHEDULER.lock();
            let sched = guard.as_mut().unwrap();
            sched.mark_blocked(first, ThreadState::BlockedProcess(id));
            sched.mark_blocked(second, ThreadState::BlockedProcess(id));
            sched.mark_blocked(unrelated, ThreadState::BlockedWait(id));
        }
        let expected = ProcessStatus {
            kind: ruzt_abi::PROCESS_EXITED,
            code: 23,
        };
        publisher.publish(expected);
        {
            let guard = SCHEDULER.lock();
            let sched = guard.as_ref().unwrap();
            assert_eq!(sched.run_queue, [first, second]);
            assert_eq!(sched.wait_queue, [unrelated]);
            assert_eq!(sched.threads[first].ipc_error, None);
        }
        assert_eq!(
            crate::process::wait_for_status(process, observer, false),
            Ok(expected)
        );
        assert_eq!(
            crate::process::wait_for_status(process, observer, true),
            Ok(expected)
        );
        drop(caps);
        assert!(object::get(id).is_none());
    }

    #[test]
    fn thread_message_buffer() {
        let _state = crate::isolated_kernel_state();
        let id = current_thread_id();

        let msg = ruzt_abi::IpcMessage {
            label: 99,
            length: 3,
            cap_count: 0,
            flags: 0,
            data: {
                let mut d = [0u8; 56];
                d[..3].copy_from_slice(b"abc");
                d
            },
            caps: [ruzt_abi::CapTransferSlot {
                cptr: 0,
                rights: ruzt_abi::CapRights::empty(),
                badge: 0,
            }; 4],
        };

        set_thread_message(id, Packet::inline(msg));

        let taken = take_thread_message(id);
        assert!(taken.is_some());
        let taken = taken.unwrap().message;
        assert_eq!(taken.label, 99);
        assert_eq!(&taken.data[..3], b"abc");

        // Second take should be None
        let taken2 = take_thread_message(id);
        assert!(taken2.is_none());
    }
}
