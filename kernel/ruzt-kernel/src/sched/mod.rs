//! Round-robin scheduler.

use crate::cap::object::KObjectId;
use crate::process::UserProcess;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
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
    /// A user driver is blocked waiting for a device interrupt.
    BlockedIrq(u32),
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
    message: Option<ruzt_abi::IpcMessage>,
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
}

impl Scheduler {
    fn mark_blocked(&mut self, id: ThreadId, reason: ThreadState) {
        self.run_queue.retain(|&thread| thread != id);
        self.threads[id].state = reason;
        self.wait_queue.push_back(id);
    }

    fn mark_runnable(&mut self, id: ThreadId) {
        if self.threads[id].state != ThreadState::Runnable {
            self.wait_queue.retain(|&thread| thread != id);
            self.threads[id].state = ThreadState::Runnable;
            self.run_queue.push_back(id);
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
    };
    sched.threads.push(alloc::boxed::Box::new(Thread {
        stack: None,
        rsp: 0,
        fp: FpState::default(),
        state: ThreadState::Runnable,
        message: None,
        user: None,
    }));
    sched.run_queue.push_back(0);
    *guard = Some(sched);
}

/// Block the current thread with the given reason and yield immediately.
///
/// Must be called with interrupts disabled.
pub fn block_current(reason: ThreadState) {
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
    sched.mark_blocked(current_id, reason);

    // Switch to next runnable thread.
    let next_id = *sched
        .run_queue
        .front()
        .expect("the idle thread is runnable");
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

/// Return the current thread's ID.
pub fn current_thread_id() -> ThreadId {
    let guard = SCHEDULER.lock();
    let sched = guard.as_ref().expect("scheduler not initialised");
    sched.current
}

/// Return a copy of the current thread's message buffer, clearing it.
pub fn take_current_message() -> Option<ruzt_abi::IpcMessage> {
    let mut guard = SCHEDULER.lock();
    let sched = guard.as_mut().expect("scheduler not initialised");
    let current_id = sched.current;
    sched.threads[current_id].message.take()
}

/// Store a message into the given thread's buffer.
pub fn set_thread_message(thread_id: ThreadId, msg: ruzt_abi::IpcMessage) {
    let mut guard = SCHEDULER.lock();
    let sched = guard.as_mut().expect("scheduler not initialised");
    sched.threads[thread_id].message = Some(msg);
}

/// Take a message from the given thread's buffer, clearing it.
pub fn take_thread_message(thread_id: ThreadId) -> Option<ruzt_abi::IpcMessage> {
    let mut guard = SCHEDULER.lock();
    let sched = guard.as_mut().expect("scheduler not initialised");
    sched.threads[thread_id].message.take()
}

/// Spawn a new kernel thread that starts executing `f`.
///
/// Allocates a 64 KiB stack, sets up an initial frame, and pushes the thread
/// onto the run queue.
pub fn spawn(f: fn() -> !) -> ThreadId {
    spawn_thread(f, None)
}

pub(crate) fn spawn_user(user: UserProcess, entry: fn() -> !) -> ThreadId {
    spawn_thread(entry, Some(user))
}

fn spawn_thread(f: fn() -> !, user: Option<UserProcess>) -> ThreadId {
    let mut guard = SCHEDULER.lock();
    let sched = guard.as_mut().expect("scheduler not initialised");

    let id = sched.threads.len();
    let mut stack = alloc::vec![0u8; 64 * 1024].into_boxed_slice();

    #[allow(unsafe_code)]
    let rsp = unsafe { ruzt_hal_x86_64::context::init_stack(&mut *stack, f) };

    sched.threads.push(alloc::boxed::Box::new(Thread {
        stack: Some(stack),
        rsp,
        fp: FpState::default(),
        state: ThreadState::Runnable,
        message: None,
        user,
    }));
    sched.run_queue.push_back(id);

    id
}

/// Rotate the run queue and, if a different thread should run, perform the
/// context switch.
///
/// Must be called with interrupts disabled to prevent re-entrancy.
pub fn yield_thread() {
    let mut guard = SCHEDULER.lock();
    let sched = guard.as_mut().expect("scheduler not initialised");

    let current_id = sched.current;

    // Rotate the run queue, skipping blocked threads.
    if let Some(id) = sched.run_queue.pop_front() {
        if matches!(sched.threads[id].state, ThreadState::Runnable) {
            sched.run_queue.push_back(id);
        }
    }

    // Find the next runnable thread.
    let mut next_id = current_id;
    for _ in 0..sched.run_queue.len() {
        if let Some(&id) = sched.run_queue.front() {
            if matches!(sched.threads[id].state, ThreadState::Runnable) {
                next_id = id;
                break;
            }
            // Skip blocked thread and rotate.
            sched.run_queue.pop_front();
        }
    }

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
        user.root.base.as_u64()
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
        assert_eq!(sched.run_queue, [0, later_spawned, earlier_spawned]);
        assert_eq!(sched.wait_queue, [unrelated]);
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

        set_thread_message(id, msg);

        let taken = take_thread_message(id);
        assert!(taken.is_some());
        let taken = taken.unwrap();
        assert_eq!(taken.label, 99);
        assert_eq!(&taken.data[..3], b"abc");

        // Second take should be None
        let taken2 = take_thread_message(id);
        assert!(taken2.is_none());
    }
}
