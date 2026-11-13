//! Round-robin scheduler.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;
use crate::cap::object::KObjectId;

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
}

/// Per-thread state.
struct Thread {
    /// Owned kernel stack (64 KiB).  `None` for the idle thread.
    #[allow(dead_code)]
    stack: Option<alloc::boxed::Box<[u8; 64 * 1024]>>,
    /// Saved stack pointer from the last context switch.
    rsp: u64,
    /// Current scheduling state.
    state: ThreadState,
    /// IPC message buffer for rendezvous delivery.
    message: Option<ruzt_abi::IpcMessage>,
    /// Per-thread capability space.
    #[allow(dead_code)]
    cspace: Option<alloc::boxed::Box<crate::cap::cspace::CSpace>>,
}

/// Scheduler state.
#[allow(clippy::vec_box)]
struct Scheduler {
    threads: Vec<alloc::boxed::Box<Thread>>,
    run_queue: VecDeque<ThreadId>,
    current: ThreadId,
}

static SCHEDULER: Mutex<Option<Scheduler>> = Mutex::new(None);

/// Set by the timer ISR when a tick has occurred.
static NEED_SWITCH: AtomicBool = AtomicBool::new(false);

/// Ticks remaining before QEMU test shutdown.
static TEST_TICKS: AtomicU64 = AtomicU64::new(300);

/// Set by the timer ISR to request a context switch.
pub fn request_switch() {
    NEED_SWITCH.store(true, Ordering::Relaxed);
}

/// Check whether the timer ISR has requested a context switch.
pub fn should_switch() -> bool {
    NEED_SWITCH.swap(false, Ordering::Relaxed)
}

/// Decrement the test tick counter and return `true` if QEMU should shut down.
pub fn test_tick() -> bool {
    TEST_TICKS.fetch_sub(1, Ordering::Relaxed) == 1
}

/// Initialise the scheduler, registering the current execution context as the
/// idle thread (thread 0).
pub fn init() {
    let mut guard = SCHEDULER.lock();
    let mut sched = Scheduler {
        threads: Vec::with_capacity(16),
        run_queue: VecDeque::new(),
        current: 0,
    };
    sched.threads.push(alloc::boxed::Box::new(Thread {
        stack: None,
        rsp: 0,
        state: ThreadState::Runnable,
        message: None,
        cspace: None,
    }));
    sched.run_queue.push_back(0);
    *guard = Some(sched);
}

/// Block the current thread with the given reason and yield immediately.
///
/// Must be called with interrupts disabled.
#[allow(unsafe_code)]
pub fn block_current(reason: ThreadState) {
    crate::serial_println!("block_current: thread={} reason={:?}", current_thread_id(), reason);
    let mut guard = SCHEDULER.lock();
    let sched = guard.as_mut().expect("scheduler not initialised");
    let current_id = sched.current;

    // Remove current from run queue.
    sched.run_queue.retain(|&id| id != current_id);
    sched.threads[current_id].state = reason;

    // Switch to next runnable thread.
    let next_id = *sched.run_queue.front().unwrap_or(&0);
    if next_id != current_id {
        let old_rsp = &mut sched.threads[current_id].rsp as *mut u64;
        let new_rsp = sched.threads[next_id].rsp;
        sched.current = next_id;
        // Release the mutex before switching so the next thread can acquire it.
        drop(guard);
        // SAFETY: `old_rsp` points to valid writable memory in the scheduler.
        // `new_rsp` was initialised by `init_stack` or a previous switch.
        // Interrupts are disabled by the caller.
        unsafe {
            ruzt_hal_x86_64::context::switch(old_rsp, new_rsp);
        }
    }
}

/// Unblock a thread and return it to the run queue.
pub fn unblock(thread_id: ThreadId) {
    let mut guard = SCHEDULER.lock();
    let sched = guard.as_mut().expect("scheduler not initialised");
    if !matches!(sched.threads[thread_id].state, ThreadState::Runnable) {
        sched.threads[thread_id].state = ThreadState::Runnable;
        sched.run_queue.push_back(thread_id);
    }
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
    let mut guard = SCHEDULER.lock();
    let sched = guard.as_mut().expect("scheduler not initialised");

    let id = sched.threads.len();
    let mut stack = alloc::boxed::Box::new([0u8; 64 * 1024]);

    #[allow(unsafe_code)]
    let rsp = unsafe {
        ruzt_hal_x86_64::context::init_stack(&mut *stack, f)
    };

    sched.threads.push(alloc::boxed::Box::new(Thread {
        stack: Some(stack),
        rsp,
        state: ThreadState::Runnable,
        message: None,
        cspace: None,
    }));
    sched.run_queue.push_back(id);

    id
}

/// Rotate the run queue and, if a different thread should run, perform the
/// context switch.
///
/// Must be called with interrupts disabled to prevent re-entrancy.
#[allow(unsafe_code)]
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
        let old_rsp = &mut sched.threads[current_id].rsp as *mut u64;
        let new_rsp = sched.threads[next_id].rsp;
        sched.current = next_id;
        // Release the mutex before switching so the next thread can acquire it.
        drop(guard);
        // SAFETY: `old_rsp` points to valid writable memory in the scheduler.
        // `new_rsp` was initialised by `init_stack` or a previous switch.
        // Interrupts are disabled by the caller.
        unsafe {
            ruzt_hal_x86_64::context::switch(old_rsp, new_rsp);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduler_init_creates_idle_thread() {
        init();
        let id = current_thread_id();
        assert_eq!(id, 0);
    }

    #[test]
    fn block_and_unblock() {
        init();
        let id = current_thread_id();
        assert_eq!(id, 0);

        // Simulate blocking (we can't actually context switch in tests)
        // but we can verify the state changes
        {
            let mut guard = SCHEDULER.lock();
            let sched = guard.as_mut().unwrap();
            sched.threads[id].state = ThreadState::BlockedSend(KObjectId(0));
            sched.run_queue.retain(|&i| i != id);
        }

        // Verify blocked
        {
            let guard = SCHEDULER.lock();
            let sched = guard.as_ref().unwrap();
            assert!(matches!(sched.threads[id].state, ThreadState::BlockedSend(_)));
            assert!(!sched.run_queue.contains(&id));
        }

        // Unblock
        unblock(id);

        // Verify runnable
        {
            let guard = SCHEDULER.lock();
            let sched = guard.as_ref().unwrap();
            assert!(matches!(sched.threads[id].state, ThreadState::Runnable));
            assert!(sched.run_queue.contains(&id));
        }
    }

    #[test]
    fn thread_message_buffer() {
        init();
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
