//! Round-robin scheduler.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

/// Opaque handle for a scheduler thread.
pub type ThreadId = usize;

/// Per-thread state.
struct Thread {
    /// Owned kernel stack (64 KiB).  `None` for the idle thread.
    #[allow(dead_code)]
    stack: Option<alloc::boxed::Box<[u8; 64 * 1024]>>,
    /// Saved stack pointer from the last context switch.
    rsp: u64,
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
    }));
    sched.run_queue.push_back(0);
    *guard = Some(sched);
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

    if let Some(id) = sched.run_queue.pop_front() {
        sched.run_queue.push_back(id);
    }

    let next_id = *sched.run_queue.front().unwrap_or(&current_id);

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
