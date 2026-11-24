//! Round-robin scheduler.

use crate::cap::cspace::{self, CapabilityId};
use crate::cap::object::KObjectId;
use crate::ipc::wait::{Sources, Target};
use crate::ipc::{Packet, ReceiveSlots};
use crate::process::UserProcess;
use crate::transaction::{self, Transaction};
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use ruzt_abi::{ErrorCode, ProcessStatus};
use ruzt_hal::time::Timer;
use ruzt_hal_x86_64::context::FpState;
use ruzt_hal_x86_64::time::X86_64Timer;
use spin::Mutex;

mod cpu;
use cpu::{Cpu, BOOT_CPU, CPU_SLOTS};
#[cfg(all(feature = "qemu-smp-test", not(test)))]
pub(crate) mod qemu;

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
    /// Thread is blocked until any source in its wait list becomes ready.
    BlockedAny,
    /// The task has terminated and its context is being reclaimed.
    Exiting,
    /// The task's resources have been reclaimed and its slot may be reused.
    Exited,
}

/// Per-thread state.
struct Thread {
    /// Owned kernel stack (64 KiB). `None` for a CPU's idle context.
    stack: Option<alloc::boxed::Box<[u8]>>,
    /// Saved stack pointer from the last context switch.
    rsp: u64,
    /// Saved architectural floating-point context.
    fp: FpState,
    /// Current scheduling state.
    state: ThreadState,
    /// CPU whose ready queue owns this thread.
    cpu: usize,
    /// Whether an idle CPU may steal the saved context.
    migratable: bool,
    /// IPC message buffer for rendezvous delivery.
    message: Option<Packet>,
    receive_slots: ReceiveSlots,
    wait_capability: Option<CapabilityId>,
    wait_sources: Option<Sources>,
    wait_deadline: Option<u64>,
    /// An error that ended a blocking operation.
    ipc_error: Option<ErrorCode>,
    /// Address space and capabilities of a user-mode thread.
    user: Option<UserProcess>,
}

impl Thread {
    fn idle(cpu: usize) -> Self {
        Self {
            stack: None,
            rsp: 0,
            fp: FpState::default(),
            state: ThreadState::Runnable,
            cpu,
            migratable: false,
            message: None,
            receive_slots: ReceiveSlots::default(),
            wait_capability: None,
            wait_sources: None,
            wait_deadline: None,
            ipc_error: None,
            user: None,
        }
    }

    fn waits_for(&self, target: Target) -> bool {
        self.wait_sources.as_ref().is_some_and(|sources| {
            sources
                .iter()
                .flatten()
                .any(|source| source.target == target)
        })
    }
}

/// Scheduler state.
#[allow(clippy::vec_box)]
struct Scheduler {
    threads: Vec<alloc::boxed::Box<Thread>>,
    cpus: Vec<Option<Cpu>>,
    wait_queue: VecDeque<ThreadId>,
    next_deadline: Option<u64>,
    kernel_cr3: u64,
}

impl Scheduler {
    fn mark_blocked(&mut self, id: ThreadId, reason: ThreadState) {
        self.remove_ready(id);
        self.threads[id].state = reason;
        self.wait_queue.push_back(id);
    }

    fn mark_runnable(&mut self, id: ThreadId) {
        if !matches!(
            self.threads[id].state,
            ThreadState::Runnable | ThreadState::Exiting | ThreadState::Exited
        ) {
            self.wait_queue.retain(|&thread| thread != id);
            self.threads[id].state = ThreadState::Runnable;
            self.threads[id].wait_capability = None;
            self.threads[id].wait_sources = None;
            self.threads[id].wait_deadline = None;
            self.threads[id].receive_slots = ReceiveSlots::default();
            let cpu = self.threads[id].cpu;
            self.cpu_mut(cpu).run_queue.push_back(id);
            #[cfg(not(test))]
            if cpu == current_cpu() {
                NEED_SWITCH[cpu].store(true, Ordering::Relaxed);
            } else {
                crate::smp::reschedule(cpu);
            }
        }
    }

    fn remove_ready(&mut self, id: ThreadId) {
        let cpu = self.threads[id].cpu;
        self.cpu_mut(cpu).run_queue.retain(|&thread| thread != id);
    }

    fn wake_wait_any(&mut self, target: Target) {
        self.expire_waits();
        self.finish_waiters(None, |thread| thread.waits_for(target));
    }

    fn set_wait_deadline(&mut self, id: ThreadId, deadline: u64) {
        self.threads[id].wait_deadline = Some(deadline);
        self.next_deadline = Some(
            self.next_deadline
                .map_or(deadline, |next| next.min(deadline)),
        );
    }

    fn expire_waits(&mut self) {
        if self.next_deadline.is_some() {
            self.expire_waits_at(X86_64Timer::now_monotonic_ns());
        }
    }

    fn expire_waits_at(&mut self, now: u64) {
        if self.next_deadline.is_none_or(|deadline| deadline > now) {
            return;
        }
        self.finish_waiters(Some(ErrorCode::TimedOut), |thread| {
            thread.wait_deadline.is_some_and(|deadline| deadline <= now)
        });
        // Waking a task for another reason may leave an earlier cached
        // deadline. Refresh it once that deadline is reached.
        self.next_deadline = self
            .wait_queue
            .iter()
            .filter_map(|&thread| self.threads[thread].wait_deadline)
            .min();
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

struct SchedulerGuard {
    lock: spin::MutexGuard<'static, Option<Scheduler>>,
    #[cfg(not(test))]
    _interrupts: ruzt_hal_x86_64::cpu::X86_64InterruptGuard,
}

impl core::ops::Deref for SchedulerGuard {
    type Target = Option<Scheduler>;

    fn deref(&self) -> &Self::Target {
        &self.lock
    }
}

impl core::ops::DerefMut for SchedulerGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.lock
    }
}

fn lock_scheduler() -> SchedulerGuard {
    #[cfg(not(test))]
    let interrupts = {
        use ruzt_hal::cpu::CpuOps;
        ruzt_hal_x86_64::cpu::X86_64Cpu::disable_interrupts()
    };
    // A holder can be unmapping memory while waiting for our TLB ack.
    let lock = loop {
        if let Some(lock) = SCHEDULER.try_lock() {
            break lock;
        }
        #[cfg(not(test))]
        crate::smp::poll_synchronous_ipis();
        core::hint::spin_loop();
    };
    SchedulerGuard {
        lock,
        #[cfg(not(test))]
        _interrupts: interrupts,
    }
}

#[allow(unsafe_code)]
extern "C" fn finish_switch() {
    // SAFETY: switch_to transferred the single lock acquisition to this
    // callback, which runs after the previous stack and CR3 were replaced.
    unsafe { SCHEDULER.force_unlock() };
}

/// CPU-local scheduling hints from interrupts and thread exit.
static NEED_SWITCH: [AtomicBool; CPU_SLOTS] = [const { AtomicBool::new(false) }; CPU_SLOTS];

fn current_cpu() -> usize {
    #[cfg(not(test))]
    return crate::smp::scheduler_slot();
    #[cfg(test)]
    BOOT_CPU
}

/// Request a scheduling check on the current CPU.
pub fn request_switch() {
    NEED_SWITCH[current_cpu()].store(true, Ordering::Relaxed);
}

/// Consume a pending scheduling hint on the current CPU.
pub fn should_switch() -> bool {
    NEED_SWITCH[current_cpu()].swap(false, Ordering::Relaxed)
}

/// Initialise the scheduler, registering the current execution context as the
/// idle thread (thread 0).
pub fn init() {
    #[cfg(not(test))]
    let kernel_cr3 = ruzt_hal_x86_64::context::current_cr3();
    #[cfg(test)]
    let kernel_cr3 = 0;
    let mut guard = lock_scheduler();
    let mut sched = Scheduler {
        threads: Vec::with_capacity(16),
        cpus: (0..CPU_SLOTS).map(|_| None).collect(),
        wait_queue: VecDeque::new(),
        next_deadline: None,
        kernel_cr3,
    };
    sched.threads.push(alloc::boxed::Box::new(Thread::idle(BOOT_CPU)));
    sched.cpus[BOOT_CPU] = Some(Cpu::new(0));
    *guard = Some(sched);
}

pub(crate) fn register_secondary(id: u8) -> Result<(), ErrorCode> {
    let cpu = crate::smp::secondary_scheduler_slot(id);
    let mut guard = lock_scheduler();
    let sched = guard.as_mut().expect("scheduler not initialised");
    assert!(sched.cpus[cpu].is_none());
    sched.threads.try_reserve(1).map_err(|_| ErrorCode::NoMemory)?;
    let idle = alloc::boxed::Box::try_new(Thread::idle(cpu)).map_err(|_| ErrorCode::NoMemory)?;
    let id = sched.threads.len();
    sched.threads.push(idle);
    sched.cpus[cpu] = Some(Cpu::new(id));
    Ok(())
}

pub(crate) fn block_with_authority(
    transaction: &mut Transaction,
    reason: ThreadState,
    capability: Option<CapabilityId>,
    slots: ReceiveSlots,
) {
    block(transaction, reason, capability, slots, None, None);
}

pub(crate) fn block_wait_any(transaction: &mut Transaction, sources: &Sources, deadline: Option<u64>) {
    block(
        transaction,
        ThreadState::BlockedAny,
        None,
        ReceiveSlots::default(),
        Some(sources),
        deadline,
    );
}

fn block(
    transaction: &mut Transaction,
    reason: ThreadState,
    capability: Option<CapabilityId>,
    slots: ReceiveSlots,
    sources: Option<&Sources>,
    deadline: Option<u64>,
) {
    #[cfg(feature = "qemu-smoke-test")]
    crate::serial_println!(
        "block_current: thread={} reason={:?}",
        current_thread_id(),
        reason
    );
    let mut guard = lock_scheduler();
    let sched = guard.as_mut().expect("scheduler not initialised");
    let cpu = current_cpu();
    let current_id = sched.cpu(cpu).current;

    // Remove current from run queue.
    assert_ne!(current_id, sched.cpu(cpu).idle, "the idle thread cannot block");
    sched.threads[current_id].wait_capability = capability;
    sched.threads[current_id].receive_slots = slots;
    sched.threads[current_id].wait_sources = sources.copied();
    if let Some(deadline) = deadline {
        sched.set_wait_deadline(current_id, deadline);
    }
    sched.mark_blocked(current_id, reason);
    if let ThreadState::BlockedSend(endpoint) = reason {
        // A selector can consume the sender only after it joins the queue.
        sched.wake_wait_any(Target::Endpoint(endpoint));
    }

    // The waiter is visible before releasing the transaction. The scheduler
    // lock stays held until the context is saved, even if it wakes immediately.
    let next_id = sched.pick_next(cpu);
    transaction.park(|| switch_to(guard, cpu, next_id));
}

/// Unblock a thread and return it to the run queue.
pub fn unblock(thread_id: ThreadId) {
    let mut guard = lock_scheduler();
    let sched = guard.as_mut().expect("scheduler not initialised");
    sched.mark_runnable(thread_id);
}

pub(crate) fn first_waiter(reason: ThreadState) -> Option<ThreadId> {
    let guard = lock_scheduler();
    let sched = guard.as_ref().expect("scheduler not initialised");
    sched
        .wait_queue
        .iter()
        .copied()
        .find(|&id| sched.threads[id].state == reason)
}

pub(crate) fn cancel_endpoint_waiters(endpoint: KObjectId) {
    let mut guard = lock_scheduler();
    let sched = guard.as_mut().expect("scheduler not initialised");
    sched.finish_waiters(Some(ErrorCode::NotFound), |thread| {
        matches!(
            thread.state,
            ThreadState::BlockedSend(object) | ThreadState::BlockedRecv(object)
                if object == endpoint
        )
    });
    sched.wake_wait_any(Target::Endpoint(endpoint));
}

pub(crate) fn wake_wait_any(target: Target) {
    if let Some(sched) = lock_scheduler().as_mut() {
        sched.wake_wait_any(target);
    }
}

pub(crate) fn apply_capability_removals(_transaction: &Transaction) {
    crate::irq::detach_revoked();
    crate::iommu::detach_revoked();
    let mut guard = lock_scheduler();
    let Some(sched) = guard.as_mut() else { return };
    for thread in &mut sched.threads {
        if let Some(user) = &mut thread.user {
            user.unmap_revoked_frames();
            user.unmap_revoked_device_memory();
        }
    }
    sched.finish_waiters(Some(ErrorCode::InvalidCap), |thread| {
        thread
            .wait_capability
            .is_some_and(|id| !cspace::is_live(id))
            || thread.wait_sources.as_ref().is_some_and(|sources| {
                sources
                    .iter()
                    .flatten()
                    .any(|source| !source.authority.is_live())
            })
    });
}

pub(crate) fn wake_process_waiters(process: KObjectId) {
    let mut guard = lock_scheduler();
    let sched = guard.as_mut().expect("scheduler not initialised");
    sched.finish_waiters(None, |thread| {
        thread.state == ThreadState::BlockedProcess(process)
    });
    sched.wake_wait_any(Target::Process(process));
}

pub(crate) fn expire_waits(_transaction: &Transaction) {
    if let Some(sched) = lock_scheduler().as_mut() {
        sched.expire_waits();
    }
}

pub(crate) fn complete_ipc(id: ThreadId, error: Option<ErrorCode>) {
    let mut guard = lock_scheduler();
    let sched = guard.as_mut().expect("scheduler not initialised");
    sched.threads[id].ipc_error = error;
    sched.mark_runnable(id);
}

pub(crate) fn deliver_to_waiter(id: ThreadId, packet: Packet) -> Result<(), ErrorCode> {
    let mut guard = lock_scheduler();
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
    let mut guard = lock_scheduler();
    let sched = guard.as_mut().expect("scheduler not initialised");
    let current = sched.cpu(current_cpu()).current;
    sched.threads[current]
        .ipc_error
        .take()
        .map_or(Ok(()), Err)
}

pub(crate) fn wake_irq(thread_id: ThreadId, irq: u32) {
    let mut guard = lock_scheduler();
    let sched = guard.as_mut().expect("scheduler not initialised");
    sched.expire_waits();
    if sched
        .threads
        .get(thread_id)
        .is_some_and(|thread| thread.waits_for(Target::Irq(irq)))
    {
        sched.mark_runnable(thread_id);
    }
}

pub(crate) fn with_current_user<T>(f: impl FnOnce(&mut UserProcess) -> T) -> Option<T> {
    let mut guard = lock_scheduler();
    let sched = guard.as_mut()?;
    let current = sched.cpu(current_cpu()).current;
    sched.threads[current].user.as_mut().map(f)
}

/// Leave the dying task on its own stack until the idle thread can reap it.
/// Called from a syscall or user fault with interrupts disabled.
pub(crate) fn retire_current_user(transaction: Transaction, status: ProcessStatus) -> ! {
    retire_current(Some((transaction, status)))
}

pub(crate) fn retire_current_worker() -> ! {
    retire_current(None)
}

fn retire_current(exit: Option<(Transaction, ProcessStatus)>) -> ! {
    let mut guard = lock_scheduler();
    let sched = guard.as_mut().expect("scheduler not initialised");
    let cpu = current_cpu();
    let local = sched.cpu(cpu);
    let (id, idle) = (local.current, local.idle);
    assert_ne!(id, idle);
    assert_eq!(sched.threads[id].user.is_some(), exit.is_some());
    assert!(local.retired.is_none());
    sched.remove_ready(id);
    sched.threads[id].state = ThreadState::Exiting;
    sched.cpu_mut(cpu).retired = Some((id, exit.as_ref().map(|(_, status)| *status)));
    request_switch();
    drop(exit);
    switch_to(guard, cpu, idle);
    unreachable!("exited thread resumed");
}

pub(crate) fn reap_retired() {
    let (id, user, stack, status) = {
        let mut guard = lock_scheduler();
        let sched = guard.as_mut().expect("scheduler not initialised");
        let local = sched.cpu_mut(current_cpu());
        let Some((id, status)) = local.retired.take() else {
            return;
        };
        assert_eq!(local.current, local.idle);
        let retired = &mut sched.threads[id];
        retired.fp = FpState::default();
        (id, retired.user.take(), retired.stack.take(), status)
    };
    drop(stack);
    if let Some(mut user) = user {
        let transaction = transaction::enter();
        let name = user.name;
        let publisher = user.exit_publisher.take();
        drop(user);
        // A shared CNode can contain caps owned by the reaped task that other
        // tasks have used for wait operations or shared mappings.
        apply_capability_removals(&transaction);
        crate::serial_println!("reaped user process {name}");
        if let Some(publisher) = publisher {
            publisher.publish(&transaction, status.expect("retired user task has an exit status"));
        }
    }
    {
        let mut guard = lock_scheduler();
        let sched = guard.as_mut().expect("scheduler not initialised");
        sched.threads[id].state = ThreadState::Exited;
    }
}

/// Return the current thread's ID.
pub fn current_thread_id() -> ThreadId {
    let guard = lock_scheduler();
    let sched = guard.as_ref().expect("scheduler not initialised");
    sched.cpu(current_cpu()).current
}

/// Return a copy of the current thread's message buffer, clearing it.
pub(crate) fn take_current_message() -> Option<Packet> {
    let mut guard = lock_scheduler();
    let sched = guard.as_mut().expect("scheduler not initialised");
    let current_id = sched.cpu(current_cpu()).current;
    sched.threads[current_id].message.take()
}

/// Store a message into the given thread's buffer.
pub(crate) fn set_thread_message(thread_id: ThreadId, msg: Packet) {
    let mut guard = lock_scheduler();
    let sched = guard.as_mut().expect("scheduler not initialised");
    sched.threads[thread_id].message = Some(msg);
}

/// Take a message from the given thread's buffer, clearing it.
pub(crate) fn take_thread_message(thread_id: ThreadId) -> Option<Packet> {
    let mut guard = lock_scheduler();
    let sched = guard.as_mut().expect("scheduler not initialised");
    sched.threads[thread_id].message.take()
}

/// Spawn a new kernel thread that starts executing `f`.
///
/// Allocates a 64 KiB stack, sets up an initial frame, and pushes the thread
/// onto the run queue.
pub fn spawn(f: fn() -> !) -> ThreadId {
    spawn_thread(f, None, false).expect("allocate kernel thread")
}

pub(crate) fn spawn_user(user: UserProcess, entry: fn() -> !) -> Result<ThreadId, ErrorCode> {
    // Device vector allocation still checks the boot CPU's local APIC.
    spawn_thread(entry, Some(user), false)
}

/// Spawn a kernel worker that may run on any scheduler CPU. Workers must
/// use only SMP-safe APIs. Device-control operations still run on the BSP.
pub(crate) fn spawn_worker(f: fn() -> !) -> ThreadId {
    spawn_thread(f, None, true).expect("allocate kernel worker")
}

fn spawn_thread(
    f: fn() -> !,
    user: Option<UserProcess>,
    migratable: bool,
) -> Result<ThreadId, ErrorCode> {
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

    let mut guard = lock_scheduler();
    let sched = guard.as_mut().expect("scheduler not initialised");
    let cpu = if migratable { current_cpu() } else { BOOT_CPU };
    sched
        .cpu_mut(cpu)
        .run_queue
        .try_reserve(1)
        .map_err(|_| ErrorCode::NoMemory)?;
    let thread = Thread {
        stack: Some(stack),
        rsp,
        fp: FpState::default(),
        state: ThreadState::Runnable,
        cpu,
        migratable,
        message: None,
        receive_slots: ReceiveSlots::default(),
        wait_capability: None,
        wait_sources: None,
        wait_deadline: None,
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
    sched.cpu_mut(cpu).run_queue.push_back(id);

    Ok(id)
}

/// Rotate the run queue and, if a different thread should run, perform the
/// context switch.
///
/// Must be called with interrupts disabled to prevent re-entrancy.
pub fn yield_thread() {
    let mut guard = lock_scheduler();
    let sched = guard.as_mut().expect("scheduler not initialised");
    let cpu = current_cpu();
    let next_id = sched.pick_next(cpu);
    if next_id != sched.cpu(cpu).current {
        switch_to(guard, cpu, next_id);
    }
}

#[allow(unsafe_code)]
fn switch_to(mut guard: SchedulerGuard, cpu: usize, next_id: ThreadId) {
    let sched = guard.as_mut().expect("scheduler not initialised");
    let current_id = sched.cpu(cpu).current;
    let current = &mut sched.threads[current_id];
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
        unsafe { crate::smp::set_trap_stack(cpu, Some(stack_top)) };
        user.root().base.as_u64()
    } else {
        // SAFETY: Bookkeeping runs with interrupts disabled. A kernel thread
        // must stop using the outgoing user thread's privilege stack.
        unsafe { crate::smp::set_trap_stack(cpu, None) };
        sched.kernel_cr3
    };
    sched.cpu_mut(cpu).current = next_id;
    // Transfer unlock to the incoming stack. Other CPUs must not reuse this
    // context while the outgoing thread is still saving registers or CR3.
    core::mem::forget(guard.lock);
    // SAFETY: Both thread records are pinned in separate boxes, and the boot
    // kernel heap, the switch code, and both stacks are mapped in both roots.
    unsafe {
        ruzt_hal_x86_64::context::switch(old_rsp, new_rsp, new_cr3, old_fp, new_fp, finish_switch)
    };
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
    fn idle_cpu_steals_only_migratable_threads_that_are_off_cpu() {
        let _state = crate::isolated_kernel_state();
        fn entry() -> ! {
            panic!("host tests do not switch stacks")
        }
        let running = spawn_worker(entry);
        let ready = spawn_worker(entry);
        let pinned = spawn(entry);
        register_secondary(7).unwrap();
        register_secondary(8).unwrap();
        let thief = crate::smp::secondary_scheduler_slot(7);
        let peer = crate::smp::secondary_scheduler_slot(8);

        let mut guard = lock_scheduler();
        let sched = guard.as_mut().unwrap();
        sched.cpu_mut(BOOT_CPU).current = running;
        assert_eq!(sched.pick_next(thief), ready);
        sched.cpu_mut(thief).current = ready;
        assert_eq!(sched.threads[ready].cpu, thief);
        assert_eq!(sched.cpu(BOOT_CPU).run_queue, [running, pinned]);
        assert_eq!(sched.cpu(thief).run_queue, [ready]);
        assert_eq!(sched.pick_next(peer), sched.cpu(peer).idle);
    }

    #[test]
    fn thread_slot_is_reused_after_its_stack_is_released() {
        let _state = crate::isolated_kernel_state();
        fn entry() -> ! {
            panic!("host tests do not switch stacks")
        }
        let retired = spawn(entry);
        {
            let mut guard = lock_scheduler();
            let sched = guard.as_mut().unwrap();
            sched.cpu_mut(BOOT_CPU).run_queue.clear();
            sched.threads[retired].state = ThreadState::Exited;
        }
        let live = spawn(entry);
        assert_ne!(live, retired);
        {
            let mut guard = lock_scheduler();
            let sched = guard.as_mut().unwrap();
            sched.threads[retired].stack = None;
        }
        assert_eq!(spawn(entry), retired);
        let guard = lock_scheduler();
        let sched = guard.as_ref().unwrap();
        assert_eq!(sched.cpu(BOOT_CPU).run_queue, [live, retired]);
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
            let mut guard = lock_scheduler();
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
        let guard = lock_scheduler();
        let sched = guard.as_ref().unwrap();
        assert_eq!(sched.cpu(BOOT_CPU).run_queue, [later_spawned, earlier_spawned]);
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
            let mut guard = lock_scheduler();
            let scheduler = guard.as_mut().unwrap();
            scheduler.threads[survivor].wait_capability = Some(surviving_cap);
            scheduler.threads[revoked].wait_capability = Some(revoked_cap);
            scheduler.mark_blocked(survivor, ThreadState::BlockedWait(id));
            scheduler.mark_blocked(revoked, ThreadState::BlockedWait(id));
        }
        caps.revoke(0).unwrap();
        apply_capability_removals(&transaction::enter());
        let guard = lock_scheduler();
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
        let mut transaction = transaction::enter();
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
            crate::process::wait_for_status(&mut transaction, process, observer, true),
            Err(ErrorCode::WouldBlock)
        );
        fn entry() -> ! {
            panic!("host tests do not switch stacks")
        }
        let first = spawn(entry);
        let second = spawn(entry);
        let unrelated = spawn(entry);
        {
            let mut guard = lock_scheduler();
            let sched = guard.as_mut().unwrap();
            sched.mark_blocked(first, ThreadState::BlockedProcess(id));
            sched.mark_blocked(second, ThreadState::BlockedProcess(id));
            sched.mark_blocked(unrelated, ThreadState::BlockedWait(id));
        }
        let expected = ProcessStatus {
            kind: ruzt_abi::PROCESS_EXITED,
            code: 23,
        };
        publisher.publish(&transaction, expected);
        {
            let guard = lock_scheduler();
            let sched = guard.as_ref().unwrap();
            assert_eq!(sched.cpu(BOOT_CPU).run_queue, [first, second]);
            assert_eq!(sched.wait_queue, [unrelated]);
            assert_eq!(sched.threads[first].ipc_error, None);
        }
        assert_eq!(
            crate::process::wait_for_status(&mut transaction, process, observer, false),
            Ok(expected)
        );
        assert_eq!(
            crate::process::wait_for_status(&mut transaction, process, observer, true),
            Ok(expected)
        );
        drop(caps);
        assert!(object::get(id).is_none());
    }

    #[test]
    fn wait_any_wakes_for_matching_sources_and_cancels_revoked_authority() {
        use crate::cap::object;
        use crate::ipc::wait::Source;
        use ruzt_cap::{CapRights, CapSlot, CapType, EndpointId, NotificationId};

        let _state = crate::isolated_kernel_state();
        let transaction = transaction::enter();
        let endpoint = object::allocate(CapType::Endpoint(EndpointId(0))).unwrap();
        let notification = object::allocate(CapType::Notification(NotificationId(0))).unwrap();
        let mut caps = cspace::CSpace::new(1);
        for (cptr, cap_type) in [
            CapType::Endpoint(EndpointId(endpoint.0)),
            CapType::Notification(NotificationId(notification.0)),
        ]
        .into_iter()
        .enumerate()
        {
            caps.insert(
                cptr as u64,
                CapSlot {
                    cap_type,
                    rights: CapRights::READ,
                    badge: 0,
                },
            )
            .unwrap();
        }
        fn entry() -> ! {
            panic!("host tests do not switch stacks")
        }
        let endpoint_waiter = spawn(entry);
        let notification_waiter = spawn(entry);
        {
            let mut guard = lock_scheduler();
            let scheduler = guard.as_mut().unwrap();
            for (cptr, thread) in [endpoint_waiter, notification_waiter]
                .into_iter()
                .enumerate()
            {
                let (path, slot) = caps.lookup_path(cptr as u64).unwrap();
                let mut sources = Sources::default();
                sources[0] = Some(Source::new(path, slot, thread).unwrap());
                scheduler.threads[thread].wait_sources = Some(sources);
                scheduler.mark_blocked(thread, ThreadState::BlockedAny);
            }
        }
        crate::ipc::close_endpoint(&transaction, EndpointId(endpoint.0));
        {
            let guard = lock_scheduler();
            let scheduler = guard.as_ref().unwrap();
            assert_eq!(scheduler.cpu(BOOT_CPU).run_queue, [endpoint_waiter]);
            assert_eq!(scheduler.wait_queue, [notification_waiter]);
            assert_eq!(scheduler.threads[endpoint_waiter].ipc_error, None);
        }
        caps.delete(1).unwrap();
        apply_capability_removals(&transaction);
        let guard = lock_scheduler();
        let scheduler = guard.as_ref().unwrap();
        assert_eq!(scheduler.cpu(BOOT_CPU).run_queue, [endpoint_waiter, notification_waiter]);
        assert!(scheduler.wait_queue.is_empty());
        assert_eq!(
            scheduler.threads[notification_waiter].ipc_error,
            Some(ErrorCode::InvalidCap)
        );
    }

    #[test]
    fn wait_deadlines_expire_once_and_leave_other_waiters_queued() {
        let _state = crate::isolated_kernel_state();
        fn entry() -> ! {
            panic!("host tests do not switch stacks")
        }
        let early_event = spawn(entry);
        let short = spawn(entry);
        let tied = spawn(entry);
        let long = spawn(entry);
        let indefinite = spawn(entry);
        let mut guard = lock_scheduler();
        let scheduler = guard.as_mut().unwrap();
        for id in [early_event, short, tied, long, indefinite] {
            scheduler.mark_blocked(id, ThreadState::BlockedAny);
        }
        for (id, deadline) in [(early_event, 10), (short, 20), (tied, 20), (long, 30)] {
            scheduler.set_wait_deadline(id, deadline);
        }
        scheduler.mark_runnable(early_event);
        scheduler.expire_waits_at(10);
        assert_eq!(scheduler.next_deadline, Some(20));
        assert_eq!(scheduler.cpu(BOOT_CPU).run_queue, [early_event]);
        assert_eq!(scheduler.threads[early_event].ipc_error, None);

        scheduler.expire_waits_at(20);
        assert_eq!(scheduler.next_deadline, Some(30));
        assert_eq!(scheduler.wait_queue, [long, indefinite]);
        assert_eq!(scheduler.cpu(BOOT_CPU).run_queue, [early_event, short, tied]);
        for id in [short, tied] {
            assert_eq!(scheduler.threads[id].ipc_error, Some(ErrorCode::TimedOut));
            assert_eq!(scheduler.threads[id].wait_deadline, None);
        }

        scheduler.expire_waits_at(u64::MAX);
        assert_eq!(scheduler.next_deadline, None);
        assert_eq!(scheduler.wait_queue, [indefinite]);
        assert_eq!(scheduler.cpu(BOOT_CPU).run_queue, [early_event, short, tied, long]);
        assert_eq!(scheduler.threads[long].ipc_error, Some(ErrorCode::TimedOut));
        assert_eq!(scheduler.threads[indefinite].ipc_error, None);
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
