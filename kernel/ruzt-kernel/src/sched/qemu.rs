//! Verify that another CPU can resume a saved worker context.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use ruzt_hal::cpu::CpuOps;
use ruzt_hal_x86_64::cpu::X86_64Cpu;

use super::{current_cpu, current_thread_id, lock_scheduler, retire_current_worker, spawn_worker};

const SECONDARIES: usize = 3;
static LEADER: AtomicUsize = AtomicUsize::new(0);
static PARENTS: AtomicUsize = AtomicUsize::new(0);
static CHILDREN: AtomicUsize = AtomicUsize::new(0);
static MIGRATED: AtomicBool = AtomicBool::new(false);

pub(crate) fn enqueue() {
    for _ in 0..SECONDARIES {
        spawn_worker(parent);
    }
}

pub(crate) fn verify() {
    for _ in 0..50_000_000 {
        if MIGRATED.load(Ordering::Acquire)
            && lock_scheduler()
                .as_ref()
                .expect("scheduler initialized")
                .threads
                .iter()
                .filter(|thread| thread.migratable)
                .all(|thread| thread.state == super::ThreadState::Exited && thread.stack.is_none())
        {
            crate::serial_println!(
                "SMP scheduler migrated a saved worker and reaped all worker stacks"
            );
            return;
        }
        core::hint::spin_loop();
    }
    panic!("SMP scheduler did not migrate and reap the workers");
}

fn parent() -> ! {
    X86_64Cpu::enable_interrupts();
    let cpu = current_cpu();
    let id = current_thread_id();
    assert_ne!(cpu, 0, "the BSP cannot run the migration probe");
    let _ = LEADER.compare_exchange(0, cpu, Ordering::Release, Ordering::Relaxed);
    rendezvous(&PARENTS);

    // Every secondary is executing a parent when the children are queued.
    // After the yield, each child owns the CPU and its parent is stealable.
    spawn_worker(child);
    {
        let _interrupts = X86_64Cpu::disable_interrupts();
        super::yield_thread();
    }
    assert_eq!(current_thread_id(), id);
    if current_cpu() != cpu {
        MIGRATED.store(true, Ordering::Release);
    }
    retire_current_worker();
}

fn child() -> ! {
    X86_64Cpu::enable_interrupts();
    rendezvous(&CHILDREN);
    // The leader retires both local workers, leaving one CPU free to steal.
    // Other children occupy their CPUs until a parent resumes elsewhere.
    if current_cpu() != LEADER.load(Ordering::Acquire) {
        while !MIGRATED.load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
    }
    retire_current_worker();
}

fn rendezvous(count: &AtomicUsize) {
    count.fetch_add(1, Ordering::AcqRel);
    while count.load(Ordering::Acquire) != SECONDARIES {
        core::hint::spin_loop();
    }
}
