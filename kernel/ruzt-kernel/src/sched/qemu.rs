//! Verify cross-CPU context migration, reaping, and IPC.

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use ruzt_abi::IpcMessage;
use ruzt_cap::{CapType, EndpointId};
use ruzt_hal::cpu::CpuOps;
use ruzt_hal_x86_64::cpu::X86_64Cpu;

use super::{
    current_cpu, current_thread_id, lock_scheduler, retire_current_worker, spawn_worker,
    ThreadState,
};
use crate::cap::object::{self, KObjectId};
use crate::ipc::{self, Packet, ReceiveSlots};
use crate::transaction;

const SECONDARIES: usize = 3;
static LEADER: AtomicUsize = AtomicUsize::new(0);
static PARENTS: AtomicUsize = AtomicUsize::new(0);
static CHILDREN: AtomicUsize = AtomicUsize::new(0);
static MIGRATED: AtomicBool = AtomicBool::new(false);
static ENDPOINT: AtomicU64 = AtomicU64::new(0);
static RECEIVER_CPU: AtomicUsize = AtomicUsize::new(0);
static SENDER_CPU: AtomicUsize = AtomicUsize::new(0);
static IPC_COMPLETE: AtomicBool = AtomicBool::new(false);
static VECTOR_PROBE_STARTED: AtomicBool = AtomicBool::new(false);
const IPC_LABEL: u64 = 0x736d_702d_6970_6321;

pub(crate) fn enqueue() {
    for _ in 0..SECONDARIES {
        spawn_worker(parent);
    }
}

pub(crate) fn verify() {
    for _ in 0..50_000_000 {
        if MIGRATED.load(Ordering::Acquire) && workers_reaped() {
            crate::serial_println!(
                "SMP scheduler migrated a saved worker and reaped all worker stacks"
            );
            return;
        }
        core::hint::spin_loop();
    }
    panic!("SMP scheduler did not migrate and reap the workers");
}

pub(crate) fn verify_ipc() {
    let endpoint = object::allocate(CapType::Endpoint(EndpointId(0))).expect("probe endpoint");
    ENDPOINT.store(endpoint.0, Ordering::Release);
    spawn_worker(receive);
    spawn_worker(send);
    // The boot CPU holds IF clear until the fixture completes. The receiver
    // depends on the sender's targeted reschedule IPI once it has parked.
    crate::smp::tick_schedulers();
    for _ in 0..50_000_000 {
        if IPC_COMPLETE.load(Ordering::Acquire) && workers_reaped() {
            object::deallocate(endpoint);
            crate::serial_println!(
                "SMP IPC registered a waiter and completed a cross-CPU rendezvous"
            );
            return;
        }
        core::hint::spin_loop();
    }
    panic!("cross-CPU IPC did not unblock its receiver");
}

#[allow(unsafe_code)]
pub(crate) fn verify_irq_probe() {
    use ruzt_hal_x86_64::{
        apic::{Ipi, TLB_VECTOR},
        irq,
    };

    let bsp = crate::apic::cpu_topology().expect("QEMU APIC topology").bsp;
    // SAFETY: The BSP has IF clear, owns its ICR, and has no TLB mailbox request.
    // This makes a vector pending only on the receiving CPU.
    assert!(unsafe { irq::send_ipi(bsp, Ipi::Tlb) });
    // SAFETY: Same CPU and interrupt state. Pass only after IRR observes it.
    assert!(
        (0..1_000_000).any(|_| unsafe { irq::local_boot_vector_idle(TLB_VECTOR) } == Some(false))
    );
    spawn_worker(probe_irq);
    crate::smp::tick_schedulers();
    for _ in 0..50_000_000 {
        if VECTOR_PROBE_STARTED.load(Ordering::Acquire) {
            // The AP holds this transaction. While waiting, the BSP must
            // service both probes with its interrupt gate still masked.
            drop(transaction::enter());
            crate::serial_println!(
                "SMP LAPIC probe distinguished pending and idle boot CPU vectors"
            );
            return;
        }
        core::hint::spin_loop();
    }
    panic!("secondary CPU did not start its LAPIC probe");
}

#[allow(unsafe_code)]
fn probe_irq() -> ! {
    use ruzt_hal_x86_64::{apic::TLB_VECTOR, irq};

    assert_ne!(current_cpu(), 0);
    let _interrupts = X86_64Cpu::disable_interrupts();
    let transaction = transaction::enter();
    VECTOR_PROBE_STARTED.store(true, Ordering::Release);
    // SAFETY: This test owns the vectors with IF clear under the transaction.
    // Only the BSP's TLB vector was raised. No device routes are installed.
    unsafe {
        assert!(!irq::boot_vector_idle(TLB_VECTOR));
        assert!(irq::boot_vector_idle(
            irq::VECTOR_BASE + irq::IRQ_COUNT as u8 - 1
        ));
    }
    drop(transaction);
    retire_current_worker();
}

fn workers_reaped() -> bool {
    lock_scheduler()
        .as_ref()
        .expect("scheduler initialized")
        .threads
        .iter()
        .filter(|thread| thread.migratable)
        .all(|thread| thread.state == ThreadState::Exited && thread.stack.is_none())
}

fn receive() -> ! {
    let _interrupts = X86_64Cpu::disable_interrupts();
    let mut transaction = transaction::enter();
    let cpu = current_cpu();
    assert_ne!(cpu, 0);
    RECEIVER_CPU.store(cpu, Ordering::Release);
    while SENDER_CPU.load(Ordering::Acquire) == 0 {
        core::hint::spin_loop();
    }

    let endpoint = EndpointId(ENDPOINT.load(Ordering::Acquire));
    let received = ipc::receive_packet(&mut transaction, endpoint, None, ReceiveSlots::default())
        .expect("receive cross-CPU IPC");
    assert_eq!(received.label, IPC_LABEL);
    drop(transaction);
    IPC_COMPLETE.store(true, Ordering::Release);
    retire_current_worker();
}

fn send() -> ! {
    let _interrupts = X86_64Cpu::disable_interrupts();
    let receiver_cpu = loop {
        let cpu = RECEIVER_CPU.load(Ordering::Acquire);
        if cpu != 0 {
            break cpu;
        }
        core::hint::spin_loop();
    };
    let cpu = current_cpu();
    assert_ne!(cpu, 0);
    assert_ne!(cpu, receiver_cpu, "the rendezvous must cross CPUs");
    SENDER_CPU.store(cpu, Ordering::Release);

    let mut transaction = transaction::enter();
    let id = ENDPOINT.load(Ordering::Acquire);
    assert!(super::first_waiter(ThreadState::BlockedRecv(KObjectId(id))).is_some());
    let message = IpcMessage {
        label: IPC_LABEL,
        ..IpcMessage::default()
    };
    ipc::send_packet(
        &mut transaction,
        EndpointId(id),
        None,
        Packet::inline(message),
    )
    .expect("send cross-CPU IPC");
    drop(transaction);
    // Keep the sender on its CPU until the receiver wakes. Otherwise the
    // sender's idle context could steal the receiver without an IPI.
    while !IPC_COMPLETE.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }
    retire_current_worker();
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
