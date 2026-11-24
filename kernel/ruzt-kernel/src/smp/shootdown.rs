//! Synchronous requests published under the global page-table lock.

use core::sync::atomic::{fence, AtomicU64, AtomicU8, Ordering};

use ruzt_hal::mem::{PhysAddr, PhysFrame, VirtAddr};
use ruzt_hal_x86_64::{
    apic::Ipi,
    irq,
    tlb::{self, Invalidation},
};

use super::{READY, STATE};
use crate::apic;

const IDLE: u8 = 0;
const PAGE: u8 = 1;
const ALL: u8 = 2;
const USER: u8 = 3;
const INACTIVE: u8 = 4;
#[cfg(feature = "qemu-smp-test")]
const PROBE: u8 = 5;
#[cfg(feature = "qemu-smp-test")]
const CONTEND: u8 = 6;
#[cfg(feature = "qemu-smp-test")]
const SELECT_ROOT: u8 = 7;

struct Mailbox {
    command: AtomicU8,
    argument: AtomicU64,
    #[cfg(feature = "qemu-smp-test")]
    observed: AtomicU64,
    #[cfg(feature = "qemu-smp-test")]
    page_flushes: AtomicU64,
    #[cfg(feature = "qemu-smp-test")]
    user_flushes: AtomicU64,
}

impl Mailbox {
    const fn new() -> Self {
        Self {
            command: AtomicU8::new(IDLE),
            argument: AtomicU64::new(0),
            #[cfg(feature = "qemu-smp-test")]
            observed: AtomicU64::new(0),
            #[cfg(feature = "qemu-smp-test")]
            page_flushes: AtomicU64::new(0),
            #[cfg(feature = "qemu-smp-test")]
            user_flushes: AtomicU64::new(0),
        }
    }

    fn service(&self) {
        let command = self.command.load(Ordering::Acquire);
        let argument = self.argument.load(Ordering::Relaxed);
        let root = || PhysFrame::from_base(PhysAddr::new(argument)).expect("published root frame");
        match command {
            IDLE => return,
            PAGE => {
                tlb::apply_local(Invalidation::Page(VirtAddr::new(argument)));
                #[cfg(feature = "qemu-smp-test")]
                self.page_flushes.fetch_add(1, Ordering::Relaxed);
            }
            ALL => tlb::apply_local(Invalidation::All),
            USER => {
                tlb::apply_local(Invalidation::User(root()));
                #[cfg(feature = "qemu-smp-test")]
                if x86_64::registers::control::Cr3::read()
                    .0
                    .start_address()
                    .as_u64()
                    == argument
                {
                    self.user_flushes.fetch_add(1, Ordering::Relaxed);
                }
            }
            INACTIVE => tlb::apply_local(Invalidation::Inactive(root())),
            #[cfg(feature = "qemu-smp-test")]
            PROBE => {
                #[allow(unsafe_code)]
                // SAFETY: The QEMU test holds the mapper lock and owns this
                // live supervisor page until all reads have completed.
                let observed = unsafe { (argument as *const u64).read_volatile() };
                self.observed.store(observed, Ordering::Relaxed);
            }
            #[cfg(feature = "qemu-smp-test")]
            CONTEND => {
                // This test command is issued once to idle APs while the BSP
                // holds the lock. Acknowledge before attempting to take it.
                self.command.store(IDLE, Ordering::Release);
                ruzt_hal_x86_64::mapper::with_mapper(|_| ());
                return;
            }
            #[cfg(feature = "qemu-smp-test")]
            SELECT_ROOT => {
                #[allow(unsafe_code)]
                // SAFETY: The fixture owns this root and copied all live
                // supervisor mappings before any AP may load it.
                unsafe {
                    core::arch::asm!("mov cr3, {}", in(reg) argument, options(nostack, preserves_flags));
                }
            }
            _ => unreachable!("invalid TLB mailbox command"),
        }
        self.command.store(IDLE, Ordering::Release);
    }
}

static MAILBOXES: [Mailbox; STATE.len()] = [const { Mailbox::new() }; STATE.len()];

pub(super) fn install_shootdown() {
    tlb::install(invalidate_remote, super::poll_synchronous_ipis);
}

fn invalidate_remote(request: Invalidation) {
    let (command, argument) = match request {
        Invalidation::Page(address) => (PAGE, address.as_u64()),
        Invalidation::All => (ALL, 0),
        Invalidation::User(root) => (USER, root.base.as_u64()),
        Invalidation::Inactive(root) => (INACTIVE, root.base.as_u64()),
    };
    broadcast(command, argument);
}

#[allow(unsafe_code)]
fn broadcast(command: u8, argument: u64) {
    let Some(topology) = apic::cpu_topology() else {
        return;
    };
    // SAFETY: The caller is an initialized CPU holding the mapper lock with IF clear.
    let current = unsafe { irq::current_apic_id() }.expect("online CPU has a LAPIC");
    let mut targets = [0; STATE.len()];
    let mut count = 0;
    for (index, slot) in STATE.iter().enumerate() {
        let id = index as u8;
        if id == current || (id != topology.bsp && slot.load(Ordering::Acquire) < READY) {
            continue;
        }
        targets[count] = id;
        count += 1;
        let mailbox = &MAILBOXES[index];
        assert_eq!(mailbox.command.load(Ordering::Acquire), IDLE);
        mailbox.argument.store(argument, Ordering::Relaxed);
        mailbox.command.store(command, Ordering::Release);
    }
    if count == 0 {
        return;
    }
    // Complete publication and prior PTE stores before either MMIO or
    // x2APIC MSR sends. The latter is not a fully serializing instruction.
    fence(Ordering::SeqCst);
    for &id in &targets[..count] {
        // SAFETY: IF is still clear and these CPUs have loaded the IPI gate.
        assert!(
            unsafe { irq::send_ipi(id, Ipi::Tlb) },
            "could not send TLB IPI to APIC {id}"
        );
    }
    for &id in &targets[..count] {
        let mailbox = &MAILBOXES[usize::from(id)];
        let mut budget = 50_000_000;
        while mailbox.command.load(Ordering::Acquire) != IDLE {
            assert!(budget != 0, "TLB acknowledgement timed out on APIC {id}");
            budget -= 1;
            // A remote CPU waiting on a route check can answer the shootdown
            // while this CPU services the pending LAPIC query.
            super::irq_probe::poll_boot();
            core::hint::spin_loop();
        }
    }
}

#[allow(unsafe_code)]
pub(crate) fn poll_local() {
    // SAFETY: The mapper wait loop has interrupts disabled. An IPI handler
    // cannot service the same local request concurrently.
    if let Some(id) = unsafe { irq::current_apic_id() } {
        MAILBOXES[usize::from(id)].service();
    }
}

#[allow(unsafe_code)]
pub(crate) fn handle_tlb_ipi() {
    // SAFETY: The dedicated interrupt gate entered with IF clear.
    if let Some(id) = unsafe { irq::finish_ipi() } {
        MAILBOXES[usize::from(id)].service();
    }
}

#[cfg(feature = "qemu-smp-test")]
pub(crate) fn verify_shootdown() {
    use ruzt_hal::mem::{Mapper, PageFlags};
    use ruzt_hal_x86_64::mapper;

    use crate::mm::{exception_stack, frame};

    struct TestTables;

    // SAFETY: Fresh global allocator frames have exclusive physmap aliases.
    // Test reclaim scrubs only tables that are detached and synchronized.
    #[allow(unsafe_code)]
    unsafe impl mapper::UserPageFrames for TestTables {
        fn allocate(&self) -> Option<PhysFrame> {
            frame::allocate()
        }

        unsafe fn deallocate(&self, frame: PhysFrame) {
            // SAFETY: The mapper has detached each table and flushed its users.
            unsafe { mapper::zero_frame(frame) };
            frame::deallocate(frame);
        }
    }

    let online = STATE
        .iter()
        .filter(|slot| slot.load(Ordering::Acquire) >= READY);
    assert_eq!(online.clone().count(), 3, "four-CPU QEMU fixture");
    let address = VirtAddr::new(exception_stack::TOP + super::STRIDE * STATE.len() as u64);
    let before = frame::allocate().expect("shootdown fixture frame");
    let after = frame::allocate().expect("shootdown replacement frame");
    const ORIGINAL: u64 = 0x1122_3344_5566_7788;
    const REPLACEMENT: u64 = 0x8877_6655_4433_2211;
    for (frame, value) in [(before, ORIGINAL), (after, REPLACEMENT)] {
        #[allow(unsafe_code)]
        // SAFETY: These are fresh frames owned by this test.
        unsafe { mapper::copy_to_frame(frame, 0, &value.to_ne_bytes()) }.unwrap();
    }
    mapper::with_mapper(|mapper| {
        let observe = |address: VirtAddr, expected| {
            broadcast(PROBE, address.as_u64());
            for (slot, mailbox) in STATE.iter().zip(&MAILBOXES) {
                if slot.load(Ordering::Acquire) >= READY {
                    assert_eq!(mailbox.observed.load(Ordering::Relaxed), expected);
                }
            }
        };
        let expect_flushes = |counter: fn(&Mailbox) -> &AtomicU64, expected| {
            for (id, (slot, mailbox)) in STATE.iter().zip(&MAILBOXES).enumerate() {
                if slot.load(Ordering::Acquire) >= READY {
                    assert_eq!(
                        counter(mailbox).load(Ordering::Relaxed),
                        expected,
                        "APIC {id} did not invalidate the active translation before reclaim"
                    );
                }
            }
        };
        mapper.map(address, before, PageFlags::empty()).unwrap();
        observe(address, ORIGINAL);
        // Force servicing from the contended-lock path with IF clear.
        broadcast(CONTEND, 0);
        assert_eq!(mapper.unmap(address).unwrap(), before);
        expect_flushes(|mailbox| &mailbox.page_flushes, 1);
        mapper.map(address, after, PageFlags::empty()).unwrap();
        observe(address, REPLACEMENT);
        assert_eq!(mapper.unmap(address).unwrap(), after);

        let root = mapper.create_user_address_space(&TestTables).unwrap();
        let lower = VirtAddr::new(0x4000);
        #[allow(unsafe_code)]
        // SAFETY: The fixture exclusively owns both data frames and the user
        // root. The BSP holds the mapper lock, and all CPUs leave the root
        // before destruction. The test leaf is supervisor-only for AP probes.
        unsafe {
            mapper
                .map_in_address_space(root, lower, before, PageFlags::empty(), &TestTables)
                .unwrap();
            broadcast(SELECT_ROOT, root.base.as_u64());
            observe(lower, ORIGINAL);
            assert_eq!(
                mapper.unmap_in_address_space(root, lower, &TestTables),
                before
            );
            expect_flushes(|mailbox| &mailbox.user_flushes, 1);
            mapper
                .map_in_address_space(root, lower, after, PageFlags::empty(), &TestTables)
                .unwrap();
            observe(lower, REPLACEMENT);
            assert_eq!(
                mapper.unmap_in_address_space(root, lower, &TestTables),
                after
            );
            broadcast(
                SELECT_ROOT,
                *super::PERMANENT_ROOT.get().expect("boot root"),
            );
            mapper.destroy_user_address_space(root, &TestTables);
        }
    });
    frame::deallocate(before);
    frame::deallocate(after);
    crate::serial_println!("SMP TLB shootdown replaced a translation cached on every secondary");
    crate::serial_println!("SMP TLB shootdown reclaimed page tables active on the secondaries");
}
