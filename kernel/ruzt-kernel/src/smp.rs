//! Start firmware-enabled application processors and dispatch CPU-local work.

use core::sync::atomic::{fence, AtomicU8, Ordering};

use ruzt_hal::mem::{Mapper, PageFlags, PhysFrame, VirtAddr};
use ruzt_hal_x86_64::{
    apic::{Ipi, LocalApic},
    context, cpu, gdt, irq, mapper,
    startup::Trampoline,
    timer::startup_delay_us,
};
use spin::Once;
use x86_64::{
    instructions::interrupts,
    registers::control::{Cr3, Cr4, Cr4Flags},
};

use crate::{
    apic, exceptions,
    mm::{entry_stack, exception_stack, frame},
    sched,
};

const PAGE: u64 = PhysFrame::SIZE as u64;
const STACK_PAGES: u64 = 16;
const FAULT_PAGES: u64 = 8;
const STRIDE: u64 = (STACK_PAGES + FAULT_PAGES + 2) * PAGE;
const OFFLINE: u8 = 0;
const READY: u8 = 1;
const WOKEN: u8 = 2;
const SCHEDULING: u8 = 3;

static STATE: [AtomicU8; 255] = [const { AtomicU8::new(OFFLINE) }; 255];
static PERMANENT_ROOT: Once<u64> = Once::new();
pub(crate) const SCHEDULER_SLOTS: usize = STATE.len() + 1;

mod irq_probe;
mod shootdown;
pub(crate) use irq_probe::handle as handle_lapic_probe;
pub(crate) use shootdown::handle_tlb_ipi;
#[cfg(feature = "qemu-smp-test")]
pub(crate) use shootdown::verify_shootdown;

pub(crate) fn install_remote_operations() {
    shootdown::install_shootdown();
    irq_probe::install();
}

pub(crate) fn poll_synchronous_ipis() {
    shootdown::poll_local();
    irq_probe::poll_boot();
}

pub(crate) fn secondary_scheduler_slot(id: u8) -> usize {
    usize::from(id) + 1
}

pub(crate) fn scheduler_slots() -> impl Iterator<Item = usize> {
    core::iter::once(0).chain(STATE.iter().enumerate().filter_map(|(id, state)| {
        (state.load(Ordering::Acquire) == SCHEDULING).then_some(id + 1)
    }))
}

pub(crate) fn entry_pages() -> impl Iterator<Item = (u8, usize, u64)> {
    STATE.iter().enumerate().filter_map(|(id, state)| {
        (state.load(Ordering::Acquire) >= READY).then(|| {
            let id = id as u8;
            (id, secondary_scheduler_slot(id), stack_bounds(id).1 - PAGE)
        })
    })
}

#[allow(unsafe_code)]
#[cfg(not(test))]
pub(crate) fn scheduler_slot() -> usize {
    let Some(topology) = apic::cpu_topology() else {
        return 0;
    };
    // SAFETY: The BSP and all scheduler CPUs use the negotiated APIC mode.
    let id = unsafe { irq::current_apic_id() }.expect("scheduler CPU has a LAPIC");
    if id == topology.bsp {
        0
    } else {
        secondary_scheduler_slot(id)
    }
}

#[allow(unsafe_code)]
pub(crate) fn start_scheduling() {
    for (id, state) in STATE.iter().enumerate() {
        if state.load(Ordering::Acquire) != WOKEN {
            continue;
        }
        let id = id as u8;
        if sched::register_secondary(id).is_err() {
            crate::serial_println!("SMP APIC {id} could not allocate its idle thread");
            continue;
        }
        crate::mm::heap::provision_cpu(secondary_scheduler_slot(id));
        state.store(SCHEDULING, Ordering::Release);
        // Publish the scheduler state before a wake via x2APIC's ICR MSR.
        fence(Ordering::SeqCst);
        // SAFETY: The BSP owns its ICR with interrupts disabled and the AP
        // acknowledged an earlier fixed interrupt on this vector.
        if !unsafe { irq::send_ipi(id, Ipi::Wake) } {
            crate::serial_println!("SMP APIC {id} scheduler wake will retry on PIT tick");
        }
    }
}

#[allow(unsafe_code)]
pub(crate) fn tick_schedulers() {
    for (id, state) in STATE.iter().enumerate() {
        if state.load(Ordering::Relaxed) == SCHEDULING {
            // SAFETY: The BSP's PIT gate runs with interrupts disabled.
            // A busy ICR can defer a reschedule hint until the next tick.
            unsafe { irq::send_ipi(id as u8, Ipi::Wake) };
        }
    }
}

#[allow(unsafe_code)]
#[cfg(not(test))]
pub(crate) fn reschedule(slot: usize) {
    let topology = apic::cpu_topology().expect("registered secondaries have LAPICs");
    let id = if slot == 0 {
        topology.bsp
    } else {
        u8::try_from(slot - 1).expect("registered APIC ID")
    };
    // The scheduler published ready state before notifying the remote CPU.
    fence(Ordering::SeqCst);
    // SAFETY: The scheduler lock is held with interrupts disabled and the
    // registered target has acknowledged its fixed IPI gate. A failed kick
    // will be retried by the periodic scheduling tick.
    unsafe { irq::send_ipi(id, Ipi::Wake) };
}

/// Reserve conventional memory before the general allocator can use it.
pub(crate) fn reserve_startup_page() -> Option<PhysFrame> {
    frame::allocate_in_range(PAGE, 0x9f000)
}

pub(crate) fn start(page: Option<PhysFrame>) {
    let Some(topology) = apic::cpu_topology() else {
        if let Some(page) = page {
            frame::deallocate(page);
        }
        return;
    };
    let targets = topology
        .enabled
        .iter()
        .enumerate()
        .filter_map(|(id, &enabled)| (enabled && id as u8 != topology.bsp).then_some(id as u8));
    if targets.clone().next().is_none() {
        if let Some(page) = page {
            frame::deallocate(page);
        }
        return;
    }
    let Some(page) = page else {
        crate::serial_println!("SMP startup unavailable: no conventional memory page");
        return;
    };
    if Cr4::read().contains(Cr4Flags::L5_PAGING) {
        frame::deallocate(page);
        crate::serial_println!("SMP startup unavailable with five-level paging");
        return;
    }
    let Some(tables) = startup_tables() else {
        frame::deallocate(page);
        crate::serial_println!("SMP startup unavailable: no temporary page tables");
        return;
    };
    let Some(alias) = mapper::with_mapper(|mapper| mapper.physmap_alias(page.base.as_u64(), PAGE))
    else {
        release_startup(page, tables, false);
        crate::serial_println!("SMP startup unavailable: startup page lacks a physmap alias");
        return;
    };
    // The AP inherits the root frame, and uses its own CR3 control flags.
    PERMANENT_ROOT.call_once(|| Cr3::read().0.start_address().as_u64());
    #[allow(unsafe_code)]
    // SAFETY: The five frames are exclusive. The temporary root is below
    // 4 GiB and shares the permanent supervisor hierarchy and AP stacks.
    let mut trampoline = unsafe {
        mapper::with_mapper(|mapper| mapper.prepare_startup_tables(tables, page));
        Trampoline::install(page, alias, tables[0], secondary_entry)
    };
    let mut online = 0;
    for id in targets {
        if !map_stacks(id) {
            crate::serial_println!("SMP APIC {id} stack allocation failed");
            break;
        }
        if !start_one(&mut trampoline, id) {
            // A delayed target can still read the handoff or walk the
            // temporary tables. Stop publishing new data and keep them pinned.
            crate::serial_println!(
                "SMP APIC {id} did not complete startup; startup pages retained"
            );
            return;
        }
        online += 1;
        crate::serial_println!("SMP APIC {id} online and acknowledged a wake IPI");
    }
    release_startup(page, tables, true);
    crate::serial_println!("SMP initialized {online} secondary CPUs");
}

fn startup_tables() -> Option<[PhysFrame; 4]> {
    let root = frame::allocate_in_range(0x10_0000, 1 << 32)?;
    let mut tables = [root; 4];
    for index in 1..tables.len() {
        let Some(next) = frame::allocate() else {
            for table in &tables[..index] {
                frame::deallocate(*table);
            }
            return None;
        };
        tables[index] = next;
    }
    Some(tables)
}

fn release_startup(page: PhysFrame, tables: [PhysFrame; 4], initialized: bool) {
    for frame in core::iter::once(page).chain(tables) {
        if initialized {
            #[allow(unsafe_code)]
            // SAFETY: Every started CPU has left the temporary root.
            unsafe {
                mapper::zero_frame(frame)
            };
        }
        frame::deallocate(frame);
    }
}

fn stack_bounds(id: u8) -> (u64, u64) {
    let start = exception_stack::TOP + u64::from(id) * STRIDE;
    (start + (STACK_PAGES + 1) * PAGE, start + STRIDE)
}

fn map_stacks(id: u8) -> bool {
    let (stack, fault) = stack_bounds(id);
    let slot = secondary_scheduler_slot(id);
    let entry = entry_stack::bottom(slot);
    mapper::with_mapper(|mapper| {
        let first = stack - STACK_PAGES * PAGE;
        let second = fault - FAULT_PAGES * PAGE;
        if [first - PAGE, second - PAGE, entry_stack::guard(slot), entry_stack::top(slot), entry_stack::nmi_top(slot)]
            .into_iter()
            .any(|address| mapper.translate(VirtAddr::new(address)).is_some())
        {
            return false;
        }
        let pages = (first..stack)
            .step_by(PhysFrame::SIZE)
            .chain((second..fault).step_by(PhysFrame::SIZE))
            .chain([entry, entry_stack::nmi_bottom(slot), entry_stack::nmi_kernel_bottom(slot)]);
        for (index, address) in pages.clone().enumerate() {
            let new = if address >= second {
                entry_stack::allocate_frame()
            } else {
                frame::allocate()
            };
            let mapped = new.is_some_and(|frame| {
                mapper
                    .map(VirtAddr::new(address), frame, PageFlags::WRITABLE)
                    .is_ok()
            });
            if mapped {
                continue;
            }
            if let Some(frame) = new {
                frame::deallocate(frame);
            }
            for address in pages.take(index) {
                frame::deallocate(
                    mapper
                        .unmap(VirtAddr::new(address))
                        .expect("private AP stack"),
                );
            }
            return false;
        }
        true
    })
}

#[allow(unsafe_code)]
fn start_one(trampoline: &mut Trampoline, id: u8) -> bool {
    let (stack, _) = stack_bounds(id);
    // SAFETY: This is the BSP with IF clear. MADT identified a unique AP
    // target, and the previous target has left the shared startup page.
    unsafe {
        let vector = trampoline.handoff(stack, u64::from(id));
        if !irq::send_ipi(id, Ipi::Init)
            || !startup_delay_us(10_000)
            || !irq::send_ipi(id, Ipi::Startup(vector))
            || !startup_delay_us(200)
            || !irq::send_ipi(id, Ipi::Startup(vector))
            || !wait_for(id, READY)
            || !irq::send_ipi(id, Ipi::Wake)
        {
            return false;
        }
        wait_for(id, WOKEN)
    }
}

#[allow(unsafe_code)]
fn wait_for(id: u8, state: u8) -> bool {
    let slot = &STATE[usize::from(id)];
    for _ in 0..20 {
        if slot.load(Ordering::Acquire) == state {
            return true;
        }
        // SAFETY: Called only by the BSP startup path with IF clear.
        if !unsafe { startup_delay_us(10_000) } {
            return false;
        }
    }
    slot.load(Ordering::Acquire) == state
}

#[allow(unsafe_code)]
extern "C" fn secondary_entry(id: u64) -> ! {
    let id = u8::try_from(id).expect("validated APIC ID");
    let topology = apic::cpu_topology().expect("published APIC topology");
    let (_, fault) = stack_bounds(id);
    let root = *PERMANENT_ROOT.get().expect("published kernel root");
    // SAFETY: The temporary and permanent roots map the same live kernel
    // and private stacks. INIT kept interrupts disabled; load the AP's own
    // descriptors and restore supervisor protections before accepting IPIs.
    unsafe {
        core::arch::asm!("mov cr3, {}", in(reg) root, options(nostack, preserves_flags));
        let slot = secondary_scheduler_slot(id);
        gdt::init_secondary(id, entry_stack::top(slot), fault, entry_stack::nmi_top(slot));
        context::init_fp();
        cpu::disable_global_translations();
        cpu::enable_supervisor_protection();
    }
    exceptions::init_idt();
    crate::cet::init_cpu(secondary_scheduler_slot(id));
    // SAFETY: This AP owns its LAPIC and has a valid IDT and stacks.
    let local = unsafe { LocalApic::init_secondary(topology.local_physical, topology.local_alias) };
    if local.is_none_or(|local| local.id() != id) {
        loop {
            x86_64::instructions::hlt();
        }
    }
    let state = &STATE[usize::from(id)];
    state.store(READY, Ordering::Release);
    loop {
        interrupts::disable();
        if state.load(Ordering::Acquire) == SCHEDULING {
            break;
        }
        interrupts::enable_and_hlt();
    }
    sched::request_switch();
    crate::idle_loop();
}

#[allow(unsafe_code)]
pub(crate) fn wake() -> bool {
    // SAFETY: The dedicated IDT gate runs only for a fixed local APIC IPI.
    if let Some(id) = unsafe { irq::finish_ipi() } {
        if apic::cpu_topology().is_some_and(|topology| topology.bsp == id) {
            return true;
        }
        if let Some(slot) = STATE.get(usize::from(id)) {
            match slot.load(Ordering::Acquire) {
                READY => slot.store(WOKEN, Ordering::Release),
                SCHEDULING => return true,
                _ => {}
            }
        }
    }
    false
}
