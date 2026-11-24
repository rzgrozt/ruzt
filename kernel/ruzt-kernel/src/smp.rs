//! Bring firmware-enabled application processors into the kernel's IPI loop.

use core::sync::atomic::{AtomicU8, Ordering};

use ruzt_hal::mem::{Mapper, PageFlags, PhysFrame, VirtAddr};
use ruzt_hal_x86_64::{
    apic::{Ipi, LocalApic},
    context, cpu, gdt, irq, mapper,
    startup::Trampoline,
    timer::startup_delay_us,
};
use spin::Once;
use x86_64::registers::control::{Cr3, Cr4, Cr4Flags};

use crate::{
    apic, exceptions,
    mm::{exception_stack, frame},
};

const PAGE: u64 = PhysFrame::SIZE as u64;
const STACK_PAGES: u64 = 16;
const FAULT_PAGES: u64 = 8;
const STRIDE: u64 = (STACK_PAGES + FAULT_PAGES + 2) * PAGE;
const OFFLINE: u8 = 0;
const READY: u8 = 1;
const WOKEN: u8 = 2;

static STATE: [AtomicU8; 255] = [const { AtomicU8::new(OFFLINE) }; 255];
static PERMANENT_ROOT: Once<u64> = Once::new();

mod shootdown;
pub(crate) use shootdown::{handle_tlb_ipi, install_shootdown};
#[cfg(feature = "qemu-smp-test")]
pub(crate) use shootdown::verify_shootdown;

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
    mapper::with_mapper(|mapper| {
        let first = stack - STACK_PAGES * PAGE;
        let second = fault - FAULT_PAGES * PAGE;
        if [first - PAGE, second - PAGE]
            .into_iter()
            .any(|address| mapper.translate(VirtAddr::new(address)).is_some())
        {
            return false;
        }
        let pages = (first..stack)
            .step_by(PhysFrame::SIZE)
            .chain((second..fault).step_by(PhysFrame::SIZE));
        for (index, address) in pages.clone().enumerate() {
            let new = frame::allocate();
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
    let (stack, fault) = stack_bounds(id);
    let root = *PERMANENT_ROOT.get().expect("published kernel root");
    // SAFETY: The temporary and permanent roots map the same live kernel
    // and private stacks. INIT kept interrupts disabled; load the AP's own
    // descriptors and restore supervisor protections before accepting IPIs.
    unsafe {
        core::arch::asm!("mov cr3, {}", in(reg) root, options(nostack, preserves_flags));
        gdt::init_secondary(id, stack, fault);
        context::init_fp();
        cpu::enable_supervisor_protection();
    }
    exceptions::init_idt();
    // SAFETY: This AP owns its LAPIC and has a valid IDT and stacks.
    let local = unsafe { LocalApic::init_secondary(topology.local_physical, topology.local_alias) };
    if local.is_none_or(|local| local.id() != id) {
        loop {
            x86_64::instructions::hlt();
        }
    }
    STATE[usize::from(id)].store(READY, Ordering::Release);
    loop {
        x86_64::instructions::interrupts::enable_and_hlt();
    }
}

#[allow(unsafe_code)]
pub(crate) fn wake() {
    // SAFETY: The dedicated IDT gate runs only for a fixed local APIC IPI.
    if let Some(id) = unsafe { irq::finish_ipi() } {
        if let Some(slot) = STATE.get(usize::from(id)) {
            if slot.load(Ordering::Relaxed) == READY {
                slot.store(WOKEN, Ordering::Release);
            }
        }
    }
}
