#![no_std]
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]
#![feature(abi_x86_interrupt)]
#![feature(alloc_error_handler)]
#![feature(allocator_api)]


//! Ruzt microkernel — Phase 2.

extern crate alloc;
#[cfg(test)]
extern crate std;

mod boot_screen;
mod acpi;
mod apic;
mod iommu;
mod irq;
mod pci;
mod smp;
pub mod serial;
pub mod vga;
pub mod exceptions;
pub mod mm;
pub mod sched;
pub mod keyboard;
pub mod cap;
pub mod syscall;
pub mod ipc;
pub mod elf;
pub mod process;

use ruzt_hal::boot::BootInfo;
use ruzt_hal::cpu::CpuOps;

#[cfg(test)]
fn isolated_kernel_state() -> spin::MutexGuard<'static, ()> {
    static TEST_STATE: spin::Mutex<()> = spin::Mutex::new(());
    let guard = TEST_STATE.lock();
    cap::object::init();
    sched::init();
    guard
}

/// Kernel main entry point.
///
/// # Safety
/// Called exactly once from the boot entry point, before any concurrent
/// code exists. Serial/VGA globals are uninitialised at this point and
/// this is the sole initialiser.
pub fn main(boot_info: &'static mut BootInfo) -> ! {
    serial::SERIAL1.lock().init();

    let (mut screen, undrawn_framebuffer) = match boot_info.framebuffer.take() {
        Some(framebuffer) => match boot_screen::BootScreen::new(framebuffer) {
            Ok(screen) => (Some(screen), None),
            Err(framebuffer) => (None, Some(framebuffer)),
        },
        None => (None, None),
    };
    let mut advance_screen = || {
        if let Some(screen) = &mut screen {
            screen.advance();
        }
    };

    mm::frame::init(boot_info);
    let startup = if matches!(boot_info.firmware_tables, ruzt_hal::boot::FirmwareTables::Acpi { .. }) {
        smp::reserve_startup_page()
    } else {
        None
    };

    let offset = boot_info
        .physical_memory_offset
        .expect("physical_memory_offset required for mapper init");
    #[allow(unsafe_code)]
    // Safety: Called exactly once after frame allocator init, before any use
    // of the mapper. The bootloader identity-maps all physical memory at
    // `physical_memory_offset` and loaded a valid page table into CR3.
    unsafe {
        ruzt_hal_x86_64::mapper::init(offset, mm::frame::allocate);
    }

    mm::heap::init();
    advance_screen();

    iommu::init(boot_info);

    cap::object::init();
    serial_println!("cap object table initialised.");
    advance_screen();

    mm::exception_stack::map();
    #[allow(unsafe_code)]
    // SAFETY: Both supervisor stacks are mapped for the single boot CPU
    // before interrupts and IDT initialization.
    unsafe {
        ruzt_hal_x86_64::gdt::init(mm::exception_stack::TOP);
        ruzt_hal_x86_64::context::init_fp();
    }
    serial_println!("GDT+TSS initialised.");

    serial_println!("Ruzt booting...");

    exceptions::init_idt();
    #[allow(unsafe_code)]
    // SAFETY: The kernel and physmap use supervisor mappings. Every IDT
    // entry clears AC and DF before entering Rust, and interrupts are off.
    let (smep, smap) = unsafe { ruzt_hal_x86_64::cpu::enable_supervisor_protection() };
    serial_println!("x86 supervisor protection (SMEP={smep}, SMAP={smap})");
    #[cfg(feature = "qemu-hardening-test")]
    assert!(smep && smap, "the hardening fixture requires SMEP and SMAP");
    #[cfg(feature = "qemu-double-fault-test")]
    exceptions::trigger_double_fault();
    syscall::init();
    serial_println!("IDT loaded.");

    serial_println!("Firing int3 breakpoint...");
    x86_64::instructions::interrupts::int3();
    serial_println!("Breakpoint returned cleanly.");
    advance_screen();

    mm::heap::smoke_test();

    apic::init(boot_info);
    smp::start(startup);

    #[allow(unsafe_code)]
    // Safety: Called once after IRQ routing is ready, before enabling interrupts.
    unsafe {
        ruzt_hal_x86_64::timer::init();
    }
    serial_println!("PIT timer initialised.");

    sched::init();
    serial_println!("Scheduler initialised.");
    advance_screen();

    if let Some(image) = boot_info.initrd {
        let framebuffer = screen.map(boot_screen::BootScreen::hand_off).or(undrawn_framebuffer);
        pci::init(boot_info.memory_map, framebuffer.as_ref());
        #[cfg(feature = "qemu-vtd-test")]
        iommu::verify_unassigned_device();
        process::enqueue_initial(image, framebuffer);
    } else {
        assert!(!cfg!(feature = "qemu-rootsrv-test"), "rootsrv is missing from the boot image");

        sched::spawn(thread_a);
        sched::spawn(thread_b);
        serial_println!("Threads spawned.");

        sched::spawn(keyboard_echo);
        serial_println!("keyboard_echo task started");

        // Kernel-internal IPC self-test.
        ipc_test_init();
        sched::spawn(ipc_test_sender);
        sched::spawn(ipc_test_receiver);
        serial_println!("IPC self-test threads spawned");

        boot_screen::attach(screen);
    }
    serial_println!("Enabling interrupts...");
    ruzt_hal_x86_64::cpu::X86_64Cpu::enable_interrupts();

    serial_println!("Hello, world from ring 0. Entering idle loop.");

    idle_loop();
}

fn idle_loop() -> ! {
    loop {
        let mut guard = ruzt_hal_x86_64::cpu::X86_64Cpu::disable_interrupts();
        if crate::sched::should_switch() {
            crate::sched::reap_retired_user();
            crate::sched::yield_thread();
        } else {
            // Pair the work check with STI/HLT so an interrupt between them
            // wakes the idle CPU instead of being handled before it halts.
            guard.halt_until_interrupt();
        }
    }
}

fn thread_a() -> ! {
    ruzt_hal_x86_64::cpu::X86_64Cpu::enable_interrupts();
    for _ in 0..3 {
        serial_println!("thread A ticking");
        for _ in 0..10_000_000 {
            core::hint::spin_loop();
            if crate::sched::should_switch() {
                let _guard = ruzt_hal_x86_64::cpu::X86_64Cpu::disable_interrupts();
                crate::sched::yield_thread();
            }
        }
    }
    idle_loop();
}

fn thread_b() -> ! {
    ruzt_hal_x86_64::cpu::X86_64Cpu::enable_interrupts();
    for _ in 0..3 {
        serial_println!("thread B ticking");
        for _ in 0..10_000_000 {
            core::hint::spin_loop();
            if crate::sched::should_switch() {
                let _guard = ruzt_hal_x86_64::cpu::X86_64Cpu::disable_interrupts();
                crate::sched::yield_thread();
            }
        }
    }
    idle_loop();
}

/// Initialise the IPC self-test endpoint and CSpace.
fn ipc_test_init() {
    let mut guard = crate::cap::cspace::kernel_cspace();
    let cspace = guard.as_mut().expect("kernel cspace not initialised");
    let id = crate::cap::object::allocate(ruzt_cap::CapType::Endpoint(ruzt_cap::EndpointId(0)))
        .expect("ipc_test_init: allocate endpoint failed");
    serial_println!("ipc_test_init: allocated endpoint id={}", id.0);
    let slot = ruzt_cap::CapSlot {
        cap_type: ruzt_cap::CapType::Endpoint(ruzt_cap::EndpointId(id.0)),
        rights: ruzt_cap::CapRights::new(),
        badge: 0,
    };
    cspace.insert(0, slot).expect("ipc_test_init: insert endpoint failed");
    serial_println!("ipc_test_init: endpoint inserted at cptr 0");
}

const KERNEL_IPC_PROBE: &[u8] = b"Hello, IPC!";

/// IPC self-test sender thread.
#[allow(unsafe_code)]
fn ipc_test_sender() -> ! {
    ruzt_hal_x86_64::cpu::X86_64Cpu::enable_interrupts();
    let msg = ruzt_abi::IpcMessage {
        label: 42,
        length: KERNEL_IPC_PROBE.len() as u16,
        cap_count: 0,
        flags: 0,
        data: {
            let mut d = [0u8; 56];
            d[..KERNEL_IPC_PROBE.len()].copy_from_slice(KERNEL_IPC_PROBE);
            d
        },
        caps: [ruzt_abi::CapTransferSlot {
            cptr: 0,
            rights: ruzt_abi::CapRights::empty(),
            badge: 0,
        }; 4],
    };
    let args = ruzt_abi::SyscallArgs {
        number: ruzt_abi::SyscallNumber::Invoke as u64,
        arg0: 0,
        arg1: 0,
        arg2: &msg.data as *const _ as u64,
        arg3: 42,
        arg4: u64::from(msg.length),
        arg5: 0,
    };
    serial_println!("ipc_test_sender: about to call int 0x80");
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("rax") args.number => ret,
            in("rdi") args.arg0,
            in("rsi") args.arg1,
            in("rdx") args.arg2,
            in("r10") args.arg3,
            in("r8") args.arg4,
            in("r9") args.arg5,
        );
    }
    if ret == ruzt_abi::ErrorCode::Ok.as_u64() {
        serial_println!("ipc_test_sender: message sent successfully");
        if cfg!(feature = "qemu-smoke-test") {
            ruzt_hal_x86_64::cpu::qemu_shutdown();
        }
    } else {
        serial_println!("ipc_test_sender: syscall failed, ret={}", ret);
    }
    idle_loop();
}

/// IPC self-test receiver thread.
#[allow(unsafe_code)]
fn ipc_test_receiver() -> ! {
    ruzt_hal_x86_64::cpu::X86_64Cpu::enable_interrupts();
    let mut buf = [0u8; 56];
    let args = ruzt_abi::SyscallArgs {
        number: ruzt_abi::SyscallNumber::Invoke as u64,
        arg0: 0,
        arg1: 1,
        arg2: &mut buf as *mut _ as u64,
        arg3: 0,
        arg4: 0,
        arg5: 0,
    };
    serial_println!("ipc_test_receiver: about to call int 0x80");
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("rax") args.number => ret,
            in("rdi") args.arg0,
            in("rsi") args.arg1,
            in("rdx") args.arg2,
            in("r10") args.arg3,
            in("r8") args.arg4,
            in("r9") args.arg5,
        );
    }
    if ret == ruzt_abi::ErrorCode::Ok.as_u64() {
        let msg = core::str::from_utf8(&buf[..KERNEL_IPC_PROBE.len()]).unwrap_or("invalid utf8");
        serial_println!("ipc_test_receiver: got message: {}", msg);
    } else {
        serial_println!("ipc_test_receiver: syscall failed, ret={}", ret);
    }
    idle_loop();
}

#[allow(unsafe_code)]
fn keyboard_echo() -> ! {
    ruzt_hal_x86_64::cpu::X86_64Cpu::enable_interrupts();
    serial_println!("keyboard_echo task running");
    loop {
        if let Some(scancode) = crate::keyboard::try_read() {
            if let Some(c) = crate::keyboard::scancode_to_ascii(scancode) {
                serial_print!("{}", c);
            }
        }
        if crate::sched::should_switch() {
            let _guard = ruzt_hal_x86_64::cpu::X86_64Cpu::disable_interrupts();
            crate::sched::yield_thread();
        }
        for _ in 0..1_000_000 {
            unsafe { core::arch::asm!("nop"); }
        }
    }
}
