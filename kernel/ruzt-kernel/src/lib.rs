#![no_std]
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]
#![feature(abi_x86_interrupt)]
#![feature(alloc_error_handler)]


//! Ruzt microkernel — Phase 2.

extern crate alloc;

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

/// Kernel main entry point.
///
/// # Safety
/// Called exactly once from the boot entry point, before any concurrent
/// code exists. Serial/VGA globals are uninitialised at this point and
/// this is the sole initialiser.
pub fn main(boot_info: &'static mut BootInfo) -> ! {
    serial::SERIAL1.lock().init();

    mm::frame::init(boot_info);

    let offset = boot_info
        .physical_memory_offset
        .expect("physical_memory_offset required for mapper init");
    #[allow(unsafe_code)]
    // Safety: Called exactly once after frame allocator init, before any use
    // of the mapper. The bootloader identity-maps all physical memory at
    // `physical_memory_offset` and loaded a valid page table into CR3.
    unsafe {
        ruzt_hal_x86_64::mapper::init(offset, mm::frame::allocate, mm::frame::deallocate);
    }

    mm::heap::init();

    cap::object::init();
    serial_println!("cap object table initialised.");

    syscall::init();
    serial_println!("syscall entry initialised.");

    serial_println!("Ruzt booting...");

    exceptions::init_idt();
    serial_println!("IDT loaded.");

    serial_println!("Firing int3 breakpoint...");
    x86_64::instructions::interrupts::int3();
    serial_println!("Breakpoint returned cleanly.");

    if cfg!(feature = "qemu-smoke-test") {
        ruzt_hal_x86_64::cpu::qemu_shutdown();
    }

    mm::heap::smoke_test();

    #[allow(unsafe_code)]
    // Safety: Called exactly once during early boot, before interrupts enabled.
    unsafe {
        ruzt_hal_x86_64::pic::init();
    }
    serial_println!("PIC initialised.");

    #[allow(unsafe_code)]
    // Safety: Called exactly once after PIC init, before interrupts enabled.
    unsafe {
        ruzt_hal_x86_64::timer::init();
    }
    serial_println!("PIT timer initialised.");

    sched::init();
    serial_println!("Scheduler initialised.");

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

    serial_println!("Enabling interrupts...");
    ruzt_hal_x86_64::cpu::X86_64Cpu::enable_interrupts();

    serial_println!("Hello, world from ring 0. Entering idle loop.");

    idle_loop();
}

fn idle_loop() -> ! {
    loop {
        if crate::sched::should_switch() {
            let _guard = ruzt_hal_x86_64::cpu::X86_64Cpu::disable_interrupts();
            crate::sched::yield_thread();
        }
        ruzt_hal_x86_64::cpu::X86_64Cpu::cpu_idle();
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

/// IPC self-test sender thread.
#[allow(unsafe_code)]
fn ipc_test_sender() -> ! {
    let msg = ruzt_abi::IpcMessage {
        label: 42,
        length: 13,
        cap_count: 0,
        flags: 0,
        data: {
            let mut d = [0u8; 56];
            let s = b"Hello, IPC!";
            d[..s.len()].copy_from_slice(s);
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
        arg4: 13,
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
    } else {
        serial_println!("ipc_test_sender: syscall failed, ret={}", ret);
    }
    idle_loop();
}

/// IPC self-test receiver thread.
#[allow(unsafe_code)]
fn ipc_test_receiver() -> ! {
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
        let msg = core::str::from_utf8(&buf[..13]).unwrap_or("invalid utf8");
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
