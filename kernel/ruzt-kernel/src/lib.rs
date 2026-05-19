#![no_std]
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]
#![feature(abi_x86_interrupt)]
#![feature(alloc_error_handler)]

//! Ruzt microkernel — Phase 0.

extern crate alloc;

pub mod serial;
pub mod vga;
pub mod exceptions;
pub mod mm;
pub mod sched;
pub mod keyboard;

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

    serial_println!("Ruzt booting...");

    exceptions::init_idt();
    serial_println!("IDT loaded.");

    serial_println!("Firing int3 breakpoint...");
    x86_64::instructions::interrupts::int3();
    serial_println!("Breakpoint returned cleanly.");

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
