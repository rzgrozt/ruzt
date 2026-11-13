//! x86_64 interrupt descriptor table and exception handlers.

use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};
use spin::Once;
use crate::serial_println;
use ruzt_hal::cpu::CpuOps;
use ruzt_hal::time::Timer;

/// Static IDT, initialised once.
static IDT: Once<InterruptDescriptorTable> = Once::new();

/// One-time flag so the timer handler only prints its tick value once.
static TIMER_TICK_PRINTED: Once<()> = Once::new();

/// Initialises the global IDT with breakpoint, double-fault, page-fault, timer,
/// keyboard, and syscall handlers.
#[allow(unsafe_code)]
pub fn init_idt() {
    let idt = IDT.call_once(|| {
        let mut idt = InterruptDescriptorTable::new();
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        idt.double_fault.set_handler_fn(double_fault_handler);
        idt.page_fault.set_handler_fn(page_fault_handler);
        idt[32].set_handler_fn(timer_handler);
        idt[33].set_handler_fn(keyboard_handler);
        unsafe {
            idt[0x80].set_handler_addr(x86_64::VirtAddr::new(syscall_handler as *const () as usize as u64));
        }
        idt
    });
    idt.load();
}

#[allow(unsafe_code)]
extern "C" fn syscall_handler_debug() {
    crate::serial_println!("syscall_handler: entered!");
}

#[unsafe(naked)]
extern "C" fn syscall_handler() {
    core::arch::naked_asm!(
        "push r15",
        "push r9",
        "push r8",
        "push r10",
        "push rdx",
        "push rsi",
        "push rdi",
        "push rax",
        "push r11",
        "mov r11, rsp",
        "add r11, 8",
        "mov rdi, r11",
        "call {syscall_dispatch}",
        "mov r15, rax",
        "pop r11",
        "pop rax",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop r10",
        "pop r8",
        "pop r9",
        "mov rax, r15",
        "pop r15",
        "iretq",
        syscall_dispatch = sym crate::syscall::syscall_dispatch,
    );
}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    serial_println!("EXCEPTION: BREAKPOINT @ {:?}", stack_frame.instruction_pointer);
}

extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    serial_println!("EXCEPTION: DOUBLE FAULT\n{:#?}", stack_frame);
    loop {
        ruzt_hal_x86_64::cpu::X86_64Cpu::cpu_idle();
    }
}

extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    serial_println!("EXCEPTION: PAGE FAULT");
    serial_println!("Error Code: {:?}", error_code);
    serial_println!("{:#?}", stack_frame);
    loop {
        ruzt_hal_x86_64::cpu::X86_64Cpu::cpu_idle();
    }
}

#[allow(unsafe_code)]
extern "x86-interrupt" fn timer_handler(_stack_frame: InterruptStackFrame) {
    ruzt_hal_x86_64::time::increment_tick();
    TIMER_TICK_PRINTED.call_once(|| {
        serial_println!(
            "Timer monotonic ns: {}",
            ruzt_hal_x86_64::time::X86_64Timer::now_monotonic_ns()
        );
    });
    if crate::sched::test_tick() {
        ruzt_hal_x86_64::cpu::qemu_shutdown();
    }
    crate::sched::request_switch();
    ruzt_hal_x86_64::pic::send_eoi(0);
}

#[allow(unsafe_code)]
extern "x86-interrupt" fn keyboard_handler(_stack_frame: InterruptStackFrame) {
    crate::keyboard::on_interrupt();
    ruzt_hal_x86_64::pic::send_eoi(1);
}
