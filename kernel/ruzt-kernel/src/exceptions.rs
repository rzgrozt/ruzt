//! x86_64 interrupt descriptor table and exception handlers.

use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};
use spin::Once;
use crate::serial_println;

/// Static IDT, initialised once.
static IDT: Once<InterruptDescriptorTable> = Once::new();

/// Initialises the global IDT with breakpoint, double-fault, page-fault, and timer handlers.
pub fn init_idt() {
    let idt = IDT.call_once(|| {
        let mut idt = InterruptDescriptorTable::new();
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        idt.double_fault.set_handler_fn(double_fault_handler);
        idt.page_fault.set_handler_fn(page_fault_handler);
        idt[32].set_handler_fn(timer_handler);
        idt
    });
    idt.load();
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
        x86_64::instructions::hlt();
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
        x86_64::instructions::hlt();
    }
}

#[allow(unsafe_code)]
extern "x86-interrupt" fn timer_handler(_stack_frame: InterruptStackFrame) {
    if crate::sched::test_tick() {
        ruzt_hal_x86_64::cpu::qemu_shutdown();
    }
    crate::sched::request_switch();
    ruzt_hal_x86_64::pic::send_eoi(0);
}
