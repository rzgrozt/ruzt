//! x86_64 interrupt descriptor table and exception handlers.

use crate::serial_println;
use ruzt_hal::cpu::CpuOps;
use ruzt_hal::time::Timer;
use spin::Once;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

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
        idt.divide_error.set_handler_fn(arithmetic_fault);
        idt.x87_floating_point.set_handler_fn(arithmetic_fault);
        idt.simd_floating_point.set_handler_fn(arithmetic_fault);
        idt.debug.set_handler_fn(instruction_fault);
        idt.overflow.set_handler_fn(arithmetic_fault);
        idt.bound_range_exceeded.set_handler_fn(arithmetic_fault);
        idt.invalid_opcode.set_handler_fn(instruction_fault);
        idt.device_not_available.set_handler_fn(instruction_fault);
        idt.invalid_tss.set_handler_fn(protection_fault);
        idt.segment_not_present.set_handler_fn(protection_fault);
        idt.stack_segment_fault.set_handler_fn(protection_fault);
        idt.general_protection_fault
            .set_handler_fn(protection_fault);
        idt.alignment_check.set_handler_fn(protection_fault);
        idt[32].set_handler_fn(timer_handler);
        idt[33].set_handler_fn(keyboard_handler);
        unsafe {
            idt[0x80]
                .set_handler_addr(x86_64::VirtAddr::from_ptr(syscall_handler as *const ()))
                .set_privilege_level(x86_64::PrivilegeLevel::Ring3);
        }
        idt
    });
    idt.load();
}

#[unsafe(naked)]
extern "C" fn syscall_handler() {
    core::arch::naked_asm!(
        // Save caller-clobbered registers and build SyscallArgs on the stack.
        "push rcx",
        "push r11",
        "push r9",
        "push r8",
        "push r10",
        "push rdx",
        "push rsi",
        "push rdi",
        "push rax",
        "mov rdi, rsp",
        // Nine saved registers and one hardware-saved RIP precede CS.
        "mov rsi, [rsp + 80]",
        "cld",
        "call {syscall_dispatch}",
        "add rsp, 8",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop r10",
        "pop r8",
        "pop r9",
        "pop r11",
        "pop rcx",
        "iretq",
        syscall_dispatch = sym crate::syscall::syscall_dispatch,
    );
}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    serial_println!(
        "EXCEPTION: BREAKPOINT @ {:?}",
        stack_frame.instruction_pointer
    );
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
    fatal_fault(stack_frame, format_args!("page fault ({error_code:?})"));
}

extern "x86-interrupt" fn arithmetic_fault(frame: InterruptStackFrame) {
    fatal_fault(frame, format_args!("arithmetic exception"));
}

extern "x86-interrupt" fn instruction_fault(frame: InterruptStackFrame) {
    fatal_fault(frame, format_args!("instruction exception"));
}

extern "x86-interrupt" fn protection_fault(frame: InterruptStackFrame, code: u64) {
    fatal_fault(frame, format_args!("protection fault ({code:#x})"));
}

fn fatal_fault(frame: InterruptStackFrame, reason: core::fmt::Arguments<'_>) -> ! {
    if frame.code_segment.rpl() == x86_64::PrivilegeLevel::Ring3 {
        crate::process::terminate_current(format_args!(
            "{reason} at {:?}",
            frame.instruction_pointer
        ));
    }
    panic!("kernel {reason}\n{frame:#?}");
}

#[allow(unsafe_code)]
extern "x86-interrupt" fn timer_handler(stack_frame: InterruptStackFrame) {
    ruzt_hal_x86_64::time::increment_tick();
    TIMER_TICK_PRINTED.call_once(|| {
        crate::boot_screen::timer_started();
        serial_println!(
            "Timer monotonic ns: {}",
            ruzt_hal_x86_64::time::X86_64Timer::now_monotonic_ns()
        );
    });
    ruzt_hal_x86_64::pic::send_eoi(0);
    // Kernel execution can hold locks and schedules at its own safe points.
    if stack_frame.code_segment.rpl() == x86_64::PrivilegeLevel::Ring3 {
        crate::sched::yield_thread();
    } else {
        crate::sched::request_switch();
    }
}

#[allow(unsafe_code)]
extern "x86-interrupt" fn keyboard_handler(_stack_frame: InterruptStackFrame) {
    crate::keyboard::on_interrupt();
    ruzt_hal_x86_64::pic::send_eoi(1);
}
