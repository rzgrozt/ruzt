//! x86_64 interrupt descriptor table and exception handlers.

use crate::serial_println;
use ruzt_abi::{ProcessStatus, PROCESS_FAULTED};
use ruzt_hal::cpu::CpuOps;
use ruzt_hal::time::Timer;
use spin::Once;
use x86_64::{
    registers::rflags::RFlags,
    structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode},
    VirtAddr,
};

/// Static IDT, initialised once.
static IDT: Once<InterruptDescriptorTable> = Once::new();

/// One-time flag so the timer handler only prints its tick value once.
static TIMER_TICK_PRINTED: Once<()> = Once::new();

macro_rules! kernel_entry {
    ($($asm:tt)*) => {
        core::arch::naked_asm!(
            // AC can be set by ring 3. Clear the live flag without changing
            // the hardware-saved frame or requiring a CPU that has CLAC.
            "pushfq",
            "and qword ptr [rsp], {without_ac}",
            "popfq",
            "cld",
            $($asm)*
            without_ac = const !(RFlags::ALIGNMENT_CHECK.bits() as i32),
        );
    };
}

macro_rules! interrupt_entry {
    ($stub:ident $(<$vector:ident: $ty:ty>)? => $handler:ident) => {
        #[unsafe(naked)]
        extern "C" fn $stub$(<const $vector: $ty>)?() {
            // The jump preserves the hardware stack layout, including any
            // error code, for the x86-interrupt handler and its IRETQ.
            kernel_entry!("jmp {handler}", handler = sym $handler$(::<$vector>)?,);
        }
    };
}

interrupt_entry!(breakpoint_entry => breakpoint_handler);
interrupt_entry!(double_fault_entry => double_fault_handler);
interrupt_entry!(page_fault_entry => page_fault_handler);
interrupt_entry!(arithmetic_entry<VECTOR: u32> => arithmetic_fault);
interrupt_entry!(instruction_entry<VECTOR: u32> => instruction_fault);
interrupt_entry!(protection_entry<VECTOR: u32> => protection_fault);
interrupt_entry!(timer_entry => timer_handler);
interrupt_entry!(device_entry<LINE: u8> => device_irq);

/// Initialises the global IDT with breakpoint, double-fault, page-fault, timer,
/// keyboard, and syscall handlers.
#[allow(unsafe_code)]
pub fn init_idt() {
    let idt = IDT.call_once(|| {
        let mut idt = InterruptDescriptorTable::new();

        macro_rules! gate {
            ($entry:expr, $handler:expr) => {
                $entry.set_handler_addr(VirtAddr::from_ptr($handler as *const ()))
            };
        }

        // SAFETY: Each stub preserves the interrupt frame for its matching
        // typed handler. Only the syscall vector is callable from ring 3.
        unsafe {
            gate!(idt.breakpoint, breakpoint_entry);
            gate!(idt.double_fault, double_fault_entry)
                .set_stack_index(ruzt_hal_x86_64::gdt::DOUBLE_FAULT_IST_INDEX);
            gate!(idt.page_fault, page_fault_entry);
            gate!(idt.divide_error, arithmetic_entry::<0>);
            gate!(idt.x87_floating_point, arithmetic_entry::<16>);
            gate!(idt.simd_floating_point, arithmetic_entry::<19>);
            gate!(idt.debug, instruction_entry::<1>);
            gate!(idt.overflow, arithmetic_entry::<4>);
            gate!(idt.bound_range_exceeded, arithmetic_entry::<5>);
            gate!(idt.invalid_opcode, instruction_entry::<6>);
            gate!(idt.device_not_available, instruction_entry::<7>);
            gate!(idt.invalid_tss, protection_entry::<10>);
            gate!(idt.segment_not_present, protection_entry::<11>);
            gate!(idt.stack_segment_fault, protection_entry::<12>);
            gate!(idt.general_protection_fault, protection_entry::<13>);
            gate!(idt.alignment_check, protection_entry::<17>);
            gate!(idt[32], timer_entry);
            gate!(idt[33], device_entry::<1>);
            gate!(idt[34], device_entry::<2>);
            gate!(idt[35], device_entry::<3>);
            gate!(idt[36], device_entry::<4>);
            gate!(idt[37], device_entry::<5>);
            gate!(idt[38], device_entry::<6>);
            gate!(idt[39], device_entry::<7>);
            gate!(idt[40], device_entry::<8>);
            gate!(idt[41], device_entry::<9>);
            gate!(idt[42], device_entry::<10>);
            gate!(idt[43], device_entry::<11>);
            gate!(idt[44], device_entry::<12>);
            gate!(idt[45], device_entry::<13>);
            gate!(idt[46], device_entry::<14>);
            gate!(idt[47], device_entry::<15>);
            gate!(idt[0x80], syscall_handler).set_privilege_level(x86_64::PrivilegeLevel::Ring3);
        }
        idt
    });
    idt.load();
}

#[unsafe(naked)]
extern "C" fn syscall_handler() {
    kernel_entry!(
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

#[cfg(feature = "qemu-hardening-test")]
pub(crate) fn assert_entry_flags() {
    let flags = x86_64::registers::rflags::read();
    assert!(!flags.intersects(RFlags::ALIGNMENT_CHECK | RFlags::DIRECTION_FLAG));
}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    #[cfg(feature = "qemu-kaslr-test")]
    serial_println!(
        "EXCEPTION: BREAKPOINT @ {:?}",
        stack_frame.instruction_pointer
    );
    #[cfg(not(feature = "qemu-kaslr-test"))]
    {
        let _ = stack_frame;
        serial_println!("EXCEPTION: BREAKPOINT");
    }
}

extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) -> ! {
    crate::serial::emergency_print(format_args!(
        "EXCEPTION: DOUBLE FAULT ({error_code:#x})\n{stack_frame:#?}\n"
    ));
    #[cfg(feature = "qemu-double-fault-test")]
    {
        use crate::mm::exception_stack::{BOTTOM, TOP};
        let stack_pointer: u64;
        #[allow(unsafe_code)]
        // SAFETY: This only reads the live handler stack pointer.
        unsafe {
            core::arch::asm!(
                "mov {}, rsp",
                out(reg) stack_pointer,
                options(nomem, nostack, preserves_flags),
            );
        }
        if (BOTTOM..TOP).contains(&stack_pointer)
            && stack_frame.stack_pointer.as_u64() == TEST_FAULT_RSP
            && error_code == 0
            && crate::serial::SERIAL1.is_locked()
        {
            crate::serial::emergency_print(format_args!(
                "double fault entered the emergency stack while the serial lock was held\n"
            ));
            ruzt_hal_x86_64::cpu::qemu_shutdown();
        }
    }
    loop {
        ruzt_hal_x86_64::cpu::X86_64Cpu::cpu_idle();
    }
}

#[cfg(feature = "qemu-double-fault-test")]
const TEST_FAULT_RSP: u64 = crate::mm::exception_stack::GUARD + 128;

#[cfg(feature = "qemu-double-fault-test")]
#[allow(unsafe_code)]
pub(crate) fn trigger_double_fault() {
    serial_println!("testing double fault with an unmapped stack");
    let _serial = crate::serial::SERIAL1.lock();
    // SAFETY: This test runs in a disposable guest. The read faults in the
    // verified guard page, and exception delivery faults on that same page.
    unsafe {
        core::arch::asm!(
            "mov rsp, {guard}",
            "mov eax, [rsp]",
            "ud2",
            guard = in(reg) TEST_FAULT_RSP,
            options(noreturn),
        )
    }
}

extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    fatal_fault(stack_frame, 14, format_args!("page fault ({error_code:?})"));
}

extern "x86-interrupt" fn arithmetic_fault<const VECTOR: u32>(frame: InterruptStackFrame) {
    fatal_fault(frame, VECTOR, format_args!("arithmetic exception"));
}

extern "x86-interrupt" fn instruction_fault<const VECTOR: u32>(frame: InterruptStackFrame) {
    fatal_fault(frame, VECTOR, format_args!("instruction exception"));
}

extern "x86-interrupt" fn protection_fault<const VECTOR: u32>(
    frame: InterruptStackFrame,
    code: u64,
) {
    fatal_fault(frame, VECTOR, format_args!("protection fault ({code:#x})"));
}

fn fatal_fault(frame: InterruptStackFrame, vector: u32, reason: core::fmt::Arguments<'_>) -> ! {
    #[cfg(feature = "qemu-hardening-test")]
    assert_entry_flags();
    if frame.code_segment.rpl() == x86_64::PrivilegeLevel::Ring3 {
        crate::process::terminate_current(
            ProcessStatus {
                kind: PROCESS_FAULTED,
                code: vector,
            },
            format_args!("{reason} at {:?}", frame.instruction_pointer),
        );
    }
    panic!("kernel {reason}\n{frame:#?}");
}

#[allow(unsafe_code)]
extern "x86-interrupt" fn timer_handler(stack_frame: InterruptStackFrame) {
    #[cfg(feature = "qemu-hardening-test")]
    {
        assert_entry_flags();
        if stack_frame.cpu_flags.contains(RFlags::ALIGNMENT_CHECK) {
            static USER_AC_OBSERVED: Once<()> = Once::new();
            USER_AC_OBSERVED.call_once(|| serial_println!("kernel: timer entry cleared user AC"));
        }
    }
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
extern "x86-interrupt" fn device_irq<const LINE: u8>(_stack_frame: InterruptStackFrame) {
    crate::irq::on_interrupt(LINE);
}
