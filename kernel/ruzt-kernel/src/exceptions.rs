//! x86_64 interrupt descriptor table and exception handlers.

use crate::serial_println;
use ruzt_abi::{ProcessStatus, PROCESS_FAULTED};
use ruzt_hal::cpu::CpuOps;
use ruzt_hal::time::Timer;
use ruzt_hal_x86_64::{
    apic::{LAPIC_PROBE_VECTOR, SPURIOUS_VECTOR, TLB_VECTOR, WAKE_VECTOR},
    irq::{IRQ_COUNT, VECTOR_BASE},
};
use spin::Once;
#[cfg(feature = "qemu-hardening-test")]
use x86_64::registers::rflags::RFlags;
use x86_64::structures::idt::{
    InterruptDescriptorTable, InterruptStackFrameValue, PageFaultErrorCode,
};

/// Static IDT, initialised once.
#[repr(align(4096))]
struct DescriptorPage(InterruptDescriptorTable);

const _: () = assert!(core::mem::size_of::<DescriptorPage>() == 4096);
static IDT: Once<DescriptorPage> = Once::new();

/// One-time flag so the timer handler only prints its tick value once.
static TIMER_TICK_PRINTED: Once<()> = Once::new();
#[cfg(feature = "qemu-hardening-test")]
static USER_NMI: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

mod entry;

const SYSCALL_VECTOR: u8 = 0x80;

/// Initialise and load the IDT on the current CPU.
#[allow(unsafe_code)]
pub fn init_idt() {
    let idt = IDT.call_once(|| {
        let mut idt = InterruptDescriptorTable::new();
        macro_rules! gate {
            ($entry:expr, $vector:expr) => {
                $entry.set_handler_addr(entry::vector_entry($vector))
            };
        }

        // SAFETY: Every installed entry normalizes its hardware frame before
        // dispatch. Only the syscall interrupt can be invoked from ring 3.
        unsafe {
            gate!(idt.breakpoint, 3);
            gate!(idt.non_maskable_interrupt, 2)
                .set_stack_index(ruzt_hal_x86_64::gdt::NMI_IST_INDEX);
            gate!(idt.double_fault, 8)
                .set_stack_index(ruzt_hal_x86_64::gdt::DOUBLE_FAULT_IST_INDEX);
            gate!(idt.page_fault, 14);
            gate!(idt.divide_error, 0);
            gate!(idt.x87_floating_point, 16);
            gate!(idt.simd_floating_point, 19);
            gate!(idt.debug, 1);
            gate!(idt.overflow, 4);
            gate!(idt.bound_range_exceeded, 5);
            gate!(idt.invalid_opcode, 6);
            gate!(idt.device_not_available, 7);
            gate!(idt.invalid_tss, 10);
            gate!(idt.segment_not_present, 11);
            gate!(idt.stack_segment_fault, 12);
            gate!(idt.general_protection_fault, 13);
            gate!(idt.alignment_check, 17);
            gate!(idt.cp_protection_exception, 21);
            for line in 0..IRQ_COUNT as u8 {
                let vector = VECTOR_BASE + line;
                gate!(idt[vector], vector);
            }
            gate!(idt[SPURIOUS_VECTOR], SPURIOUS_VECTOR);
            gate!(idt[WAKE_VECTOR], WAKE_VECTOR);
            gate!(idt[TLB_VECTOR], TLB_VECTOR);
            gate!(idt[LAPIC_PROBE_VECTOR], LAPIC_PROBE_VECTOR);
            gate!(idt[SYSCALL_VECTOR], SYSCALL_VECTOR)
                .set_privilege_level(x86_64::PrivilegeLevel::Ring3);
        }
        DescriptorPage(idt)
    });
    idt.0.load();
}

pub(crate) fn descriptor_page() -> u64 {
    core::ptr::from_ref(IDT.get().expect("IDT installed")) as u64
}

pub(crate) fn entry_code_pages() -> impl Iterator<Item = u64> {
    entry::code_pages()
}

/// # Safety
/// Run on the current user's kernel stack with interrupts disabled, with
/// both the entry point and stack mapped in its isolated root.
#[allow(unsafe_code)]
pub(crate) unsafe fn enter_user(ip: u64, sp: u64) -> ! {
    // SAFETY: The caller provides the scheduled task and its validated frame.
    unsafe { entry::enter_user(ip, sp) }
}

#[repr(C)]
struct UserReturn {
    entry_top: u64,
    root: u64,
}

extern "C" fn user_return(trap: &entry::Trap) -> UserReturn {
    let frame = trap.frame;
    // IRET must not fault on a user-controlled noncanonical stack pointer
    // after loading the restricted root. Only 64-bit user mode is supported.
    if frame.stack_pointer.as_u64() >= 1 << 47 || frame.instruction_pointer.as_u64() >= 1 << 47 {
        fatal_fault(frame, 13, format_args!("invalid user return address"));
    }
    let root = crate::sched::with_current_user(|user| user.root()).expect("returning user process");
    UserReturn {
        entry_top: crate::mm::entry_stack::top(crate::sched::current_cpu()),
        root: root.base.as_u64(),
    }
}

extern "C" fn dispatch(trap: &mut entry::Trap) {
    let frame = trap.frame;
    let vector = trap.vector as u8;
    #[cfg(any(feature = "qemu-hardening-test", feature = "qemu-smp-test"))]
    if frame.code_segment.rpl() == x86_64::PrivilegeLevel::Ring3 {
        crate::pti::assert_kernel_root();
    }
    match vector {
        0 | 16 | 19 => fatal_fault(frame, vector.into(), format_args!("arithmetic exception")),
        1 | 4..=7 => fatal_fault(frame, vector.into(), format_args!("instruction exception")),
        // No NMI sources are configured. Return on the same IST without
        // locks, scheduling, or changing the interrupted address space.
        2 =>
        {
            #[cfg(feature = "qemu-hardening-test")]
            if frame.code_segment.rpl() == x86_64::PrivilegeLevel::Ring3 {
                USER_NMI.store(true, core::sync::atomic::Ordering::Relaxed);
            }
        }
        3 => breakpoint_handler(frame),
        8 => double_fault_handler(frame, trap.error),
        10..=13 | 17 => {
            fatal_fault(
                frame,
                vector.into(),
                format_args!("protection fault ({:#x})", trap.error),
            );
        }
        14 => {
            let code = PageFaultErrorCode::from_bits_retain(trap.error);
            fatal_fault(frame, 14, format_args!("page fault ({code:?})"));
        }
        21 => fatal_fault(frame, 21, format_args!("control-protection fault ({:#x})", trap.error)),
        VECTOR_BASE => timer_handler(frame),
        irq if (VECTOR_BASE..VECTOR_BASE + IRQ_COUNT as u8).contains(&irq) => {
            crate::irq::on_interrupt(irq - VECTOR_BASE);
        }
        SYSCALL_VECTOR => {
            trap.args.number =
                crate::syscall::syscall_dispatch(&trap.args, frame.code_segment.0.into());
        }
        WAKE_VECTOR => {
            if crate::smp::wake() {
                schedule_after_interrupt(frame);
            }
        }
        TLB_VECTOR => crate::smp::handle_tlb_ipi(),
        LAPIC_PROBE_VECTOR => crate::smp::handle_lapic_probe(),
        // The local APIC does not put its spurious vector in service.
        SPURIOUS_VECTOR => {}
        _ => panic!("unhandled interrupt {vector:#x}\n{frame:#?}"),
    }
}

#[cfg(feature = "qemu-hardening-test")]
pub(crate) fn assert_entry_flags() {
    let flags = x86_64::registers::rflags::read();
    assert!(!flags.intersects(RFlags::ALIGNMENT_CHECK | RFlags::DIRECTION_FLAG));
}

fn breakpoint_handler(stack_frame: InterruptStackFrameValue) {
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

fn double_fault_handler(stack_frame: InterruptStackFrameValue, error_code: u64) -> ! {
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

fn fatal_fault(
    frame: InterruptStackFrameValue,
    vector: u32,
    reason: core::fmt::Arguments<'_>,
) -> ! {
    #[cfg(feature = "qemu-hardening-test")]
    assert_entry_flags();
    if frame.code_segment.rpl() == x86_64::PrivilegeLevel::Ring3 {
        crate::process::terminate_current(
            crate::transaction::enter(),
            ProcessStatus {
                kind: PROCESS_FAULTED,
                code: vector,
            },
            format_args!("{reason} at {:?}", frame.instruction_pointer),
        );
    }
    panic!("kernel {reason}\n{frame:#?}");
}

fn timer_handler(stack_frame: InterruptStackFrameValue) {
    #[cfg(feature = "qemu-hardening-test")]
    {
        assert_entry_flags();
        if USER_NMI.swap(false, core::sync::atomic::Ordering::Relaxed) {
            serial_println!("KPTI resumed an NMI that interrupted user mode");
        }
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
    crate::irq::end_of_interrupt(0);
    crate::sched::expire_waits(&crate::transaction::enter());
    crate::smp::tick_schedulers();
    schedule_after_interrupt(stack_frame);
}

fn schedule_after_interrupt(frame: InterruptStackFrameValue) {
    // Kernel execution can hold locks and schedules at its own safe points.
    if frame.code_segment.rpl() == x86_64::PrivilegeLevel::Ring3 {
        crate::sched::yield_thread();
    } else {
        crate::sched::request_switch();
    }
}
