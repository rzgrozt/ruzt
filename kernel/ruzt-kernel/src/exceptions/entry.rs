//! Hardware trap frames and the common x86 interrupt entry and return path.

#![allow(unsafe_code)]

use core::mem::{offset_of, size_of};

use ruzt_abi::SyscallArgs;
use x86_64::{
    instructions::segmentation::{Segment, DS, ES, FS, GS},
    registers::rflags::RFlags,
    structures::{gdt::SegmentSelector, idt::InterruptStackFrameValue},
    VirtAddr,
};

use ruzt_hal_x86_64::gdt::{USER_CODE_SELECTOR, USER_DATA_SELECTOR};

#[repr(C)]
pub(super) struct Trap {
    pub(super) args: SyscallArgs,
    saved: [u64; 8],
    pub(super) vector: u64,
    pub(super) error: u64,
    pub(super) frame: InterruptStackFrameValue,
}

const _: () = {
    assert!(offset_of!(Trap, vector) == 15 * 8);
    assert!(offset_of!(Trap, frame) == 17 * 8);
    assert!(size_of::<Trap>() == 22 * 8);
};

const STUB_SIZE: usize = 16;

unsafe extern "C" {
    static ruzt_vector_stubs: u8;
    static ruzt_entry_end: u8;
    fn ruzt_return_user(frame: &Trap, entry_top: u64, root: u64) -> !;
}

pub(super) fn vector_entry(vector: u8) -> VirtAddr {
    VirtAddr::from_ptr((&raw const ruzt_vector_stubs).wrapping_add(usize::from(vector) * STUB_SIZE))
}

pub(super) fn code_pages() -> impl Iterator<Item = u64> {
    let start = &raw const ruzt_vector_stubs as u64;
    let end = &raw const ruzt_entry_end as u64;
    assert_eq!(start % 4096, 0);
    assert_eq!(end - start, 8192);
    (start..end).step_by(4096)
}

pub(super) unsafe fn enter_user(ip: u64, sp: u64) -> ! {
    let data = SegmentSelector(USER_DATA_SELECTOR as u16);
    let trap = Trap {
        args: SyscallArgs {
            number: 0,
            arg0: 0,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        saved: [0; 8],
        vector: 0,
        error: 0,
        frame: InterruptStackFrameValue::new(
            VirtAddr::new(ip),
            SegmentSelector(USER_CODE_SELECTOR as u16),
            RFlags::from_bits_retain(0x202),
            VirtAddr::new(sp),
            data,
        ),
    };
    let target = super::user_return(&trap);
    // SAFETY: The GDT supplies flat ring-3 data segments, the scheduler has
    // installed this task, and its entry and stack are mapped in the root.
    unsafe {
        DS::set_reg(data);
        ES::set_reg(data);
        FS::set_reg(data);
        GS::set_reg(data);
        ruzt_return_user(&trap, target.entry_top, target.root)
    }
}

// Every installed IDT gate lands at a fixed offset. Error-code exceptions
// already have the code in their hardware frame. Supply a zero word at the
// same offset for each other vector so all paths can use one restore sequence.
core::arch::global_asm!(
    r#"
    .pushsection .text.ruzt_entry,"ax",@progbits
    .p2align 12
    .global ruzt_vector_stubs
ruzt_vector_stubs:
    .set .Lvector, 0
    .rept 256
    .if .Lvector != 8 && .Lvector != 10 && .Lvector != 11 && .Lvector != 12 && .Lvector != 13 && .Lvector != 14 && .Lvector != 17 && .Lvector != 21 && .Lvector != 29 && .Lvector != 30
    push 0
    .endif
    push .Lvector
    jmp .Ltrap_entry
    .p2align 4, 0xcc
    .set .Lvector, .Lvector + 1
    .endr

.Ltrap_entry:
    pushfq
    and qword ptr [rsp], {without_ac}
    popfq
    cld

    push r15
    push r14
    push r13
    push r12
    push rbp
    push rbx
    push r11
    push rcx
    push r9
    push r8
    push r10
    push rdx
    push rsi
    push rdi
    push rax

    # An NMI can arrive even between MOV CR3 and IRET. It uses its own IST,
    # and the dummy error slot holds the exact interrupted root for return.
    cmp qword ptr [rsp + {vector_offset}], 2
    je .Lnmi_entry
    cmp qword ptr [rsp + {vector_offset}], 8
    je .Lload_kernel_root
    test word ptr [rsp + {cs_offset}], 3
    jnz .Lload_kernel_root

    # A fault in the shared transition code can also arrive with CPL0 and
    # an isolated root. Other kernel traps already have a supervisor root.
    mov rdx, [rsp + {rip_offset}]
    lea rax, [rip + ruzt_vector_stubs]
    cmp rdx, rax
    jb .Ldispatch
    lea rax, [rip + ruzt_entry_end]
    cmp rdx, rax
    jae .Ldispatch
    jmp .Lload_kernel_root

.Lnmi_entry:
    mov rax, cr3
    mov [rsp + {error_offset}], rax
.Lload_kernel_root:
    mov rax, [rip + {kernel_root}]
    mov cr3, rax

    # Switch from the shared, hardware-facing IST pages to kernel-only
    # stack pages and erase the interrupted state in the shared pages.
    cmp qword ptr [rsp + {vector_offset}], 2
    je .Lmove_nmi
    cmp qword ptr [rsp + {vector_offset}], 8
    je .Lmove_double_fault

    # A regular user-mode trap arrives on the CPU's fixed RSP0 stack.
    # Move the complete frame to the current thread so it can block or migrate.
    test word ptr [rsp + {cs_offset}], 3
    jz .Ldispatch
    mov rax, rsp
    mov rcx, {stack_base}
    sub rax, rcx
    shr rax, {slot_shift}
    cmp rax, {slot_count}
    jae .Lbad_entry
    lea rcx, [rip + {thread_stacks}]
    mov rdi, [rcx + rax * 8]
    test rdi, rdi
    jz .Lbad_entry
    sub rdi, {trap_size}
    jmp .Lmove_frame

.Lmove_nmi:
    lea rdi, [rsp + {nmi_kernel_offset}]
    jmp .Lmove_frame

.Lmove_double_fault:
    lea rdi, [rsp - 4096]

.Lmove_frame:
    mov rdx, rsp
    mov rsi, rsp
    mov rsp, rdi
    mov ecx, {trap_words}
    rep movsq

    # The entry stack is per CPU and may next serve a different user thread.
    mov rdi, rdx
    xor eax, eax
    mov ecx, {trap_words}
    rep stosq

.Ldispatch:
    mov rdi, rsp
    mov rbx, rsp
    and rsp, -16
    call {dispatch}
    cmp qword ptr [rbx + {vector_offset}], 2
    je .Lnmi_return
    test word ptr [rbx + {cs_offset}], 3
    jz .Lkernel_return

    # The task may have migrated while it was parked inside dispatch.
    mov rdi, rbx
    call {user_return}
    mov rdi, rbx
    mov rsi, rax
    jmp ruzt_return_user

.Lnmi_return:
    mov rdx, [rbx + {error_offset}]
    cmp rdx, [rip + {kernel_root}]
    je .Lkernel_return
    # Resume an interrupted restricted root using the mapped side of its IST.
    mov rdi, rbx
    lea rsi, [rbx - {nmi_kernel_offset} + {trap_size}]
    jmp ruzt_return_user

.Lkernel_return:
    mov rsp, rbx
    jmp .Lrestore

    .global ruzt_return_user
ruzt_return_user:
    mov rax, rdi
    lea rdi, [rsi - {trap_size}]
    mov rsi, rax
    mov rsp, rdi
    mov ecx, {trap_words}
    rep movsq
    # An NMI in the return window must only observe user state. Remove
    # kernel scratch, including the source stack pointer, before switching.
    xor eax, eax
    xor ebx, ebx
    xor ecx, ecx
    xor ebp, ebp
    xor edi, edi
    xor esi, esi
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
    xor r12d, r12d
    xor r13d, r13d
    xor r14d, r14d
    xor r15d, r15d
    mov cr3, rdx
    jmp .Lrestore_isolated

    .macro restore clear
    .irp reg,rax,rdi,rsi,rdx,r10,r8,r9,rcx,r11,rbx,rbp,r12,r13,r14,r15
    pop \reg
    .if \clear
    mov qword ptr [rsp - 8], 0
    .endif
    .endr
    .if \clear
    mov qword ptr [rsp], 0
    mov qword ptr [rsp + 8], 0
    .endif
    add rsp, 16
    iretq
    .endm

.Lrestore_isolated:
    restore 1
.Lrestore:
    restore 0
.Lbad_entry:
    ud2
    .p2align 12, 0xcc
    .global ruzt_entry_end
ruzt_entry_end:
    .popsection
    "#,
    dispatch = sym super::dispatch,
    user_return = sym super::user_return,
    kernel_root = sym crate::pti::KERNEL_ROOT,
    thread_stacks = sym crate::mm::entry_stack::THREAD_STACKS,
    stack_base = const crate::mm::entry_stack::BASE,
    slot_shift = const crate::mm::entry_stack::SLOT_SHIFT,
    slot_count = const crate::smp::SCHEDULER_SLOTS,
    nmi_kernel_offset = const crate::mm::entry_stack::NMI_KERNEL_OFFSET,
    trap_size = const size_of::<Trap>(),
    trap_words = const size_of::<Trap>() / 8,
    cs_offset = const offset_of!(Trap, frame) + offset_of!(InterruptStackFrameValue, code_segment),
    rip_offset = const offset_of!(Trap, frame) + offset_of!(InterruptStackFrameValue, instruction_pointer),
    vector_offset = const offset_of!(Trap, vector),
    error_offset = const offset_of!(Trap, error),
    without_ac = const !(RFlags::ALIGNMENT_CHECK.bits() as i32),
);
