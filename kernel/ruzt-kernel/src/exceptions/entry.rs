//! Hardware trap frames and the common x86 interrupt entry and return path.

#![allow(unsafe_code)]

use core::mem::{offset_of, size_of};

use ruzt_abi::SyscallArgs;
use x86_64::{registers::rflags::RFlags, structures::idt::InterruptStackFrameValue, VirtAddr};

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
}

pub(super) fn vector_entry(vector: u8) -> VirtAddr {
    VirtAddr::from_ptr((&raw const ruzt_vector_stubs).wrapping_add(usize::from(vector) * STUB_SIZE))
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

    # A regular user-mode trap arrives on the CPU's fixed RSP0 stack.
    # Move the complete frame to the current thread so it can block or migrate.
    # Double faults are terminal and stay on their separate IST stack.
    test word ptr [rsp + {cs_offset}], 3
    jz .Ldispatch
    cmp qword ptr [rsp + {vector_offset}], 8
    je .Ldispatch
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
    mov rsp, rbx

    pop rax
    pop rdi
    pop rsi
    pop rdx
    pop r10
    pop r8
    pop r9
    pop rcx
    pop r11
    pop rbx
    pop rbp
    pop r12
    pop r13
    pop r14
    pop r15
    add rsp, 16
    iretq
.Lbad_entry:
    ud2
    .p2align 12, 0xcc
    .popsection
    "#,
    dispatch = sym super::dispatch,
    thread_stacks = sym crate::mm::entry_stack::THREAD_STACKS,
    stack_base = const crate::mm::entry_stack::BASE,
    slot_shift = const crate::mm::entry_stack::SLOT_SHIFT,
    slot_count = const crate::smp::SCHEDULER_SLOTS,
    trap_size = const size_of::<Trap>(),
    trap_words = const size_of::<Trap>() / 8,
    cs_offset = const offset_of!(Trap, frame) + offset_of!(InterruptStackFrameValue, code_segment),
    vector_offset = const offset_of!(Trap, vector),
    without_ac = const !(RFlags::ALIGNMENT_CHECK.bits() as i32),
);
