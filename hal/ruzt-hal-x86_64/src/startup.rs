//! Real-mode entry page for APIC startup IPIs.

use core::arch::global_asm;
use ruzt_hal::mem::{PhysFrame, VirtAddr};

global_asm!(
    r#"
    .section .rodata.ruzt_secondary_start,"a",@progbits
    .balign 16
    .global ruzt_ap_start, ruzt_ap_end, ruzt_ap_long, ruzt_ap_jump
    .global ruzt_ap_data, ruzt_ap_gdt, ruzt_ap_gdtr
    .code16
ruzt_ap_start:
    cli
    cld
    movw %cs, %ax
    movw %ax, %ds
    # PAE, OSFXSR and OSXMMEXCPT. The trampoline uses four-level tables.
    movl $0x620, %eax
    movl %eax, %cr4
    movl (ruzt_ap_data - ruzt_ap_start), %eax
    movl %eax, %cr3
    movl $0xc0000080, %ecx
    rdmsr
    orl (ruzt_ap_data - ruzt_ap_start + 4), %eax
    wrmsr
    lgdt (ruzt_ap_gdtr - ruzt_ap_start)
    # PG, WP, NE, ET, MP and PE. Enable caching and clear EM and TS.
    movl $0x80010033, %eax
    movl %eax, %cr0
    .byte 0x66, 0xea
ruzt_ap_jump:
    .long 0
    .word 0x08
    .code64
ruzt_ap_long:
    movw $0x10, %ax
    movw %ax, %ss
    movw %ax, %ds
    movw %ax, %es
    movq ruzt_ap_data+8(%rip), %rsp
    xorq %rbp, %rbp
    pushq $0
    movq ruzt_ap_data+16(%rip), %rdi
    jmp *ruzt_ap_data+24(%rip)
    .balign 8
ruzt_ap_data:
    .long 0, 0
    .quad 0, 0, 0
ruzt_ap_gdt:
    .quad 0
    .quad 0x00af9b000000ffff
    .quad 0x00cf93000000ffff
ruzt_ap_gdtr:
    .word ruzt_ap_gdtr - ruzt_ap_gdt - 1
    .long 0
ruzt_ap_end:
    .previous
    "#,
    options(att_syntax)
);

unsafe extern "C" {
    static ruzt_ap_start: u8;
    static ruzt_ap_end: u8;
    static ruzt_ap_long: u8;
    static ruzt_ap_jump: u8;
    static ruzt_ap_data: u8;
    static ruzt_ap_gdt: u8;
    static ruzt_ap_gdtr: u8;
}

/// The startup arguments shared with one secondary CPU.
pub struct Trampoline {
    data: *mut u64,
    vector: u8,
}

impl Trampoline {
    /// Copy the relocatable bootstrap and fix its real-mode addresses.
    ///
    /// # Safety
    /// The page is exclusive conventional memory below 1 MiB, and the alias
    /// covers the whole page. The startup root fits in 32 bits and maps the
    /// page at its physical address and the kernel in the supervisor half.
    pub unsafe fn install(
        frame: PhysFrame,
        alias: VirtAddr,
        startup_root: PhysFrame,
        entry: extern "C" fn(u64) -> !,
    ) -> Self {
        let start = &raw const ruzt_ap_start;
        let displacement = |label: *const u8| label.addr() - start.addr();
        let length = displacement(&raw const ruzt_ap_end);
        let base = u32::try_from(frame.base.as_u64()).expect("SIPI frame address");
        let cr3 = u32::try_from(startup_root.base.as_u64()).expect("startup CR3");
        assert!(length <= PhysFrame::SIZE && (0x1000..0x10_0000).contains(&base));
        let page = alias.as_u64() as *mut u8;
        // SAFETY: The complete source and destination fit the distinct ranges.
        unsafe { core::ptr::copy_nonoverlapping(start, page, length) };
        for (field, value) in [
            (
                displacement(&raw const ruzt_ap_jump),
                base + displacement(&raw const ruzt_ap_long) as u32,
            ),
            (
                displacement(&raw const ruzt_ap_gdtr) + 2,
                base + displacement(&raw const ruzt_ap_gdt) as u32,
            ),
            (displacement(&raw const ruzt_ap_data), cr3),
            // LME and NXE. Supervisor mappings require an NX-enabled CPU.
            (
                displacement(&raw const ruzt_ap_data) + 4,
                (1 << 8) | (1 << 11),
            ),
        ] {
            // SAFETY: Each field is a dword inside the copied template.
            unsafe { page.add(field).cast::<u32>().write_unaligned(value) };
        }
        // SAFETY: This is the aligned 64-bit handoff inside the startup page.
        let data = unsafe {
            page.add(displacement(&raw const ruzt_ap_data) + 8)
                .cast::<u64>()
        };
        // SAFETY: The third qword holds the kernel entry, linked at runtime.
        unsafe { data.add(2).write(entry as *const () as u64) };
        Self {
            data,
            vector: (base >> 12) as u8,
        }
    }

    /// Prepare the stack and first C ABI argument for the next SIPI.
    ///
    /// # Safety
    /// No previous target may still be executing in the startup page. The
    /// new stack is canonical, aligned, live, and exclusively owned.
    pub unsafe fn handoff(&mut self, stack: u64, argument: u64) -> u8 {
        // SAFETY: The two qwords are exclusively owned until the SIPI.
        unsafe {
            self.data.write_volatile(stack);
            self.data.add(1).write_volatile(argument);
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        self.vector
    }
}
