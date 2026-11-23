//! x86_64 global descriptor table and task-state segment setup.

use core::cell::UnsafeCell;

use spin::Once;
use x86_64::{
    instructions::{
        segmentation::{Segment, CS, DS, ES, SS},
        tables::load_tss,
    },
    structures::{
        gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector},
        tss::TaskStateSegment,
    },
    VirtAddr,
};

const GDT_ENTRY_COUNT: usize = 7;
const KERNEL_CODE_SELECTOR: u64 = 0x08;
const KERNEL_DATA_SELECTOR: u64 = 0x10;
const TSS_SELECTOR: u64 = 0x28;
const RING3_TRAP_STACK_SIZE: usize = 64 * 1024;

/// Ring-3 code-segment selector, including requested privilege level 3.
pub const USER_CODE_SELECTOR: u64 = 0x1B;

/// Ring-3 data-segment selector, including requested privilege level 3.
pub const USER_DATA_SELECTOR: u64 = 0x23;

/// Zero-based IST slot used for the double-fault stack.
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

const _: () = assert!(RING3_TRAP_STACK_SIZE % 16 == 0);

#[repr(align(16))]
struct Ring3TrapStack {
    bytes: UnsafeCell<[u8; RING3_TRAP_STACK_SIZE]>,
}

impl Ring3TrapStack {
    const fn new() -> Self {
        Self {
            bytes: UnsafeCell::new([0; RING3_TRAP_STACK_SIZE]),
        }
    }

    fn top(&'static self) -> VirtAddr {
        let start = self.bytes.get().cast::<u8>();
        VirtAddr::from_ptr(start.wrapping_add(RING3_TRAP_STACK_SIZE))
    }
}

// SAFETY: [Category 2/9 - Data races and Send/Sync] The wrapper exposes only
// the stack's one-past-end address. Rust never reads or writes the bytes.
unsafe impl Sync for Ring3TrapStack {}

struct GdtState {
    table: GlobalDescriptorTable<GDT_ENTRY_COUNT>,
    kernel_code: SegmentSelector,
    kernel_data: SegmentSelector,
    tss: SegmentSelector,
}

static RING3_TRAP_STACK: Ring3TrapStack = Ring3TrapStack::new();

struct CpuTss(UnsafeCell<TaskStateSegment>);

// SAFETY: The boot CPU is the only CPU that reads or updates the TSS.
unsafe impl Sync for CpuTss {}

static TASK_STATE_SEGMENT: CpuTss = CpuTss(UnsafeCell::new(TaskStateSegment::new()));
static GDT: Once<GdtState> = Once::new();
static INIT: Once<()> = Once::new();

unsafe fn build_gdt(tss: *const TaskStateSegment) -> GdtState {
    let mut table = GlobalDescriptorTable::<GDT_ENTRY_COUNT>::empty();
    let kernel_code = table.append(Descriptor::kernel_code_segment());
    let kernel_data = table.append(Descriptor::kernel_data_segment());
    let user_code = table.append(Descriptor::user_code_segment());
    let user_data = table.append(Descriptor::user_data_segment());
    // SAFETY: The caller supplies the address of a static TSS.
    let tss = table.append(unsafe { Descriptor::tss_segment_unchecked(tss) });

    assert_eq!(u64::from(kernel_code.0), KERNEL_CODE_SELECTOR);
    assert_eq!(u64::from(kernel_data.0), KERNEL_DATA_SELECTOR);
    assert_eq!(u64::from(user_code.0), USER_CODE_SELECTOR);
    assert_eq!(u64::from(user_data.0), USER_DATA_SELECTOR);
    assert_eq!(u64::from(tss.0), TSS_SELECTOR);

    GdtState {
        table,
        kernel_code,
        kernel_data,
        tss,
    }
}

/// Install the GDT and TSS on the current CPU.
///
/// The GDT layout is fixed to kernel code/data, user code/data, then the
/// two-entry TSS descriptor. The TSS starts with a dedicated 64 KiB stack,
/// and the scheduler installs the active user thread's stack before entry.
/// Double faults use a separate interrupt stack.
///
/// # Safety
///
/// Call this exactly once from CPL0 on the boot CPU with interrupts disabled,
/// before loading the IDT or entering ring 3. The kernel image containing the
/// GDT, TSS, and stacks must remain mapped supervisor-only in every installed
/// CR3. `double_fault_top` must be the aligned top of a dedicated writable
/// stack that no other handler or CPU uses.
pub unsafe fn init(double_fault_top: u64) {
    INIT.call_once(|| {
        // SAFETY: The boot CPU owns this TSS and interrupts are disabled.
        unsafe {
            set_trap_stack(RING3_TRAP_STACK.top().as_u64());
            let tss = TASK_STATE_SEGMENT.0.get();
            core::ptr::addr_of_mut!((*tss).interrupt_stack_table)
                .cast::<VirtAddr>()
                .add(usize::from(DOUBLE_FAULT_IST_INDEX))
                .write_unaligned(VirtAddr::new(double_fault_top));
        }
        // SAFETY: The TSS lives at a fixed address for the kernel's lifetime.
        let gdt = GDT.call_once(|| unsafe { build_gdt(TASK_STATE_SEGMENT.0.get()) });

        gdt.table.load();

        // SAFETY: [Category 13 - Library contract] `build_gdt` verified that
        // this selector names the present 64-bit ring-0 code descriptor.
        unsafe { CS::set_reg(gdt.kernel_code) };
        // SAFETY: [Category 13 - Library contract] `build_gdt` verified that
        // this selector names the present writable ring-0 data descriptor.
        unsafe { SS::set_reg(gdt.kernel_data) };
        // SAFETY: [Category 13 - Library contract] The same verified ring-0
        // data descriptor is valid for DS in 64-bit mode.
        unsafe { DS::set_reg(gdt.kernel_data) };
        // SAFETY: [Category 13 - Library contract] The same verified ring-0
        // data descriptor is valid for ES in 64-bit mode.
        unsafe { ES::set_reg(gdt.kernel_data) };
        // SAFETY: [Category 13 - Library contract] `gdt.tss` selects the
        // static TSS whose canonical RSP0 points to the aligned trap stack.
        unsafe { load_tss(gdt.tss) };
    });
}

/// Set the kernel stack used for the next privilege transition from ring 3.
///
/// # Safety
/// Call on the boot CPU with interrupts disabled. The stack must be aligned,
/// remain live while it is installed, and be mapped supervisor-only in every
/// active address space.
pub unsafe fn set_trap_stack(top: u64) {
    let tss = TASK_STATE_SEGMENT.0.get();
    // SAFETY: The caller owns this CPU's TSS. RSP0 is packed, so use an
    // unaligned write through the raw pointer without borrowing the field.
    unsafe {
        core::ptr::addr_of_mut!((*tss).privilege_stack_table)
            .cast::<VirtAddr>()
            .write_unaligned(VirtAddr::new(top));
    }
}

/// Restore the boot CPU's fallback privilege stack.
///
/// # Safety
/// Call on the boot CPU with interrupts disabled.
pub unsafe fn use_boot_trap_stack() {
    // SAFETY: The static fallback stack lives for the kernel's lifetime.
    unsafe { set_trap_stack(RING3_TRAP_STACK.top().as_u64()) };
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_TSS: TaskStateSegment = TaskStateSegment::new();

    #[test]
    fn descriptor_insertion_order_produces_required_selectors() {
        // SAFETY: TEST_TSS is static for the whole test process.
        let gdt = unsafe { build_gdt(&TEST_TSS) };

        assert_eq!(u64::from(gdt.kernel_code.0), KERNEL_CODE_SELECTOR);
        assert_eq!(u64::from(gdt.kernel_data.0), KERNEL_DATA_SELECTOR);
        assert_eq!(u64::from(gdt.tss.0), TSS_SELECTOR);
    }

    #[test]
    fn ring3_trap_stack_top_is_aligned_and_exclusive() {
        let start = VirtAddr::from_ptr(RING3_TRAP_STACK.bytes.get()).as_u64();
        let top = RING3_TRAP_STACK.top().as_u64();

        assert_eq!(top - start, RING3_TRAP_STACK_SIZE as u64);
        assert_eq!(top & 0xF, 0);
    }
}
