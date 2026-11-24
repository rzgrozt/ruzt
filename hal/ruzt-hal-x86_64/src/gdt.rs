//! x86_64 global descriptor table and task-state segment setup.

use core::{cell::UnsafeCell, mem::MaybeUninit};

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

struct CpuTables {
    tss: UnsafeCell<TaskStateSegment>,
    gdt: UnsafeCell<MaybeUninit<GdtState>>,
}

impl CpuTables {
    const fn new() -> Self {
        Self {
            tss: UnsafeCell::new(TaskStateSegment::new()),
            gdt: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    unsafe fn load(&'static self, trap_top: u64, double_fault_top: u64) {
        let tss = self.tss.get();
        // SAFETY: This CPU exclusively owns these tables and interrupts
        // stay disabled while it constructs and installs the descriptors.
        unsafe {
            self.write_trap_stack(trap_top);
            core::ptr::addr_of_mut!((*tss).interrupt_stack_table)
                .cast::<VirtAddr>()
                .add(usize::from(DOUBLE_FAULT_IST_INDEX))
                .write_unaligned(VirtAddr::new(double_fault_top));
            let gdt = (*self.gdt.get()).write(build_gdt(tss));
            gdt.table.load();
            CS::set_reg(gdt.kernel_code);
            SS::set_reg(gdt.kernel_data);
            DS::set_reg(gdt.kernel_data);
            ES::set_reg(gdt.kernel_data);
            load_tss(gdt.tss);
        }
    }

    unsafe fn write_trap_stack(&self, top: u64) {
        let tss = self.tss.get();
        // SAFETY: RSP0 is packed. The caller owns the CPU's TSS.
        unsafe {
            core::ptr::addr_of_mut!((*tss).privilege_stack_table)
                .cast::<VirtAddr>()
                .write_unaligned(VirtAddr::new(top));
        }
    }
}

// SAFETY: A CPU exclusively owns its tables after initialization. Hardware
// marks its own GDT's TSS descriptor busy through the interior-mutable cell.
unsafe impl Sync for CpuTables {}

static BSP: CpuTables = CpuTables::new();
static SECONDARIES: [CpuTables; 255] = [const { CpuTables::new() }; 255];
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
        // SAFETY: The boot CPU owns these tables and interrupts are disabled.
        unsafe { BSP.load(RING3_TRAP_STACK.top().as_u64(), double_fault_top) };
    });
}

/// Install distinct descriptor tables on a secondary CPU.
///
/// # Safety
/// Call once on the secondary with interrupts disabled and its assigned
/// APIC ID. Both stacks must be private, supervisor-only, and remain live.
pub unsafe fn init_secondary(id: u8, trap_top: u64, double_fault_top: u64) {
    // SAFETY: The caller exclusively owns this CPU's tables and stacks.
    unsafe { SECONDARIES[usize::from(id)].load(trap_top, double_fault_top) };
}

/// Set the kernel stack used for the next privilege transition from ring 3.
///
/// # Safety
/// Call on the boot CPU with interrupts disabled. The stack must be aligned,
/// remain live while it is installed, and be mapped supervisor-only in every
/// active address space.
pub unsafe fn set_trap_stack(top: u64) {
    // SAFETY: The caller owns the boot CPU's TSS with interrupts disabled.
    unsafe { BSP.write_trap_stack(top) };
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
