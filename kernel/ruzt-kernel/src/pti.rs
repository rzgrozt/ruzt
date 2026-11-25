//! Page-table isolation for x86 privilege transitions.

use core::sync::atomic::{AtomicU64, Ordering};

use ruzt_hal::mem::{PageFlags, PhysFrame, VirtAddr};
use ruzt_hal_x86_64::{
    context, gdt,
    mapper::{self, UserEntryMappings, UserPageFrames},
};
use spin::Once;

use crate::{
    exceptions,
    mm::{entry_stack, exception_stack, frame},
    smp,
};

#[repr(C, align(4096))]
pub(crate) struct KernelRoot(AtomicU64);

// The restricted roots map just this word and zero padding in its page.
// The trampoline reads it before it can access general kernel memory.
pub(crate) static KERNEL_ROOT: KernelRoot = KernelRoot(AtomicU64::new(0));
static ENTRY_MAPPINGS: Once<UserEntryMappings> = Once::new();
const PAGE: u64 = PhysFrame::SIZE as u64;

pub(crate) fn publish_kernel_root() {
    KERNEL_ROOT
        .0
        .store(context::current_cr3(), Ordering::Release);
}

pub(crate) fn init_entry_mappings() {
    ENTRY_MAPPINGS.call_once(|| {
        let code = exceptions::entry_code_pages()
            .map(|address| (VirtAddr::new(address), PageFlags::EXECUTABLE));
        let descriptors = [
            exceptions::descriptor_page(),
            core::ptr::from_ref(&KERNEL_ROOT) as u64,
        ]
        .map(|address| (VirtAddr::new(address), PageFlags::empty()));
        let boot = core::iter::once((None, 0, exception_stack::TOP - PAGE));
        let hardware = boot
            .chain(smp::entry_pages().map(|(id, slot, fault)| (Some(id), slot, fault)))
            .flat_map(|(id, slot, fault)| {
                [
                    gdt::descriptor_page(id),
                    entry_stack::bottom(slot),
                    entry_stack::nmi_bottom(slot),
                    fault,
                ]
                .map(|address| (VirtAddr::new(address), PageFlags::WRITABLE))
            });
        mapper::with_mapper(|mapper| {
            #[allow(unsafe_code)]
            // SAFETY: These are dedicated entry pages in the permanently
            // pinned kernel image or permanent CPU stacks. No leaf contains
            // unrelated kernel data and the upper tree is never updated.
            unsafe {
                mapper.create_user_entry_mappings(
                    code.chain(descriptors).chain(hardware),
                    &EntryFrames,
                )
            }
            .expect("build isolated user entry mappings")
        })
    });
}

pub(crate) fn entry_mappings() -> &'static UserEntryMappings {
    ENTRY_MAPPINGS
        .get()
        .expect("user entry mappings initialized")
}

#[cfg(any(feature = "qemu-hardening-test", feature = "qemu-smp-test"))]
#[allow(unsafe_code)]
pub(crate) fn verify_user_root(root: PhysFrame, user_entry: u64) {
    use x86_64::structures::paging::PageTableFlags as Flags;

    mapper::with_mapper(|mapper| {
        let direct_map = mapper
            .physmap_alias(root.base.as_u64(), PAGE)
            .expect("live root alias");
        let cpu = crate::sched::current_cpu();
        let mut lookup = |address| {
            // SAFETY: This user task owns the live root and we hold the mapper.
            unsafe { mapper.address_space_flags(root, address) }
        };
        for address in [
            direct_map,
            VirtAddr::new(crate::mm::heap::HEAP_START),
            VirtAddr::new(core::ptr::from_ref(&entry_stack::THREAD_STACKS) as u64),
            VirtAddr::new(entry_stack::guard(cpu)),
            VirtAddr::new(entry_stack::nmi_kernel_bottom(cpu)),
        ] {
            assert!(
                lookup(address).is_none(),
                "private kernel page mapped in the user root"
            );
        }
        for address in exceptions::entry_code_pages() {
            let flags = lookup(VirtAddr::new(address)).expect("trampoline is mapped");
            assert!(!flags.intersects(Flags::USER_ACCESSIBLE | Flags::NO_EXECUTE | Flags::WRITABLE));
        }
        for address in [entry_stack::bottom(cpu), entry_stack::nmi_bottom(cpu)] {
            let flags = lookup(VirtAddr::new(address)).expect("entry stack is mapped");
            assert!(flags.contains(Flags::WRITABLE | Flags::NO_EXECUTE));
            assert!(!flags.contains(Flags::USER_ACCESSIBLE));
        }
        let flags = lookup(VirtAddr::new(user_entry)).expect("user text is mapped");
        assert!(flags.contains(Flags::USER_ACCESSIBLE));
        assert!(!flags.intersects(Flags::NO_EXECUTE | Flags::WRITABLE));
    });
    static OBSERVED: Once<()> = Once::new();
    OBSERVED.call_once(|| {
        crate::serial_println!("KPTI user root excludes the kernel heap and physmap")
    });
}

#[cfg(any(feature = "qemu-hardening-test", feature = "qemu-smp-test"))]
pub(crate) fn assert_kernel_root() {
    assert_eq!(
        context::current_cr3(),
        KERNEL_ROOT.0.load(Ordering::Acquire)
    );
}

struct EntryFrames;

// SAFETY: The boot allocator hands out exclusive physmapped frames.
#[allow(unsafe_code)]
unsafe impl UserPageFrames for EntryFrames {
    fn allocate(&self) -> Option<PhysFrame> {
        frame::allocate()
    }

    unsafe fn deallocate(&self, physical: PhysFrame) {
        // SAFETY: An unpublished page-table build still owns the frame.
        unsafe { mapper::zero_frame(physical) };
        frame::deallocate(physical);
    }
}
