//! x86_64 [`Mapper`] implementation via [`OffsetPageTable`].
//!
//! The bootloader sets up 4-level page tables and identity-maps all physical
//! memory at `physical_memory_offset`.  We drive those existing tables through
//! the x86_64 crate rather than building new ones.

use core::mem::MaybeUninit;
use ruzt_hal::mem::{MapError, Mapper, PageFlags, PhysAddr, PhysFrame, VirtAddr};
use spin::{Mutex, Once};
use x86_64::{
    registers::control::Cr3,
    structures::paging::{
        mapper::{MapToError, Translate, TranslateResult, UnmapError},
        FrameAllocator as X64FrameAllocator, Mapper as X64Mapper, OffsetPageTable,
        Page, PageTable, PageTableFlags, PhysFrame as X64PhysFrame, Size4KiB,
    },
    PhysAddr as X64PhysAddr, VirtAddr as X64VirtAddr,
};

/// Thin wrapper that satisfies the x86_64 crate's [`FrameAllocator`] using
/// function pointers to the kernel's bitmap allocator.
struct CallbackFrameAlloc {
    alloc: fn() -> Option<PhysFrame>,
}

unsafe impl X64FrameAllocator<Size4KiB> for CallbackFrameAlloc {
    fn allocate_frame(&mut self) -> Option<X64PhysFrame<Size4KiB>> {
        let hal_frame = (self.alloc)()?;
        Some(X64PhysFrame::containing_address(X64PhysAddr::new(
            hal_frame.base.as_u64(),
        )))
    }
}

/// Convert [`PageFlags`] to x86_64 [`PageTableFlags`].
///
/// If [`PageFlags::EXECUTABLE`] is **not** set, the page is marked
/// non-executable via the NX bit.  The bootloader already enables EFER.NXE,
/// so the NX bit is honoured.
fn convert_flags(flags: PageFlags) -> PageTableFlags {
    let mut f = PageTableFlags::PRESENT;

    if flags.contains(PageFlags::WRITABLE) {
        f |= PageTableFlags::WRITABLE;
    }
    if flags.contains(PageFlags::USER) {
        f |= PageTableFlags::USER_ACCESSIBLE;
    }
    if !flags.contains(PageFlags::EXECUTABLE) {
        f |= PageTableFlags::NO_EXECUTE;
    }
    if flags.contains(PageFlags::NOCACHE) {
        f |= PageTableFlags::NO_CACHE;
    }
    if flags.contains(PageFlags::WRITETHROUGH) {
        f |= PageTableFlags::WRITE_THROUGH;
    }
    // SENSITIVE has no x86_64 page-table equivalent — the allocator zeroes
    // the frame on deallocation.

    f
}

/// x86_64 [`Mapper`] implementation backed by [`OffsetPageTable`].
pub struct X86_64Mapper {
    inner: OffsetPageTable<'static>,
    alloc: fn() -> Option<PhysFrame>,
    /// Currently unused — the x86_64 crate's `FrameAllocator` only allocates.
    /// Reserved for future page-table frame reclamation.
    _dealloc: fn(PhysFrame),
}

impl Mapper for X86_64Mapper {
    fn map(
        &mut self,
        virt: VirtAddr,
        phys: PhysFrame,
        flags: PageFlags,
    ) -> Result<(), MapError> {
        // W^X enforcement — checked before any page table mutation.
        if flags.contains(PageFlags::WRITABLE | PageFlags::EXECUTABLE) {
            return Err(MapError::WriteExecute);
        }

        if virt.as_u64() & 0xFFF != 0 {
            return Err(MapError::InvalidAlignment);
        }
        if !phys.base.is_aligned_4k() {
            return Err(MapError::InvalidAlignment);
        }

        let page: Page<Size4KiB> = Page::containing_address(X64VirtAddr::new(virt.as_u64()));
        let frame = X64PhysFrame::containing_address(X64PhysAddr::new(phys.base.as_u64()));
        let pt_flags = convert_flags(flags);

        let mut allocator = CallbackFrameAlloc {
            alloc: self.alloc,
        };

        // SAFETY: `page` and `frame` are 4 KiB-aligned. The `page` is not
        // already mapped (we would have returned `AlreadyMapped` from the
        // x86_64 crate). The allocator provides valid frames.
        unsafe {
            self.inner
                .map_to(page, frame, pt_flags, &mut allocator)
                .map_err(|e| match e {
                    MapToError::PageAlreadyMapped(_) => MapError::AlreadyMapped,
                    MapToError::FrameAllocationFailed => MapError::FrameAllocationFailed,
                    MapToError::ParentEntryHugePage => MapError::FrameAllocationFailed,
                })?
                .flush();
        }

        Ok(())
    }

    fn unmap(&mut self, virt: VirtAddr) -> Result<PhysFrame, MapError> {
        if virt.as_u64() & 0xFFF != 0 {
            return Err(MapError::InvalidAlignment);
        }

        let page: Page<Size4KiB> = Page::containing_address(X64VirtAddr::new(virt.as_u64()));

        let (frame, flush) = self.inner.unmap(page).map_err(|e| match e {
            UnmapError::PageNotMapped => MapError::AlreadyMapped,
            UnmapError::ParentEntryHugePage => MapError::FrameAllocationFailed,
            UnmapError::InvalidFrameAddress(_) => MapError::InvalidAlignment,
        })?;

        flush.flush();

        PhysFrame::from_base(PhysAddr::new(frame.start_address().as_u64()))
            .ok_or(MapError::InvalidAlignment)
    }

    fn translate(&self, virt: VirtAddr) -> Option<PhysAddr> {
        let addr = X64VirtAddr::new(virt.as_u64());
        match self.inner.translate(addr) {
            TranslateResult::Mapped { frame, .. } => {
                Some(PhysAddr::new(frame.start_address().as_u64()))
            }
            _ => None,
        }
    }

    fn flush(&mut self, virt: VirtAddr) {
        x86_64::instructions::tlb::flush(X64VirtAddr::new(virt.as_u64()));
    }

    fn flush_all_smp(&mut self) {
        // Phase 7: broadcast IPI for TLB shootdown across all CPUs.
        // Single-core stub — only flush the local TLB.
        x86_64::instructions::tlb::flush_all();
    }
}

static MAPPER: Mutex<MaybeUninit<X86_64Mapper>> = Mutex::new(MaybeUninit::uninit());
static INIT: Once = Once::new();

/// Initialise the x86_64 mapper from the current CR3 page table.
///
/// # Safety
/// Must be called exactly once, after the frame allocator is initialised.
/// `physical_memory_offset` must match the offset used by the bootloader's
/// identity mapping.
pub unsafe fn init(
    physical_memory_offset: u64,
    alloc: fn() -> Option<PhysFrame>,
    dealloc: fn(PhysFrame),
) {
    INIT.call_once(|| {
        let offset = X64VirtAddr::new(physical_memory_offset);
        let (level_4_frame, _) = Cr3::read();
        let phys = level_4_frame.start_address();
        let virt = X64VirtAddr::new(phys.as_u64() + physical_memory_offset);

        // SAFETY: The bootloader set up valid page tables and loaded them into
        // CR3.  `physical_memory_offset` is the identity-map offset established
        // by the bootloader, so `virt` points to the currently active level-4
        // page table.  This is the exact address space that OffsetPageTable
        // needs to operate on.
        let page_table: &mut PageTable = unsafe { &mut *virt.as_mut_ptr() };

        // SAFETY: `page_table` points to the active level-4 page table and
        // `offset` is the correct physical-memory offset.  The page table
        // remains valid for `'static` because it is identity-mapped by the
        // bootloader and never unmapped.
        let inner = unsafe { OffsetPageTable::new(page_table, offset) };

        let mapper = X86_64Mapper { inner, alloc, _dealloc: dealloc };
        MAPPER.lock().write(mapper);
    });
}

/// Run `f` with a mutable reference to the initialised mapper.
///
/// # Panics
/// Panics if called before [`init()`].
pub fn with_mapper<R>(f: impl FnOnce(&mut X86_64Mapper) -> R) -> R {
    let mut guard = MAPPER.lock();
    let mapper = unsafe {
        // SAFETY: [`init()`] was called exactly once before any use.
        guard.assume_init_mut()
    };
    f(mapper)
}
