//! x86_64 [`Mapper`] implementation via [`OffsetPageTable`].
//!
//! The bootloader sets up 4-level page tables and identity-maps all physical
//! memory at `physical_memory_offset`.  We drive those existing tables through
//! the x86_64 crate rather than building new ones.

use core::{mem::MaybeUninit, ptr};
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

// SAFETY: [Category 13 - Library contract] The callback is installed only by
// `init`, whose caller guarantees that every returned `PhysFrame` is a fresh,
// exclusively owned, 4 KiB-aligned frame suitable for a page table.
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

fn mapping_parts(
    virt: VirtAddr,
    phys: PhysFrame,
    flags: PageFlags,
) -> Result<
    (
        Page<Size4KiB>,
        X64PhysFrame<Size4KiB>,
        PageTableFlags,
    ),
    MapError,
> {
    if flags.contains(PageFlags::WRITABLE | PageFlags::EXECUTABLE) {
        return Err(MapError::WriteExecute);
    }
    if virt.as_u64() & 0xFFF != 0 || !phys.base.is_aligned_4k() {
        return Err(MapError::InvalidAlignment);
    }

    Ok((
        Page::containing_address(X64VirtAddr::new(virt.as_u64())),
        X64PhysFrame::containing_address(X64PhysAddr::new(phys.base.as_u64())),
        convert_flags(flags),
    ))
}

const fn validate_frame_range(offset: usize, length: usize) -> Result<(), MapError> {
    match offset.checked_add(length) {
        Some(end) if end <= PhysFrame::SIZE => Ok(()),
        Some(_) | None => Err(MapError::InvalidAlignment),
    }
}

fn convert_map_error(error: MapToError<Size4KiB>) -> MapError {
    match error {
        MapToError::PageAlreadyMapped(_) => MapError::AlreadyMapped,
        MapToError::FrameAllocationFailed | MapToError::ParentEntryHugePage => {
            MapError::FrameAllocationFailed
        }
    }
}

/// x86_64 [`Mapper`] implementation backed by [`OffsetPageTable`].
pub struct X86_64Mapper {
    inner: OffsetPageTable<'static>,
    alloc: fn() -> Option<PhysFrame>,
    /// Currently unused — the x86_64 crate's `FrameAllocator` only allocates.
    /// Reserved for future page-table frame reclamation.
    _dealloc: fn(PhysFrame),
}

impl X86_64Mapper {
    /// Allocate an empty user PML4 that shares only the active kernel half.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::FrameAllocationFailed`] when no root frame is
    /// available.
    pub fn create_user_address_space(&mut self) -> Result<PhysFrame, MapError> {
        let root = (self.alloc)().ok_or(MapError::FrameAllocationFailed)?;
        // SAFETY: [Categories 3/10/11 - Dangling, bounds, provenance] The
        // configured allocator returned this fresh 4 KiB frame, and `init`
        // guarantees every allocated frame is covered by the physmap.
        unsafe { zero_frame(root) };

        let (active_root, _) = Cr3::read();
        let source_address = physical_memory_offset() + active_root.start_address().as_u64();
        let source_pointer = source_address.as_ptr::<PageTable>();
        let destination_pointer = frame_pointer(root).cast::<PageTable>();

        // SAFETY: [Categories 3/6/11 - Dangling, alignment, provenance]
        // `init` guarantees the physmap covers the active root frame, and
        // `Cr3::read` guarantees that frame's 4 KiB alignment and validity.
        let source = unsafe { &*source_pointer };
        // SAFETY: [Categories 1/3/6/11 - Aliasing, dangling, alignment,
        // provenance] The allocator contract makes `root` fresh and distinct
        // from the active root; `zero_frame` initialized all 4096 mapped bytes.
        let destination = unsafe { &mut *destination_pointer };

        for index in 256..512 {
            destination[index] = source[index].clone();
        }

        Ok(root)
    }

    /// Map one 4 KiB page in an inactive PML4 without flushing the active TLB.
    ///
    /// # Errors
    ///
    /// Returns the same alignment, W^X, allocation, and duplicate-mapping
    /// errors as [`Mapper::map`].
    ///
    /// # Safety
    ///
    /// `root` must be a uniquely borrowed, inactive PML4 returned by
    /// [`Self::create_user_address_space`]. `virt` must name an unused page in
    /// that address space, and `phys` must remain valid for the mapping's
    /// lifetime. Mapping a shared higher-half page is forbidden because those
    /// page-table branches are shared with the active kernel address space.
    pub unsafe fn map_in_address_space(
        &mut self,
        root: PhysFrame,
        virt: VirtAddr,
        phys: PhysFrame,
        flags: PageFlags,
    ) -> Result<(), MapError> {
        let (page, frame, page_table_flags) = mapping_parts(virt, phys, flags)?;
        let root_pointer = frame_pointer(root).cast::<PageTable>();

        // SAFETY: [Categories 1/3/5/6/11 - Aliasing, dangling, validity,
        // alignment, provenance] The caller guarantees `root` uniquely names
        // an initialized inactive PML4, and `init` guarantees its physmap span.
        let root_table = unsafe { &mut *root_pointer };
        // SAFETY: [Category 13 - Library contract] `root_table` is the valid
        // PML4 proven above and the offset is the complete boot physmap.
        let mut mapper = unsafe { OffsetPageTable::new(root_table, physical_memory_offset()) };
        let mut allocator = CallbackFrameAlloc { alloc: self.alloc };

        // SAFETY: [Categories 1/5/13 - Aliasing, validity, library contract]
        // The caller owns the unused page and mapped frame; the callback gives
        // the crate fresh intermediate-table frames, which it zeroes itself.
        let flush = unsafe {
            mapper.map_to(page, frame, page_table_flags, &mut allocator)
        }
        .map_err(convert_map_error)?;
        flush.ignore();

        Ok(())
    }
}

impl Mapper for X86_64Mapper {
    fn map(
        &mut self,
        virt: VirtAddr,
        phys: PhysFrame,
        flags: PageFlags,
    ) -> Result<(), MapError> {
        let (page, frame, page_table_flags) = mapping_parts(virt, phys, flags)?;

        let mut allocator = CallbackFrameAlloc {
            alloc: self.alloc,
        };

        // SAFETY: [Categories 1/5/13 - Aliasing, validity, library contract]
        // The HAL Mapper contract assigns the page/frame pair to this mapping;
        // validation proved alignment and W^X, and the callback yields fresh
        // intermediate-table frames.
        let flush = unsafe {
            self.inner
                .map_to(page, frame, page_table_flags, &mut allocator)
        }
        .map_err(convert_map_error)?;
        flush.flush();

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
static PHYSICAL_MEMORY_OFFSET: Once<X64VirtAddr> = Once::new();

fn physical_memory_offset() -> X64VirtAddr {
    match PHYSICAL_MEMORY_OFFSET.get() {
        Some(offset) => *offset,
        None => panic!("x86_64 mapper used before init"),
    }
}

fn frame_pointer(frame: PhysFrame) -> *mut u8 {
    (physical_memory_offset() + frame.base.as_u64()).as_mut_ptr()
}

/// Zero exactly one 4 KiB physical frame through the boot physmap.
///
/// # Panics
///
/// Panics when called before [`init`].
///
/// # Safety
///
/// `frame` must name a live, exclusively owned 4 KiB physical frame covered
/// by the physical-memory mapping supplied to [`init`].
pub unsafe fn zero_frame(frame: PhysFrame) {
    let destination = frame_pointer(frame);

    // SAFETY: [Categories 3/6/10/11 - Dangling, alignment, bounds,
    // provenance] `init` guarantees the physmap covers every valid frame;
    // `PhysFrame` guarantees a 4 KiB frame and the write is exactly 4096 bytes.
    unsafe { ptr::write_bytes(destination, 0, PhysFrame::SIZE) };
}

/// Copy bytes into a checked range of one physical frame through the physmap.
///
/// The copy supports an overlapping source and destination.
///
/// # Errors
///
/// Returns [`MapError::InvalidAlignment`] when `offset + bytes.len()`
/// overflows or exceeds 4096.
///
/// # Panics
///
/// Panics when called before [`init`] after the range has been validated.
///
/// # Safety
///
/// `frame` must name a live physical frame covered by the physical-memory
/// mapping supplied to [`init`]. The caller must own the destination byte
/// range exclusively for the duration of the copy.
pub unsafe fn copy_to_frame(
    frame: PhysFrame,
    offset: usize,
    bytes: &[u8],
) -> Result<(), MapError> {
    validate_frame_range(offset, bytes.len())?;
    let destination = frame_pointer(frame).wrapping_add(offset);

    // SAFETY: [Categories 3/6/10/11/13 - Dangling, alignment, bounds,
    // provenance, library contract] The checked range lies wholly in the
    // physmapped frame, `bytes` is valid for its length, and `ptr::copy`
    // permits overlap.
    unsafe { ptr::copy(bytes.as_ptr(), destination, bytes.len()) };
    Ok(())
}

/// Initialise the x86_64 mapper from the current CR3 page table.
///
/// # Safety
/// Must be called exactly once, after the frame allocator is initialised.
/// `physical_memory_offset` must match the offset used by the bootloader's
/// complete physical-memory mapping. `alloc` must return fresh, exclusively
/// owned, 4 KiB frames that are covered by that mapping.
pub unsafe fn init(
    physical_memory_offset: u64,
    alloc: fn() -> Option<PhysFrame>,
    dealloc: fn(PhysFrame),
) {
    INIT.call_once(|| {
        let offset = *PHYSICAL_MEMORY_OFFSET
            .call_once(|| X64VirtAddr::new(physical_memory_offset));
        let (level_4_frame, _) = Cr3::read();
        let phys = level_4_frame.start_address();
        let virt = offset + phys.as_u64();

        // SAFETY: [Categories 3/5/6/11 - Dangling, validity, alignment,
        // provenance] CR3 supplies a live aligned PML4 frame and the caller's
        // physmap contract makes `virt` a valid pointer to all 4096 bytes.
        let page_table: &mut PageTable = unsafe { &mut *virt.as_mut_ptr() };

        // SAFETY: [Category 13 - Library contract] `page_table` is the active
        // PML4 proven above, and `offset` maps all physical page-table frames
        // for the mapper's static lifetime.
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
    // SAFETY: [Category 4 - Uninitialized memory] The public contract requires
    // `init` to complete before use, and `INIT` writes `MAPPER` exactly once.
    let mapper = unsafe { guard.assume_init_mut() };
    f(mapper)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_range_is_valid_when_copy_ends_at_frame_boundary() {
        assert_eq!(validate_frame_range(4095, 1), Ok(()));
    }

    #[test]
    fn frame_range_is_invalid_when_offset_addition_overflows() {
        assert_eq!(
            validate_frame_range(usize::MAX, 1),
            Err(MapError::InvalidAlignment),
        );
    }
}
