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
        mapper::{CleanUp, MapToError, Translate, TranslateResult, UnmapError},
        FrameAllocator as X64FrameAllocator, FrameDeallocator, Mapper as X64Mapper,
        OffsetPageTable, Page, PageTable, PageTableFlags, PhysFrame as X64PhysFrame, Size4KiB,
    },
    PhysAddr as X64PhysAddr, VirtAddr as X64VirtAddr,
};

/// Frame source for the private page tables of one user address space.
///
/// # Safety
/// Every allocation must be a fresh, exclusively owned 4 KiB frame covered
/// by the boot physmap. Deallocation must scrub it before reuse.
pub unsafe trait UserPageFrames {
    /// Allocate a private page-table frame.
    fn allocate(&self) -> Option<PhysFrame>;

    /// Scrub and release a frame that belongs to this allocator.
    ///
    /// # Safety
    /// The frame must come from this allocator and have no live page-table
    /// references or translations on any CPU.
    unsafe fn deallocate(&self, frame: PhysFrame);
}

struct CallbackFrameAlloc<F>(F);

// SAFETY: Call sites supply either the trusted boot allocator or the
// address-space allocator with the exclusive-frame contract above.
unsafe impl<F: FnMut() -> Option<PhysFrame>> X64FrameAllocator<Size4KiB> for CallbackFrameAlloc<F> {
    fn allocate_frame(&mut self) -> Option<X64PhysFrame<Size4KiB>> {
        let hal_frame = (self.0)()?;
        Some(X64PhysFrame::containing_address(X64PhysAddr::new(
            hal_frame.base.as_u64(),
        )))
    }
}

struct DetachedTables([Option<PhysFrame>; 3]);

impl FrameDeallocator<Size4KiB> for DetachedTables {
    unsafe fn deallocate_frame(&mut self, frame: X64PhysFrame<Size4KiB>) {
        let frame = PhysFrame::from_base(PhysAddr::new(frame.start_address().as_u64()))
            .expect("aligned page-table frame");
        let slot = self
            .0
            .iter_mut()
            .find(|entry| entry.is_none())
            .expect("a single mapping has at most three intermediate tables");
        *slot = Some(frame);
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
    if flags.contains(PageFlags::DMA) {
        f |= DMA_PAGE;
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
}

impl X86_64Mapper {
    /// Create four private startup tables with one low identity mapping.
    ///
    /// # Safety
    /// All four frames must be distinct, allocator-owned and direct-mapped.
    /// The root frame is below 4 GiB, and the startup page is below 1 MiB.
    /// Keep the tables and shared supervisor hierarchy live until every
    /// startup target has switched to the permanent kernel root.
    pub unsafe fn prepare_startup_tables(
        &mut self,
        tables: [PhysFrame; 4],
        startup: PhysFrame,
    ) {
        let [root, l3, l2, l1] = tables;
        let offset = physical_memory_offset();
        let table = |frame: PhysFrame| (offset + frame.base.as_u64()).as_mut_ptr::<PageTable>();
        // SAFETY: The input frames are fresh and mutually exclusive. Only
        // the permanent supervisor roots are borrowed, not their ownership.
        unsafe {
            for frame in tables {
                table(frame).write(PageTable::new());
            }
            let top = &mut *table(root);
            let bsp = self.inner.level_4_table();
            for index in 256..512 {
                top[index] = bsp[index].clone();
            }
            let present = PageTableFlags::PRESENT;
            top[0].set_addr(X64PhysAddr::new(l3.base.as_u64()), present);
            (&mut *table(l3))[0].set_addr(X64PhysAddr::new(l2.base.as_u64()), present);
            (&mut *table(l2))[0].set_addr(X64PhysAddr::new(l1.base.as_u64()), present);
            let physical = startup.base.as_u64();
            (&mut *table(l1))[X64VirtAddr::new(physical).p1_index()]
                .set_addr(X64PhysAddr::new(physical), present);
        }
    }

    /// Return the direct-map virtual address if the entire physical range is mapped.
    pub fn physmap_alias(&self, start: u64, bytes: u64) -> Option<VirtAddr> {
        let page = PhysFrame::SIZE as u64;
        let end = start.checked_add(bytes)?;
        if bytes == 0 {
            return None;
        }
        let offset = physical_memory_offset().as_u64();
        for physical in (start & !(page - 1)..end).step_by(PhysFrame::SIZE) {
            let alias = X64VirtAddr::try_new(offset.checked_add(physical)?).ok()?;
            if self.inner.translate_addr(alias)?.as_u64() != physical {
                return None;
            }
        }
        Some(VirtAddr::new(offset.checked_add(start)?))
    }

    /// Match the boot physmap's cache attributes to a device's user mappings.
    ///
    /// # Safety
    /// The page-aligned range must contain only device memory. It must have no
    /// existing access or mapping outside the boot physmap. The boot CPU must
    /// serialize higher-half page-table edits with interrupts disabled.
    pub unsafe fn make_device_physmap_uncached(
        &mut self,
        base: u64,
        bytes: u64,
    ) -> Result<(), MapError> {
        const HUGE_BYTES: u64 = 2 * 1024 * 1024;
        let end = base.checked_add(bytes).ok_or(MapError::InvalidAlignment)?;
        if bytes == 0
            || end > 1 << 52
            || base % PhysFrame::SIZE as u64 != 0
            || end % PhysFrame::SIZE as u64 != 0
        {
            return Err(MapError::InvalidAlignment);
        }
        let mut start = base;
        let result = (|| {
            while start < end {
                let chunk_end = end.min((start | (HUGE_BYTES - 1)) + 1);
                // SAFETY: This chunk is inside the caller's exclusive device
                // range and is contained by a single 2 MiB physmap slot.
                unsafe {
                    self.uncache_physmap_chunk(start, chunk_end)?;
                }
                start = chunk_end;
            }
            Ok(())
        })();
        // All boot physmap changes are shared with user roots, non-global, and
        // made on the only CPU. Flush even if a later chunk could not split.
        x86_64::instructions::tlb::flush_all();
        result
    }

    unsafe fn uncache_physmap_chunk(&mut self, start: u64, end: u64) -> Result<(), MapError> {
        const HUGE_BYTES: u64 = 2 * 1024 * 1024;
        const UC: PageTableFlags = PageTableFlags::NO_CACHE.union(PageTableFlags::WRITE_THROUGH);
        let offset = physical_memory_offset();
        let Some(address) = offset
            .as_u64()
            .checked_add(start)
            .and_then(|raw| X64VirtAddr::try_new(raw).ok())
        else {
            return Ok(());
        };
        let root = self.inner.level_4_table();
        let Ok(l3) = root[address.p4_index()].frame() else {
            return Ok(());
        };
        // SAFETY: A present non-leaf in the boot physmap names a live page
        // table mapped by the physmap itself.
        let l3 = unsafe { &*(offset + l3.start_address().as_u64()).as_ptr::<PageTable>() };
        let entry = &l3[address.p3_index()];
        if entry.flags().contains(PageTableFlags::HUGE_PAGE) {
            // This bootloader builds the physmap with at most 2 MiB pages.
            return Err(MapError::InvalidAlignment);
        }
        let Ok(l2) = entry.frame() else { return Ok(()) };
        // SAFETY: The same page-table ownership and boot physmap contract
        // covers the L2 table. The caller serializes all higher-half edits.
        let l2 = unsafe { &mut *(offset + l2.start_address().as_u64()).as_mut_ptr::<PageTable>() };
        let entry = &mut l2[address.p2_index()];
        if !entry.flags().contains(PageTableFlags::PRESENT) {
            return Ok(());
        }
        let huge_base = start & !(HUGE_BYTES - 1);
        if entry.flags().contains(PageTableFlags::HUGE_PAGE) {
            if entry.addr().as_u64() != huge_base {
                return Err(MapError::InvalidAlignment);
            }
            let flags = entry.flags();
            if start == huge_base && end == huge_base + HUGE_BYTES {
                entry.set_flags(flags | UC);
                return Ok(());
            }
            let table = (self.alloc)().ok_or(MapError::FrameAllocationFailed)?;
            // SAFETY: The allocator returned one exclusively owned table
            // frame. Each leaf below replaces part of the same physmap span.
            let l1 = unsafe { &mut *frame_pointer(table).cast::<PageTable>() };
            for (index, page) in l1.iter_mut().enumerate() {
                let physical = huge_base + index as u64 * PhysFrame::SIZE as u64;
                let page_flags = flags & !PageTableFlags::HUGE_PAGE;
                let page_flags = if (start..end).contains(&physical) {
                    page_flags | UC
                } else {
                    page_flags
                };
                page.set_addr(X64PhysAddr::new(physical), page_flags);
            }
            entry.set_addr(
                X64PhysAddr::new(table.base.as_u64()),
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
            );
            return Ok(());
        }
        let l1 = entry.frame().map_err(|_| MapError::InvalidAlignment)?;
        // SAFETY: As above, the present L2 entry names a live, serialized table.
        let l1 = unsafe { &mut *(offset + l1.start_address().as_u64()).as_mut_ptr::<PageTable>() };
        for physical in (start..end).step_by(PhysFrame::SIZE) {
            let entry = &mut l1[(offset + physical).p1_index()];
            if !entry.flags().contains(PageTableFlags::PRESENT) {
                continue;
            }
            if entry.addr().as_u64() != physical {
                return Err(MapError::InvalidAlignment);
            }
            entry.set_flags(entry.flags() | UC);
        }
        Ok(())
    }

    /// Free an inactive user root and the page tables owned by its lower half.
    ///
    /// Mapped leaf frames and the shared supervisor tables stay with their owners.
    ///
    /// # Safety
    /// The caller must own the root returned by [`Self::create_user_address_space`].
    /// The scheduler must have stopped using the root on every CPU. Its lower
    /// half must contain only private tables built from `frames`.
    pub unsafe fn destroy_user_address_space(
        &mut self,
        root: PhysFrame,
        frames: &dyn UserPageFrames,
    ) {
        assert_ne!(Cr3::read().0.start_address().as_u64(), root.base.as_u64());
        // SAFETY: The caller owns the inactive root and all its lower-half tables.
        unsafe { Self::free_user_tables(root, 4, frames) };
    }

    unsafe fn free_user_tables(frame: PhysFrame, level: u8, frames: &dyn UserPageFrames) {
        if level > 1 {
            // SAFETY: This owned frame is a populated page table covered by
            // the boot physmap. No CPU can walk it during destruction.
            let table = unsafe { &*frame_pointer(frame).cast::<PageTable>() };
            let count = if level == 4 { 256 } else { 512 };
            for entry in table.iter().take(count) {
                let flags = entry.flags();
                if flags.contains(PageTableFlags::PRESENT) {
                    assert!(!flags.contains(PageTableFlags::HUGE_PAGE));
                    let child = PhysFrame::from_base(PhysAddr::new(entry.addr().as_u64()))
                        .expect("aligned child page table");
                    // SAFETY: Present non-leaf entries in the private part
                    // of the tree name exclusive child page tables.
                    unsafe { Self::free_user_tables(child, level - 1, frames) };
                }
            }
        }
        // SAFETY: The table is still exclusively owned until deallocation.
        unsafe { frames.deallocate(frame) };
    }

    /// Allocate an empty user PML4 that shares only the active kernel half.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::FrameAllocationFailed`] when no root frame is
    /// available.
    pub fn create_user_address_space(
        &mut self,
        frames: &dyn UserPageFrames,
    ) -> Result<PhysFrame, MapError> {
        let root = frames.allocate().ok_or(MapError::FrameAllocationFailed)?;
        // SAFETY: [Categories 3/10/11 - Dangling, bounds, provenance] The
        // configured allocator returned this fresh 4 KiB frame, and `init`
        // guarantees every allocated frame is covered by the physmap.
        unsafe { zero_frame(root) };

        let source = self.inner.level_4_table();
        let destination_pointer = frame_pointer(root).cast::<PageTable>();

        // SAFETY: [Categories 1/3/6/11 - Aliasing, dangling, alignment,
        // provenance] The allocator contract makes `root` fresh and distinct
        // from the active root; `zero_frame` initialized all 4096 mapped bytes.
        let destination = unsafe { &mut *destination_pointer };

        for index in 256..512 {
            destination[index] = source[index].clone();
        }

        Ok(root)
    }

    /// Map one 4 KiB page in a private, lower-half user address space.
    ///
    /// # Errors
    ///
    /// Returns the same alignment, W^X, allocation, and duplicate-mapping
    /// errors as [`Mapper::map`].
    ///
    /// # Safety
    ///
    /// `root` must be an exclusively managed PML4 from
    /// [`Self::create_user_address_space`]. It can be active only on the
    /// calling CPU. Use the same `frames` as when creating the root.
    /// `phys` must remain valid for the mapping's lifetime.
    pub unsafe fn map_in_address_space(
        &mut self,
        root: PhysFrame,
        virt: VirtAddr,
        phys: PhysFrame,
        flags: PageFlags,
        frames: &dyn UserPageFrames,
    ) -> Result<(), MapError> {
        if virt.as_u64() >= 1 << 47 {
            return Err(MapError::InvalidAlignment);
        }
        let (page, frame, page_table_flags) = mapping_parts(virt, phys, flags)?;
        // SAFETY: The caller owns the user root and serializes its updates.
        let mut mapper = unsafe { user_mapper(root) };
        let mut allocator = CallbackFrameAlloc(|| frames.allocate());
        let active = root_is_active(root);

        // SAFETY: The destination is in the private half and the mapped frame
        // stays live. The allocator supplies exclusive intermediate tables.
        let result = unsafe { mapper.map_to(page, frame, page_table_flags, &mut allocator) };
        match result {
            Ok(flush) if active => flush.flush(),
            Ok(flush) => flush.ignore(),
            Err(error) => {
                if matches!(error, MapToError::FrameAllocationFailed) {
                    // SAFETY: Only tables on the requested private path can
                    // have been allocated on failure.
                    unsafe { Self::reclaim_user_tables(&mut mapper, page, active, frames) };
                }
                return Err(convert_map_error(error));
            }
        }
        Ok(())
    }

    /// Remove a tracked user mapping and reclaim empty intermediate tables.
    ///
    /// # Safety
    /// The root must obey the same ownership and CPU constraints as for
    /// [`Self::map_in_address_space`]. The page must be a live 4 KiB mapping
    /// that the caller owns in the private half of that root.
    pub unsafe fn unmap_in_address_space(
        &mut self,
        root: PhysFrame,
        virt: VirtAddr,
        frames: &dyn UserPageFrames,
    ) -> PhysFrame {
        assert!(virt.as_u64() < 1 << 47 && virt.as_u64() % PhysFrame::SIZE as u64 == 0);
        let page: Page<Size4KiB> = Page::containing_address(X64VirtAddr::new(virt.as_u64()));
        // SAFETY: The caller serializes this private root's updates.
        let mut mapper = unsafe { user_mapper(root) };
        let (frame, flush) = mapper
            .unmap(page)
            .expect("tracked user page must be mapped");
        flush.ignore();
        // SAFETY: The caller owns the private tables on this path.
        unsafe { Self::reclaim_user_tables(&mut mapper, page, root_is_active(root), frames) };
        PhysFrame::from_base(PhysAddr::new(frame.start_address().as_u64()))
            .expect("aligned user frame")
    }

    unsafe fn reclaim_user_tables(
        mapper: &mut OffsetPageTable<'_>,
        page: Page<Size4KiB>,
        active: bool,
        frames: &dyn UserPageFrames,
    ) {
        let mut detached = DetachedTables([None; 3]);
        // SAFETY: The range is a single lower-half page. All intermediate
        // tables for that address are owned exclusively by this user root.
        unsafe { mapper.clean_up_addr_range(Page::range_inclusive(page, page), &mut detached) };
        if active {
            // Also discard cached intermediate entries after detaching tables.
            x86_64::instructions::tlb::flush_all();
        }
        // Inactive user roots have non-global mappings and are flushed on load.
        for frame in detached.0.into_iter().flatten() {
            // SAFETY: The table is detached and cached translations for the
            // root cannot reference it on any CPU.
            unsafe { frames.deallocate(frame) };
        }
    }
}

fn root_is_active(root: PhysFrame) -> bool {
    Cr3::read().0.start_address().as_u64() == root.base.as_u64()
}

unsafe fn user_mapper<'root>(root: PhysFrame) -> OffsetPageTable<'root> {
    // SAFETY: The caller owns this initialized PML4 for the borrow and the
    // boot physmap covers it and all its descendants.
    unsafe {
        OffsetPageTable::new(
            &mut *frame_pointer(root).cast::<PageTable>(),
            physical_memory_offset(),
        )
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

        let mut allocator = CallbackFrameAlloc(self.alloc);

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
const DMA_PAGE: PageTableFlags = PageTableFlags::BIT_9;

fn physical_memory_offset() -> X64VirtAddr {
    match PHYSICAL_MEMORY_OFFSET.get() {
        Some(offset) => *offset,
        None => panic!("x86_64 mapper used before init"),
    }
}

fn frame_pointer(frame: PhysFrame) -> *mut u8 {
    (physical_memory_offset() + frame.base.as_u64()).as_mut_ptr()
}

/// Check all pages in a nonempty user buffer in the expected active root.
///
/// Every level must permit user access and, for an output buffer, writes.
/// MMIO and DMA mappings cannot serve as syscall buffers.
pub fn active_user_range_accessible(
    root: PhysFrame,
    address: u64,
    len: usize,
    writable: bool,
) -> bool {
    UserRange::check(root, address, len, writable).is_some()
}

struct UserRange {
    root: PhysFrame,
    address: u64,
    len: usize,
    required: PageTableFlags,
}

impl UserRange {
    fn check(root: PhysFrame, address: u64, len: usize, writable: bool) -> Option<Self> {
        let last = address.checked_add(len as u64)?.checked_sub(1)?;
        if len == 0 || address == 0 || last >= 1 << 47 || !root_is_active(root) {
            return None;
        }

        let mut required = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
        if writable {
            required |= PageTableFlags::WRITABLE;
        }
        let page_mask = !(PhysFrame::SIZE as u64 - 1);
        (address & page_mask..=last & page_mask)
            .step_by(PhysFrame::SIZE)
            .all(|page| user_page_frame(root, X64VirtAddr::new(page), required).is_some())
            .then_some(Self { root, address, len, required })
    }

    fn visit_pieces(&self, mut visit: impl FnMut(*mut u8, usize, usize)) {
        let mut consumed = 0;
        while consumed < self.len {
            let address = X64VirtAddr::new(self.address + consumed as u64);
            let frame = user_page_frame(self.root, address, self.required)
                .expect("checked user mappings must remain stable");
            let offset = usize::from(address.page_offset());
            let length = (PhysFrame::SIZE - offset).min(self.len - consumed);
            visit(frame_pointer(frame).wrapping_add(offset), consumed, length);
            consumed += length;
        }
    }
}

/// Read a checked user buffer through supervisor-only aliases.
///
/// Return false without copying if any page is outside the accessible range.
///
/// # Safety
/// The caller must keep the root, mappings, and backing frames stable for the
/// call. The source must be ordinary RAM and disjoint from the destination.
pub unsafe fn copy_from_active_user(root: PhysFrame, address: u64, buf: &mut [u8]) -> bool {
    let Some(range) = UserRange::check(root, address, buf.len(), false) else {
        return false;
    };
    range.visit_pieces(|source, offset, length| {
        // SAFETY: The checked source piece is in a live RAM frame, and the
        // caller provides a disjoint destination with room for every piece.
        unsafe { ptr::copy_nonoverlapping(source, buf.as_mut_ptr().add(offset), length) };
    });
    true
}

/// Write a checked user buffer through supervisor-only aliases.
///
/// Return false without calling `produce` or writing if any page is outside
/// the accessible range. The produced buffer must contain exactly `len` bytes.
///
/// # Safety
/// The caller must keep the root, mappings, and backing frames stable for the
/// call, including during `produce`. The destination must be ordinary RAM
/// exclusively writable during the copy and disjoint from the source.
pub unsafe fn copy_to_active_user_with<T: AsRef<[u8]>>(
    root: PhysFrame,
    address: u64,
    len: usize,
    produce: impl FnOnce() -> T,
) -> bool {
    let Some(range) = UserRange::check(root, address, len, true) else {
        return false;
    };
    let output = produce();
    let buf = output.as_ref();
    assert_eq!(buf.len(), len);
    range.visit_pieces(|destination, offset, length| {
        // SAFETY: The checked destination piece is in a live, exclusively
        // writable RAM frame, and the caller provides a disjoint source.
        unsafe { ptr::copy_nonoverlapping(buf.as_ptr().add(offset), destination, length) };
    });
    true
}

fn user_page_frame(
    root: PhysFrame,
    addr: X64VirtAddr,
    required: PageTableFlags,
) -> Option<PhysFrame> {
    let mut physical = root.base.as_u64();
    for (level, index) in [addr.p4_index(), addr.p3_index(), addr.p2_index(), addr.p1_index()]
        .into_iter()
        .enumerate()
    {
        let virtual_addr = physical_memory_offset() + physical;
        // SAFETY: CR3 supplies a live root and each preceding present,
        // non-huge entry names a live table. The boot physmap covers them.
        let table = unsafe { &*virtual_addr.as_ptr::<PageTable>() };
        let entry = &table[index];
        let flags = entry.flags();
        if !flags.contains(required) {
            return None;
        }
        if level == 3 {
            if flags.intersects(PageTableFlags::NO_CACHE | DMA_PAGE) {
                return None;
            }
            return PhysFrame::from_base(PhysAddr::new(entry.addr().as_u64()));
        }
        if flags.contains(PageTableFlags::HUGE_PAGE) {
            return None;
        }
        physical = entry.addr().as_u64();
    }
    unreachable!("four-level walk has a leaf")
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
pub unsafe fn init(physical_memory_offset: u64, alloc: fn() -> Option<PhysFrame>) {
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

        let mapper = X86_64Mapper { inner, alloc };
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
