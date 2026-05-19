//! aarch64 [`Mapper`] stub — Phase 6.

use ruzt_hal::mem::{MapError, Mapper, PageFlags, PhysFrame, VirtAddr};

/// aarch64 page-table mapper (stubbed until Phase 6).
pub struct AArch64Mapper;

impl Mapper for AArch64Mapper {
    fn map(
        &mut self,
        _virt: VirtAddr,
        _phys: PhysFrame,
        _flags: PageFlags,
    ) -> Result<(), MapError> {
        todo!("aarch64 MMU stage-1 page table walk. Phase 6.");
    }

    fn unmap(&mut self, _virt: VirtAddr) -> Result<PhysFrame, MapError> {
        todo!("aarch64 MMU unmap. Phase 6.");
    }

    fn translate(&self, _virt: VirtAddr) -> Option<ruzt_hal::mem::PhysAddr> {
        todo!("aarch64 MMU translate. Phase 6.");
    }

    fn flush(&mut self, _virt: VirtAddr) {
        // aarch64: TLBI VAE1, ISB
        todo!("aarch64 TLB invalidate. Phase 6.");
    }

    fn flush_all_smp(&mut self) {
        // aarch64: TLBI VMALLE1IS, ISB
        todo!("aarch64 TLB invalidate all SMP. Phase 6.");
    }
}

/// Initialise the aarch64 mapper.
///
/// # Safety
/// Must be called exactly once, after the frame allocator is initialised.
pub unsafe fn init(
    _physical_memory_offset: u64,
    _alloc: fn() -> Option<PhysFrame>,
    _dealloc: fn(PhysFrame),
) {
    todo!("aarch64 mapper init: read TTBR0_EL1, set up page table walker. Phase 6.");
}

/// Run `f` with a mutable reference to the initialised mapper.
///
/// # Panics
/// Panics if called before [`init()`].
pub fn with_mapper<R>(_f: impl FnOnce(&mut AArch64Mapper) -> R) -> R {
    todo!("aarch64 with_mapper: init and lock. Phase 6.");
}
