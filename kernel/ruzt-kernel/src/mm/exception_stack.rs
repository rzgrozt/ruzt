//! Supervisor stack reserved for double-fault entry on the boot CPU.

use ruzt_hal::mem::{Mapper, PageFlags, PhysFrame, VirtAddr};
use ruzt_hal_x86_64::mapper;

use super::{entry_stack, heap::HEAP_END};

const PAGE_BYTES: u64 = PhysFrame::SIZE as u64;
const STACK_PAGES: u64 = 8;
pub(crate) const GUARD: u64 = HEAP_END;
pub(crate) const BOTTOM: u64 = GUARD + PAGE_BYTES;
pub(crate) const TOP: u64 = BOTTOM + STACK_PAGES * PAGE_BYTES;

pub(crate) fn map() {
    mapper::with_mapper(|mapper| {
        assert!(
            mapper.translate(VirtAddr::new(GUARD)).is_none(),
            "double-fault stack guard must be unmapped",
        );
        for address in (BOTTOM..TOP).step_by(PhysFrame::SIZE) {
            let frame = entry_stack::allocate_frame().expect("double-fault stack frame");
            mapper
                .map(VirtAddr::new(address), frame, PageFlags::WRITABLE)
                .expect("map double-fault stack");
        }
    });
}
