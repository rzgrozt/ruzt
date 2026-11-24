//! Fixed, guarded stacks for hardware entry from user mode.

use core::sync::atomic::{AtomicU64, Ordering};

use ruzt_hal::mem::{Mapper, PageFlags, PhysFrame, VirtAddr};
use ruzt_hal_x86_64::mapper;

use super::{frame, heap::HEAP_START};
use crate::smp::SCHEDULER_SLOTS;

const PAGE: u64 = PhysFrame::SIZE as u64;
pub(crate) const BASE: u64 = HEAP_START + 64 * 1024 * 1024;
pub(crate) const SLOT_SHIFT: u32 = 13;
const _: () = assert!(1 << SLOT_SHIFT == 2 * PAGE);

/// Thread stack tops are kernel-only data. Hardware enters on the fixed
/// stack, and the entry stub looks up the current thread after saving state.
pub(crate) static THREAD_STACKS: [AtomicU64; SCHEDULER_SLOTS] =
    [const { AtomicU64::new(0) }; SCHEDULER_SLOTS];

pub(crate) fn guard(slot: usize) -> u64 {
    BASE + ((slot as u64) << SLOT_SHIFT)
}

pub(crate) fn bottom(slot: usize) -> u64 {
    guard(slot) + PAGE
}

pub(crate) fn top(slot: usize) -> u64 {
    bottom(slot) + PAGE
}

pub(crate) fn allocate_frame() -> Option<PhysFrame> {
    let physical = frame::allocate()?;
    #[allow(unsafe_code)]
    // SAFETY: This fresh frame is exclusively owned before it is mapped.
    unsafe {
        mapper::zero_frame(physical);
    }
    Some(physical)
}

pub(crate) fn map_boot() {
    mapper::with_mapper(|mapper| {
        assert!(mapper.translate(VirtAddr::new(guard(0))).is_none());
        let physical = allocate_frame().expect("boot CPU entry stack frame");
        mapper
            .map(VirtAddr::new(bottom(0)), physical, PageFlags::WRITABLE)
            .expect("map boot CPU entry stack");
    });
}

/// # Safety
/// Set only on the owning CPU with interrupts disabled. A supplied stack
/// must be aligned and live until that thread stops running locally.
#[allow(unsafe_code)]
pub(crate) unsafe fn set_thread_stack(slot: usize, top: Option<u64>) {
    THREAD_STACKS[slot].store(top.unwrap_or(0), Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_stack_slots_have_a_guard_and_decode_their_frame_address() {
        for slot in 0..SCHEDULER_SLOTS {
            assert_eq!(bottom(slot) - guard(slot), PAGE);
            assert_eq!(top(slot) - bottom(slot), PAGE);
            for address in [bottom(slot), top(slot) - 1] {
                assert_eq!((address - BASE) >> SLOT_SHIFT, slot as u64);
            }
        }
    }
}
