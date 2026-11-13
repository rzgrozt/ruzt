#![allow(unsafe_code)]

use linked_list_allocator::LockedHeap;

const HEAP_START: usize = 0x4000_0000;
const HEAP_SIZE: usize = 1024 * 1024;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

pub fn init() {
    let heap_start = core::ptr::with_exposed_provenance_mut(HEAP_START);

    // SAFETY: [Categories 10, 11, and 13 - bounds, provenance, and library
    // contract] The Ruzt process loader maps the writable range
    // 0x4000_0000..0x4010_0000 exclusively for this process heap before
    // `_start`; the pointer and exact 1 MiB extent therefore satisfy `init`.
    unsafe {
        ALLOCATOR.lock().init(heap_start, HEAP_SIZE);
    }
}
