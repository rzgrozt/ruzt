#![allow(unsafe_code)]

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::{self, NonNull};
use linked_list_allocator::LockedHeap;
use ruzt_abi::{
    CapOp, ErrorCode, SyscallNumber, FRAME_BYTES, PROCESS_ADDRESS_SPACE, USER_HEAP_INITIAL_BYTES,
    USER_HEAP_LIMIT, USER_HEAP_START,
};

struct GrowingHeap(LockedHeap);

#[global_allocator]
static ALLOCATOR: GrowingHeap = GrowingHeap(LockedHeap::empty());

// SAFETY: The heap lock serializes all allocation and growth. Newly mapped
// pages belong to this heap for the remainder of the process lifetime.
unsafe impl GlobalAlloc for GrowingHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut heap = self.0.lock();
        if heap.bottom().is_null() {
            return ptr::null_mut();
        }
        if let Ok(ptr) = heap.allocate_first_fit(layout) {
            return ptr.as_ptr();
        }
        let top = heap.top().addr();
        let Some(bytes) = extension_size(top, layout) else {
            return ptr::null_mut();
        };
        // SAFETY: GrowHeap takes scalar arguments and checks the committed
        // end before mapping the entire extension as one operation.
        let result = unsafe {
            crate::syscall::syscall(
                SyscallNumber::Invoke,
                PROCESS_ADDRESS_SPACE,
                CapOp::GrowHeap as u64,
                top as u64,
                (bytes / FRAME_BYTES) as u64,
                0,
                0,
            )
        };
        if result != ErrorCode::Ok.as_u64() {
            return ptr::null_mut();
        }
        // SAFETY: The successful syscall mapped writable memory immediately
        // after the heap. Other mapping operations preserve the heap window.
        unsafe { heap.extend(bytes) };
        heap.allocate_first_fit(layout)
            .map_or(ptr::null_mut(), NonNull::as_ptr)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: GlobalAlloc requires a live allocation from this heap with
        // the same layout used to allocate it.
        unsafe {
            self.0
                .lock()
                .deallocate(NonNull::new_unchecked(ptr), layout)
        };
    }
}

fn extension_size(top: usize, layout: Layout) -> Option<usize> {
    // A fresh trailing hole must accommodate the allocation and any holes
    // left around it. linked_list_allocator stores two words in each hole.
    const MIN_HOLE: usize = 2 * size_of::<usize>();
    let start = if top.is_multiple_of(layout.align()) {
        top
    } else {
        top.checked_add(MIN_HOLE)?
            .checked_next_multiple_of(layout.align())?
    };
    let size = layout
        .size()
        .max(MIN_HOLE)
        .checked_next_multiple_of(align_of::<usize>())?;
    let requested = start.checked_sub(top)?.checked_add(size)?;
    let mut bytes = requested.checked_next_multiple_of(FRAME_BYTES)?;
    if (1..MIN_HOLE).contains(&(bytes - requested)) {
        bytes = bytes.checked_add(FRAME_BYTES)?;
    }
    (top.checked_add(bytes)? <= USER_HEAP_LIMIT as usize).then_some(bytes)
}

pub fn init() {
    let heap_start = ptr::with_exposed_provenance_mut(USER_HEAP_START as usize);

    // SAFETY: The loader maps the initial writable heap before entering user
    // mode, and the runtime initializes this allocator once.
    unsafe {
        ALLOCATOR.0.lock().init(heap_start, USER_HEAP_INITIAL_BYTES);
    }
}
