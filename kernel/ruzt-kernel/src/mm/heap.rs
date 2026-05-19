//! Kernel heap backed by `linked_list_allocator::LockedHeap`.

extern crate alloc;

#[cfg(not(test))]
use core::alloc::Layout;
use linked_list_allocator::LockedHeap;
#[cfg(not(test))]
use ruzt_hal::cpu::CpuOps;
use ruzt_hal::mem::{Mapper, PageFlags, VirtAddr};

/// Virtual start address of the kernel heap.
/// Chosen well above the kernel image in canonical higher-half space.
const HEAP_START: u64 = 0xFFFF_C000_0000_0000;

/// Size of the heap in bytes (4 MiB).
const HEAP_SIZE: usize = 4 * 1024 * 1024;

/// Number of 4 KiB pages needed for the heap.
const HEAP_PAGES: usize = HEAP_SIZE / 4096;

/// Global heap allocator.
///
/// In tests the host default allocator is used; this static exists only
/// so that `init()` compiles on the host target.
#[cfg(test)]
static HEAP_ALLOCATOR: LockedHeap = LockedHeap::empty();

#[cfg(not(test))]
#[global_allocator]
static HEAP_ALLOCATOR: LockedHeap = LockedHeap::empty();

/// Allocation error handler — prints to serial and halts.
#[cfg(not(test))]
#[alloc_error_handler]
#[allow(unsafe_code)]
fn alloc_error(layout: Layout) -> ! {
    // This function must not allocate (obviously).
    crate::serial_println!(
        "ALLOCATION ERROR: size={}, align={}",
        layout.size(),
        layout.align()
    );
    loop {
        ruzt_hal_x86_64::cpu::X86_64Cpu::cpu_idle();
    }
}

/// Map physical frames for the heap and initialise the allocator.
#[allow(unsafe_code)]
pub fn init() {
    ruzt_hal_x86_64::mapper::with_mapper(|mapper| {
        for i in 0..HEAP_PAGES {
            let virt = VirtAddr::new(HEAP_START + (i * 4096) as u64);
            let frame = crate::mm::frame::allocate()
                .expect("heap frame allocation failed");
            mapper.map(virt, frame, PageFlags::PRESENT | PageFlags::WRITABLE)
                .expect("heap mapping failed");
        }
    });

    // SAFETY: All pages in [HEAP_START, HEAP_START + HEAP_SIZE) have been
    // mapped to valid physical frames. The region is exclusively owned by the
    // heap allocator and is not accessed by any other code.
    unsafe {
        HEAP_ALLOCATOR.lock().init(HEAP_START as *mut u8, HEAP_SIZE);
    }
}

/// Allocate a heap object and return its value via serial output.
///
/// Used as a runtime smoke-test inside QEMU.
pub fn smoke_test() {
    let v = alloc::vec![1, 2, 3];
    let sum: u64 = v.iter().sum();
    crate::serial_println!("Heap smoke-test: Vec sum = {}", sum);

    let b = alloc::boxed::Box::new(42u64);
    crate::serial_println!("Heap smoke-test: Box value = {}", *b);
}

#[cfg(test)]
mod tests {
    #[test]
    fn heap_allocation_smoke_test() {
        let mut v = alloc::vec![1, 2, 3];
        v.push(4);
        assert_eq!(v, [1, 2, 3, 4]);

        let b = alloc::boxed::Box::new(42u64);
        assert_eq!(*b, 42);
    }
}
