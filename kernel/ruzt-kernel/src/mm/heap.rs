//! Bounded CPU-local heaps with a shared kernel fallback.

extern crate alloc;

#[cfg(not(test))]
use core::alloc::{GlobalAlloc, Layout};
use linked_list_allocator::LockedHeap;
#[cfg(not(test))]
use ruzt_hal::cpu::CpuOps;
use ruzt_hal::mem::{Mapper, PageFlags, VirtAddr};

use crate::smp::SCHEDULER_SLOTS;

/// Start of the kernel heap, at the last PML4 slot in the supervisor half.
///
/// The bootloader's dynamic mapping range ends below this slot.
pub const HEAP_START: u64 = 0xFFFF_FF80_0000_0000;

/// Size of the heap in bytes (4 MiB).
const HEAP_SIZE: usize = 4 * 1024 * 1024;
pub(super) const HEAP_END: u64 = HEAP_START + HEAP_SIZE as u64;

/// Number of 4 KiB pages needed for the heap.
const HEAP_PAGES: usize = HEAP_SIZE / 4096;
const CPU_HEAP_START: u64 = HEAP_START + 128 * 1024 * 1024;
const CPU_HEAP_SIZE: usize = 64 * 1024;
#[cfg(not(test))]
const LOCAL_LIMIT: usize = 4096;

struct KernelHeap {
    global: LockedHeap,
    cpu: [LockedHeap; SCHEDULER_SLOTS],
}

#[cfg_attr(not(test), global_allocator)]
static HEAP_ALLOCATOR: KernelHeap = KernelHeap {
    global: LockedHeap::empty(),
    cpu: [const { LockedHeap::empty() }; SCHEDULER_SLOTS],
};

fn cpu_heap_start(slot: usize) -> u64 {
    CPU_HEAP_START + (slot * CPU_HEAP_SIZE) as u64
}

pub(crate) fn owner(address: u64) -> Option<usize> {
    let offset = address.checked_sub(CPU_HEAP_START)?;
    let slot = (offset / CPU_HEAP_SIZE as u64) as usize;
    (slot < SCHEDULER_SLOTS).then_some(slot)
}

#[cfg(not(test))]
#[allow(unsafe_code)]
// SAFETY: Every arena has a disjoint virtual range and one locked allocator.
// The address selects the original owner on free, including after migration.
unsafe impl GlobalAlloc for KernelHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        x86_64::instructions::interrupts::without_interrupts(|| {
            if layout.size() <= LOCAL_LIMIT && layout.align() <= LOCAL_LIMIT {
                let cpu = crate::smp::scheduler_slot();
                // SAFETY: Forward the caller's valid layout. An unprovisioned
                // local arena returns null, as does an exhausted one.
                let ptr = unsafe { self.cpu[cpu].alloc(layout) };
                if !ptr.is_null() {
                    return ptr;
                }
            }
            // SAFETY: The caller supplied a valid, nonempty layout.
            unsafe { self.global.alloc(layout) }
        })
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        x86_64::instructions::interrupts::without_interrupts(|| {
            let arena = owner(ptr as u64).map_or(&self.global, |slot| &self.cpu[slot]);
            // SAFETY: The pointer's range identifies the heap that issued it,
            // and the caller supplied its original layout.
            unsafe { arena.dealloc(ptr, layout) };
        });
    }
}

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
            let frame = crate::mm::frame::allocate().expect("heap frame allocation failed");
            mapper
                .map(virt, frame, PageFlags::PRESENT | PageFlags::WRITABLE)
                .expect("heap mapping failed");
        }
    });

    // SAFETY: All pages in [HEAP_START, HEAP_START + HEAP_SIZE) have been
    // mapped to valid physical frames. The region is exclusively owned by the
    // heap allocator and is not accessed by any other code.
    unsafe {
        HEAP_ALLOCATOR
            .global
            .lock()
            .init(HEAP_START as *mut u8, HEAP_SIZE);
    }
    provision_cpu(0);
}

/// Map a CPU's local arena before it begins scheduling. A CPU whose arena
/// cannot be provisioned uses the shared heap.
#[allow(unsafe_code)]
pub(crate) fn provision_cpu(slot: usize) -> bool {
    let start = cpu_heap_start(slot);
    ruzt_hal_x86_64::mapper::with_mapper(|mapper| {
        let pages = (start..start + CPU_HEAP_SIZE as u64).step_by(4096);
        for (index, address) in pages.clone().enumerate() {
            let frame = crate::mm::frame::allocate();
            if let Some(frame) = frame {
                if mapper
                    .map(VirtAddr::new(address), frame, PageFlags::WRITABLE)
                    .is_ok()
                {
                    continue;
                }
                crate::mm::frame::deallocate(frame);
            }
            for address in pages.take(index) {
                let frame = mapper
                    .unmap(VirtAddr::new(address))
                    .expect("staged CPU heap page");
                crate::mm::frame::deallocate(frame);
            }
            return false;
        }
        // SAFETY: Every page in the CPU's disjoint arena has just been mapped.
        // The scheduler publishes this CPU only after the allocator is ready.
        unsafe {
            HEAP_ALLOCATOR.cpu[slot]
                .lock()
                .init(start as *mut u8, CPU_HEAP_SIZE)
        };
        true
    })
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
    fn free_routes_by_arena_address() {
        use super::*;
        assert_eq!(owner(HEAP_START), None);
        for slot in 0..SCHEDULER_SLOTS {
            let start = cpu_heap_start(slot);
            assert_eq!(owner(start), Some(slot));
            assert_eq!(owner(start + CPU_HEAP_SIZE as u64 - 1), Some(slot));
        }
        assert_eq!(owner(cpu_heap_start(SCHEDULER_SLOTS)), None);
    }

    #[test]
    fn heap_allocation_smoke_test() {
        let mut v = alloc::vec![1, 2, 3];
        v.push(4);
        assert_eq!(v, [1, 2, 3, 4]);

        let b = alloc::boxed::Box::new(42u64);
        assert_eq!(*b, 42);
    }
}
