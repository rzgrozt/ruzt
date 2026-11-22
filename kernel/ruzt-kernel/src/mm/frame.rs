//! Bitmap-based physical frame allocator.
//!
//! Stores a single bit per 4 KiB physical frame.  Initialised once from the
//! boot memory map.  All operations are guarded by a spinlock so they are
//! safe to call from interrupt context.

use ruzt_hal::boot::{BootInfo, MemoryRegionKind};
use ruzt_hal::mem::{FrameAllocator, PhysAddr, PhysFrame};
use spin::{Mutex, Once};

/// Size of a physical frame in bytes.
const FRAME_SIZE: usize = PhysFrame::SIZE;

/// Maximum number of frames we can track.  4 M frames = 16 GiB of RAM.
const MAX_FRAMES: usize = 4 * 1024 * 1024;

/// Number of `u64` words in the bitmap.
const BITMAP_WORDS: usize = MAX_FRAMES / 64;

/// 0 bit = free, 1 bit = allocated.
pub struct BitmapAllocator {
    bitmap: [u64; BITMAP_WORDS],
    // Lower bound for the first free frame.
    next_hint: usize,
    max_frame: usize,
}

impl BitmapAllocator {
    const fn new() -> Self {
        Self {
            bitmap: [0u64; BITMAP_WORDS],
            next_hint: 0,
            max_frame: 0,
        }
    }

    /// Reset the allocator and mark only [`MemoryRegionKind::Usable`] frames as free.
    fn init(&mut self, boot_info: &BootInfo) {
        self.bitmap.fill(u64::MAX);
        self.next_hint = 0;
        self.max_frame = 0;

        for region in boot_info.memory_map {
            if matches!(region.kind, MemoryRegionKind::Usable) {
                let start = region.start.as_u64().div_ceil(FRAME_SIZE as u64);
                let end = (region.end.as_u64() / FRAME_SIZE as u64).min(MAX_FRAMES as u64);
                if start >= end {
                    continue;
                }
                let (start, end) = (start as usize, end as usize);

                for frame in start..end {
                    let word = frame / 64;
                    let bit = frame % 64;
                    self.bitmap[word] &= !(1 << bit);
                }

                if end > self.max_frame {
                    self.max_frame = end;
                }
            }
        }
    }

    /// Is the given frame index currently free?
    fn is_free(&self, frame: usize) -> bool {
        let word = frame / 64;
        let bit = frame % 64;
        (self.bitmap[word] & (1 << bit)) == 0
    }

    /// Mark a specific frame as allocated.
    fn alloc_specific(&mut self, frame: usize) {
        let word = frame / 64;
        let bit = frame % 64;
        self.bitmap[word] |= 1 << bit;
    }

    /// Mark a specific frame as free.
    fn free_specific(&mut self, frame: usize) {
        let word = frame / 64;
        let bit = frame % 64;
        self.bitmap[word] &= !(1 << bit);
    }

    /// Find a run respecting an alignment expressed as a power of two in frames.
    fn allocate_run(&mut self, count: usize, alignment: usize) -> Option<PhysFrame> {
        debug_assert!(alignment.is_power_of_two() && alignment <= MAX_FRAMES);
        if count == 0 {
            return None;
        }

        let last_start = self.max_frame.checked_sub(count)?;
        let mut start = self.next_hint.next_multiple_of(alignment);
        while start <= last_start {
            let end = start + count;
            if let Some(used) = (start..end).find(|&frame| !self.is_free(frame)) {
                // Every start through this occupied frame would intersect it.
                start = (used + 1).next_multiple_of(alignment);
                continue;
            }

            for frame in start..end {
                self.alloc_specific(frame);
            }
            // A skipped prefix may contain smaller free runs.
            if self.next_hint == start {
                self.next_hint = end;
            }
            return PhysFrame::from_base(PhysAddr::new((start * FRAME_SIZE) as u64));
        }

        None
    }
}

impl FrameAllocator for BitmapAllocator {
    fn allocate(&mut self) -> Option<PhysFrame> {
        let start_word = self.next_hint / 64;

        for word in start_word..BITMAP_WORDS {
            if self.bitmap[word] != u64::MAX {
                let inv = !self.bitmap[word];
                let bit = inv.trailing_zeros() as usize;
                let frame = word * 64 + bit;

                if frame >= self.max_frame {
                    return None;
                }

                self.bitmap[word] |= 1 << bit;
                self.next_hint = frame + 1;

                return PhysFrame::from_base(PhysAddr::new((frame * FRAME_SIZE) as u64));
            }
        }

        None
    }

    fn allocate_contiguous(&mut self, count: usize) -> Option<PhysFrame> {
        self.allocate_run(count, 1)
    }

    fn deallocate(&mut self, frame: PhysFrame) {
        let idx = (frame.base.as_u64() as usize) / FRAME_SIZE;
        self.free_specific(idx);
        if idx < self.next_hint {
            self.next_hint = idx;
        }
    }
}

/// Global allocator instance.
static ALLOCATOR: Mutex<BitmapAllocator> = Mutex::new(BitmapAllocator::new());

/// Ensure `init` runs at most once.
static INIT: Once = Once::new();

/// Initialise the global frame allocator from the boot memory map.
///
/// Must be called exactly once before any allocation.
pub fn init(boot_info: &BootInfo) {
    INIT.call_once(|| {
        ALLOCATOR.lock().init(boot_info);
    });
}

/// Allocate a single 4 KiB physical frame.
pub fn allocate() -> Option<PhysFrame> {
    ALLOCATOR.lock().allocate()
}

/// Allocate `count` physically contiguous 4 KiB frames.
pub fn allocate_contiguous(count: usize) -> Option<PhysFrame> {
    ALLOCATOR.lock().allocate_contiguous(count)
}

/// Reserve a physically contiguous, naturally aligned range for an Untyped budget.
pub(crate) fn allocate_untyped(count: usize) -> Option<PhysFrame> {
    assert!(count.is_power_of_two() && count <= MAX_FRAMES);
    ALLOCATOR.lock().allocate_run(count, count)
}

/// Release a contiguous range previously reserved by the frame allocator.
pub(crate) fn deallocate_contiguous(base: PhysFrame, count: usize) {
    let mut allocator = ALLOCATOR.lock();
    let start = base.base.as_u64() as usize / FRAME_SIZE;
    for frame in start..start + count {
        allocator.free_specific(frame);
    }
    allocator.next_hint = allocator.next_hint.min(start);
}

/// Deallocate a previously allocated frame.
pub fn deallocate(frame: PhysFrame) {
    ALLOCATOR.lock().deallocate(frame);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruzt_hal::boot::{MemoryRegion, MemoryRegionKind};

    /// Build a fake [`BootInfo`] backed by a static region array.
    fn boot_info_from(regions: &'static [MemoryRegion]) -> BootInfo {
        BootInfo {
            framebuffer: None,
            memory_map: regions,
            firmware_tables: ruzt_hal::boot::FirmwareTables::None,
            initrd: None,
            physical_memory_offset: None,
        }
    }

    #[test]
    fn allocate_returns_distinct_frames() {
        static REGIONS: [MemoryRegion; 1] = [MemoryRegion {
            start: PhysAddr::new(0x0010_0000),
            end: PhysAddr::new(0x0020_0000),
            kind: MemoryRegionKind::Usable,
        }];
        let info = boot_info_from(&REGIONS);

        let mut a = BitmapAllocator::new();
        a.init(&info);

        let f1 = a.allocate().expect("first allocate should succeed");
        let f2 = a.allocate().expect("second allocate should succeed");
        assert_ne!(f1.base.as_u64(), f2.base.as_u64());
    }

    #[test]
    fn deallocate_makes_frame_reusable() {
        static REGIONS: [MemoryRegion; 1] = [MemoryRegion {
            start: PhysAddr::new(0x0010_0000),
            end: PhysAddr::new(0x0010_1000),
            kind: MemoryRegionKind::Usable,
        }];
        let info = boot_info_from(&REGIONS);

        let mut a = BitmapAllocator::new();
        a.init(&info);

        let f = a.allocate().expect("should allocate the single frame");
        assert!(a.allocate().is_none(), "no frames left");

        a.deallocate(f);
        let f2 = a.allocate().expect("deallocated frame should be reusable");
        assert_eq!(f.base.as_u64(), f2.base.as_u64());
    }

    #[test]
    fn allocate_past_capacity_returns_none() {
        static REGIONS: [MemoryRegion; 1] = [MemoryRegion {
            start: PhysAddr::new(0x0010_0000),
            end: PhysAddr::new(0x0010_2000),
            kind: MemoryRegionKind::Usable,
        }];
        let info = boot_info_from(&REGIONS);

        let mut a = BitmapAllocator::new();
        a.init(&info);

        let _ = a.allocate().expect("first");
        assert!(a.allocate_contiguous(usize::MAX).is_none());
        let _ = a.allocate().expect("second");
        assert!(a.allocate().is_none(), "third allocate should fail (only 2 frames)");
    }

    #[test]
    fn contiguous_allocation_succeeds_when_space_exists() {
        static REGIONS: [MemoryRegion; 1] = [MemoryRegion {
            start: PhysAddr::new(0x0010_0000),
            end: PhysAddr::new(0x0010_4000),
            kind: MemoryRegionKind::Usable,
        }];
        let info = boot_info_from(&REGIONS);

        let mut a = BitmapAllocator::new();
        a.init(&info);

        let base = a.allocate_contiguous(2).expect("should allocate 2 contiguous frames");
        assert_eq!(base.base.as_u64(), 0x0010_0000);
    }

    #[test]
    fn contiguous_allocation_fails_when_fragmented() {
        static REGIONS: [MemoryRegion; 1] = [MemoryRegion {
            start: PhysAddr::new(0x0010_0000),
            end: PhysAddr::new(0x0010_3000),
            kind: MemoryRegionKind::Usable,
        }];
        let info = boot_info_from(&REGIONS);

        let mut a = BitmapAllocator::new();
        a.init(&info);

        // Allocate every other frame to fragment the region
        let f0 = a.allocate().unwrap();
        let _ = a.allocate().unwrap(); // f1
        a.deallocate(f0); // free f0, but f1 is still allocated

        assert!(
            a.allocate_contiguous(2).is_none(),
            "should fail when no 2 contiguous free frames exist"
        );
    }

    #[test]
    fn contiguous_allocation_preserves_smaller_free_runs() {
        static REGIONS: [MemoryRegion; 2] = [
            MemoryRegion {
                start: PhysAddr::new(0x0010_0000),
                end: PhysAddr::new(0x0010_2000),
                kind: MemoryRegionKind::Usable,
            },
            MemoryRegion {
                start: PhysAddr::new(0x0014_0000),
                end: PhysAddr::new(0x0014_4000),
                kind: MemoryRegionKind::Usable,
            },
        ];
        let mut allocator = BitmapAllocator::new();
        allocator.init(&boot_info_from(&REGIONS));

        let large = allocator.allocate_contiguous(4).unwrap();
        let small = allocator.allocate_contiguous(2).unwrap();
        assert_eq!(large.base.as_u64(), 0x0014_0000);
        assert_eq!(small.base.as_u64(), 0x0010_0000);
        assert!(allocator.allocate().is_none());
    }

    #[test]
    fn only_whole_usable_frames_are_allocated() {
        static REGIONS: [MemoryRegion; 1] = [MemoryRegion {
            start: PhysAddr::new(0x0010_0001),
            end: PhysAddr::new(0x0010_2fff),
            kind: MemoryRegionKind::Usable,
        }];
        let mut allocator = BitmapAllocator::new();
        allocator.init(&boot_info_from(&REGIONS));

        assert_eq!(allocator.allocate().unwrap().base.as_u64(), 0x0010_1000);
        assert!(allocator.allocate().is_none());
    }

    #[test]
    fn aligned_run_leaves_preceding_pages_available() {
        static REGIONS: [MemoryRegion; 1] = [MemoryRegion {
            start: PhysAddr::new(0x0010_1000),
            end: PhysAddr::new(0x0010_4000),
            kind: MemoryRegionKind::Usable,
        }];
        let mut allocator = BitmapAllocator::new();
        allocator.init(&boot_info_from(&REGIONS));

        let base = allocator.allocate_run(2, 2).unwrap();
        assert_eq!(base.base.as_u64(), 0x0010_2000);
        assert_eq!(allocator.allocate().unwrap().base.as_u64(), 0x0010_1000);
        assert!(allocator.allocate().is_none());
    }
}
