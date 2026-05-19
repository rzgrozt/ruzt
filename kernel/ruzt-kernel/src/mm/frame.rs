//! Bitmap-based physical frame allocator.
//!
//! Stores a single bit per 4 KiB physical frame.  Initialised once from the
//! boot memory map.  All operations are guarded by a spinlock so they are
//! safe to call from interrupt context.

use ruzt_hal::boot::{BootInfo, MemoryRegionKind};
use ruzt_hal::mem::{FrameAllocator, PhysAddr, PhysFrame};
use spin::{Mutex, Once};

/// Size of a physical frame in bytes.
const FRAME_SIZE: usize = 4096;

/// Maximum number of frames we can track.  4 M frames = 16 GiB of RAM.
const MAX_FRAMES: usize = 4 * 1024 * 1024;

/// Number of `u64` words in the bitmap.
const BITMAP_WORDS: usize = MAX_FRAMES / 64;

/// 0 bit = free, 1 bit = allocated.
pub struct BitmapAllocator {
    bitmap: [u64; BITMAP_WORDS],
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
                let start = (region.start.as_u64() as usize) / FRAME_SIZE;
                let end = ((region.end.as_u64() as usize) / FRAME_SIZE).min(MAX_FRAMES);

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
        if count == 0 {
            return None;
        }

        for start in self.next_hint..self.max_frame {
            if start + count > self.max_frame {
                return None;
            }

            let mut all_free = true;
            for i in 0..count {
                if !self.is_free(start + i) {
                    all_free = false;
                    break;
                }
            }

            if all_free {
                for i in 0..count {
                    self.alloc_specific(start + i);
                }
                self.next_hint = start + count;
                return PhysFrame::from_base(PhysAddr::new((start * FRAME_SIZE) as u64));
            }
        }

        None
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
}
