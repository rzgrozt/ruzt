//! Memory management types and traits.
//!
//! SOURCE: Design Report §7.2 — "Memory management"

use bitflags::bitflags;

/// A 64-bit physical address.
// SOURCE: Design Report §7.2 — "Physical frame allocator"
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(transparent)]
pub struct PhysAddr(u64);

impl PhysAddr {
    /// Create a new physical address.
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }
    /// Return the raw u64 value.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
    /// Align down to a 4 KiB boundary.
    // SOURCE: Design Report §7.2(a) — "granule is 4 KiB"
    pub const fn align_down_4k(self) -> Self {
        Self(self.0 & !0xFFF)
    }
    /// Check that the address is 4 KiB aligned.
    pub const fn is_aligned_4k(self) -> bool {
        self.0 & 0xFFF == 0
    }
}

/// A 64-bit virtual address.
// SOURCE: Design Report §7.2(b) — "Virtual memory"
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(transparent)]
pub struct VirtAddr(u64);

impl VirtAddr {
    /// Create a new virtual address.
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }
    /// Return the raw u64 value.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// A 4 KiB-aligned physical memory frame.
// SOURCE: Design Report §7.2(a) — "granule is 4 KiB; standardize on 4 KiB"
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct PhysFrame {
    /// The base physical address of this frame (always 4 KiB aligned).
    pub base: PhysAddr,
}

impl PhysFrame {
    /// The size of a single frame in bytes.
    pub const SIZE: usize = 4096;

    /// Create a `PhysFrame` from a 4 KiB-aligned address.
    /// Returns `None` if the address is not aligned.
    pub fn from_base(addr: PhysAddr) -> Option<Self> {
        if addr.is_aligned_4k() {
            Some(Self { base: addr })
        } else {
            None
        }
    }
}

bitflags! {
    /// Page table entry flags for virtual memory mappings.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PageFlags: u64 {
        /// Page is mapped and accessible.
        const PRESENT       = 1 << 0;
        /// Page is writable. Must NOT be combined with EXECUTABLE (W^X).
        const WRITABLE      = 1 << 1;
        /// Page is accessible from user space (ring 3).
        const USER          = 1 << 2;
        /// Page is executable. Must NOT be combined with WRITABLE (W^X).
        const EXECUTABLE    = 1 << 3;
        /// Disable caching (write-through/uncacheable for MMIO).
        const NOCACHE       = 1 << 4;
        /// Write-through caching policy.
        const WRITETHROUGH  = 1 << 5;
        /// Mark page as "sensitive" — kernel zeroes on free (key material, passwords).
        // SOURCE: Design Report §10.3 — "Sensitive flag — kernel zeros on free"
        const SENSITIVE     = 1 << 6;
    }
}

/// Errors returned by [`Mapper::map`].
// SOURCE: Design Report §7.2(b) — AddressSpace::map W^X check
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapError {
    /// Caller requested both WRITABLE and EXECUTABLE (W^X violation).
    WriteExecute,
    /// A mapping already exists at the given virtual address.
    AlreadyMapped,
    /// The frame allocator could not provide a frame for a page table node.
    FrameAllocationFailed,
    /// The virtual or physical address is not 4 KiB aligned.
    InvalidAlignment,
}

/// Allocates and deallocates physical memory frames.
// SOURCE: Design Report §7.2(a) — "Physical frame allocator" — three methods
pub trait FrameAllocator {
    /// Allocate a single 4 KiB frame. Returns `None` if out of memory.
    fn allocate(&mut self) -> Option<PhysFrame>;
    /// Allocate `count` physically contiguous frames.
    /// Returns the base frame or `None`.
    // SOURCE: Design Report §7.2(a) — "buddy allocator for contiguous-frame requests (DMA)"
    fn allocate_contiguous(&mut self, count: usize) -> Option<PhysFrame>;
    /// Return a previously allocated frame to the free pool.
    fn deallocate(&mut self, frame: PhysFrame);
}

/// Maps, unmaps, and queries the virtual address space.
// SOURCE: Design Report §7.2(b) — Mapper trait (exact signatures)
pub trait Mapper {
    /// Map `virt` to `phys` with `flags`.
    ///
    /// # Contract
    /// Enforces W^X: returns [`Err(MapError::WriteExecute)`] if both
    /// [`WRITABLE`](PageFlags::WRITABLE) and [`EXECUTABLE`](PageFlags::EXECUTABLE)
    /// are set.
    // SOURCE: Design Report §7.2(b) — AddressSpace::map W^X check
    fn map(
        &mut self,
        virt: VirtAddr,
        phys: PhysFrame,
        flags: PageFlags,
    ) -> Result<(), MapError>;
    /// Remove the mapping at `virt`. Returns the physical frame that was mapped.
    fn unmap(&mut self, virt: VirtAddr) -> Result<PhysFrame, MapError>;
    /// Translate a virtual address to its physical address, or `None` if unmapped.
    fn translate(&self, virt: VirtAddr) -> Option<PhysAddr>;
    /// Invalidate the TLB entry for `virt` on the local CPU.
    // SOURCE: Design Report §7.2(b) — "local TLB invalidate"
    fn flush(&mut self, virt: VirtAddr);
    /// Broadcast a TLB invalidation for `virt` to all CPUs (IPI / DSB+TLBI).
    // SOURCE: Design Report §7.2(b) — "IPI / DSB+TLBI broadcast"
    fn flush_all_smp(&mut self);
}
