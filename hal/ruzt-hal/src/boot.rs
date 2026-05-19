//! Normalized boot info types.
//!
//! The kernel receives these regardless of architecture or bootloader.
//! SOURCE: Design Report §6 — BootInfo struct

/// Pixel color channel layout for the linear framebuffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PixelFormat {
    /// Red, Green, Blue — one byte each.
    Rgb,
    /// Blue, Green, Red — one byte each.
    Bgr,
    /// Single byte grayscale.
    U8,
    /// Packed with caller-specified byte positions.
    Unknown {
        /// Bit position of the red channel within a pixel.
        red_position: u8,
        /// Bit position of the green channel within a pixel.
        green_position: u8,
        /// Bit position of the blue channel within a pixel.
        blue_position: u8,
    },
}

/// The linear framebuffer provided by the bootloader.
// SOURCE: Design Report §6 — "paint a brand-mark to the framebuffer"
pub struct Framebuffer {
    /// Raw pixel data. Length = stride * height bytes.
    pub buffer: &'static mut [u8],
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Bytes per row (may be larger than width * bytes_per_pixel due to padding).
    pub stride: u32,
    /// Pixel color channel layout.
    pub pixel_format: PixelFormat,
}

/// Classification of a memory region reported by the firmware/bootloader.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryRegionKind {
    /// Freely usable RAM.
    Usable,
    /// Reserved by firmware or hardware; must not be used.
    Reserved,
    /// ACPI reclaimable memory (usable after ACPI tables are parsed).
    AcpiReclaimable,
    /// ACPI non-volatile storage (must be preserved).
    AcpiNvs,
    /// Memory marked as bad / failed by firmware.
    BadMemory,
    /// Firmware / bootloader memory that can be reclaimed after boot.
    BootloaderReclaimable,
    /// Kernel image and associated modules.
    KernelAndModules,
    /// The framebuffer region.
    Framebuffer,
    /// An unrecognized region type from the firmware.
    Unknown(u64),
}

/// A contiguous region of physical memory.
#[derive(Clone, Copy, Debug)]
pub struct MemoryRegion {
    /// First byte of the region (physical address).
    pub start: crate::mem::PhysAddr,
    /// One byte past the last byte of the region (exclusive end).
    pub end: crate::mem::PhysAddr,
    /// Classification of this region.
    pub kind: MemoryRegionKind,
}

/// Firmware-provided tables: ACPI, Device Tree, or Apple Device Tree.
// SOURCE: Design Report §6 — "firmware_tables: FirmwareTables — ACPI, DTB, or ADT"
pub enum FirmwareTables {
    /// ACPI RSDP pointer.
    Acpi {
        /// Physical address of the RSDP structure.
        rsdp_addr: crate::mem::PhysAddr,
    },
    /// Flattened Device Tree blob.
    DeviceTree {
        /// Physical address of the DTB.
        dtb_addr: crate::mem::PhysAddr,
    },
    /// Apple Device Tree.
    AppleDeviceTree {
        /// Physical address of the ADT.
        adt_addr: crate::mem::PhysAddr,
    },
    /// No firmware tables were provided.
    None,
}

/// The normalized boot info the kernel's entry point receives.
///
/// The HAL backend is responsible for building this from the raw
/// bootloader output.
// SOURCE: Design Report §6 — BootInfo struct
pub struct BootInfo {
    /// The linear framebuffer, if one was provided.
    pub framebuffer: Option<Framebuffer>,
    /// The physical memory map.
    pub memory_map: &'static [MemoryRegion],
    /// Firmware tables (ACPI root pointer, DTB address, or ADT address).
    pub firmware_tables: FirmwareTables,
    /// Optional initial ramdisk.
    pub initrd: Option<&'static [u8]>,
    /// Offset added to a physical address to get the kernel's virtual view of it.
    ///
    /// Bootloader 0.11 maps physical memory at a dynamic offset; the kernel
    /// needs this to convert `PhysAddr` → `VirtAddr` without knowing the arch.
    pub physical_memory_offset: Option<u64>,
}

/// Implemented by the HAL backend to normalize raw bootloader output
/// into [`BootInfo`].
// SOURCE: Design Report §8 — BootInfoSource trait
pub trait BootInfoSource {
    /// Consume the raw bootloader handoff and produce the canonical [`BootInfo`].
    ///
    /// Called exactly once, at kernel entry, before any other HAL initialization.
    fn build() -> &'static BootInfo;
}
