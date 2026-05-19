//! Boot info normalisation for aarch64 — stubbed for Phase 6.
//!
//! Constructs a minimal [`BootInfo`] for QEMU virt machine.

use core::mem::MaybeUninit;
use ruzt_hal::boot::{
    BootInfo, BootInfoSource, FirmwareTables, MemoryRegion, MemoryRegionKind,
};
use ruzt_hal::mem::PhysAddr;

const MAX_REGIONS: usize = 256;

static mut NORMALIZED_REGIONS: [MemoryRegion; MAX_REGIONS] =
    [MemoryRegion {
        start: PhysAddr::new(0),
        end: PhysAddr::new(0),
        kind: MemoryRegionKind::Unknown(0),
    }; MAX_REGIONS];

static mut REGION_COUNT: usize = 0;
static mut NORMALIZED_BOOT_INFO: MaybeUninit<BootInfo> = MaybeUninit::uninit();

/// Construct a minimal BootInfo for QEMU virt machine.
///
/// Memory map: one usable region from 0x4000_0000 to 0x4800_0000 (128 MiB DRAM).
/// Framebuffer: None (serial-only for now).
/// Firmware tables: FirmwareTables::None.
/// initrd: None.
/// physical_memory_offset: None (not identity-mapped by bootloader on aarch64).
#[allow(static_mut_refs)]
pub fn boot_from_uefi() {
    unsafe {
        NORMALIZED_REGIONS[0] = MemoryRegion {
            start: PhysAddr::new(0x4000_0000),
            end: PhysAddr::new(0x4800_0000),
            kind: MemoryRegionKind::Usable,
        };
        REGION_COUNT = 1;

        NORMALIZED_BOOT_INFO.write(BootInfo {
            framebuffer: None,
            memory_map: core::slice::from_raw_parts(
                &NORMALIZED_REGIONS[0],
                REGION_COUNT,
            ),
            firmware_tables: FirmwareTables::None,
            initrd: None,
            physical_memory_offset: None,
        });
    }
}

/// aarch64 implementation of [`BootInfoSource`] — stubbed for Phase 6.
pub struct AArch64BootInfoSource;

impl BootInfoSource for AArch64BootInfoSource {
    #[allow(static_mut_refs)]
    fn build() -> &'static BootInfo {
        unsafe { NORMALIZED_BOOT_INFO.assume_init_ref() }
    }
}
