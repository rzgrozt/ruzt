//! Boot info normalisation — `bootloader_api::BootInfo` → `ruzt_hal::boot::BootInfo`.

use bootloader_api::info::PixelFormat as BlPixelFormat;
use core::mem::MaybeUninit;
use ruzt_hal::boot::{
    BootInfo, FirmwareTables, Framebuffer, MemoryRegion, MemoryRegionKind, PixelFormat,
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

/// Convert the bootloader memory region kind to our normalised kind.
fn convert_kind(kind: bootloader_api::info::MemoryRegionKind) -> MemoryRegionKind {
    use bootloader_api::info::MemoryRegionKind as BlKind;
    match kind {
        BlKind::Usable => MemoryRegionKind::Usable,
        BlKind::Bootloader => MemoryRegionKind::BootloaderReclaimable,
        BlKind::UnknownUefi(tag) => MemoryRegionKind::Unknown(tag as u64),
        BlKind::UnknownBios(tag) => MemoryRegionKind::Unknown(tag as u64),
        _ => MemoryRegionKind::Unknown(0),
    }
}

/// Convert the bootloader pixel format to our normalised pixel format.
fn convert_pixel_format(fmt: BlPixelFormat) -> PixelFormat {
    match fmt {
        BlPixelFormat::Rgb => PixelFormat::Rgb,
        BlPixelFormat::Bgr => PixelFormat::Bgr,
        BlPixelFormat::U8 => PixelFormat::U8,
        BlPixelFormat::Unknown {
            red_position,
            green_position,
            blue_position,
        } => PixelFormat::Unknown {
            red_position,
            green_position,
            blue_position,
        },
        _ => PixelFormat::Unknown {
            red_position: 0,
            green_position: 0,
            blue_position: 0,
        },
    }
}

/// Consume the raw bootloader `BootInfo` and produce a canonical `ruzt_hal::boot::BootInfo`
/// stored with `'static` lifetime.
///
/// # Safety
/// Must be called exactly once, at kernel entry, before any concurrent access.
#[allow(static_mut_refs)]
pub unsafe fn normalize(raw: &'static mut bootloader_api::BootInfo) -> &'static mut BootInfo {
    let count = raw.memory_regions.len().min(MAX_REGIONS);
    for (i, region) in raw.memory_regions.iter().enumerate().take(count) {
        unsafe {
            NORMALIZED_REGIONS[i] = MemoryRegion {
                start: PhysAddr::new(region.start),
                end: PhysAddr::new(region.end),
                kind: convert_kind(region.kind),
            };
        }
    }
    unsafe {
        REGION_COUNT = count;
    }

    let framebuffer = raw.framebuffer.as_mut().map(|fb| {
        let info = fb.info();
        let buffer = fb.buffer_mut();
        Framebuffer {
            buffer,
            width: info.width as u32,
            height: info.height as u32,
            stride: info.stride as u32,
            bytes_per_pixel: info.bytes_per_pixel,
            pixel_format: convert_pixel_format(info.pixel_format),
        }
    });

    let firmware_tables = match raw.rsdp_addr.into_option() {
        Some(addr) => FirmwareTables::Acpi {
            rsdp_addr: PhysAddr::new(addr),
        },
        None => FirmwareTables::None,
    };

    let initrd = match raw.ramdisk_addr.into_option() {
        Some(addr) if raw.ramdisk_len > 0 => unsafe {
            Some(core::slice::from_raw_parts(
                addr as *const u8,
                raw.ramdisk_len as usize,
            ))
        },
        _ => None,
    };

    let physical_memory_offset = raw.physical_memory_offset.into_option();

    unsafe {
        NORMALIZED_BOOT_INFO.write(BootInfo {
            framebuffer,
            memory_map: core::slice::from_raw_parts(
                &NORMALIZED_REGIONS[0],
                REGION_COUNT,
            ),
            firmware_tables,
            initrd,
            physical_memory_offset,
        });

        NORMALIZED_BOOT_INFO.assume_init_mut()
    }
}

use ruzt_hal::boot::BootInfoSource;

/// x86_64 implementation of [`BootInfoSource`].
pub struct X86_64BootInfoSource;

impl BootInfoSource for X86_64BootInfoSource {
    #[allow(static_mut_refs)]
    fn build() -> &'static BootInfo {
        // SAFETY: `normalize()` was called exactly once in `hal::init()`.
        unsafe { NORMALIZED_BOOT_INFO.assume_init_ref() }
    }
}


