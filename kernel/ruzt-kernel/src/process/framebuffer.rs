//! Boot framebuffer ownership transfer to the initial process.

use ruzt_abi::{FramebufferInfo, FRAMEBUFFER_BGR, FRAMEBUFFER_GRAY8, FRAMEBUFFER_RGB};
use ruzt_hal::boot::{Framebuffer, PixelFormat};
use ruzt_hal::mem::{MapError, Mapper, PageFlags, PhysFrame, VirtAddr};
use ruzt_hal_x86_64::mapper::X86_64Mapper;

const USER_FRAMEBUFFER_BASE: u64 = 0x1_0000_0000;
const PAGE_SIZE: usize = PhysFrame::SIZE;

pub(super) fn map(
    mapper: &mut X86_64Mapper,
    root: PhysFrame,
    framebuffer: Framebuffer,
) -> Result<Option<FramebufferInfo>, MapError> {
    let Some(info) = layout(&framebuffer) else {
        return Ok(None);
    };
    let kernel_address = framebuffer.buffer.as_ptr() as u64;
    let byte_len = info.byte_len as usize;
    if !kernel_address.is_multiple_of(PAGE_SIZE as u64) {
        return Err(MapError::InvalidAlignment);
    }

    for offset in (0..byte_len).step_by(PAGE_SIZE) {
        let phys = mapper
            .translate(VirtAddr::new(kernel_address + offset as u64))
            .and_then(PhysFrame::from_base)
            .ok_or(MapError::InvalidAlignment)?;
        let user_page = VirtAddr::new(info.address + offset as u64);
        #[allow(unsafe_code)]
        // SAFETY: The bootloader maps these device pages exclusively for the
        // framebuffer. The private root is inactive, and the kernel gives up
        // its mutable pixel slice before the initial process can run.
        unsafe {
            mapper.map_in_address_space(
                root,
                user_page,
                phys,
                PageFlags::USER | PageFlags::WRITABLE,
            )?;
        }
    }

    Ok(Some(info))
}

fn layout(framebuffer: &Framebuffer) -> Option<FramebufferInfo> {
    let bytes_per_pixel = u32::try_from(framebuffer.bytes_per_pixel).ok()?;
    let format = match framebuffer.pixel_format {
        PixelFormat::Rgb if bytes_per_pixel >= 3 => FRAMEBUFFER_RGB,
        PixelFormat::Bgr if bytes_per_pixel >= 3 => FRAMEBUFFER_BGR,
        PixelFormat::U8 if bytes_per_pixel == 1 => FRAMEBUFFER_GRAY8,
        _ => return None,
    };
    let pitch = framebuffer.stride.checked_mul(bytes_per_pixel)?;
    let byte_len = u64::from(pitch) * u64::from(framebuffer.height);
    if framebuffer.width == 0
        || framebuffer.height == 0
        || framebuffer.width > framebuffer.stride
        || byte_len > framebuffer.buffer.len() as u64
        || USER_FRAMEBUFFER_BASE.checked_add(byte_len)? >= 1 << 47
    {
        return None;
    }
    Some(FramebufferInfo {
        address: USER_FRAMEBUFFER_BASE,
        byte_len,
        width: framebuffer.width,
        height: framebuffer.height,
        pitch,
        bytes_per_pixel,
        format,
        reserved: 0,
    })
}
