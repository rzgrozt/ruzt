use ruzt_abi::{ErrorCode, FramebufferInfo, FRAMEBUFFER_BGR, FRAMEBUFFER_GRAY8, FRAMEBUFFER_RGB};

const SIDE: usize = 24;
const MARGIN: usize = 16;
const IDLE: [u8; 3] = [0x8a, 0xb4, 0xff];
const PRESSED: [u8; 3] = [0x7f, 0xe3, 0xc4];

pub(super) struct Tile {
    address: usize,
    pitch: usize,
    bytes_per_pixel: usize,
    format: u32,
    active: bool,
}

impl Tile {
    pub(super) fn from_capability(capability: u64) -> Result<Option<Self>, ErrorCode> {
        let info = ruzt_driver_sdk::framebuffer_info(capability)?;
        Ok(Self::new(info))
    }

    fn new(info: FramebufferInfo) -> Option<Self> {
        let width = info.width as usize;
        let height = info.height as usize;
        let pitch = info.pitch as usize;
        let bytes_per_pixel = info.bytes_per_pixel as usize;
        let address = usize::try_from(info.address).ok()?;
        let byte_len = usize::try_from(info.byte_len).ok()?;
        let supported = match info.format {
            FRAMEBUFFER_RGB | FRAMEBUFFER_BGR => bytes_per_pixel >= 3,
            FRAMEBUFFER_GRAY8 => bytes_per_pixel == 1,
            _ => false,
        };
        if !supported
            || address == 0
            || width < SIDE + MARGIN
            || height < SIDE + MARGIN
            || width.checked_mul(bytes_per_pixel)? > pitch
            || pitch.checked_mul(height)? > byte_len
        {
            return None;
        }
        address.checked_add(byte_len)?;

        let tile = Self {
            address: address + MARGIN * pitch + (width - MARGIN - SIDE) * bytes_per_pixel,
            pitch,
            bytes_per_pixel,
            format: info.format,
            active: false,
        };
        tile.draw();
        Some(tile)
    }

    pub(super) fn toggle(&mut self) {
        self.active = !self.active;
        self.draw();
    }

    fn draw(&self) {
        let [r, g, b] = if self.active { PRESSED } else { IDLE };
        let rgb = [r, g, b];
        let bgr = [b, g, r];
        let gray = [((u16::from(r) * 54 + u16::from(g) * 183 + u16::from(b) * 19) / 256) as u8];
        let pixel: &[u8] = match self.format {
            FRAMEBUFFER_RGB => &rgb,
            FRAMEBUFFER_BGR => &bgr,
            _ => &gray,
        };
        for y in 0..SIDE {
            for x in 0..SIDE {
                let start = self.address + y * self.pitch + x * self.bytes_per_pixel;
                for (offset, &byte) in pixel.iter().enumerate() {
                    let destination = core::ptr::without_provenance_mut(start + offset);
                    // SAFETY: The kernel granted a writable device mapping.
                    // Tile::new checked that every pixel fits in that mapping.
                    unsafe { core::ptr::write_volatile(destination, byte) };
                }
            }
        }
    }
}
