//! Read-only PCI discovery. BAR probing and access control remain in the kernel.

use ruzt_abi::ErrorCode;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Region {
    pub bar: u8,
    pub offset: u64,
    pub bytes: u64,
}

impl Region {
    /// Select a bounded part, preserving the BAR-relative address.
    pub fn subrange(self, offset: u64, bytes: u64) -> Result<Self, ErrorCode> {
        if bytes == 0 || offset.checked_add(bytes).is_none_or(|end| end > self.bytes) {
            return Err(ErrorCode::BadMessage);
        }
        let offset = self
            .offset
            .checked_add(offset)
            .ok_or(ErrorCode::BadMessage)?;
        offset.checked_add(bytes).ok_or(ErrorCode::BadMessage)?;
        Ok(Self {
            offset,
            bytes,
            ..self
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capabilities {
    pub common: Region,
    pub notify: Region,
    pub device: Region,
    pub notify_multiplier: u32,
}

impl Capabilities {
    /// Read the conventional configuration header through one device lease.
    /// Reserved types/BARs are skipped and the first supported instance wins.
    pub fn read(
        mut read: impl FnMut(u8) -> Result<u32, ErrorCode>,
        device_type: u16,
    ) -> Result<Self, ErrorCode> {
        let device_id = 0x1040u16
            .checked_add(device_type)
            .ok_or(ErrorCode::BadMessage)?;
        if read(0)? != (u32::from(device_id) << 16 | 0x1af4)
            || read(4)? & (1 << 20) == 0
            || (read(12)? >> 16) & 0x7f != 0
        {
            return Err(ErrorCode::NotFound);
        }
        let mut next = read(0x34)? as u8;
        let mut visited = 0u64;
        let (mut common, mut notify, mut device) = (None, None, None);
        let mut multiplier = 0;
        while next != 0 {
            if next < 0x40 || !next.is_multiple_of(4) || visited & (1u64 << (next / 4)) != 0 {
                return Err(ErrorCode::BadMessage);
            }
            visited |= 1u64 << (next / 4);
            let header = read(next)?;
            let position = next;
            next = (header >> 8) as u8;
            if header as u8 != 9 {
                continue;
            }
            let length = (header >> 16) as u8;
            let kind = (header >> 24) as u8;
            if !(1..=4).contains(&kind) {
                continue;
            }
            if length < 16 || u16::from(position) + u16::from(length) > 256 {
                return Err(ErrorCode::BadMessage);
            }
            let bar = read(position + 4)? as u8;
            if bar >= 6 {
                continue;
            }
            let region = Region {
                bar,
                offset: u64::from(read(position + 8)?),
                bytes: u64::from(read(position + 12)?),
            };
            match kind {
                1 if common.is_none() && region.bytes >= 56 && region.offset.is_multiple_of(4) => {
                    common = Some(region)
                }
                2 if notify.is_none() && region.bytes >= 2 && region.offset.is_multiple_of(2) => {
                    if length < 20 {
                        return Err(ErrorCode::BadMessage);
                    }
                    multiplier = read(position + 16)?;
                    notify = Some(region);
                }
                4 if device.is_none() && region.bytes >= 8 && region.offset.is_multiple_of(4) => {
                    device = Some(region)
                }
                _ => {}
            }
        }
        Ok(Self {
            common: common.ok_or(ErrorCode::NotFound)?,
            notify: notify.ok_or(ErrorCode::NotFound)?,
            device: device.ok_or(ErrorCode::NotFound)?,
            notify_multiplier: multiplier,
        })
    }

    pub fn notification(self, queue_offset: u16) -> Result<Region, ErrorCode> {
        let offset = u64::from(queue_offset) * u64::from(self.notify_multiplier);
        let region = self.notify.subrange(offset, 2)?;
        if region.offset % 2 != 0 {
            return Err(ErrorCode::BadMessage);
        }
        Ok(region)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> [u32; 64] {
        let mut words = [0u32; 64];
        words[0] = 0x1042_1af4;
        words[1] = 1 << 20;
        words[0x34 / 4] = 0x40;
        for (at, next, len, kind, offset, bytes) in [
            (0x40, 0x50, 16, 1, 0, 4096),
            (0x50, 0x64, 20, 2, 12288, 4096),
            (0x64, 0, 16, 4, 8192, 4096),
        ] {
            words[at / 4] = 9 | next << 8 | len << 16 | kind << 24;
            words[at / 4 + 1] = 4;
            words[at / 4 + 2] = offset;
            words[at / 4 + 3] = bytes;
        }
        words[0x60 / 4] = 4;
        words
    }

    fn parse(words: &[u32; 64]) -> Result<Capabilities, ErrorCode> {
        Capabilities::read(|offset| Ok(words[usize::from(offset) / 4]), 2)
    }

    #[test]
    fn modern_regions_and_notification_are_bounded() {
        let caps = parse(&config()).unwrap();
        assert_eq!(caps.common.bar, 4);
        assert_eq!(
            caps.notification(3).unwrap(),
            Region {
                bar: 4,
                offset: 12300,
                bytes: 2
            }
        );
        assert_eq!(caps.notification(1024), Err(ErrorCode::BadMessage));
        assert_eq!(
            caps.common.subrange(u64::MAX, 2),
            Err(ErrorCode::BadMessage)
        );
    }

    #[test]
    fn malformed_chains_and_truncated_capabilities_are_rejected() {
        for (index, value) in [
            (0x34 / 4, 0x41),
            (0x34 / 4, 0x3c),
            (0x64 / 4, 9 | 0x40 << 8 | 16 << 16 | 4 << 24),
            (0x50 / 4, 9 | 0x64 << 8 | 16 << 16 | 2 << 24),
            (0x64 / 4, 9 | 255 << 16 | 4 << 24),
        ] {
            let mut words = config();
            words[index] = value;
            assert_eq!(parse(&words), Err(ErrorCode::BadMessage));
        }
        let mut words = config();
        words[0x44 / 4] = 6;
        assert_eq!(parse(&words), Err(ErrorCode::NotFound));
        words = config();
        words[0] = 0x1001_1af4;
        assert_eq!(parse(&words), Err(ErrorCode::NotFound));
    }
}
