//! PCI MSI configuration under an exclusive function lease.

use super::{read_config, write_command, write_config, write_word, COMMAND};

const CAP_LIST: u32 = 1 << 20;
const INTX_DISABLE: u16 = 1 << 10;
const MSI: u8 = 5;
const MSIX: u8 = 0x11;
const ENABLE: u16 = 1;
const MULTI_MESSAGE_ENABLE: u16 = 7 << 4;
const ADDRESS_64: u16 = 1 << 7;
const PER_VECTOR_MASK: u16 = 1 << 8;
const MSIX_ENABLE: u16 = 1 << 15;

/// The single-message MSI configuration of one exclusive PCI function.
#[derive(Clone, Copy)]
pub struct Msi {
    function: u16,
    offset: u8,
    control: u16,
    intx_disabled: bool,
}

impl Msi {
    /// Find an inactive MSI capability on a type-zero PCI function.
    ///
    /// # Safety
    /// The caller owns the function and serializes configuration transactions.
    pub unsafe fn inspect(function: u16) -> Option<Self> {
        // SAFETY: The caller serializes this capability walk.
        let read = |offset| unsafe { read_config(function, offset) };
        let command = read(COMMAND);
        if command == u32::MAX || command & CAP_LIST == 0 || (read(0x0c) >> 16) as u8 & 0x7f != 0 {
            return None;
        }
        let (offset, control) = find_msi(read)?;
        Some(Self {
            function,
            offset,
            control,
            intx_disabled: command as u16 & INTX_DISABLE != 0,
        })
    }

    pub(crate) fn function(self) -> u16 {
        self.function
    }

    pub(crate) fn program(self, address: u32) -> bool {
        // The endpoint will use remapped message data zero. It remains
        // disabled until a driver binds the corresponding IRQ capability.
        if !self.set_enabled(false) || !self.set_intx_disabled(true) {
            return false;
        }
        write_config(self.function, self.offset + 4, address);
        let data = self.data_offset();
        if self.control & ADDRESS_64 != 0 {
            write_config(self.function, self.offset + 8, 0);
        }
        write_word(self.function, data, 0);
        if self.control & PER_VECTOR_MASK != 0 {
            let mask = data + 4;
            write_config(self.function, mask, self.read(mask) & !1);
        }
        self.read(self.offset + 4) == address
            && (self.control & ADDRESS_64 == 0 || self.read(self.offset + 8) == 0)
            && self.read(data) as u16 == 0
    }

    pub(crate) fn set_enabled(self, enabled: bool) -> bool {
        let control = (self.control & !(ENABLE | MULTI_MESSAGE_ENABLE)) | u16::from(enabled);
        write_word(self.function, self.offset + 2, control);
        let actual = self.read(self.offset);
        actual as u8 == MSI
            && ((actual >> 16) as u16 & (ENABLE | MULTI_MESSAGE_ENABLE)) == u16::from(enabled)
    }

    pub(crate) fn restore_intx(self) -> bool {
        self.set_intx_disabled(self.intx_disabled)
    }

    fn set_intx_disabled(self, disabled: bool) -> bool {
        let command = self.read(COMMAND);
        if command == u32::MAX {
            return false;
        }
        let command = (command as u16 & !INTX_DISABLE) | (u16::from(disabled) << 10);
        write_command(self.function, command);
        let actual = self.read(COMMAND);
        actual != u32::MAX && (actual as u16 & INTX_DISABLE != 0) == disabled
    }

    fn data_offset(self) -> u8 {
        self.offset
            + if self.control & ADDRESS_64 != 0 {
                12
            } else {
                8
            }
    }

    fn read(self, offset: u8) -> u32 {
        // SAFETY: All accesses are serialized while the live PCI lease owns this function.
        unsafe { read_config(self.function, offset) }
    }
}

fn find_msi(read: impl Fn(u8) -> u32) -> Option<(u8, u16)> {
    let mut offset = read(0x34) as u8;
    let mut seen = 0u64;
    let mut msi = None;
    let mut has_msix = false;
    while offset != 0 {
        if offset < 0x40 || offset % 4 != 0 || seen & (1u64 << (offset / 4)) != 0 {
            return None;
        }
        seen |= 1u64 << (offset / 4);
        let header = read(offset);
        let control = (header >> 16) as u16;
        match header as u8 {
            MSI => {
                if msi.is_some() || control & ENABLE != 0 {
                    return None;
                }
                let bytes = 10
                    + if control & ADDRESS_64 != 0 { 4 } else { 0 }
                    + if control & PER_VECTOR_MASK != 0 {
                        10
                    } else {
                        0
                    };
                if usize::from(offset) + bytes > 256 {
                    return None;
                }
                msi = Some((offset, control));
            }
            MSIX if has_msix || control & MSIX_ENABLE != 0 => return None,
            MSIX => has_msix = true,
            0xff => return None,
            _ => {}
        }
        offset = (header >> 8) as u8;
    }
    let (offset, control) = msi?;
    // A malformed list can link another capability inside the MSI body.
    let words = 3
        + u32::from(control & ADDRESS_64 != 0)
        + if control & PER_VECTOR_MASK != 0 { 2 } else { 0 };
    let covered = ((1u64 << words) - 2) << (offset / 4);
    (seen & covered == 0).then_some((offset, control))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_the_capability_walk_and_rejects_active_or_overlapping_entries() {
        let mut registers = [0; 64];
        registers[0x34 / 4] = 0x40;
        registers[0x40 / 4] = u32::from(MSI) | 0x60 << 8 | u32::from(ADDRESS_64) << 16;
        registers[0x60 / 4] = u32::from(MSIX);
        let inspect = |config: &[u32; 64]| find_msi(|reg| config[usize::from(reg / 4)]);
        assert_eq!(inspect(&registers), Some((0x40, ADDRESS_64)));
        registers[0x60 / 4] |= u32::from(MSIX_ENABLE) << 16;
        assert_eq!(inspect(&registers), None);
        registers[0x60 / 4] = 0x40 << 8;
        assert_eq!(inspect(&registers), None);
        registers[0x40 / 4] ^= (0x60 ^ 0x48) << 8;
        assert_eq!(inspect(&registers), None);
        registers[0x34 / 4] = 0xfc;
        registers[0xfc / 4] = u32::from(MSI);
        assert_eq!(inspect(&registers), None);
    }
}
