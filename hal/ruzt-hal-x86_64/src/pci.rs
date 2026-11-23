//! Legacy PCI configuration mechanism one.

use x86_64::instructions::port::{Port, PortWriteOnly};

const CONFIG_ADDRESS: u16 = 0xcf8;
const CONFIG_DATA: u16 = 0xcfc;
const COMMAND: u8 = 4;
const MEMORY_DECODE: u16 = 1 << 1;
const BUS_MASTER: u16 = 1 << 2;

/// Number of BAR slots in an endpoint's PCI configuration header.
pub const BAR_COUNT: usize = 6;

/// A firmware-programmed PCI memory BAR.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryBar {
    /// First physical byte decoded by the PCI device.
    pub base: u64,
    /// Size in bytes, as obtained from the BAR mask.
    pub bytes: u64,
}

fn select(function: u16, offset: u8) {
    let address = 0x8000_0000 | (u32::from(function) << 8) | u32::from(offset & !3);
    // SAFETY: This port selects a PCI configuration dword for CONFIG_DATA.
    unsafe { PortWriteOnly::<u32>::new(CONFIG_ADDRESS).write(address) };
}

/// Read one PCI configuration dword from a packed bus/device/function address.
///
/// # Safety
/// The platform must support mechanism one and the caller must serialize all
/// accesses to the configuration address and data ports.
pub unsafe fn read_config(function: u16, offset: u8) -> u32 {
    select(function, offset);
    // SAFETY: CONFIG_ADDRESS selected this configuration dword.
    unsafe { Port::<u32>::new(CONFIG_DATA).read() }
}

fn write_config(function: u16, offset: u8, value: u32) {
    select(function, offset);
    // SAFETY: CONFIG_ADDRESS selected this configuration dword.
    unsafe { PortWriteOnly::<u32>::new(CONFIG_DATA).write(value) };
}

fn write_command(function: u16, value: u16) {
    select(function, COMMAND);
    // SAFETY: A word write changes PCI_COMMAND without touching the
    // write-one-to-clear PCI_STATUS register in the upper half.
    unsafe { PortWriteOnly::<u16>::new(CONFIG_DATA).write(value) };
}

/// Set or clear bus mastering on a PCI function.
///
/// # Safety
/// The caller holds the function exclusively, serializes configuration
/// access, and has active DMA isolation for the requester before enabling it.
pub unsafe fn set_bus_master(function: u16, enabled: bool) -> bool {
    // SAFETY: The caller serializes PCI configuration accesses.
    let command = unsafe { read_config(function, COMMAND) } as u16;
    let command = if enabled {
        command | BUS_MASTER
    } else {
        command & !BUS_MASTER
    };
    write_command(function, command);
    // SAFETY: The caller still owns this serialized transaction.
    let actual = unsafe { read_config(function, COMMAND) };
    actual != u32::MAX && (actual as u16 & BUS_MASTER != 0) == enabled
}

/// Size assigned memory BARs while the endpoint's memory decode is disabled.
///
/// If `allow_handoff` is true, an endpoint may arrive with bus mastering
/// enabled by firmware. The probe clears it and verifies that both memory
/// decode and bus mastering are off before writing any BARs. It restores
/// the BARs and the other command bits before returning.
///
/// # Safety
/// Mechanism one must be present, configuration operations must be
/// serialized, and no driver may be using this PCI function.
/// Allow a handoff only while a draining IOMMU denies DMA from the endpoint.
pub unsafe fn probe_bars(
    function: u16,
    allow_handoff: bool,
) -> Option<[Option<MemoryBar>; BAR_COUNT]> {
    // SAFETY: The caller serializes the entire probe including these reads.
    let read = |offset| unsafe { read_config(function, offset) };
    if read(0) as u16 == u16::MAX || (read(0x0c) >> 16) as u8 & 0x7f != 0 {
        return None;
    }
    let command = read(COMMAND);
    if command == u32::MAX
        || command as u16 & MEMORY_DECODE == 0
        || (!allow_handoff && command as u16 & BUS_MASTER != 0)
    {
        return None;
    }
    let command = command as u16 & !BUS_MASTER;
    write_command(function, command & !MEMORY_DECODE);
    if read(COMMAND) as u16 & (MEMORY_DECODE | BUS_MASTER) != 0 {
        write_command(function, command);
        return None;
    }
    let mut bars = [None; BAR_COUNT];
    let mut index = 0;
    while index < BAR_COUNT {
        let offset = 0x10 + index as u8 * 4;
        let low = read(offset);
        let kind = low & 0x7;
        if kind == 0 {
            write_config(function, offset, u32::MAX);
            let mask = read(offset);
            write_config(function, offset, low);
            bars[index] = decode_bar(u64::from(low), u64::from(mask) | 0xffff_ffff_0000_0000);
        } else if kind == 4 && index + 1 < BAR_COUNT {
            let upper_offset = offset + 4;
            let high = read(upper_offset);
            write_config(function, offset, u32::MAX);
            write_config(function, upper_offset, u32::MAX);
            let mask = (u64::from(read(upper_offset)) << 32) | u64::from(read(offset));
            write_config(function, upper_offset, high);
            write_config(function, offset, low);
            bars[index] = decode_bar((u64::from(high) << 32) | u64::from(low), mask);
            index += 1;
        }
        index += 1;
    }
    write_command(function, command);
    (read(COMMAND) as u16 & (MEMORY_DECODE | BUS_MASTER) == MEMORY_DECODE).then_some(bars)
}

fn decode_bar(base: u64, mask: u64) -> Option<MemoryBar> {
    let base = base & !0xf;
    let bytes = (!(mask & !0xf)).checked_add(1)?;
    if base == 0 || !bytes.is_power_of_two() || base % bytes != 0 {
        return None;
    }
    // A conforming BAR returns the canonical contiguous address mask.
    if (mask & !0xf) != !(bytes - 1) {
        return None;
    }
    Some(MemoryBar { base, bytes })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_32_and_64_bit_bars_and_rejects_invalid_masks() {
        assert_eq!(
            decode_bar(0xfea0_0000, 0xffff_ffff_fff0_0000),
            Some(MemoryBar {
                base: 0xfea0_0000,
                bytes: 0x10_0000
            })
        );
        assert_eq!(
            decode_bar(0x1_0000_000c, 0xffff_ffff_ffff_c00c),
            Some(MemoryBar {
                base: 0x1_0000_0000,
                bytes: 0x4000
            })
        );
        assert_eq!(decode_bar(0, u64::MAX), None);
        assert_eq!(decode_bar(0xfea0_0010, 0xffff_ffff_fff0_0000), None);
        assert_eq!(decode_bar(0xfea0_0000, 0xffff_ffef_fff0_0000), None);
    }
}
