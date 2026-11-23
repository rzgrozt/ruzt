//! Bounded reads of the firmware's ACPI system description tables.

use alloc::vec::Vec;
use ruzt_hal::boot::{MemoryRegion, MemoryRegionKind};
use ruzt_hal_x86_64::mapper;

const HEADER_BYTES: usize = 36;
const MAX_TABLE_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    InvalidTable,
    NoMemory,
}

pub(crate) struct Firmware {
    regions: &'static [MemoryRegion],
}

impl Firmware {
    pub(crate) fn new(regions: &'static [MemoryRegion]) -> Self {
        Self { regions }
    }

    pub(crate) fn find(&self, rsdp: u64, signature: [u8; 4]) -> Result<Option<Vec<u8>>, Error> {
        find(rsdp, signature, |address, bytes| self.read(address, bytes))
    }

    fn read(&self, address: u64, bytes: &mut [u8]) -> Result<(), Error> {
        let end = address
            .checked_add(bytes.len() as u64)
            .ok_or(Error::InvalidTable)?;
        let legacy_bios = (0x80000..0xa0000).contains(&address) && end <= 0xa0000
            || (0xe0000..0x100000).contains(&address) && end <= 0x100000;
        let reserved = self.regions.iter().any(|region| {
            region.start.as_u64() <= address && end <= region.end.as_u64()
                && (matches!(region.kind, MemoryRegionKind::AcpiReclaimable | MemoryRegionKind::AcpiNvs)
                    // SeaBIOS can report the ACPI table pool as ordinary
                    // reserved memory below the chipset aperture.
                    || region.kind == MemoryRegionKind::Reserved && end <= 0xfec0_0000)
        });
        let overlaps_usable = self.regions.iter().any(|region| {
            region.kind == MemoryRegionKind::Usable
                && address < region.end.as_u64()
                && region.start.as_u64() < end
        });
        if !(legacy_bios || reserved) || overlaps_usable || bytes.is_empty() {
            return Err(Error::InvalidTable);
        }
        let alias = mapper::with_mapper(|mapper| mapper.physmap_alias(address, bytes.len() as u64))
            .ok_or(Error::InvalidTable)?;
        #[allow(unsafe_code)]
        // SAFETY: Firmware-owned data lies in the validated direct-map range
        // and cannot be allocated or changed by the kernel during boot.
        unsafe {
            core::ptr::copy_nonoverlapping(
                alias.as_u64() as *const u8,
                bytes.as_mut_ptr(),
                bytes.len(),
            )
        };
        Ok(())
    }
}

fn find(
    rsdp: u64,
    signature: [u8; 4],
    mut read: impl FnMut(u64, &mut [u8]) -> Result<(), Error>,
) -> Result<Option<Vec<u8>>, Error> {
    let mut legacy = [0; 20];
    read(rsdp, &mut legacy)?;
    if &legacy[..8] != b"RSD PTR " || !checksum_ok(&legacy) {
        return Err(Error::InvalidTable);
    }
    let mut root = (u64::from(dword(&legacy[16..])), *b"RSDT", 4);
    if legacy[15] >= 2 {
        let mut extended = [0; 36];
        read(rsdp, &mut extended)?;
        let length = dword(&extended[20..]) as usize;
        if !(extended.len()..=4096).contains(&length) {
            return Err(Error::InvalidTable);
        }
        let record = read_blob(&mut read, rsdp, length)?;
        if !checksum_ok(&record) {
            return Err(Error::InvalidTable);
        }
        let xsdt = qword(&record[24..]);
        if xsdt != 0 {
            root = (xsdt, *b"XSDT", 8);
        }
    }
    let (address, root_signature, width) = root;
    let table = read_table(&mut read, address, root_signature)?;
    let pointers = table[HEADER_BYTES..].chunks_exact(width);
    if !pointers.remainder().is_empty() {
        return Err(Error::InvalidTable);
    }
    let mut found = None;
    for pointer in pointers {
        let address = if width == 8 {
            qword(pointer)
        } else {
            u64::from(dword(pointer))
        };
        let mut name = [0; 4];
        read(address, &mut name)?;
        if name == signature {
            if found.is_some() {
                return Err(Error::InvalidTable);
            }
            found = Some(read_table(&mut read, address, signature)?);
        }
    }
    Ok(found)
}

fn read_table(
    read: &mut impl FnMut(u64, &mut [u8]) -> Result<(), Error>,
    address: u64,
    signature: [u8; 4],
) -> Result<Vec<u8>, Error> {
    let mut header = [0; HEADER_BYTES];
    read(address, &mut header)?;
    let length = dword(&header[4..]) as usize;
    if header[..4] != signature || !(HEADER_BYTES..=MAX_TABLE_BYTES).contains(&length) {
        return Err(Error::InvalidTable);
    }
    let table = read_blob(read, address, length)?;
    if table[..HEADER_BYTES] != header || !checksum_ok(&table) {
        return Err(Error::InvalidTable);
    }
    Ok(table)
}

fn read_blob(
    read: &mut impl FnMut(u64, &mut [u8]) -> Result<(), Error>,
    address: u64,
    length: usize,
) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| Error::NoMemory)?;
    bytes.resize(length, 0);
    read(address, &mut bytes)?;
    Ok(bytes)
}

fn checksum_ok(bytes: &[u8]) -> bool {
    bytes.iter().copied().fold(0u8, u8::wrapping_add) == 0
}

fn dword(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes[..4].try_into().unwrap())
}

fn qword(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes[..8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seal(bytes: &mut [u8], offset: usize) {
        bytes[offset] = 0;
        bytes[offset] = 0u8.wrapping_sub(bytes.iter().copied().fold(0, u8::wrapping_add));
    }

    #[test]
    fn validates_both_root_formats_and_rejects_bad_checksums() {
        let mut memory = [0; 256];
        let rsdp = 16;
        let root = 64;
        let dmar = 144;
        memory[rsdp..rsdp + 8].copy_from_slice(b"RSD PTR ");
        memory[rsdp + 16..rsdp + 20].copy_from_slice(&(root as u32).to_le_bytes());
        seal(&mut memory[rsdp..rsdp + 20], 8);
        memory[root..root + 4].copy_from_slice(b"RSDT");
        memory[root + 4] = 40;
        memory[root + 36..root + 40].copy_from_slice(&(dmar as u32).to_le_bytes());
        seal(&mut memory[root..root + 40], 9);
        memory[dmar..dmar + 4].copy_from_slice(b"DMAR");
        memory[dmar + 4] = 48;
        seal(&mut memory[dmar..dmar + 48], 9);
        fn walk(memory: &[u8], rsdp: usize) -> Result<Option<Vec<u8>>, Error> {
            find(rsdp as u64, *b"DMAR", |address, bytes| {
                let index = address as usize;
                bytes.copy_from_slice(
                    memory
                        .get(index..index + bytes.len())
                        .ok_or(Error::InvalidTable)?,
                );
                Ok(())
            })
        }
        assert_eq!(walk(&memory, rsdp).unwrap().unwrap().len(), 48);
        memory[rsdp + 15] = 2;
        memory[rsdp + 20] = 36;
        memory[rsdp + 24..rsdp + 32].copy_from_slice(&(root as u64).to_le_bytes());
        seal(&mut memory[rsdp..rsdp + 20], 8);
        seal(&mut memory[rsdp..rsdp + 36], 32);
        memory[root..root + 4].copy_from_slice(b"XSDT");
        memory[root + 4] = 44;
        seal(&mut memory[root..root + 44], 9);
        assert_eq!(walk(&memory, rsdp).unwrap().unwrap().len(), 48);
        memory[dmar + 9] ^= 1;
        assert_eq!(walk(&memory, rsdp), Err(Error::InvalidTable));
    }
}
