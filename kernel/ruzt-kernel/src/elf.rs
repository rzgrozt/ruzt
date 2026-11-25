//! Safe ELF64 executable parsing.

#![deny(unsafe_code)]

use alloc::vec::Vec;
use ruzt_abi::ErrorCode;
use ruzt_hal::mem::PageFlags;

const ELF_HEADER_SIZE: usize = 64;
const PROGRAM_HEADER_SIZE: usize = 56;
const PAGE_MASK: u64 = 0xFFF;
const USER_ADDRESS_LIMIT: u64 = 1 << 47;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

/// A parsed executable image ready for address-space construction.
#[derive(Debug)]
pub struct LoadedElf {
    /// Initial user instruction pointer.
    pub entry_point: u64,
    /// Loadable image segments.
    pub segments: Vec<LoadedSegment>,
    /// Initial user stack allocation in bytes.
    pub stack_size: usize,
}

/// One validated `PT_LOAD` segment.
#[derive(Debug)]
pub struct LoadedSegment {
    /// First virtual byte occupied by the segment.
    pub vaddr: u64,
    /// In-memory segment size, including zero-filled bytes.
    pub mem_size: u64,
    /// File-backed bytes copied into the segment.
    pub data: &'static [u8],
    /// Kernel page permissions derived from the ELF flags.
    pub flags: PageFlags,
}

struct ElfHeader {
    entry_point: u64,
    program_headers: core::ops::Range<usize>,
}

/// Parse a little-endian x86_64 ELF executable without pointer reinterpretation.
///
/// # Errors
///
/// Returns [`ErrorCode::BadMessage`] for malformed or unsupported input and
/// [`ErrorCode::NoMemory`] if segment metadata cannot be allocated.
pub fn load_elf(bytes: &'static [u8]) -> Result<LoadedElf, ErrorCode> {
    let header = parse_header(bytes, 2)?;
    let program_header_count = header.program_headers.len() / PROGRAM_HEADER_SIZE;
    let mut segments = Vec::new();
    segments
        .try_reserve(program_header_count)
        .map_err(|_| ErrorCode::NoMemory)?;
    let mut entry_is_executable = false;

    for offset in header.program_headers.step_by(PROGRAM_HEADER_SIZE) {
        let end = offset
            .checked_add(PROGRAM_HEADER_SIZE)
            .ok_or(ErrorCode::BadMessage)?;
        let program_header = bytes.get(offset..end).ok_or(ErrorCode::BadMessage)?;
        if read_u32(program_header, 0)? != PT_LOAD {
            continue;
        }

        let segment = parse_load_segment(bytes, program_header)?;
        let segment_end = segment
            .vaddr
            .checked_add(segment.mem_size)
            .ok_or(ErrorCode::BadMessage)?;
        entry_is_executable |= segment.flags.contains(PageFlags::EXECUTABLE)
            && (segment.vaddr..segment_end).contains(&header.entry_point);
        segments.push(segment);
    }

    if !entry_is_executable {
        return Err(ErrorCode::BadMessage);
    }

    Ok(LoadedElf {
        entry_point: header.entry_point,
        segments,
        stack_size: 128 * 1024,
    })
}

pub(crate) fn has_kernel_ibt(bytes: &[u8]) -> bool {
    kernel_ibt_property(bytes).unwrap_or(false)
}

fn kernel_ibt_property(bytes: &[u8]) -> Result<bool, ErrorCode> {
    const PT_GNU_PROPERTY: u32 = 0x6474_e553;
    const GNU_PROPERTY_X86_FEATURE_1_AND: u32 = 0xc000_0002;
    let kind = read_u16(bytes, 16)?;
    if !matches!(kind, 2 | 3) {
        return Err(ErrorCode::BadMessage);
    }
    let header = parse_header(bytes, kind)?;
    for ph in bytes[header.program_headers].chunks_exact(PROGRAM_HEADER_SIZE) {
        if read_u32(ph, 0)? != PT_GNU_PROPERTY {
            continue;
        }
        let start = usize::try_from(read_u64(ph, 8)?).map_err(|_| ErrorCode::BadMessage)?;
        let size = usize::try_from(read_u64(ph, 32)?).map_err(|_| ErrorCode::BadMessage)?;
        let end = start.checked_add(size).ok_or(ErrorCode::BadMessage)?;
        let note = bytes.get(start..end).ok_or(ErrorCode::BadMessage)?;
        if read_u32(note, 0)? != 4 || read_u32(note, 8)? != 5 || read::<4>(note, 12)? != *b"GNU\0" {
            return Err(ErrorCode::BadMessage);
        }
        let size = read_u32(note, 4)? as usize;
        if size != note.len() - 16 || size % 8 != 0 {
            return Err(ErrorCode::BadMessage);
        }
        let mut properties = &note[16..];
        while !properties.is_empty() {
            let kind = read_u32(properties, 0)?;
            let length = read_u32(properties, 4)? as usize;
            let end = 8 + length.next_multiple_of(8);
            let property = properties.get(..end).ok_or(ErrorCode::BadMessage)?;
            if kind == GNU_PROPERTY_X86_FEATURE_1_AND {
                return Ok(length == 4 && read_u32(property, 8)? & 1 != 0);
            }
            properties = &properties[end..];
        }
    }
    Ok(false)
}

fn parse_header(bytes: &[u8], kind: u16) -> Result<ElfHeader, ErrorCode> {
    if bytes.len() < ELF_HEADER_SIZE
        || bytes[..4] != *b"\x7fELF"
        || bytes[4] != 2
        || bytes[5] != 1
        || bytes[6] != 1
        || read_u16(bytes, 16)? != kind
        || read_u16(bytes, 18)? != 62
        || read_u32(bytes, 20)? != 1
        || usize::from(read_u16(bytes, 52)?) != ELF_HEADER_SIZE
        || usize::from(read_u16(bytes, 54)?) != PROGRAM_HEADER_SIZE
    {
        return Err(ErrorCode::BadMessage);
    }

    let table_start = usize::try_from(read_u64(bytes, 32)?)
        .map_err(|_| ErrorCode::BadMessage)?;
    let table_size = usize::from(read_u16(bytes, 56)?)
        .checked_mul(PROGRAM_HEADER_SIZE)
        .ok_or(ErrorCode::BadMessage)?;
    let table_end = table_start
        .checked_add(table_size)
        .filter(|end| *end <= bytes.len())
        .ok_or(ErrorCode::BadMessage)?;

    Ok(ElfHeader {
        entry_point: read_u64(bytes, 24)?,
        program_headers: table_start..table_end,
    })
}

fn parse_load_segment(
    bytes: &'static [u8],
    program_header: &[u8],
) -> Result<LoadedSegment, ErrorCode> {
    let raw_flags = read_u32(program_header, 4)?;
    if raw_flags & !(PF_X | PF_W | PF_R) != 0 || raw_flags & (PF_X | PF_W) == PF_X | PF_W {
        return Err(ErrorCode::BadMessage);
    }

    let file_offset = read_u64(program_header, 8)?;
    let vaddr = read_u64(program_header, 16)?;
    let file_size = read_u64(program_header, 32)?;
    let mem_size = read_u64(program_header, 40)?;
    if file_size > mem_size {
        return Err(ErrorCode::BadMessage);
    }

    let segment_end = vaddr.checked_add(mem_size).ok_or(ErrorCode::BadMessage)?;
    let mapped_end = segment_end
        .checked_add(PAGE_MASK)
        .map(|end| end & !PAGE_MASK)
        .filter(|end| *end <= USER_ADDRESS_LIMIT)
        .ok_or(ErrorCode::BadMessage)?;
    if vaddr >= USER_ADDRESS_LIMIT || mapped_end > USER_ADDRESS_LIMIT {
        return Err(ErrorCode::BadMessage);
    }

    let data_start = usize::try_from(file_offset).map_err(|_| ErrorCode::BadMessage)?;
    let data_length = usize::try_from(file_size).map_err(|_| ErrorCode::BadMessage)?;
    let data_end = data_start
        .checked_add(data_length)
        .ok_or(ErrorCode::BadMessage)?;
    let data = bytes
        .get(data_start..data_end)
        .ok_or(ErrorCode::BadMessage)?;

    let mut flags = PageFlags::PRESENT;
    if raw_flags & PF_W != 0 {
        flags |= PageFlags::WRITABLE;
    }
    if raw_flags & PF_X != 0 {
        flags |= PageFlags::EXECUTABLE;
    }

    Ok(LoadedSegment {
        vaddr,
        mem_size,
        data,
        flags,
    })
}

fn read<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], ErrorCode> {
    let end = offset.checked_add(N).ok_or(ErrorCode::BadMessage)?;
    bytes
        .get(offset..end)
        .ok_or(ErrorCode::BadMessage)?
        .try_into()
        .map_err(|_| ErrorCode::BadMessage)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, ErrorCode> {
    Ok(u16::from_le_bytes(read(bytes, offset)?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ErrorCode> {
    Ok(u32::from_le_bytes(read(bytes, offset)?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, ErrorCode> {
    Ok(u64::from_le_bytes(read(bytes, offset)?))
}

#[cfg(test)]
mod tests;
