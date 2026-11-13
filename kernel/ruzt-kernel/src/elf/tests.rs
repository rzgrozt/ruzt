use super::load_elf;
use ruzt_abi::ErrorCode;
use ruzt_hal::mem::PageFlags;

const ELF_LEN: usize = 124;
const PROGRAM_HEADER_OFFSET: usize = 64;

const fn write<const N: usize>(bytes: &mut [u8; ELF_LEN], offset: usize, value: [u8; N]) {
    let mut index = 0;
    while index < N {
        bytes[offset + index] = value[index];
        index += 1;
    }
}

const fn valid_elf() -> [u8; ELF_LEN] {
    let mut bytes = [0_u8; ELF_LEN];
    write(&mut bytes, 0, *b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    write(&mut bytes, 16, 2_u16.to_le_bytes());
    write(&mut bytes, 18, 62_u16.to_le_bytes());
    write(&mut bytes, 20, 1_u32.to_le_bytes());
    write(&mut bytes, 24, 0x0040_0000_u64.to_le_bytes());
    write(&mut bytes, 32, 64_u64.to_le_bytes());
    write(&mut bytes, 52, 64_u16.to_le_bytes());
    write(&mut bytes, 54, 56_u16.to_le_bytes());
    write(&mut bytes, 56, 1_u16.to_le_bytes());

    write(&mut bytes, PROGRAM_HEADER_OFFSET, 1_u32.to_le_bytes());
    write(&mut bytes, PROGRAM_HEADER_OFFSET + 4, 5_u32.to_le_bytes());
    write(&mut bytes, PROGRAM_HEADER_OFFSET + 8, 120_u64.to_le_bytes());
    write(
        &mut bytes,
        PROGRAM_HEADER_OFFSET + 16,
        0x0040_0000_u64.to_le_bytes(),
    );
    write(&mut bytes, PROGRAM_HEADER_OFFSET + 32, 4_u64.to_le_bytes());
    write(
        &mut bytes,
        PROGRAM_HEADER_OFFSET + 40,
        0x1000_u64.to_le_bytes(),
    );
    write(
        &mut bytes,
        PROGRAM_HEADER_OFFSET + 48,
        0x1000_u64.to_le_bytes(),
    );
    bytes[120] = 0x90;
    bytes[121] = 0x90;
    bytes[122] = 0xCD;
    bytes[123] = 0x80;
    bytes
}

const fn patch_u32(mut bytes: [u8; ELF_LEN], offset: usize, value: u32) -> [u8; ELF_LEN] {
    write(&mut bytes, offset, value.to_le_bytes());
    bytes
}

const fn patch_u64(mut bytes: [u8; ELF_LEN], offset: usize, value: u64) -> [u8; ELF_LEN] {
    write(&mut bytes, offset, value.to_le_bytes());
    bytes
}

static VALID_ELF: [u8; ELF_LEN] = valid_elf();
static WRITE_EXEC_ELF: [u8; ELF_LEN] =
    patch_u32(valid_elf(), PROGRAM_HEADER_OFFSET + 4, 7);
static FILE_LARGER_THAN_MEMORY_ELF: [u8; ELF_LEN] =
    patch_u64(valid_elf(), PROGRAM_HEADER_OFFSET + 32, 0x1001);
static OUT_OF_BOUNDS_PH_TABLE_ELF: [u8; ELF_LEN] = patch_u64(valid_elf(), 32, u64::MAX);
static NON_EXEC_ENTRY_ELF: [u8; ELF_LEN] =
    patch_u32(valid_elf(), PROGRAM_HEADER_OFFSET + 4, 4);
static BAD_MAGIC: [u8; 64] = [0; 64];

#[test]
fn parses_valid_elf64_executable_when_header_and_segment_are_well_formed() {
    // Given: a little-endian x86_64 ET_EXEC with one executable load segment.
    // When: the image is parsed at the kernel boundary.
    let loaded = load_elf(&VALID_ELF).expect("valid executable should parse");
    // Then: entry, segment bytes, permissions, and stack contract are preserved.
    assert_eq!(loaded.entry_point, 0x0040_0000);
    assert_eq!(loaded.stack_size, 128 * 1024);
    assert_eq!(loaded.segments.len(), 1);
    let segment = &loaded.segments[0];
    assert_eq!(segment.vaddr, 0x0040_0000);
    assert_eq!(segment.mem_size, 0x1000);
    assert_eq!(segment.data, &[0x90, 0x90, 0xCD, 0x80]);
    assert!(segment.flags.contains(PageFlags::PRESENT));
    assert!(segment.flags.contains(PageFlags::EXECUTABLE));
    assert!(!segment.flags.contains(PageFlags::WRITABLE));
}

#[test]
fn rejects_image_when_elf_identity_is_invalid() {
    // Given: bytes without the ELF64 identity.
    // When: the image is parsed.
    let result = load_elf(&BAD_MAGIC);
    // Then: malformed input is reported at the boundary.
    assert!(matches!(result, Err(ErrorCode::BadMessage)));
}

#[test]
fn rejects_segment_when_write_and_execute_are_combined() {
    // Given: a load segment carrying both PF_W and PF_X.
    // When: the image is parsed.
    let result = load_elf(&WRITE_EXEC_ELF);
    // Then: the W^X violation is rejected as malformed input.
    assert!(matches!(result, Err(ErrorCode::BadMessage)));
}

#[test]
fn rejects_segment_when_file_size_exceeds_memory_size() {
    // Given: a load segment whose file payload is larger than its memory image.
    // When: the image is parsed.
    let result = load_elf(&FILE_LARGER_THAN_MEMORY_ELF);
    // Then: the impossible segment layout is rejected.
    assert!(matches!(result, Err(ErrorCode::BadMessage)));
}

#[test]
fn rejects_image_when_program_header_table_is_out_of_bounds() {
    // Given: an overflowing program-header table offset.
    // When: the image is parsed.
    let result = load_elf(&OUT_OF_BOUNDS_PH_TABLE_ELF);
    // Then: checked table bounds reject the image.
    assert!(matches!(result, Err(ErrorCode::BadMessage)));
}

#[test]
fn rejects_entry_when_no_executable_segment_contains_it() {
    // Given: an entry point covered only by a non-executable load segment.
    // When: the image is parsed.
    let result = load_elf(&NON_EXEC_ENTRY_ELF);
    // Then: the image cannot become an initial user context.
    assert!(matches!(result, Err(ErrorCode::BadMessage)));
}
