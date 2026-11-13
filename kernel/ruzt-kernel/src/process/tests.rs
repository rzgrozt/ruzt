use super::{HEAP_REGION, STACK_REGION, initial_stack_pointer};

#[test]
fn stack_region_has_exact_phase_2_layout() {
    // Given: the fixed initial user-stack specification.
    // When: its exclusive end and initial stack pointer are derived.
    let end = STACK_REGION.end().expect("stack region must not overflow");
    // Then: exactly 32 pages occupy 0x7fff0000..0x80010000 with an 8-byte bias.
    assert_eq!(STACK_REGION.start, 0x7FFF_0000);
    assert_eq!(STACK_REGION.page_count, 32);
    assert_eq!(end, 0x8001_0000);
    assert_eq!(initial_stack_pointer(), 0x8001_0000 - 8);
}

#[test]
fn heap_region_has_exact_phase_2_layout() {
    // Given: the fixed bootstrap heap specification.
    // When: its exclusive end is derived.
    let end = HEAP_REGION.end().expect("heap region must not overflow");
    // Then: exactly 256 pages provide one MiB from 0x40000000.
    assert_eq!(HEAP_REGION.start, 0x4000_0000);
    assert_eq!(HEAP_REGION.page_count, 256);
    assert_eq!(end, 0x4010_0000);
}
