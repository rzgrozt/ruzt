//! Construction of the trusted boot-time user process.

use ruzt_hal::mem::{MapError, PageFlags, PhysFrame, VirtAddr};
use ruzt_hal_x86_64::mapper::{self, X86_64Mapper};

const PAGE_SIZE: u64 = PhysFrame::SIZE as u64;

struct Region {
    start: u64,
    page_count: u64,
}

impl Region {
    fn end(&self) -> Option<u64> {
        self.page_count
            .checked_mul(PAGE_SIZE)?
            .checked_add(self.start)
    }
}

const STACK_REGION: Region = Region {
    start: 0x7fff_0000,
    page_count: 32,
};
const HEAP_REGION: Region = Region {
    start: 0x4000_0000,
    page_count: 256,
};

fn initial_stack_pointer() -> u64 {
    // System V function entry expects an 8-byte return-address bias.
    STACK_REGION.end().unwrap() - 8
}

/// Map the bootloader-provided ELF and enter it on the boot CPU.
///
/// Any failure stops boot. These frames belong to the initial process for
/// the lifetime of the system.
pub(crate) fn launch(image: &'static [u8]) -> ! {
    let elf = crate::elf::load_elf(image).expect("Invalid rootsrv ELF");
    assert_eq!(elf.stack_size as u64, STACK_REGION.page_count * PAGE_SIZE);
    let root = mapper::with_mapper(|mapper| {
        let root = mapper.create_user_address_space()?;
        for segment in &elf.segments {
            if segment.mem_size == 0 {
                continue;
            }
            let start = segment.vaddr & !(PAGE_SIZE - 1);
            let end = (segment.vaddr + segment.mem_size).next_multiple_of(PAGE_SIZE);
            let data_end = segment.vaddr + segment.data.len() as u64;
            for page in (start..end).step_by(PhysFrame::SIZE) {
                let copy_start = page.max(segment.vaddr);
                let copy_end = (page + PAGE_SIZE).min(data_end).max(copy_start);
                let source_start = (copy_start - segment.vaddr) as usize;
                let bytes = if copy_end > copy_start {
                    &segment.data[source_start..source_start + (copy_end - copy_start) as usize]
                } else {
                    &[]
                };
                map_page(
                    mapper,
                    root,
                    page,
                    segment.flags,
                    (copy_start - page) as usize,
                    bytes,
                )?;
            }
        }

        for region in [STACK_REGION, HEAP_REGION] {
            for page in (region.start..region.end().unwrap()).step_by(PhysFrame::SIZE) {
                map_page(mapper, root, page, PageFlags::WRITABLE, 0, &[])?;
            }
        }
        Ok::<_, MapError>(root)
    })
    .expect("Failed to map rootsrv address space");

    crate::ipc::bootstrap::init(root);
    crate::serial_println!("rootsrv process created, entering user mode...");
    #[allow(unsafe_code)]
    // SAFETY: The private root shares the supervisor mappings containing the
    // kernel and its initialized GDT, TSS and IDT. The ELF entry and initial
    // stack are mapped with the permissions required by enter_user.
    unsafe {
        ruzt_hal_x86_64::context::enter_user(
            elf.entry_point,
            initial_stack_pointer(),
            root.base.as_u64(),
        )
    }
}

#[allow(unsafe_code)]
fn map_page(
    mapper: &mut X86_64Mapper,
    root: PhysFrame,
    page: u64,
    flags: PageFlags,
    offset: usize,
    bytes: &[u8],
) -> Result<(), MapError> {
    let frame = crate::mm::frame::allocate().ok_or(MapError::FrameAllocationFailed)?;
    // SAFETY: The allocator gives exclusive ownership of this physmapped
    // frame, and root is the inactive address space under construction.
    let result = unsafe {
        mapper::zero_frame(frame);
        mapper::copy_to_frame(frame, offset, bytes).and_then(|()| {
            mapper.map_in_address_space(root, VirtAddr::new(page), frame, flags | PageFlags::USER)
        })
    };
    if result.is_err() {
        crate::mm::frame::deallocate(frame);
    }
    result
}

#[cfg(test)]
mod tests;
