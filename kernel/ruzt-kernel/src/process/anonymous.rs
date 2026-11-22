//! Private anonymous mappings backed by the address space's Untyped budget.

use core::ops::Range;
use ruzt_abi::ErrorCode;
use ruzt_cap::AddressSpaceId;
use ruzt_hal::mem::{MapError, PageFlags, PhysFrame, VirtAddr};
use ruzt_hal_x86_64::mapper::{self, UserPageFrames, X86_64Mapper};

use super::{map_owned_page, UserProcess, PAGE_SIZE};
use crate::cap::object::{self, KObjectId, KernelObject, UntypedBudget};

pub(super) struct AnonymousPage {
    address: u64,
    pub(super) frame: PhysFrame,
}

impl AnonymousPage {
    #[allow(unsafe_code)]
    fn unmap(&self, mapper: &mut X86_64Mapper, root: PhysFrame, budget: &UntypedBudget) {
        // SAFETY: This record owns the mapping and its leaf. The scheduler
        // serializes updates and the HAL flushes before returning the leaf.
        unsafe {
            let frame = mapper.unmap_in_address_space(root, VirtAddr::new(self.address), budget);
            assert_eq!(frame, self.frame);
            budget.deallocate(frame);
        }
    }
}

fn page_range(address: u64, count: u64) -> Result<Range<u64>, ErrorCode> {
    let end = count
        .checked_mul(PAGE_SIZE)
        .and_then(|length| address.checked_add(length))
        .ok_or(ErrorCode::BadMessage)?;
    if address == 0 || count == 0 || address % PAGE_SIZE != 0 || end > 1 << 47 {
        return Err(ErrorCode::BadMessage);
    }
    Ok(address..end)
}

impl UserProcess {
    fn require_own_space(&self, id: AddressSpaceId) -> Result<(), ErrorCode> {
        match object::get(KObjectId(id.0)) {
            Some(KernelObject::AddressSpace { root_page_table })
                if root_page_table == self.root() =>
            {
                Ok(())
            }
            _ => Err(ErrorCode::InvalidCap),
        }
    }

    pub(crate) fn map_anonymous(
        &mut self,
        id: AddressSpaceId,
        address: u64,
        count: u64,
        writable: bool,
    ) -> Result<(), ErrorCode> {
        self.require_own_space(id)?;
        let range = page_range(address, count)?;
        let root = self.root();
        let budget = &self.space.budget;
        if count > budget.page_count() as u64 {
            return Err(ErrorCode::NoMemory);
        }
        let pages = &mut self.space.anonymous;
        pages
            .try_reserve(count as usize)
            .map_err(|_| ErrorCode::NoMemory)?;
        let old_len = pages.len();
        let flags = if writable {
            PageFlags::WRITABLE
        } else {
            PageFlags::empty()
        };
        mapper::with_mapper(|mapper| {
            for address in range.step_by(PhysFrame::SIZE) {
                match map_owned_page(mapper, root, budget, address, flags, 0, &[]) {
                    Ok(frame) => pages.push(AnonymousPage { address, frame }),
                    Err(error) => {
                        for page in pages.drain(old_len..) {
                            page.unmap(mapper, root, budget);
                        }
                        return Err(match error {
                            MapError::AlreadyMapped => ErrorCode::MappingExists,
                            MapError::FrameAllocationFailed => ErrorCode::NoMemory,
                            _ => ErrorCode::BadMessage,
                        });
                    }
                }
            }
            Ok(())
        })
    }

    pub(crate) fn unmap_anonymous(
        &mut self,
        id: AddressSpaceId,
        address: u64,
        count: u64,
    ) -> Result<(), ErrorCode> {
        self.require_own_space(id)?;
        let range = page_range(address, count)?;
        let root = self.root();
        let budget = &self.space.budget;
        let pages = &mut self.space.anonymous;
        // Every anonymous page is unique. Counting matches preflights the
        // entire request before any page is removed.
        if pages
            .iter()
            .filter(|page| range.contains(&page.address))
            .count() as u64
            != count
        {
            return Err(ErrorCode::NotFound);
        }
        mapper::with_mapper(|mapper| {
            pages.retain(|page| {
                if range.contains(&page.address) {
                    page.unmap(mapper, root, budget);
                    false
                } else {
                    true
                }
            });
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_ranges_must_be_nonempty_aligned_and_below_the_kernel_half() {
        let last_page = (1 << 47) - PAGE_SIZE;
        assert_eq!(page_range(last_page, 1), Ok(last_page..1 << 47));
        assert_eq!(page_range(last_page, 2), Err(ErrorCode::BadMessage));
        assert_eq!(page_range(PAGE_SIZE + 1, 1), Err(ErrorCode::BadMessage));
        assert_eq!(page_range(0, 1), Err(ErrorCode::BadMessage));
        assert_eq!(page_range(PAGE_SIZE, 0), Err(ErrorCode::BadMessage));
        assert_eq!(page_range(PAGE_SIZE, u64::MAX), Err(ErrorCode::BadMessage));
    }
}
