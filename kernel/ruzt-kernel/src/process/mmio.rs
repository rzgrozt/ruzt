//! User mappings backed by device register apertures.

use core::ops::Range;
use ruzt_abi::{CapRights, ErrorCode};
use ruzt_hal::mem::{MapError, PageFlags, PhysAddr, PhysFrame, VirtAddr};
use ruzt_hal_x86_64::mapper::{self, UserPageFrames, X86_64Mapper};

use super::{overlaps_heap, page_range, UserProcess, PAGE_SIZE};
use crate::cap::{cspace::CapabilityPath, object::MmioPin};

pub(super) struct Mapping {
    authority: CapabilityPath,
    addresses: Range<u64>,
    lease: MmioPin,
}

impl Mapping {
    fn frame(&self, address: u64) -> PhysFrame {
        let physical = self.lease.range.base + (address - self.addresses.start);
        PhysFrame::from_base(PhysAddr::new(physical)).expect("page-aligned MMIO mapping")
    }

    #[allow(unsafe_code)]
    fn unmap_prefix(
        &self,
        mapper: &mut X86_64Mapper,
        root: PhysFrame,
        budget: &dyn UserPageFrames,
        end: u64,
    ) {
        for address in (self.addresses.start..end).step_by(PhysFrame::SIZE) {
            // SAFETY: The mapping still holds the lease and owns these leaves.
            let frame =
                unsafe { mapper.unmap_in_address_space(root, VirtAddr::new(address), budget) };
            assert_eq!(frame, self.frame(address));
        }
    }

    fn unmap(&self, root: PhysFrame, budget: &dyn UserPageFrames) {
        mapper::with_mapper(|mapper| self.unmap_prefix(mapper, root, budget, self.addresses.end));
    }
}

impl UserProcess {
    #[allow(unsafe_code)]
    pub(crate) fn map_mmio(
        &mut self,
        cptr: u64,
        address: u64,
        writable: bool,
    ) -> Result<(), ErrorCode> {
        let mut rights = CapRights::READ;
        let mut flags = PageFlags::USER | PageFlags::NOCACHE | PageFlags::WRITETHROUGH;
        if writable {
            rights = rights.union(CapRights::WRITE);
            flags |= PageFlags::WRITABLE;
        }
        let (authority, lease) = self.cspace.device_mmio(cptr, rights)?;
        let addresses = page_range(address, lease.range.bytes / PAGE_SIZE)?;
        if overlaps_heap(addresses.start, addresses.end) {
            return Err(ErrorCode::MappingExists);
        }
        let root = self.root();
        let budget = &self.space.budget;
        let mappings = &mut self.space.device_mappings;
        if mappings
            .iter()
            .any(|mapping| mapping.authority.leaf() == authority.leaf())
        {
            return Err(ErrorCode::MappingExists);
        }
        mappings.try_reserve(1).map_err(|_| ErrorCode::NoMemory)?;
        let mapping = Mapping {
            authority,
            addresses,
            lease,
        };
        mapper::with_mapper(|mapper| {
            for address in mapping.addresses.clone().step_by(PhysFrame::SIZE) {
                // SAFETY: The lease pins the device resources, and the
                // scheduler serializes updates to this private root.
                let result = unsafe {
                    mapper.map_in_address_space(
                        root,
                        VirtAddr::new(address),
                        mapping.frame(address),
                        flags,
                        budget,
                    )
                };
                if let Err(error) = result {
                    mapping.unmap_prefix(mapper, root, budget, address);
                    return Err(match error {
                        MapError::AlreadyMapped => ErrorCode::MappingExists,
                        MapError::FrameAllocationFailed => ErrorCode::NoMemory,
                        _ => ErrorCode::BadMessage,
                    });
                }
            }
            Ok(())
        })?;
        mappings.push(mapping);
        Ok(())
    }

    pub(crate) fn unmap_mmio(&mut self, cptr: u64) -> Result<(), ErrorCode> {
        let authority = self.cspace.capability_id(cptr)?;
        let root = self.root();
        let budget = &self.space.budget;
        let mappings = &mut self.space.device_mappings;
        let index = mappings
            .iter()
            .position(|mapping| mapping.authority.leaf() == authority)
            .ok_or(ErrorCode::NotFound)?;
        mappings[index].unmap(root, budget);
        mappings.swap_remove(index);
        Ok(())
    }

    pub(crate) fn unmap_revoked_mmio(&mut self) {
        let root = self.root();
        let budget = &self.space.budget;
        self.space.device_mappings.retain(|mapping| {
            if mapping.authority.is_live() {
                true
            } else {
                mapping.unmap(root, budget);
                false
            }
        });
    }
}
