//! User mappings owned by frame capabilities.

use ruzt_abi::{CapRights, ErrorCode};
use ruzt_hal::mem::{MapError, PageFlags, PhysFrame, VirtAddr};
use ruzt_hal_x86_64::mapper;

use super::{UserProcess, PAGE_SIZE};
use crate::cap::{cspace, cspace::CapabilityId, object::FramePin};

pub(super) struct Mapping {
    authority: CapabilityId,
    address: u64,
    frame: FramePin,
}

impl Mapping {
    #[allow(unsafe_code)]
    fn unmap(&self, root: PhysFrame) {
        let frame = mapper::with_mapper(|mapper| {
            // SAFETY: This record owns the lower-half leaf, and the scheduler
            // serializes access on the sole CPU that runs user roots.
            unsafe { mapper.unmap_in_address_space(root, VirtAddr::new(self.address)) }
        });
        assert_eq!(frame, self.frame.phys);
    }
}

impl UserProcess {
    #[allow(unsafe_code)]
    pub(crate) fn map_shared_frame(
        &mut self,
        cptr: u64,
        address: u64,
        writable: bool,
    ) -> Result<(), ErrorCode> {
        if address == 0 || address >= 1 << 47 || address % PAGE_SIZE != 0 {
            return Err(ErrorCode::BadMessage);
        }
        let mut rights = CapRights::READ;
        let mut flags = PageFlags::USER;
        if writable {
            rights = rights.union(CapRights::WRITE);
            flags |= PageFlags::WRITABLE;
        }
        let (authority, frame) = self.cspace.shared_frame(cptr, rights)?;
        let mappings = &mut self.space.shared_frames;
        if mappings
            .iter()
            .any(|mapping| mapping.authority == authority)
        {
            return Err(ErrorCode::MappingExists);
        }
        mappings.try_reserve(1).map_err(|_| ErrorCode::NoMemory)?;
        mapper::with_mapper(|mapper| {
            // SAFETY: The scheduler owns this root and serializes updates on
            // the boot CPU. The frame pin outlives the installed mapping.
            unsafe {
                mapper.map_in_address_space(
                    self.space.root,
                    VirtAddr::new(address),
                    frame.phys,
                    flags,
                )
            }
        })
        .map_err(|error| match error {
            MapError::AlreadyMapped => ErrorCode::MappingExists,
            MapError::FrameAllocationFailed => ErrorCode::NoMemory,
            MapError::InvalidAlignment | MapError::WriteExecute => ErrorCode::BadMessage,
        })?;
        mappings.push(Mapping {
            authority,
            address,
            frame,
        });
        Ok(())
    }

    pub(crate) fn unmap_shared_frame(&mut self, cptr: u64) -> Result<(), ErrorCode> {
        let authority = self.cspace.capability_id(cptr)?;
        let root = self.root();
        let mappings = &mut self.space.shared_frames;
        let index = mappings
            .iter()
            .position(|mapping| mapping.authority == authority)
            .ok_or(ErrorCode::NotFound)?;
        mappings[index].unmap(root);
        mappings.swap_remove(index);
        Ok(())
    }

    pub(crate) fn unmap_revoked_frames(&mut self) {
        let root = self.root();
        self.space.shared_frames.retain(|mapping| {
            if cspace::is_live(mapping.authority) {
                true
            } else {
                mapping.unmap(root);
                false
            }
        });
    }

    pub(crate) fn receive_buffer_is_stable(&self, address: u64, length: usize) -> bool {
        let end = address.saturating_add(length as u64);
        !self
            .space
            .shared_frames
            .iter()
            .any(|mapping| address < mapping.address + PAGE_SIZE && mapping.address < end)
    }
}
