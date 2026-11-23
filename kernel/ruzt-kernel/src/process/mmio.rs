//! User mappings backed by device registers or DMA buffers.

use core::ops::Range;
use ruzt_abi::{CapRights, ErrorCode};
use ruzt_hal::mem::{MapError, PageFlags, PhysAddr, PhysFrame, VirtAddr};
use ruzt_hal_x86_64::mapper::{self, UserPageFrames, X86_64Mapper};

use super::{overlaps_heap, page_range, UserProcess, PAGE_SIZE};
use crate::cap::{
    cspace::CapabilityPath,
    object::{DmaPin, MmioPin},
};

enum Backing {
    Mmio(MmioPin),
    Dma(DmaPin),
}

impl Backing {
    fn base(&self) -> u64 {
        match self {
            Self::Mmio(lease) => lease.range.base,
            Self::Dma(buffer) => buffer.base.base.as_u64(),
        }
    }

    fn pages(&self) -> u64 {
        match self {
            Self::Mmio(lease) => lease.range.bytes / PAGE_SIZE,
            Self::Dma(buffer) => buffer.pages as u64,
        }
    }
}

pub(super) struct Mapping {
    authority: CapabilityPath,
    addresses: Range<u64>,
    backing: Backing,
}

impl Mapping {
    fn frame(&self, address: u64) -> PhysFrame {
        let physical = self.backing.base() + (address - self.addresses.start);
        PhysFrame::from_base(PhysAddr::new(physical)).expect("page-aligned device mapping")
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
    pub(crate) fn map_device_memory(
        &mut self,
        cptr: u64,
        address: u64,
        writable: bool,
        dma: bool,
    ) -> Result<(), ErrorCode> {
        let mut rights = CapRights::READ;
        let mut flags = PageFlags::USER;
        if writable {
            rights = rights.union(CapRights::WRITE);
            flags |= PageFlags::WRITABLE;
        }
        let (authority, backing) = if dma {
            flags |= PageFlags::DMA;
            let (authority, buffer) = self.cspace.dma_buffer(cptr, rights)?;
            (authority, Backing::Dma(buffer))
        } else {
            flags |= PageFlags::NOCACHE | PageFlags::WRITETHROUGH;
            let (authority, lease) = self.cspace.device_mmio(cptr, rights)?;
            (authority, Backing::Mmio(lease))
        };
        self.map_device_backing(address, flags, authority, backing)
    }

    #[allow(unsafe_code)]
    fn map_device_backing(
        &mut self,
        address: u64,
        flags: PageFlags,
        authority: CapabilityPath,
        backing: Backing,
    ) -> Result<(), ErrorCode> {
        let addresses = page_range(address, backing.pages())?;
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
            backing,
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

    pub(crate) fn unmap_device_memory(&mut self, cptr: u64, dma: bool) -> Result<(), ErrorCode> {
        let (path, slot) = self.cspace.lookup_path(cptr)?;
        if !matches!(
            (dma, slot.cap_type),
            (true, ruzt_cap::CapType::DmaBuffer(_)) | (false, ruzt_cap::CapType::Mmio(_))
        ) {
            return Err(ErrorCode::InvalidCap);
        }
        let root = self.root();
        let budget = &self.space.budget;
        let mappings = &mut self.space.device_mappings;
        let index = mappings
            .iter()
            .position(|mapping| mapping.authority.leaf() == path.leaf())
            .ok_or(ErrorCode::NotFound)?;
        mappings[index].unmap(root, budget);
        mappings.swap_remove(index);
        Ok(())
    }

    pub(crate) fn unmap_revoked_device_memory(&mut self) {
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
