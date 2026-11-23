use ruzt_abi::{CapOp, ErrorCode, PciAddress, SyscallNumber};
use ruzt_runtime::syscall::syscall;

/// Read one aligned dword from the conventional PCI configuration header.
pub fn read_pci_config(control: u64, address: PciAddress, offset: u8) -> Result<u32, ErrorCode> {
    let mut value = 0u32;
    // SAFETY: The result word is exclusively writable for the call.
    let status = unsafe {
        syscall(
            SyscallNumber::Invoke,
            control,
            CapOp::ReadPciConfig as u64,
            u64::from(address.bits()),
            u64::from(offset),
            (&raw mut value) as u64,
            0,
        )
    };
    ErrorCode::from_u64(status)?;
    Ok(value)
}

/// Claim a firmware-configured PCI function into an empty slot.
pub fn claim_pci_device(
    control: u64,
    destination: u64,
    address: PciAddress,
) -> Result<(), ErrorCode> {
    // SAFETY: These arguments describe capabilities and a PCI function only.
    let status = unsafe {
        syscall(
            SyscallNumber::Invoke,
            control,
            CapOp::ClaimPciDevice as u64,
            destination,
            u64::from(address.bits()),
            0,
            0,
        )
    };
    ErrorCode::from_u64(status)
}

/// Create a capability for a page-aligned portion of a claimed memory BAR.
pub fn open_pci_bar(
    device: u64,
    destination: u64,
    bar: u8,
    first_page: u64,
    pages: u64,
) -> Result<(), ErrorCode> {
    // SAFETY: These arguments name only slots, a BAR index and a page range.
    let status = unsafe {
        syscall(
            SyscallNumber::Invoke,
            device,
            CapOp::OpenPciBar as u64,
            destination,
            u64::from(bar),
            first_page,
            pages,
        )
    };
    ErrorCode::from_u64(status)
}

/// Map the capability's entire MMIO range at a page-aligned virtual address.
pub fn map_mmio(cap: u64, address: u64, writable: bool) -> Result<MmioRegion, ErrorCode> {
    let mut bytes = 0u64;
    // SAFETY: The resulting length is written to this local word.
    let size_status = unsafe {
        syscall(
            SyscallNumber::Invoke,
            cap,
            CapOp::MmioSize as u64,
            (&raw mut bytes) as u64,
            0,
            0,
            0,
        )
    };
    ErrorCode::from_u64(size_status)?;
    // SAFETY: The address describes a mapping destination and is not dereferenced.
    let map_status = unsafe {
        syscall(
            SyscallNumber::Invoke,
            cap,
            CapOp::MapMmio as u64,
            address,
            u64::from(writable),
            0,
            0,
        )
    };
    ErrorCode::from_u64(map_status)?;
    Ok(MmioRegion {
        address,
        bytes,
        writable,
    })
}

/// Unmap the region associated with this capability in the caller.
pub fn unmap_mmio(cap: u64) -> Result<(), ErrorCode> {
    // SAFETY: UnmapMmio only looks up the capability and its recorded mapping.
    let status = unsafe {
        syscall(
            SyscallNumber::Invoke,
            cap,
            CapOp::UnmapMmio as u64,
            0,
            0,
            0,
            0,
        )
    };
    ErrorCode::from_u64(status)
}

/// A mapped device register window. Its capability can be revoked.
#[derive(Debug, PartialEq, Eq)]
pub struct MmioRegion {
    address: u64,
    bytes: u64,
    writable: bool,
}

impl MmioRegion {
    /// Read one naturally aligned 32-bit device register.
    ///
    /// # Safety
    /// The mapping must remain live and the device must support this read.
    pub unsafe fn read_u32(&self, offset: u64) -> Result<u32, ErrorCode> {
        let address = self.register(offset)?;
        // SAFETY: Bounds and alignment were checked, with device and mapping
        // validity guaranteed by the caller.
        Ok(unsafe { core::ptr::read_volatile(core::ptr::without_provenance(address)) })
    }

    /// Write one naturally aligned 32-bit device register.
    ///
    /// # Safety
    /// The mapping must remain live and the device must support this write
    /// and all of its side effects.
    pub unsafe fn write_u32(&self, offset: u64, value: u32) -> Result<(), ErrorCode> {
        if !self.writable {
            return Err(ErrorCode::CapRightsViolation);
        }
        let address = self.register(offset)?;
        // SAFETY: Bounds, alignment and write access were checked.
        unsafe { core::ptr::write_volatile(core::ptr::without_provenance_mut(address), value) };
        Ok(())
    }

    fn register(&self, offset: u64) -> Result<usize, ErrorCode> {
        if offset % 4 != 0 || offset.checked_add(4).is_none_or(|end| end > self.bytes) {
            return Err(ErrorCode::BadMessage);
        }
        Ok((self.address + offset) as usize)
    }
}
