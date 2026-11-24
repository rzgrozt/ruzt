//! MSI-X capability layout and kernel-owned vector table operations.

use ruzt_hal::mem::VirtAddr;

use super::{
    intx_disabled,
    msi::{find_interrupt_caps, CAP_LIST, ENABLE, MSIX, MSIX_ENABLE},
    read_config, set_intx_disabled, write_word, COMMAND,
};

const FUNCTION_MASK: u16 = 1 << 14;
const TABLE_SIZE_MASK: u16 = 0x7ff;
const VECTOR_MASK: u32 = 1;
const ENTRY_BYTES: u64 = 16;

/// Invalid PCI interrupt capability layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidLayout;

/// Firmware-reported MSI-X geometry. The BAR ranges still require validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsixLayout {
    function: u16,
    offset: u8,
    msi_offset: Option<u8>,
    control: u16,
    intx_disabled: bool,
    table: u32,
    pba: u32,
}

impl MsixLayout {
    /// Discover the MSI-X capability before publishing any BAR mappings.
    ///
    /// # Safety
    /// The caller serializes configuration cycles on this owned function.
    pub unsafe fn inspect(function: u16) -> Result<Option<Self>, InvalidLayout> {
        // SAFETY: The caller holds the configuration transaction.
        let read = |offset| unsafe { read_config(function, offset) };
        let command = read(COMMAND);
        if command == u32::MAX {
            return Err(InvalidLayout);
        }
        if command & CAP_LIST == 0 {
            return Ok(None);
        }
        let caps = find_interrupt_caps(read).ok_or(InvalidLayout)?;
        Ok(caps.msix.map(|(offset, control)| Self {
            function,
            offset,
            control,
            msi_offset: caps.msi.map(|(offset, _)| offset),
            intx_disabled: intx_disabled(command),
            table: read(offset + 4),
            pba: read(offset + 8),
        }))
    }

    /// Number of table entries.
    pub fn vector_count(self) -> u16 {
        (self.control & TABLE_SIZE_MASK) + 1
    }

    /// BAR index, byte offset, and byte length of the vector table.
    pub fn table(self) -> (usize, u64, u64) {
        region(self.table, u64::from(self.vector_count()) * ENTRY_BYTES)
    }

    /// BAR index, byte offset, and byte length of the pending-bit array.
    pub fn pba(self) -> (usize, u64, u64) {
        region(self.pba, u64::from(self.vector_count()).div_ceil(64) * 8)
    }

    fn set_control(self, flags: u16) -> bool {
        write_word(
            self.function,
            self.offset + 2,
            (self.control & !(MSIX_ENABLE | FUNCTION_MASK)) | flags,
        );
        let control = self.read(self.offset);
        control as u8 == MSIX && ((control >> 16) as u16 & (MSIX_ENABLE | FUNCTION_MASK)) == flags
    }

    fn read(self, offset: u8) -> u32 {
        // SAFETY: All callers hold the exclusive function lease and serialize
        // the shared configuration ports.
        unsafe { read_config(self.function, offset) }
    }
}

fn region(register: u32, bytes: u64) -> (usize, u64, u64) {
    ((register & 7) as usize, u64::from(register & !7), bytes)
}

/// One vector in a validated uncacheable MSI-X table.
#[derive(Clone, Copy)]
pub struct Msix {
    layout: MsixLayout,
    table: u64,
    vector: u16,
}

impl Msix {
    /// Resolve a vector in a privately mapped table.
    ///
    /// # Safety
    /// The entire validated table must be live, uncached, and inaccessible
    /// to userspace. The exclusive endpoint lease outlives this vector.
    pub unsafe fn new(layout: MsixLayout, table: VirtAddr, vector: u16) -> Option<Self> {
        (vector < layout.vector_count()).then_some(Self {
            layout,
            table: table.as_u64(),
            vector,
        })
    }

    pub(crate) fn function(self) -> u16 {
        self.layout.function
    }

    pub(crate) fn vector(self) -> u16 {
        self.vector
    }

    pub(crate) fn initially_disabled(self) -> bool {
        let control = self.layout.read(self.layout.offset);
        control as u8 == MSIX
            && (control >> 16) as u16 & MSIX_ENABLE == 0
            && self
                .layout
                .msi_offset
                .is_none_or(|offset| (self.layout.read(offset) >> 16) as u16 & ENABLE == 0)
    }

    pub(crate) fn start(self) -> bool {
        if !set_intx_disabled(self.function(), true)
            || !self.layout.set_control(MSIX_ENABLE | FUNCTION_MASK)
        {
            return false;
        }
        // Hide unused firmware entries before allowing per-vector delivery.
        for vector in 0..self.layout.vector_count() {
            if !(Self { vector, ..self }).set_enabled(false) {
                return false;
            }
        }
        self.layout.set_control(MSIX_ENABLE)
    }

    pub(crate) fn program(self, address: u32) -> bool {
        if !self.set_enabled(false) {
            return false;
        }
        self.write(0, address);
        self.write(4, 0);
        self.write(8, 0);
        self.read(0) == address && self.read(4) == 0 && self.read(8) == 0
    }

    pub(crate) fn set_enabled(self, enabled: bool) -> bool {
        let control = (self.read(12) & !VECTOR_MASK) | u32::from(!enabled);
        self.write(12, control);
        self.read(12) & VECTOR_MASK == u32::from(!enabled)
    }

    pub(crate) fn finish(self) -> bool {
        self.layout.set_control(FUNCTION_MASK)
            && self.layout.set_control(self.layout.control & FUNCTION_MASK)
            && set_intx_disabled(self.function(), self.layout.intx_disabled)
    }

    fn read(self, offset: u64) -> u32 {
        let register = self.table + u64::from(self.vector) * ENTRY_BYTES + offset;
        // SAFETY: A serialized access to a dword in the validated table.
        unsafe { (register as *const u32).read_volatile() }
    }

    fn write(self, offset: u64, value: u32) {
        let register = self.table + u64::from(self.vector) * ENTRY_BYTES + offset;
        // SAFETY: This table is private and the kernel holds the function lease.
        unsafe { (register as *mut u32).write_volatile(value) }
    }
}
