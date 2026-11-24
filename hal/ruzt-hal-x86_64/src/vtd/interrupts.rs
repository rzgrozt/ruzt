//! Intel VT-d interrupt-remapping table for fixed physical delivery.

use ruzt_hal::mem::{PhysFrame, VirtAddr};

use super::{wait, Error, Unit, GLOBAL_STATUS};

const TABLE_ADDRESS: usize = 0xb8;
const SET_TABLE_POINTER: u32 = 1 << 24;
const COMPATIBILITY_FORMAT: u32 = 1 << 23;
pub(super) const ENABLE: u32 = 1 << 25;
const EXTENDED_MODE: u64 = 1 << 11;
const TABLE_SIZE: u64 = 7; // 2^(7 + 1) 128-bit entries occupy one page.
const SOURCE_VALIDATION: u64 = 1 << 18;
const PRESENT: u64 = 1;

/// A private, page-sized interrupt-remapping table on a boot-owned VT-d unit.
pub struct InterruptTable {
    unit: &'static Unit,
    frame: PhysFrame,
    alias: VirtAddr,
    extended: bool,
}

impl InterruptTable {
    /// Describe the interrupt table before programming it.
    ///
    /// # Safety
    /// The frame must be zeroed, addressable by this unit, and exclusively
    /// reserved with its writable alias for the lifetime of the hardware,
    /// including on a command timeout. The kernel serializes updates.
    pub unsafe fn new(
        unit: &'static Unit,
        frame: PhysFrame,
        alias: VirtAddr,
        extended: bool,
    ) -> Self {
        Self {
            unit,
            frame,
            alias,
            extended,
        }
    }

    /// Stage an entry that is empty or has been retired and drained.
    pub(crate) fn stage(&self, index: u8, source: u16, vector: u8, destination: u8, level: bool) {
        let destination_shift = if self.extended { 32 } else { 40 };
        let low = (u64::from(destination) << destination_shift)
            | (u64::from(vector) << 16)
            | (u64::from(level) << 4)
            | PRESENT;
        // SVT=01 and SQ=00 require an exact match of all requester ID bits.
        let high = SOURCE_VALIDATION | u64::from(source);
        let entry = self.entry(index);
        // SAFETY: Both words are in the pinned table. Publish the requester
        // before making the entry present. The preceding lease, if any,
        // was invalidated before this index was reused.
        unsafe {
            entry.add(1).write_volatile(high);
            entry.write_volatile(low);
        }
    }

    pub(crate) fn activate(&self) -> Result<(), Error> {
        self.publish()?;
        let mode = if self.extended { EXTENDED_MODE } else { 0 };
        self.unit
            .write64(TABLE_ADDRESS, self.frame.base.as_u64() | mode | TABLE_SIZE);
        self.unit.command(SET_TABLE_POINTER);
        wait(|| self.unit.read32(GLOBAL_STATUS) & SET_TABLE_POINTER != 0)?;
        self.unit.invalidate_interrupts()?;
        self.unit.command(ENABLE);
        wait(|| self.unit.read32(GLOBAL_STATUS) & (ENABLE | COMPATIBILITY_FORMAT) == ENABLE)
    }

    pub(crate) fn sync(&self) -> Result<(), Error> {
        self.publish()?;
        self.unit.invalidate_interrupts()
    }

    pub(crate) fn retire(&self, index: u8) -> Result<(), Error> {
        // SAFETY: The low qword fits in the pinned table. Clear its present
        // bit before invalidation drains any request using the old entry.
        unsafe { self.entry(index).write_volatile(0) };
        self.sync()
    }

    fn entry(&self, index: u8) -> *mut u64 {
        (self.alias.as_u64() + u64::from(index) * 16) as *mut u64
    }

    fn publish(&self) -> Result<(), Error> {
        // SAFETY: The table occupies one live, aligned frame.
        unsafe { self.unit.publish_frame(self.alias) }
    }
}
