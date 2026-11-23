//! Register interface for legacy Intel VT-d DMA translation.

use ruzt_hal::mem::{PhysFrame, VirtAddr};

const VERSION: usize = 0;
const CAPABILITY: usize = 8;
const EXTENDED_CAPABILITY: usize = 16;
const GLOBAL_COMMAND: usize = 0x18;
const GLOBAL_STATUS: usize = 0x1c;
const ROOT_ADDRESS: usize = 0x20;
const CONTEXT_COMMAND: usize = 0x28;
const FAULT_EVENT_CONTROL: usize = 0x38;
const TRANSLATION_ENABLE: u32 = 1 << 31;
const SET_ROOT_POINTER: u32 = 1 << 30;
const WRITE_BUFFER_FLUSH: u32 = 1 << 27;
const INVALIDATE: u64 = 1 << 63;
const CONTEXT_GLOBAL: u64 = 1 << 61;
const IOTLB_GLOBAL: u64 = 1 << 60;
const WAIT_LIMIT: usize = 1_000_000;

/// Error activating DMA translation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Remapping hardware or its initial mode is unsupported.
    Unsupported,
    /// A remapping register operation did not complete.
    TimedOut,
    /// Hardware rejected a requested global invalidation.
    InvalidationFailed,
}

/// A remapping unit with registers mapped uncached.
pub struct Unit {
    registers: u64,
    iotlb: usize,
    capability: u64,
    extended: u64,
}

impl Unit {
    /// Inspect the legacy remapping registers before changing their state.
    ///
    /// # Safety
    /// `registers` must be one live, uncached page of VT-d registers, owned
    /// exclusively by this caller for the lifetime of the returned unit.
    pub unsafe fn inspect(registers: VirtAddr) -> Result<Self, Error> {
        let mut unit = Self {
            registers: registers.as_u64(),
            iotlb: 0,
            capability: 0,
            extended: 0,
        };
        let version = unit.read32(VERSION);
        unit.capability = unit.read64(CAPABILITY);
        unit.extended = unit.read64(EXTENDED_CAPABILITY);
        unit.iotlb = ((unit.extended >> 8) & 0x3ff) as usize * 16 + 8;
        let status = unit.read32(GLOBAL_STATUS);
        const COMMAND_STATE: u32 = (1 << 31)
            | (1 << 30)
            | (1 << 29)
            | (1 << 28)
            | (1 << 26)
            | (1 << 25)
            | (1 << 24)
            | (1 << 23);
        let major = version >> 4 & 0xf;
        if !(1..6).contains(&major)
            || unit.capability >> 8 & 0b11111 == 0
            || unit.iotlb < 0x48
            || unit.iotlb > PhysFrame::SIZE - 8
            || status & COMMAND_STATE != 0
        {
            return Err(Error::Unsupported);
        }
        Ok(unit)
    }

    /// Whether the unit observes cached CPU writes to translation tables.
    pub fn coherent(&self) -> bool {
        self.extended & 1 != 0
    }

    /// Activate legacy translation using a fully initialized root table.
    ///
    /// # Safety
    /// The root table and all referenced tables must be visible to this unit
    /// and remain allocated for as long as it could access them, including
    /// after an error. The caller must control the covered devices.
    pub unsafe fn enable(&self, root: PhysFrame) -> Result<(), Error> {
        // Kernel polling is used for primary faults until interrupt
        // remapping and fault interrupt routing are installed.
        self.write32(FAULT_EVENT_CONTROL, 1 << 31);
        if self.capability & (1 << 4) != 0 {
            self.write32(GLOBAL_COMMAND, WRITE_BUFFER_FLUSH);
            wait(|| self.read32(GLOBAL_STATUS) & WRITE_BUFFER_FLUSH == 0)?;
        }
        self.write64(ROOT_ADDRESS, root.base.as_u64());
        self.write32(GLOBAL_COMMAND, SET_ROOT_POINTER);
        wait(|| self.read32(GLOBAL_STATUS) & SET_ROOT_POINTER != 0)?;
        self.write64(CONTEXT_COMMAND, INVALIDATE | CONTEXT_GLOBAL);
        wait(|| self.read64(CONTEXT_COMMAND) & INVALIDATE == 0)?;
        if self.read64(CONTEXT_COMMAND) >> 59 & 3 != 1 {
            return Err(Error::InvalidationFailed);
        }
        let drains = ((self.capability >> 55) & 1) << 49 | ((self.capability >> 54) & 1) << 48;
        self.write64(self.iotlb, INVALIDATE | IOTLB_GLOBAL | drains);
        wait(|| self.read64(self.iotlb) & INVALIDATE == 0)?;
        if self.read64(self.iotlb) >> 57 & 3 != 1 {
            return Err(Error::InvalidationFailed);
        }
        self.write32(GLOBAL_COMMAND, TRANSLATION_ENABLE);
        wait(|| self.read32(GLOBAL_STATUS) & TRANSLATION_ENABLE != 0)
    }

    /// Whether the unit has logged a fault for this source and DMA page.
    pub fn take_fault(&self, source: u16, address: u64) -> bool {
        let first = ((self.capability >> 24) & 0x3ff) as usize * 16;
        let count = ((self.capability >> 40) & 0xff) as usize + 1;
        if first < 0x48 || first + count * 16 > PhysFrame::SIZE {
            return false;
        }
        for index in 0..count {
            let record = first + index * 16;
            let high = self.read64(record + 8);
            if high >> 63 != 0
                && high as u16 == source
                && self.read64(record) & !0xfff == address & !0xfff
            {
                self.write64(record + 8, 1 << 63);
                return true;
            }
        }
        false
    }

    fn read32(&self, offset: usize) -> u32 {
        // SAFETY: Construction requires a live uncached register page.
        unsafe { core::ptr::read_volatile((self.registers + offset as u64) as *const u32) }
    }

    fn read64(&self, offset: usize) -> u64 {
        // SAFETY: The register offsets are aligned and in the same page.
        unsafe { core::ptr::read_volatile((self.registers + offset as u64) as *const u64) }
    }

    fn write32(&self, offset: usize, value: u32) {
        // SAFETY: These are writable registers in the exclusively owned page.
        unsafe { core::ptr::write_volatile((self.registers + offset as u64) as *mut u32, value) };
    }

    fn write64(&self, offset: usize, value: u64) {
        // SAFETY: These registers accept aligned qword writes.
        unsafe { core::ptr::write_volatile((self.registers + offset as u64) as *mut u64, value) };
    }
}

fn wait(mut ready: impl FnMut() -> bool) -> Result<(), Error> {
    for _ in 0..WAIT_LIMIT {
        if ready() {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(Error::TimedOut)
}
