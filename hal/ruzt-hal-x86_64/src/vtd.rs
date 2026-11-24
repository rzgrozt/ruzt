//! Register interface for legacy Intel VT-d DMA translation.

use core::sync::atomic::{fence, Ordering};

use ruzt_hal::mem::{PhysFrame, VirtAddr};
use spin::Mutex;

mod interrupts;
mod queue;
pub use interrupts::InterruptTable;
use queue::Queue;

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
const GLOBAL_PERSISTENT_STATE: u32 = TRANSLATION_ENABLE | queue::ENABLE | interrupts::ENABLE;
const INVALIDATE: u64 = 1 << 63;
const CONTEXT_GLOBAL: u64 = 1 << 61;
const IOTLB_GLOBAL: u64 = 1 << 60;
const WAIT_LIMIT: usize = 1_000_000;

/// Frames for the invalidation ring and its hardware completion word.
pub const INVALIDATION_PAGES: usize = 2;

/// Error activating DMA translation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Remapping hardware or its initial mode is unsupported.
    Unsupported,
    /// A remapping register operation did not complete.
    TimedOut,
    /// An invalidation failed or the queue lost synchronization.
    InvalidationFailed,
    /// The CPU cannot publish cacheable pages for a non-coherent unit.
    CacheMaintenance,
}

/// A remapping unit with registers mapped uncached.
pub struct Unit {
    registers: u64,
    iotlb: usize,
    capability: u64,
    extended: u64,
    queue: Option<Mutex<Queue>>,
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
            queue: None,
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
            || unit.capability & 7 == 7
            || unit.iotlb < 0x48
            || unit.iotlb > PhysFrame::SIZE - 8
            || status & COMMAND_STATE != 0
        {
            return Err(Error::Unsupported);
        }
        Ok(unit)
    }

    /// Whether second-stage leaves can force DMA to snoop processor caches.
    pub fn snoop_control(&self) -> bool {
        self.extended & (1 << 7) != 0
    }

    /// Supported depth for a legacy second-stage page table.
    pub fn page_table_levels(&self) -> Option<u8> {
        if self.capability & (1 << 9) != 0 {
            Some(3)
        } else if self.capability & (1 << 10) != 0 {
            Some(4)
        } else {
            None
        }
    }

    /// Whether IOTLB invalidation can drain both reads and posted writes.
    pub fn can_drain(&self) -> bool {
        self.capability >> 54 & 3 == 3
    }

    /// Whether hardware accepts queued invalidation descriptors.
    pub fn supports_queued_invalidation(&self) -> bool {
        self.extended & (1 << 1) != 0
    }

    /// Whether translation is using the invalidation queue.
    pub fn uses_queued_invalidation(&self) -> bool {
        self.queue.is_some()
    }

    /// Whether interrupt remapping is available in the requested LAPIC mode.
    pub fn supports_interrupt_remapping(&self, extended: bool) -> bool {
        let mode_supported = if extended {
            self.extended & (1 << 4) != 0
        } else {
            self.extended & (1 << 61) == 0
        };
        self.queue.is_some() && self.extended & (1 << 3) != 0 && mode_supported
    }

    /// Publish a page of translation entries to the remapper.
    ///
    /// # Safety
    /// The alias must cover one aligned, mapped page of remapping entries.
    pub unsafe fn publish_frame(&self, alias: VirtAddr) -> Result<(), Error> {
        if self.extended & 1 == 0 {
            let features = core::arch::x86_64::__cpuid(1);
            let line = ((features.ebx >> 8) & 0xff) as usize * 8;
            if features.edx & (1 << 19) == 0 || !line.is_power_of_two() || line > PhysFrame::SIZE {
                return Err(Error::CacheMaintenance);
            }
            for offset in (0..PhysFrame::SIZE).step_by(line) {
                // SAFETY: The caller guarantees the page and CPUID confirms CLFLUSH.
                unsafe {
                    core::arch::asm!("clflush [{address}]", address = in(reg) alias.as_u64() + offset as u64,
                        options(nostack, preserves_flags));
                }
            }
        }
        fence(Ordering::SeqCst);
        Ok(())
    }

    /// Maximum count of distinct domain IDs, including reserved ID zero.
    pub fn domain_count(&self) -> usize {
        1 << (4 + 2 * (self.capability & 7))
    }

    /// Activate legacy translation using a fully initialized root table.
    ///
    /// # Safety
    /// The root table and all referenced tables must be visible to this unit
    /// and remain allocated for as long as it could access them, including
    /// after an error. On units with queued invalidation, `queue` must name
    /// `INVALIDATION_PAGES` contiguous pinned RAM frames and their writable
    /// contiguous alias. Reserve both frames exclusively for VT-d. The
    /// caller must control the covered devices.
    pub unsafe fn enable(
        &mut self,
        root: PhysFrame,
        queue: Option<(PhysFrame, VirtAddr)>,
    ) -> Result<(), Error> {
        if queue.is_some() != self.supports_queued_invalidation() {
            return Err(Error::Unsupported);
        }
        // Kernel polling is used for primary faults until interrupt
        // remapping and fault interrupt routing are installed.
        self.write32(FAULT_EVENT_CONTROL, 1 << 31);
        self.write64(ROOT_ADDRESS, root.base.as_u64());
        self.command(SET_ROOT_POINTER);
        wait(|| self.read32(GLOBAL_STATUS) & SET_ROOT_POINTER != 0)?;
        if let Some((base, alias)) = queue {
            self.queue = Some(Mutex::new(Queue::start(self, base, alias)?));
        }
        self.invalidate_all()?;
        self.command(TRANSLATION_ENABLE);
        wait(|| self.read32(GLOBAL_STATUS) & TRANSLATION_ENABLE != 0)
    }

    /// Invalidate legacy context and IOTLB caches, draining pending DMA when supported.
    ///
    /// The caller must serialize register commands and keep affected pages
    /// pinned until this operation completes successfully.
    pub fn invalidate_all(&self) -> Result<(), Error> {
        if self.capability & (1 << 4) != 0 {
            self.command(WRITE_BUFFER_FLUSH);
            wait(|| self.read32(GLOBAL_STATUS) & WRITE_BUFFER_FLUSH == 0)?;
        }
        if let Some(queue) = &self.queue {
            return queue.lock().invalidate_dma(self);
        }
        self.invalidate_registers()
    }

    fn invalidate_registers(&self) -> Result<(), Error> {
        wait(|| self.read64(CONTEXT_COMMAND) & INVALIDATE == 0)?;
        wait(|| self.read64(self.iotlb) & INVALIDATE == 0)?;
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
        Ok(())
    }

    fn command(&self, bits: u32) {
        let state = self.read32(GLOBAL_STATUS) & GLOBAL_PERSISTENT_STATE;
        self.write32(GLOBAL_COMMAND, state | bits);
    }

    fn invalidate_interrupts(&self) -> Result<(), Error> {
        let queue = self.queue.as_ref().ok_or(Error::Unsupported)?;
        queue.lock().invalidate_interrupts(self)
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
