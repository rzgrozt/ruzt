//! Synchronous submission to a legacy VT-d invalidation queue.

use core::sync::atomic::{fence, Ordering};

use ruzt_hal::mem::{PhysFrame, VirtAddr};

use super::{wait, Error, Unit, CONTEXT_COMMAND, GLOBAL_STATUS, INVALIDATE};

const HEAD: usize = 0x80;
const TAIL: usize = 0x88;
const ADDRESS: usize = 0x90;
const FAULT_STATUS: usize = 0x34;
const QUEUE_ERRORS: u32 = (1 << 4) | (1 << 5) | (1 << 6);
pub(super) const ENABLE: u32 = 1 << 26;

const QUEUE_BYTES: u64 = PhysFrame::SIZE as u64;
const DESCRIPTOR_BYTES: u64 = 16;
const CONTEXT: u64 = 1;
const IOTLB: u64 = 2;
const INTERRUPT_ENTRY_CACHE: u64 = 4;
const GLOBAL: u64 = 1 << 4;
const WAIT: u64 = 5;
const STATUS_WRITE: u64 = 1 << 5;
const COMPLETE: u32 = 1;

pub(super) struct Queue {
    physical: u64,
    alias: u64,
    failed: bool,
}

impl Queue {
    pub(super) fn start(unit: &Unit, base: PhysFrame, alias: VirtAddr) -> Result<Self, Error> {
        wait(|| unit.read64(CONTEXT_COMMAND) & INVALIDATE == 0)?;
        wait(|| unit.read64(unit.iotlb) & INVALIDATE == 0)?;
        unit.write64(TAIL, 0);
        // Queue size and descriptor width zero select one page of 128-bit entries.
        unit.write64(ADDRESS, base.base.as_u64());
        unit.command(ENABLE);
        wait(|| unit.read32(GLOBAL_STATUS) & ENABLE != 0)?;
        Ok(Self {
            physical: base.base.as_u64(),
            alias: alias.as_u64(),
            failed: false,
        })
    }

    pub(super) fn invalidate_dma(&mut self, unit: &Unit) -> Result<(), Error> {
        let drains = ((unit.capability >> 55) & 1) << 7 | ((unit.capability >> 54) & 1) << 6;
        self.submit(unit, &[[CONTEXT | GLOBAL, 0], [IOTLB | GLOBAL | drains, 0]])
    }

    pub(super) fn invalidate_interrupts(&mut self, unit: &Unit) -> Result<(), Error> {
        self.submit(unit, &[[INTERRUPT_ENTRY_CACHE, 0]])
    }

    fn submit(&mut self, unit: &Unit, descriptors: &[[u64; 2]]) -> Result<(), Error> {
        assert!(descriptors.len() + 1 < (QUEUE_BYTES / DESCRIPTOR_BYTES) as usize);
        if self.failed {
            return Err(Error::InvalidationFailed);
        }
        // A hardware timeout can leave a delayed status write outstanding.
        // Abandon the queue on failure so that write cannot complete a later batch.
        self.failed = true;
        let mut tail = unit.read64(TAIL);
        if tail >= QUEUE_BYTES || tail % DESCRIPTOR_BYTES != 0 {
            return Err(Error::InvalidationFailed);
        }
        // The preceding status write may become visible before the head advances.
        Self::wait_for(unit, || unit.read64(HEAD) == tail)?;
        let status = (self.alias + QUEUE_BYTES) as *mut u32;
        // SAFETY: Queue initialization reserves the adjacent page for coherent
        // status writes. The preceding batch has completed and only this CPU submits.
        unsafe { status.write_volatile(0) };
        for descriptor in descriptors {
            tail = self.write_descriptor(tail, *descriptor);
        }
        let wait = [
            WAIT | STATUS_WRITE | (u64::from(COMPLETE) << 32),
            self.physical + QUEUE_BYTES,
        ];
        tail = self.write_descriptor(tail, wait);
        // VT-d always snoops queue and wait status accesses.
        fence(Ordering::SeqCst);
        unit.write64(TAIL, tail);
        // SAFETY: The coherent completion word remains pinned while hardware
        // can write it, including if polling times out.
        Self::wait_for(unit, || unsafe { status.read_volatile() == COMPLETE })?;
        fence(Ordering::Acquire);
        self.failed = false;
        Ok(())
    }

    fn write_descriptor(&self, offset: u64, [low, high]: [u64; 2]) -> u64 {
        let descriptor = (self.alias + offset) as *mut u64;
        // SAFETY: The queue is empty at submission and offsets name unused,
        // aligned slots. Hardware cannot fetch them until the tail advances.
        unsafe {
            descriptor.write_volatile(low);
            descriptor.add(1).write_volatile(high);
        }
        (offset + DESCRIPTOR_BYTES) % QUEUE_BYTES
    }

    fn wait_for(unit: &Unit, mut complete: impl FnMut() -> bool) -> Result<(), Error> {
        wait(|| complete() || unit.read32(FAULT_STATUS) & QUEUE_ERRORS != 0)?;
        if unit.read32(FAULT_STATUS) & QUEUE_ERRORS != 0 {
            return Err(Error::InvalidationFailed);
        }
        Ok(())
    }
}
