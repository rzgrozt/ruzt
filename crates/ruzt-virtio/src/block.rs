//! One in-flight request in a modern split virtqueue, using a pinned DMA arena.
//! No indirect descriptors, event index, packed rings or unchecked device indices.

use core::sync::atomic::{fence, Ordering};

#[cfg(test)]
mod tests;

pub const QUEUE_SIZE: u16 = 8;
pub const DMA_BYTES: usize = 8192;
pub const MAX_TRANSFER: usize = 4096;
const AVAIL: usize = 128;
const USED: usize = 256;
const HEADER: usize = 512;
const STATUS: usize = 528;
const DATA: usize = 4096;
const VERSION_1: u64 = 1 << 32;
const ACCESS_PLATFORM: u64 = 1 << 33;
const FLUSH: u64 = 1 << 9;
const READ_ONLY: u64 = 1 << 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Transport,
    Unsupported,
    Bounds,
    ReadOnly,
    Busy,
    Device,
    Io,
    Failed,
}

/// Access to live modern PCI common/device/notification windows.
/// Implementations must validate mapping bounds and register access widths.
pub trait Transport {
    fn read8(&self, offset: u64) -> Result<u8, Error>;
    fn read16(&self, offset: u64) -> Result<u16, Error>;
    fn read32(&self, offset: u64) -> Result<u32, Error>;
    fn write8(&mut self, offset: u64, value: u8) -> Result<(), Error>;
    fn write16(&mut self, offset: u64, value: u16) -> Result<(), Error>;
    fn write32(&mut self, offset: u64, value: u32) -> Result<(), Error>;
    fn device32(&self, offset: u64) -> Result<u32, Error>;
    fn notify(&mut self) -> Result<(), Error>;
}

/// Access to a cache-coherent DMA arena with a device-visible IOVA base.
/// Reads and writes must copy bytes without creating references into DMA memory.
/// The mapping and DMA lease must remain live until device reset or kernel DMA
/// teardown, including after an error or after this accessor is dropped.
pub trait Dma {
    fn bytes(&self) -> usize;
    fn iova(&self) -> u64;
    fn read(&self, offset: usize, output: &mut [u8]) -> Result<(), Error>;
    fn write(&mut self, offset: usize, input: &[u8]) -> Result<(), Error>;
    /// Naturally aligned, single-copy ring index accesses, without byte tearing.
    fn read_index(&self, offset: usize) -> Result<u16, Error>;
    fn write_index(&mut self, offset: usize, value: u16) -> Result<(), Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Idle,
    Pending { bytes: usize, read: bool },
    Failed,
}

pub struct Block<T: Transport, D: Dma> {
    transport: T,
    dma: D,
    sectors: u64,
    read_only: bool,
    flush: bool,
    index: u16,
    state: State,
}

impl<T: Transport, D: Dma> Block<T, D> {
    /// Initialize queue zero, using MSI-X entry zero for request completions.
    /// The adapter must have bound that interrupt before enabling the queue.
    pub fn new(mut transport: T, mut dma: D) -> Result<Self, Error> {
        if dma.bytes() < DMA_BYTES
            || !dma.iova().is_multiple_of(4096)
            || dma.iova().checked_add(DMA_BYTES as u64).is_none()
        {
            return Err(Error::Bounds);
        }
        transport.write8(20, 0)?;
        let mut reset = false;
        for _ in 0..1000 {
            if transport.read8(20)? == 0 {
                reset = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !reset {
            return Err(Error::Failed);
        }
        transport.write8(20, 3)?;
        transport.write32(0, 0)?;
        let low = u64::from(transport.read32(4)?);
        transport.write32(0, 1)?;
        let features = low | u64::from(transport.read32(4)?) << 32;
        if features & (VERSION_1 | ACCESS_PLATFORM) != (VERSION_1 | ACCESS_PLATFORM) {
            return Err(Error::Unsupported);
        }
        let read_only = features & READ_ONLY != 0;
        let flush = features & FLUSH != 0;
        if !read_only && !flush {
            return Err(Error::Unsupported);
        }
        let accepted = features & (VERSION_1 | ACCESS_PLATFORM | READ_ONLY | FLUSH);
        for select in 0..2 {
            transport.write32(8, select)?;
            transport.write32(12, (accepted >> (select * 32)) as u32)?;
        }
        transport.write8(20, 11)?;
        if transport.read8(20)? != 11 {
            return Err(Error::Unsupported);
        }
        let mut capacity = None;
        for _ in 0..8 {
            let before = transport.read8(21)?;
            let low = u64::from(transport.device32(0)?);
            let high = u64::from(transport.device32(4)?);
            if transport.read8(21)? == before {
                capacity = Some(low | high << 32);
                break;
            }
        }
        let sectors = capacity
            .filter(|capacity| *capacity != 0)
            .ok_or(Error::Device)?;
        transport.write16(22, 0)?;
        if transport.read16(18)? == 0
            || transport.read16(24)? < QUEUE_SIZE
            || transport.read16(28)? != 0
        {
            return Err(Error::Unsupported);
        }
        // Only queue zero is armed. Configuration changes are checked before
        // every operation and are never assigned a live interrupt vector.
        transport.write16(16, 0xffff)?;
        transport.write16(24, QUEUE_SIZE)?;
        transport.write16(26, 0)?;
        if transport.read16(26)? != 0 {
            return Err(Error::Unsupported);
        }
        for offset in (0..DMA_BYTES).step_by(64) {
            dma.write(offset, &[0; 64])?;
        }
        for (register, offset) in [(32, 0), (40, AVAIL), (48, USED)] {
            let address = dma.iova() + offset as u64;
            transport.write32(register, address as u32)?;
            transport.write32(register + 4, (address >> 32) as u32)?;
        }
        fence(Ordering::SeqCst);
        transport.write16(28, 1)?;
        transport.write8(20, 15)?;
        if transport.read8(20)? != 15 {
            return Err(Error::Failed);
        }
        Ok(Self {
            transport,
            dma,
            sectors,
            read_only,
            flush,
            index: 0,
            state: State::Idle,
        })
    }

    pub fn sectors(&self) -> u64 {
        self.sectors
    }
    pub fn read_only(&self) -> bool {
        self.read_only
    }
    pub fn supports_flush(&self) -> bool {
        self.flush
    }

    pub fn begin_read(&mut self, sector: u64, bytes: usize) -> Result<(), Error> {
        self.validate_range(sector, bytes)?;
        self.submit(0, sector, bytes, true)
    }

    pub fn begin_write(&mut self, sector: u64, data: &[u8]) -> Result<(), Error> {
        self.validate_range(sector, data.len())?;
        if self.read_only {
            return Err(Error::ReadOnly);
        }
        self.idle()?;
        self.dma.write(DATA, data)?;
        self.submit(1, sector, data.len(), false)
    }

    pub fn begin_flush(&mut self) -> Result<(), Error> {
        if !self.flush {
            return Err(Error::Unsupported);
        }
        self.submit(4, 0, 0, false)
    }

    fn validate_range(&self, sector: u64, bytes: usize) -> Result<(), Error> {
        if bytes == 0
            || bytes > MAX_TRANSFER
            || !bytes.is_multiple_of(512)
            || sector
                .checked_add((bytes / 512) as u64)
                .is_none_or(|end| end > self.sectors)
        {
            return Err(Error::Bounds);
        }
        Ok(())
    }

    fn idle(&self) -> Result<(), Error> {
        match self.state {
            State::Idle => Ok(()),
            State::Pending { .. } => Err(Error::Busy),
            State::Failed => Err(Error::Failed),
        }
    }

    fn submit(&mut self, kind: u32, sector: u64, bytes: usize, read: bool) -> Result<(), Error> {
        self.idle()?;
        // From here every failure poisons the queue. The owner must reset or
        // terminate the service before any DMA memory can be repurposed.
        self.state = State::Failed;
        if self.transport.read8(20)? != 15 {
            return Err(Error::Failed);
        }
        let generation = self.transport.read8(21)?;
        let capacity =
            u64::from(self.transport.device32(0)?) | u64::from(self.transport.device32(4)?) << 32;
        if self.transport.read8(21)? != generation || capacity != self.sectors {
            return Err(Error::Device);
        }
        self.dma.write(HEADER, &kind.to_le_bytes())?;
        self.dma.write(HEADER + 4, &0u32.to_le_bytes())?;
        self.dma.write(HEADER + 8, &sector.to_le_bytes())?;
        self.dma.write(STATUS, &[0xff])?;
        self.descriptor(0, HEADER, 16, 1, 1)?;
        if bytes != 0 {
            self.descriptor(1, DATA, bytes as u32, 1 | if read { 2 } else { 0 }, 2)?;
            self.descriptor(2, STATUS, 1, 2, 0)?;
        } else {
            self.descriptor(1, STATUS, 1, 2, 0)?;
        }
        self.dma.write(
            AVAIL + 4 + usize::from(self.index % QUEUE_SIZE) * 2,
            &0u16.to_le_bytes(),
        )?;
        fence(Ordering::SeqCst);
        self.dma
            .write_index(AVAIL + 2, self.index.wrapping_add(1))?;
        fence(Ordering::SeqCst);
        self.transport.notify()?;
        self.state = State::Pending { bytes, read };
        Ok(())
    }

    fn descriptor(
        &mut self,
        index: usize,
        offset: usize,
        bytes: u32,
        flags: u16,
        next: u16,
    ) -> Result<(), Error> {
        let at = index * 16;
        self.dma
            .write(at, &(self.dma.iova() + offset as u64).to_le_bytes())?;
        self.dma.write(at + 8, &bytes.to_le_bytes())?;
        self.dma.write(at + 12, &flags.to_le_bytes())?;
        self.dma.write(at + 14, &next.to_le_bytes())
    }

    /// Complete at most one request. A read needs an output of exactly its
    /// requested length. A pending device retains ownership until completion.
    pub fn poll(&mut self, output: &mut [u8]) -> Result<bool, Error> {
        let State::Pending { bytes, read } = self.state else {
            return Err(Error::Failed);
        };
        if output.len() != if read { bytes } else { 0 } {
            return Err(Error::Bounds);
        }
        let used = self.dma.read_index(USED + 2)?;
        if used == self.index {
            return Ok(false);
        }
        fence(Ordering::SeqCst);
        self.state = State::Failed;
        if used != self.index.wrapping_add(1) {
            return Err(Error::Device);
        }
        let mut entry = [0; 8];
        self.dma.read(
            USED + 4 + usize::from(self.index % QUEUE_SIZE) * 8,
            &mut entry,
        )?;
        let id = u32::from_le_bytes(entry[..4].try_into().unwrap());
        let written = u32::from_le_bytes(entry[4..].try_into().unwrap()) as usize;
        let mut status = [0xff];
        self.dma.read(STATUS, &mut status)?;
        if id != 0 || written == 0 || written > if read { bytes + 1 } else { 1 } {
            return Err(Error::Device);
        }
        self.index = used;
        match status[0] {
            0 => {
                if written != if read { bytes + 1 } else { 1 } {
                    return Err(Error::Device);
                }
                if read {
                    self.dma.read(DATA, output)?;
                }
                self.state = State::Idle;
                Ok(true)
            }
            1 | 2 => {
                self.state = State::Idle;
                Err(if status[0] == 1 {
                    Error::Io
                } else {
                    Error::Unsupported
                })
            }
            _ => Err(Error::Device),
        }
    }
}
