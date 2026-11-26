//! The driver's small unsafe boundary. All mappings belong to process-local
//! capability slots and are retained until exit. Kernel exit teardown disables
//! bus mastering and drains VT-d before reclaiming them, including on timeouts.

use ruzt_abi::{block, ErrorCode, DMA_READ, DMA_WRITE};
use ruzt_driver_sdk::{map_mmio, open_pci_bar, MmioRegion};
use ruzt_virtio::{
    block::{Block, Dma, Error, Transport},
    pci::{Capabilities, Region},
};

const COMMON: u64 = 4;
const DEVICE_CONFIG: u64 = 5;
const NOTIFY: u64 = 6;
pub const IRQ: u64 = 7;
pub(super) const DMA: u64 = 8;
const DMA_ADDRESS: u64 = 0x6400_0000;
const SHARED_ADDRESS: u64 = 0x6500_0000;

/// A retained CPU-only IPC frame, separate from the device's DMA arena.
pub struct SharedFrame {
    _mapped: (),
}

impl SharedFrame {
    pub fn map(cap: u64) -> Result<Self, ErrorCode> {
        ruzt_ipc::map_frame(cap, SHARED_ADDRESS, true)?;
        Ok(Self { _mapped: () })
    }

    pub fn read(&self, output: &mut [u8]) -> Result<(), Error> {
        if output.len() > ruzt_abi::FRAME_BYTES {
            return Err(Error::Bounds);
        }
        for (index, byte) in output.iter_mut().enumerate() {
            // SAFETY: This retained shared mapping covers the bounded copy.
            // A client can change bytes concurrently without creating aliases
            // to Rust references in this process.
            *byte =
                unsafe { core::ptr::read_volatile((SHARED_ADDRESS as usize + index) as *const u8) };
        }
        Ok(())
    }

    pub fn write(&self, input: &[u8]) -> Result<(), Error> {
        if input.len() > ruzt_abi::FRAME_BYTES {
            return Err(Error::Bounds);
        }
        for (index, byte) in input.iter().enumerate() {
            // SAFETY: The retained frame is writable and this index is bounded.
            unsafe {
                core::ptr::write_volatile((SHARED_ADDRESS as usize + index) as *mut u8, *byte)
            };
        }
        Ok(())
    }
}

struct Window {
    mapping: MmioRegion,
    offset: u64,
}

impl Window {
    fn map(device: u64, slot: u64, region: Region, address: u64) -> Result<Self, ErrorCode> {
        let start = region.offset & !4095;
        let offset = region.offset - start;
        let pages = (offset + region.bytes).div_ceil(4096);
        open_pci_bar(device, slot, region.bar, start / 4096, pages)?;
        Ok(Self {
            mapping: map_mmio(slot, address, true)?,
            offset,
        })
    }
}

pub struct PciTransport {
    common: Window,
    config: Window,
    notify: Window,
    queue_offset: u16,
}

impl Transport for PciTransport {
    fn read8(&self, offset: u64) -> Result<u8, Error> {
        // SAFETY: The process retains this mapping; offsets name byte registers.
        unsafe { self.common.mapping.read_u8(self.common.offset + offset) }
            .map_err(|_| Error::Transport)
    }
    fn read16(&self, offset: u64) -> Result<u16, Error> {
        // SAFETY: The process retains the mapping of modern common registers.
        unsafe { self.common.mapping.read_u16(self.common.offset + offset) }
            .map_err(|_| Error::Transport)
    }
    fn read32(&self, offset: u64) -> Result<u32, Error> {
        // SAFETY: The process retains the mapping of modern common registers.
        unsafe { self.common.mapping.read_u32(self.common.offset + offset) }
            .map_err(|_| Error::Transport)
    }
    fn write8(&mut self, offset: u64, value: u8) -> Result<(), Error> {
        // SAFETY: This service exclusively owns device state and the live mapping.
        unsafe {
            self.common
                .mapping
                .write_u8(self.common.offset + offset, value)
        }
        .map_err(|_| Error::Transport)
    }
    fn write16(&mut self, offset: u64, value: u16) -> Result<(), Error> {
        // SAFETY: This service exclusively owns device state and the live mapping.
        unsafe {
            self.common
                .mapping
                .write_u16(self.common.offset + offset, value)
        }
        .map_err(|_| Error::Transport)
    }
    fn write32(&mut self, offset: u64, value: u32) -> Result<(), Error> {
        // SAFETY: This service exclusively owns device state and the live mapping.
        unsafe {
            self.common
                .mapping
                .write_u32(self.common.offset + offset, value)
        }
        .map_err(|_| Error::Transport)
    }
    fn device32(&self, offset: u64) -> Result<u32, Error> {
        // SAFETY: Only the two mapped capacity dwords are read by the block core.
        unsafe { self.config.mapping.read_u32(self.config.offset + offset) }
            .map_err(|_| Error::Transport)
    }
    fn notify(&mut self) -> Result<(), Error> {
        if self.read16(30)? != self.queue_offset {
            return Err(Error::Device);
        }
        // SAFETY: The checked notification subrange is queue zero's doorbell.
        unsafe { self.notify.mapping.write_u16(self.notify.offset, 0) }
            .map_err(|_| Error::Transport)
    }
}

/// Non-owning accessor. Dropping it does not release the process's DMA cap.
pub struct Arena {
    iova: u64,
}
impl Dma for Arena {
    fn bytes(&self) -> usize {
        ruzt_virtio::block::DMA_BYTES
    }
    fn iova(&self) -> u64 {
        self.iova
    }
    fn read(&self, offset: usize, output: &mut [u8]) -> Result<(), Error> {
        if offset
            .checked_add(output.len())
            .is_none_or(|end| end > self.bytes())
        {
            return Err(Error::Bounds);
        }
        for (index, byte) in output.iter_mut().enumerate() {
            // SAFETY: The retained mapping covers this bounded address. Bytewise
            // volatile copies never form Rust references into device-owned RAM.
            *byte = unsafe {
                core::ptr::read_volatile((DMA_ADDRESS as usize + offset + index) as *const u8)
            };
        }
        Ok(())
    }
    fn write(&mut self, offset: usize, input: &[u8]) -> Result<(), Error> {
        if offset
            .checked_add(input.len())
            .is_none_or(|end| end > self.bytes())
        {
            return Err(Error::Bounds);
        }
        for (index, byte) in input.iter().enumerate() {
            // SAFETY: Bounds checked above. Queue ownership and fences in the
            // core prohibit CPU writes while a request is device-owned.
            unsafe {
                core::ptr::write_volatile((DMA_ADDRESS as usize + offset + index) as *mut u8, *byte)
            };
        }
        Ok(())
    }
    fn read_index(&self, offset: usize) -> Result<u16, Error> {
        if offset % 2 != 0 || offset.checked_add(2).is_none_or(|end| end > self.bytes()) {
            return Err(Error::Bounds);
        }
        // SAFETY: This aligned index lies inside the retained coherent mapping.
        Ok(u16::from_le(unsafe {
            core::ptr::read_volatile((DMA_ADDRESS as usize + offset) as *const u16)
        }))
    }
    fn write_index(&mut self, offset: usize, value: u16) -> Result<(), Error> {
        if offset % 2 != 0 || offset.checked_add(2).is_none_or(|end| end > self.bytes()) {
            return Err(Error::Bounds);
        }
        // SAFETY: Publish the aligned available index with one 16-bit store.
        unsafe {
            core::ptr::write_volatile((DMA_ADDRESS as usize + offset) as *mut u16, value.to_le())
        };
        Ok(())
    }
}

pub fn initialize() -> Result<Block<PciTransport, Arena>, Error> {
    let caps = Capabilities::read(
        |offset| ruzt_driver_sdk::read_device_config(block::DEVICE, offset),
        2,
    )
    .map_err(|_| Error::Transport)?;
    let common = Window::map(
        block::DEVICE,
        COMMON,
        caps.common.subrange(0, 56).map_err(|_| Error::Bounds)?,
        0x6000_0000,
    )
    .map_err(|_| Error::Transport)?;
    // Stop firmware queues while PCI bus mastering is still disabled. The
    // block core repeats reset during negotiation, before publishing its queue.
    // SAFETY: The claimed lease owns this modern device's live common window.
    unsafe { common.mapping.write_u8(common.offset + 20, 0) }.map_err(|_| Error::Transport)?;
    let mut reset = false;
    for _ in 0..1000 {
        // SAFETY: device_status is a byte register in the retained mapping.
        if unsafe { common.mapping.read_u8(common.offset + 20) }.map_err(|_| Error::Transport)? == 0
        {
            reset = true;
            break;
        }
        core::hint::spin_loop();
    }
    if !reset {
        return Err(Error::Failed);
    }
    // SAFETY: The live modern common window is exclusively owned by this service.
    unsafe { common.mapping.write_u16(common.offset + 22, 0) }.map_err(|_| Error::Transport)?;
    // SAFETY: queue_notify_off is a naturally aligned read-only common register.
    let queue_offset =
        unsafe { common.mapping.read_u16(common.offset + 30) }.map_err(|_| Error::Transport)?;
    let notify = Window::map(
        block::DEVICE,
        NOTIFY,
        caps.notification(queue_offset).map_err(|_| Error::Bounds)?,
        0x6002_0000,
    )
    .map_err(|_| Error::Transport)?;
    let config = Window::map(
        block::DEVICE,
        DEVICE_CONFIG,
        caps.device.subrange(0, 8).map_err(|_| Error::Bounds)?,
        0x6001_0000,
    )
    .map_err(|_| Error::Transport)?;
    ruzt_driver_sdk::allocate_dma_buffer(block::MEMORY, DMA, 13).map_err(|_| Error::Transport)?;
    ruzt_driver_sdk::map_dma_buffer(DMA, DMA_ADDRESS, true).map_err(|_| Error::Transport)?;
    let iova = ruzt_driver_sdk::bind_dma(block::DEVICE, DMA, DMA_READ | DMA_WRITE)
        .map_err(|_| Error::Transport)?;
    ruzt_driver_sdk::claim_msix(block::DEVICE, IRQ, 0).map_err(|_| Error::Transport)?;
    ruzt_driver_sdk::bind_irq(IRQ).map_err(|_| Error::Transport)?;
    Block::new(
        PciTransport {
            common,
            config,
            notify,
            queue_offset,
        },
        Arena { iova },
    )
}
