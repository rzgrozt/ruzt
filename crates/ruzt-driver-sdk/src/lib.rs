//! User-space wrappers for capability-gated device access.

#![no_std]

use ruzt_abi::{CapOp, ErrorCode, FramebufferInfo, SyscallNumber};
use ruzt_runtime::syscall::syscall;

mod dma;
mod pci;
pub use dma::{allocate_dma_buffer, bind_dma, map_dma_buffer, unbind_dma, unmap_dma_buffer};
pub use pci::{
    claim_pci_device, map_mmio, open_pci_bar, read_device_config, read_pci_config,
    unmap_mmio, MmioRegion,
};
pub use ruzt_abi::{DMA_READ, DMA_WRITE, IRQ_ACTIVE_LOW, IRQ_LEVEL_TRIGGERED};

/// Claim a device interrupt line into an empty capability slot.
pub fn claim_irq(control: u64, destination: u64, line: u32) -> Result<(), ErrorCode> {
    invoke_irq(control, CapOp::ClaimIrq, destination, u64::from(line), 0)
}

/// Claim a non-ISA global system interrupt with the platform's signal flags.
pub fn claim_gsi(control: u64, destination: u64, gsi: u32, flags: u64) -> Result<(), ErrorCode> {
    invoke_irq(control, CapOp::ClaimGsi, destination, u64::from(gsi), flags)
}

/// Claim a single remapped MSI message from an exclusive PCI device.
pub fn claim_msi(device: u64, destination: u64) -> Result<(), ErrorCode> {
    invoke_irq(device, CapOp::ClaimMsi, destination, 0, 0)
}

/// Claim one independently maskable MSI-X table entry from a PCI device.
pub fn claim_msix(device: u64, destination: u64, vector: u16) -> Result<(), ErrorCode> {
    invoke_irq(device, CapOp::ClaimMsix, destination, u64::from(vector), 0)
}

/// Bind an exclusively claimed interrupt to the calling driver.
pub fn bind_irq(cap: u64) -> Result<(), ErrorCode> {
    invoke_irq(cap, CapOp::BindIrq, 0, 0, 0)
}

/// Sleep until the bound interrupt is pending, then consume the event.
pub fn wait_irq(cap: u64) -> Result<(), ErrorCode> {
    invoke_irq(cap, CapOp::Wait, 0, 0, 0)
}

/// Re-arm the line after servicing the device and clearing its interrupt.
pub fn acknowledge_irq(cap: u64) -> Result<(), ErrorCode> {
    invoke_irq(cap, CapOp::AckIrq, 0, 0, 0)
}

/// Mask and release the calling driver's binding.
pub fn unbind_irq(cap: u64) -> Result<(), ErrorCode> {
    invoke_irq(cap, CapOp::UnbindIrq, 0, 0, 0)
}

fn invoke_irq(cap: u64, operation: CapOp, arg2: u64, arg3: u64, arg4: u64) -> Result<(), ErrorCode> {
    // SAFETY: This operation has no memory operands.
    let status = unsafe {
        syscall(
            SyscallNumber::Invoke,
            cap,
            operation as u64,
            arg2,
            arg3,
            arg4,
            0,
        )
    };
    ErrorCode::from_u64(status)
}

/// Read one byte from the I/O port designated by the capability.
pub fn read_port_u8(cap: u64) -> Result<u8, ErrorCode> {
    let mut byte = 0u8;
    // SAFETY: The kernel has exclusive write access to this byte until the
    // synchronous operation returns.
    let status = unsafe {
        syscall(
            SyscallNumber::Invoke,
            cap,
            CapOp::ReadPort8 as u64,
            &mut byte as *mut u8 as u64,
            0,
            0,
            0,
        )
    };
    ErrorCode::from_u64(status)?;
    Ok(byte)
}

/// Write one byte to the I/O port designated by the capability.
pub fn write_port_u8(cap: u64, byte: u8) -> Result<(), ErrorCode> {
    // SAFETY: This operation has no memory operands.
    let status = unsafe {
        syscall(
            SyscallNumber::Invoke,
            cap,
            CapOp::WritePort8 as u64,
            u64::from(byte),
            0,
            0,
            0,
        )
    };
    ErrorCode::from_u64(status)
}

/// Return the address and layout of the framebuffer mapped for this capability.
pub fn framebuffer_info(cap: u64) -> Result<FramebufferInfo, ErrorCode> {
    let mut info = FramebufferInfo::default();
    // SAFETY: The kernel can write this full record before returning, and all
    // bit patterns of the record's integer fields are valid.
    let status = unsafe {
        syscall(
            SyscallNumber::Invoke,
            cap,
            CapOp::FramebufferInfo as u64,
            &mut info as *mut FramebufferInfo as u64,
            0,
            0,
            0,
        )
    };
    ErrorCode::from_u64(status)?;
    Ok(info)
}
