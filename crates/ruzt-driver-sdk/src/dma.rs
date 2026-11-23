use ruzt_abi::{CapOp, ErrorCode, RetypeKind, SyscallNumber, DMA_IOVA_BASE};
use ruzt_runtime::syscall::syscall;

/// Reserve a zeroed, contiguous buffer of `2^size_bits` bytes from Untyped.
pub fn allocate_dma_buffer(untyped: u64, destination: u64, size_bits: u8) -> Result<(), ErrorCode> {
    invoke(
        untyped,
        CapOp::Retype,
        destination,
        RetypeKind::DmaBuffer as u64,
        u64::from(size_bits),
    )
}

/// Map the entire buffer at a page-aligned user address.
///
/// The driver must synchronize CPU and device access and stop using the
/// address once its capability or the capability path has been revoked.
/// Copy data to ordinary RAM before passing it as a syscall memory operand.
pub fn map_dma_buffer(buffer: u64, address: u64, writable: bool) -> Result<(), ErrorCode> {
    invoke(buffer, CapOp::MapDmaBuffer, address, u64::from(writable), 0)
}

/// Remove the CPU mapping associated with the buffer capability.
pub fn unmap_dma_buffer(buffer: u64) -> Result<(), ErrorCode> {
    invoke(buffer, CapOp::UnmapDmaBuffer, 0, 0, 0)
}

/// Isolate the requester to this buffer, then enable its PCI bus mastering.
///
/// Access is relative to the device. This returns the address to program
/// into its DMA registers. The lease ends on unbind, revocation or driver exit.
pub fn bind_dma(device: u64, buffer: u64, permissions: u64) -> Result<u64, ErrorCode> {
    invoke(device, CapOp::BindDma, buffer, permissions, 0)?;
    Ok(DMA_IOVA_BASE)
}

/// Disable PCI bus mastering and drain the caller's binding.
pub fn unbind_dma(device: u64) -> Result<(), ErrorCode> {
    invoke(device, CapOp::UnbindDma, 0, 0, 0)
}

fn invoke(cap: u64, operation: CapOp, arg2: u64, arg3: u64, arg4: u64) -> Result<(), ErrorCode> {
    // SAFETY: The kernel interprets these operands as capability references,
    // flags, sizes or a destination virtual address, without dereferencing them.
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
