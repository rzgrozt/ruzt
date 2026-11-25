//! User memory copy helpers.

use ruzt_abi::ErrorCode;
use ruzt_hal_x86_64::mapper;
#[cfg(not(test))]
use ruzt_hal::mem::Mapper;

#[cfg(not(test))]
#[allow(unsafe_code)]
/// Copy from the trusted kernel-only IPC diagnostic's payload.
pub fn copy_from_user(user_ptr: u64, kernel_buf: &mut [u8]) -> Result<(), ErrorCode> {
    crate::serial_println!("copy_from_user: user_ptr={:x} len={}", user_ptr, kernel_buf.len());
    // Check that the user pointer is valid (mapped in the page tables).
    let start = user_ptr;
    let end = user_ptr + kernel_buf.len() as u64;
    for addr in (start..end).step_by(4096) {
        let virt = ruzt_hal::mem::VirtAddr::new(addr);
        crate::serial_println!("copy_from_user: checking addr={:x}", addr);
        if ruzt_hal_x86_64::mapper::with_mapper(|m| m.translate(virt)).is_none() {
            crate::serial_println!("copy_from_user: translate failed for addr={:x}", addr);
            return Err(ErrorCode::InvalidCap);
        }
    }
    crate::serial_println!("copy_from_user: translation ok, copying");

    // SAFETY: The only caller supplies a live kernel payload with this length.
    unsafe {
        core::ptr::copy_nonoverlapping(
            user_ptr as *const u8,
            kernel_buf.as_mut_ptr(),
            kernel_buf.len(),
        );
    }
    crate::serial_println!("copy_from_user: copy done");
    Ok(())
}

#[cfg(test)]
#[allow(unsafe_code)]
/// Test-only version: skips page table checks.
pub fn copy_from_user(user_ptr: u64, kernel_buf: &mut [u8]) -> Result<(), ErrorCode> {
    unsafe {
        core::ptr::copy_nonoverlapping(
            user_ptr as *const u8,
            kernel_buf.as_mut_ptr(),
            kernel_buf.len(),
        );
    }
    Ok(())
}

#[cfg(not(test))]
#[allow(unsafe_code)]
/// Copy into the trusted kernel-only IPC diagnostic's receive buffer.
pub fn copy_to_user(kernel_buf: &[u8], user_ptr: u64) -> Result<(), ErrorCode> {
    let start = user_ptr;
    let end = user_ptr + kernel_buf.len() as u64;
    for addr in (start..end).step_by(4096) {
        let virt = ruzt_hal::mem::VirtAddr::new(addr);
        if ruzt_hal_x86_64::mapper::with_mapper(|m| m.translate(virt)).is_none() {
            return Err(ErrorCode::InvalidCap);
        }
    }

    // SAFETY: The only caller supplies a live kernel buffer of this length.
    unsafe {
        core::ptr::copy_nonoverlapping(
            kernel_buf.as_ptr(),
            user_ptr as *mut u8,
            kernel_buf.len(),
        );
    }
    Ok(())
}

#[cfg(test)]
#[allow(unsafe_code)]
/// Test-only version: skips page table checks.
pub fn copy_to_user(kernel_buf: &[u8], user_ptr: u64) -> Result<(), ErrorCode> {
    unsafe {
        core::ptr::copy_nonoverlapping(
            kernel_buf.as_ptr(),
            user_ptr as *mut u8,
            kernel_buf.len(),
        );
    }
    Ok(())
}

// Copies walk the calling process's root through the permanent kernel map.
// The kernel transaction keeps mappings and backing frames live during a copy.
#[allow(unsafe_code)]
pub(crate) fn validate_user_buffer(
    root: ruzt_hal::mem::PhysFrame,
    address: u64,
    len: usize,
    writable: bool,
) -> Result<(), ErrorCode> {
    // SAFETY: The transaction pins the scheduled task's root and mappings.
    if unsafe { mapper::user_range_accessible(root, address, len, writable) } {
        Ok(())
    } else {
        Err(ErrorCode::BadMessage)
    }
}

#[allow(unsafe_code)]
pub(crate) fn read_user_buffer(
    root: ruzt_hal::mem::PhysFrame,
    address: u64,
    buf: &mut [u8],
) -> Result<(), ErrorCode> {
    // SAFETY: The transaction holds this root's mappings stable, and the
    // user RAM frames are separate from the kernel's scratch buffers.
    if unsafe { mapper::copy_from_user_root(root, address, buf) } {
        Ok(())
    } else {
        Err(ErrorCode::BadMessage)
    }
}

pub(crate) fn write_user_buffer(
    root: ruzt_hal::mem::PhysFrame,
    address: u64,
    buf: &[u8],
) -> Result<(), ErrorCode> {
    write_user_buffer_with(root, address, buf.len(), || buf)
}

#[allow(unsafe_code)]
pub(crate) fn write_user_buffer_with<T: AsRef<[u8]>>(
    root: ruzt_hal::mem::PhysFrame,
    address: u64,
    len: usize,
    produce: impl FnOnce() -> T,
) -> Result<(), ErrorCode> {
    // SAFETY: The transaction keeps the user frames mapped. The producer runs
    // synchronously without changing mappings or scheduling, and its output
    // lives in kernel RAM separate from the user frames.
    if unsafe { mapper::copy_to_user_root_with(root, address, len, produce) } {
        Ok(())
    } else {
        Err(ErrorCode::BadMessage)
    }
}
