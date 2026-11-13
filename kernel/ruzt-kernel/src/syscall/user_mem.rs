//! User memory copy helpers.

use ruzt_abi::ErrorCode;
use ruzt_hal::mem::Mapper;

#[cfg(not(test))]
#[allow(unsafe_code)]
/// Copy `kernel_buf.len()` bytes from a user-space virtual address into a
/// kernel buffer.
///
/// For Phase 2.3 the kernel and user share the same address space, so this
/// is a direct memory copy with a page table bounds check.
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

    // SAFETY: The range has been verified as mapped. The kernel has full
    // access to all memory in Phase 2.3 (no SMAP yet).
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
/// Copy `kernel_buf.len()` bytes from a kernel buffer into a user-space
/// virtual address.
pub fn copy_to_user(kernel_buf: &[u8], user_ptr: u64) -> Result<(), ErrorCode> {
    let start = user_ptr;
    let end = user_ptr + kernel_buf.len() as u64;
    for addr in (start..end).step_by(4096) {
        let virt = ruzt_hal::mem::VirtAddr::new(addr);
        if ruzt_hal_x86_64::mapper::with_mapper(|m| m.translate(virt)).is_none() {
            return Err(ErrorCode::InvalidCap);
        }
    }

    // SAFETY: The range has been verified as mapped.
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
