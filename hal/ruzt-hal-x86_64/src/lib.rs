#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! x86_64 HAL backend for Ruzt.
//!
//! Implements the `ruzt-hal` trait surface for the x86_64 architecture.

pub mod boot;
pub mod console;
pub mod context;
pub mod cpu;
pub mod irq;
pub mod mapper;
pub mod pic;
pub mod time;
pub mod timer;

/// Initialise the x86_64 HAL from the raw bootloader hand-off.
///
/// # Safety
/// Must be called exactly once at kernel entry, before any concurrent access.
pub unsafe fn init(raw_boot_info: &'static mut bootloader_api::BootInfo) {
    // SAFETY: Caller guarantees this is called exactly once at kernel entry.
    unsafe { boot::normalize(raw_boot_info) };
}
