#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! x86_64 HAL backend for Ruzt.
//!
//! Implements the `ruzt-hal` trait surface for the x86_64 architecture.
//!
//! ```
//! use ruzt_hal::mem::{MapError, PageFlags, PhysAddr, PhysFrame, VirtAddr};
//! use ruzt_hal_x86_64::{context, gdt, mapper};
//!
//! assert_eq!(gdt::USER_CODE_SELECTOR, 0x1B);
//! assert_eq!(gdt::USER_DATA_SELECTOR, 0x23);
//!
//! let frame = PhysFrame::from_base(PhysAddr::new(0x1000)).unwrap();
//! assert_eq!(
//!     unsafe { mapper::copy_to_frame(frame, PhysFrame::SIZE, &[1]) },
//!     Err(MapError::InvalidAlignment),
//! );
//! assert_eq!(
//!     unsafe { mapper::copy_to_frame(frame, usize::MAX, &[1]) },
//!     Err(MapError::InvalidAlignment),
//! );
//!
//! let _: unsafe extern "C" fn(u64, u64, u64) -> ! = context::enter_user;
//! let _: fn(&mut mapper::X86_64Mapper) -> Result<PhysFrame, MapError> =
//!     mapper::X86_64Mapper::create_user_address_space;
//! let _: unsafe fn(
//!     &mut mapper::X86_64Mapper,
//!     PhysFrame,
//!     VirtAddr,
//!     PhysFrame,
//!     PageFlags,
//! ) -> Result<(), MapError> = mapper::X86_64Mapper::map_in_address_space;
//! let _: unsafe fn(PhysFrame) = mapper::zero_frame;
//! let _: unsafe fn(PhysFrame, usize, &[u8]) -> Result<(), MapError> = mapper::copy_to_frame;
//! ```

pub mod boot;
pub mod console;
pub mod context;
pub mod cpu;
pub mod gdt;
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
    // SAFETY: [Categories 1/13 - Aliasing and library contract] The caller
    // supplies the unique static BootInfo borrow exactly once at kernel entry.
    unsafe { boot::normalize(raw_boot_info) };
}
