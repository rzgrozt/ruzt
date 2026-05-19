#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! aarch64 HAL backend for Ruzt.
//!
//! Implements the `ruzt-hal` trait surface for aarch64.
//! Targets QEMU `virt` machine (cortex-a57 / cortex-a72).

pub mod boot;
pub mod console;
pub mod context;
pub mod cpu;
pub mod irq;
pub mod mapper;
pub mod time;
