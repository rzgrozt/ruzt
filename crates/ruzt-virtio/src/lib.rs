//! Bounded modern VirtIO PCI discovery and single-request block queues.
//!
//! Register layout and ordering follow VirtIO 1.2, sections 2.7, 3.1, 4.1 and 5.2.
//! Hardware access is supplied by the isolated driver's capability SDK adapter.
#![no_std]
#![forbid(unsafe_code)]

pub mod block;
pub mod pci;
