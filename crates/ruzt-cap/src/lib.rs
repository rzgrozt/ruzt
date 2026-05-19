//! Capability types for the Ruzt microkernel.
//!
//! This crate defines the kernel-internal representation of capabilities
//! and their associated metadata.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub use ruzt_abi::CapRights;

use ruzt_hal::mem::PhysFrame;

/// Opaque identifier for a kernel thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadId(pub u64);

/// Opaque identifier for an address space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressSpaceId(pub u64);

/// Opaque identifier for an IPC endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointId(pub u64);

/// Opaque identifier for a notification object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotificationId(pub u64);

/// Size of a frame mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameSize {
    /// 4 KiB frame.
    Size4K,
    /// 2 MiB frame.
    Size2M,
    /// 1 GiB frame.
    Size1G,
}

impl FrameSize {
    /// Number of bytes in this frame size.
    pub const fn byte_count(&self) -> u64 {
        match *self {
            Self::Size4K => 4096,
            Self::Size2M => 2 * 1024 * 1024,
            Self::Size1G => 1024 * 1024 * 1024,
        }
    }
}

/// The type of a capability and its type-specific payload.
///
/// This enum is kernel-internal; userland never sees the raw `CapType`.
/// The `#[repr(C, u32)]` layout gives a stable, predictable size for
/// storage in [`CapSlot`] arrays (CNodes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C, u32)]
pub enum CapType {
    /// Empty slot.
    Null,
    /// Untyped physical memory.
    Untyped {
        /// Physical frame where the untyped region starts.
        phys: PhysFrame,
        /// Size of the region as a power-of-two exponent (e.g. 12 = 4 KiB).
        size_bits: u8,
    },
    /// Capability table node.
    CNode {
        /// Number of bits used to index into this CNode.
        radix_bits: u8,
        /// Kernel-internal handle (opaque to userland).
        ptr: u64,
    },
    /// Thread control block.
    Thread(ThreadId),
    /// Address space (page table hierarchy).
    AddressSpace(AddressSpaceId),
    /// IPC endpoint.
    Endpoint(EndpointId),
    /// Async notification object.
    Notification(NotificationId),
    /// Mapped memory frame.
    Frame {
        /// Physical frame backing this mapping.
        phys: PhysFrame,
        /// Size of the frame.
        size: FrameSize,
    },
    /// IRQ handler.
    Irq {
        /// Hardware IRQ line number.
        irq_num: u32,
    },
}

/// A capability as it lives in a CNode slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct CapSlot {
    /// The capability type and payload.
    pub cap_type: CapType,
    /// Rights attached to this capability.
    pub rights: CapRights,
    /// Optional badge (used for endpoint and notification capabilities).
    pub badge: u64,
}

/// The canonical empty slot sentinel.
pub const NULL_SLOT: CapSlot = CapSlot {
    cap_type: CapType::Null,
    rights: CapRights::empty(),
    badge: 0,
};

// Compile-time size check for CNode layout stability.
const _: () = assert!(core::mem::size_of::<CapSlot>() == 40);

#[cfg(test)]
mod tests {
    use super::*;
    use ruzt_hal::mem::PhysAddr;

    #[test]
    fn frame_size_byte_count() {
        assert_eq!(FrameSize::Size4K.byte_count(), 4096);
        assert_eq!(FrameSize::Size2M.byte_count(), 2 * 1024 * 1024);
        assert_eq!(FrameSize::Size1G.byte_count(), 1024 * 1024 * 1024);
    }

    #[test]
    fn null_slot_is_null() {
        assert!(matches!(NULL_SLOT.cap_type, CapType::Null));
        assert_eq!(NULL_SLOT.badge, 0);
        assert!(!NULL_SLOT.rights.contains(CapRights::READ));
        assert!(!NULL_SLOT.rights.contains(CapRights::WRITE));
    }

    #[test]
    fn cap_type_discriminants() {
        let _null = CapType::Null;
        let _untyped = CapType::Untyped {
            phys: PhysFrame::from_base(PhysAddr::new(0x1000)).unwrap(),
            size_bits: 12,
        };
        let _cnode = CapType::CNode {
            radix_bits: 8,
            ptr: 0,
        };
        let _thread = CapType::Thread(ThreadId(1));
        let _as = CapType::AddressSpace(AddressSpaceId(2));
        let _ep = CapType::Endpoint(EndpointId(3));
        let _ntf = CapType::Notification(NotificationId(4));
        let _frame = CapType::Frame {
            phys: PhysFrame::from_base(PhysAddr::new(0x2000)).unwrap(),
            size: FrameSize::Size4K,
        };
        let _irq = CapType::Irq { irq_num: 32 };
    }

    #[test]
    fn cap_slot_size_is_stable() {
        // The exact size is asserted at compile time above;
        // this runtime test exists so `cargo test` has something
        // to run for this module.
        assert_eq!(core::mem::size_of::<CapSlot>(), 40);
    }
}
