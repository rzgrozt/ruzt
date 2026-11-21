//! Capability operations — the kernel side of the `invoke` syscall.

use ruzt_abi::ErrorCode;
use ruzt_cap::{CapRights, CapSlot, CapType, FrameSize};

use super::cspace::CSpace;
use super::object::KObjectId;

/// Fundamental operations on capabilities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapOp {
    /// Copy a capability with potentially reduced rights and a new badge.
    Mint {
        /// Source capability pointer.
        src_cptr: u64,
        /// Destination capability pointer.
        dest_cptr: u64,
        /// Rights to attach to the new copy.
        new_rights: CapRights,
        /// Badge to mint onto the copy.
        badge: u64,
    },
    /// Move a capability from one slot to another (no copy).
    Move {
        /// Source capability pointer.
        src_cptr: u64,
        /// Destination capability pointer.
        dest_cptr: u64,
    },
    /// Remove a capability and deallocate its kernel object if this is the
    /// last reference.
    Delete {
        /// Capability pointer to delete.
        cptr: u64,
    },
    /// Consume an Untyped capability and create a new kernel object.
    Retype {
        /// Source Untyped capability pointer.
        src_cptr: u64,
        /// Destination capability pointer for the new object.
        dest_cptr: u64,
        /// Type of the new kernel object.
        new_type: CapType,
    },
    /// Revoke the derived capabilities of the invoked slot.
    Revoke {
        /// Root of the derivation subtree.
        cptr: u64,
    },
    /// Unrecognized operation.
    Unsupported,
    /// Send an IPC message through an endpoint.
    Send,
    /// Receive an IPC message through an endpoint.
    Recv,
    /// Signal a notification object.
    Signal,
    /// Wait on a notification object.
    Wait,
}

impl CapOp {
    /// Decode a [`CapOp`] from an operation code and syscall arguments.
    ///
    /// The operation code is passed in `rsi` (arg1) and the remaining
    /// arguments are read from the syscall args.
    pub fn from(op_code: u64, _args: &ruzt_abi::SyscallArgs) -> Self {
        match op_code {
            0 => Self::Send,
            1 => Self::Recv,
            2 => Self::Signal,
            3 => Self::Wait,
            4 => Self::Delete { cptr: _args.arg2 },
            5 => Self::Retype {
                src_cptr: _args.arg2,
                dest_cptr: _args.arg3,
                new_type: CapType::Null,
            },
            6 => Self::Mint {
                src_cptr: _args.arg2,
                dest_cptr: _args.arg3,
                new_rights: CapRights::READ,
                badge: _args.arg4,
            },
            7 => Self::Move {
                src_cptr: _args.arg2,
                dest_cptr: _args.arg3,
            },
            11 => Self::Revoke { cptr: _args.arg0 },
            _ => Self::Unsupported,
        }
    }
}

/// Delete a capability from a CSpace, deallocating the underlying kernel
/// object if this is the last reference.
pub fn cap_delete(cspace: &mut CSpace, cptr: u64) -> Result<(), ErrorCode> {
    cspace.delete(cptr)?;
    Ok(())
}

/// Replace the source Untyped with a kernel object of the requested type.
/// Failed allocation or destination validation leaves the source untouched.
pub fn cap_retype(
    cspace: &mut CSpace,
    src_cptr: u64,
    dest_cptr: u64,
    new_type: CapType,
) -> Result<(), ErrorCode> {
    let src = cspace.lookup(src_cptr)?;
    let CapType::Untyped { phys, size_bits } = src.cap_type else {
        return Err(ErrorCode::InvalidCap);
    };
    if !src.rights.contains(CapRights::WRITE) {
        return Err(ErrorCode::CapRightsViolation);
    }
    cspace.require_vacant(dest_cptr)?;
    if size_bits_for_type(new_type) > size_bits {
        return Err(ErrorCode::BadMessage);
    }
    let new_type = match new_type {
        CapType::Frame { size, .. } => CapType::Frame { phys, size },
        other => other,
    };
    let id = super::object::allocate(new_type)?;
    let slot = cap_slot_with_id(new_type, id, CapRights::new());
    if let Err(error) = cspace.install(dest_cptr, slot, Some(id)) {
        super::object::deallocate(id);
        return Err(error);
    }
    cspace.delete(src_cptr)?;
    Ok(())
}

/// Copy a capability with reduced rights and preserve its derivation.
pub fn cap_mint(
    cspace: &mut CSpace,
    src_cptr: u64,
    dest_cptr: u64,
    new_rights: CapRights,
    badge: u64,
) -> Result<(), ErrorCode> {
    let source = cspace.capability_id(src_cptr)?;
    cspace.derive(source, dest_cptr, new_rights, badge)
}

/// Move a capability to an empty slot.
pub fn cap_move(cspace: &mut CSpace, src_cptr: u64, dest_cptr: u64) -> Result<(), ErrorCode> {
    cspace.move_cap(src_cptr, dest_cptr)
}

/// Create a [`CapSlot`] for a newly allocated kernel object.
fn cap_slot_with_id(cap_type: CapType, id: KObjectId, rights: CapRights) -> CapSlot {
    let cap_type = match cap_type {
        CapType::Endpoint(_) => CapType::Endpoint(ruzt_cap::EndpointId(id.0)),
        CapType::Notification(_) => CapType::Notification(ruzt_cap::NotificationId(id.0)),
        CapType::Thread(_) => CapType::Thread(ruzt_cap::ThreadId(id.0)),
        CapType::AddressSpace(_) => CapType::AddressSpace(ruzt_cap::AddressSpaceId(id.0)),
        CapType::CNode { radix_bits, .. } => CapType::CNode {
            radix_bits,
            ptr: id.0,
        },
        other => other,
    };
    CapSlot {
        cap_type,
        rights,
        badge: 0,
    }
}

/// Number of size bits required for a given capability type.
fn size_bits_for_type(cap_type: CapType) -> u8 {
    match cap_type {
        CapType::Frame { size, .. } => match size {
            FrameSize::Size4K => 12,
            FrameSize::Size2M => 21,
            FrameSize::Size1G => 30,
        },
        CapType::CNode { radix_bits, .. } => radix_bits.saturating_add(6),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruzt_hal::mem::{PhysAddr, PhysFrame};

    #[test]
    fn retype_is_atomic_and_uses_the_owned_frame() {
        let _state = crate::isolated_kernel_state();
        let mut cspace = CSpace::new(2);
        let owned = PhysFrame::from_base(PhysAddr::new(0x4000)).unwrap();
        let other = PhysFrame::from_base(PhysAddr::new(0x5000)).unwrap();
        let source = CapSlot {
            cap_type: CapType::Untyped {
                phys: owned,
                size_bits: 12,
            },
            rights: CapRights::new(),
            badge: 0,
        };
        cspace.insert(0, source).unwrap();
        cspace.insert(1, source).unwrap();
        let frame = CapType::Frame {
            phys: other,
            size: FrameSize::Size4K,
        };

        assert_eq!(
            cap_retype(&mut cspace, 0, 1, frame),
            Err(ErrorCode::SlotOccupied)
        );
        assert_eq!(
            cap_retype(&mut cspace, 0, 2, CapType::Null),
            Err(ErrorCode::InvalidCap)
        );
        assert_eq!(cspace.lookup(0), Ok(source));
        let huge = CapType::Frame {
            phys: other,
            size: FrameSize::Size2M,
        };
        assert_eq!(
            cap_retype(&mut cspace, 0, 2, huge),
            Err(ErrorCode::BadMessage)
        );
        assert_eq!(cspace.lookup(0), Ok(source));
        cap_retype(&mut cspace, 0, 2, frame).unwrap();
        assert_eq!(cspace.lookup(0), Err(ErrorCode::InvalidCap));
        assert_eq!(
            cspace.lookup(2).unwrap().cap_type,
            CapType::Frame {
                phys: owned,
                size: FrameSize::Size4K
            }
        );
    }
}
