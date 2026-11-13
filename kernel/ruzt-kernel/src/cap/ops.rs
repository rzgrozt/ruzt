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
            _ => Self::Send,
        }
    }
}

/// Delete a capability from a CSpace, deallocating the underlying kernel
/// object if this is the last reference.
pub fn cap_delete(cspace: &mut CSpace, cptr: u64) -> Result<(), ErrorCode> {
    let old = cspace.delete(cptr)?;
    if let Some(id) = kobject_id_from_cap(&old) {
        super::object::deallocate(id);
    }
    Ok(())
}

/// Consume an Untyped capability and create a new kernel object.
///
/// The source Untyped capability is removed (fully consumed) and the new
/// capability is inserted at `dest_cptr`.
pub fn cap_retype(
    cspace: &mut CSpace,
    src_cptr: u64,
    dest_cptr: u64,
    new_type: CapType,
) -> Result<(), ErrorCode> {
    let src = cspace.delete(src_cptr)?;
    let untyped = match src.cap_type {
        CapType::Untyped { phys, size_bits } => (phys, size_bits),
        _ => return Err(ErrorCode::InvalidCap),
    };

    let required_bits = size_bits_for_type(new_type);
    if required_bits > untyped.1 {
        // Put the untyped back
        cspace.insert(src_cptr, src)?;
        return Err(ErrorCode::BadMessage);
    }

    let id = super::object::allocate(new_type)?;
    let slot = cap_slot_with_id(new_type, id, CapRights::new());
    cspace.insert(dest_cptr, slot)?;
    Ok(())
}

/// Copy a capability with potentially reduced rights.
pub fn cap_mint(
    cspace: &mut CSpace,
    src_cptr: u64,
    dest_cptr: u64,
    new_rights: CapRights,
    badge: u64,
) -> Result<(), ErrorCode> {
    let src = *cspace.lookup(src_cptr)?;
    if !src.rights.contains(new_rights) {
        return Err(ErrorCode::CapRightsViolation);
    }
    let mut slot = src;
    slot.rights = new_rights;
    slot.badge = badge;
    cspace.insert(dest_cptr, slot)?;
    Ok(())
}

/// Move a capability from one slot to another.
pub fn cap_move(
    cspace: &mut CSpace,
    src_cptr: u64,
    dest_cptr: u64,
) -> Result<(), ErrorCode> {
    let src = cspace.delete(src_cptr)?;
    cspace.insert(dest_cptr, src)?;
    Ok(())
}

/// Extract the [`KObjectId`] from a capability slot, if it references a
/// kernel object.
fn kobject_id_from_cap(cap: &CapSlot) -> Option<KObjectId> {
    match cap.cap_type {
        CapType::Endpoint(id) => Some(KObjectId(id.0)),
        CapType::Notification(id) => Some(KObjectId(id.0)),
        CapType::Thread(id) => Some(KObjectId(id.0)),
        CapType::AddressSpace(id) => Some(KObjectId(id.0)),
        CapType::CNode { ptr, .. } => Some(KObjectId(ptr)),
        CapType::Frame { .. } => Some(KObjectId(cap.badge)),
        CapType::Untyped { .. } => Some(KObjectId(cap.badge)),
        CapType::Irq { .. } => Some(KObjectId(cap.badge)),
        CapType::Null => None,
    }
}

/// Create a [`CapSlot`] for a newly allocated kernel object.
fn cap_slot_with_id(cap_type: CapType, id: KObjectId, rights: CapRights) -> CapSlot {
    let cap_type = match cap_type {
        CapType::Endpoint(_) => CapType::Endpoint(ruzt_cap::EndpointId(id.0)),
        CapType::Notification(_) => CapType::Notification(ruzt_cap::NotificationId(id.0)),
        CapType::Thread(_) => CapType::Thread(ruzt_cap::ThreadId(id.0)),
        CapType::AddressSpace(_) => CapType::AddressSpace(ruzt_cap::AddressSpaceId(id.0)),
        CapType::CNode { radix_bits, .. } => CapType::CNode { radix_bits, ptr: id.0 },
        other => other,
    };
    let badge = match cap_type {
        CapType::Frame { .. } | CapType::Untyped { .. } | CapType::Irq { .. } => id.0,
        _ => 0,
    };
    CapSlot {
        cap_type,
        rights,
        badge,
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
        CapType::CNode { radix_bits, .. } => radix_bits + 4, // CapSlot is ~40 bytes
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruzt_cap::{EndpointId, FrameSize};
    use ruzt_hal::mem::PhysAddr;

    #[test]
    fn cap_delete_deallocates_object() {
        super::super::object::init();
        for i in 0..256 {
            super::super::object::deallocate(super::super::object::KObjectId(i));
        }
        let mut cspace = CSpace::new(4);
        let id = super::super::object::allocate(CapType::Endpoint(EndpointId(0))).unwrap();
        let slot = CapSlot {
            cap_type: CapType::Endpoint(EndpointId(id.0)),
            rights: CapRights::READ,
            badge: 0,
        };
        cspace.insert(0, slot).unwrap();

        // Verify the slot was inserted
        let found = cspace.lookup(0).unwrap();
        assert_eq!(found.cap_type, CapType::Endpoint(EndpointId(id.0)));

        super::cap_delete(&mut cspace, 0).unwrap();
        assert_eq!(cspace.lookup(0), Err(ErrorCode::InvalidCap));
        assert!(super::super::object::get(id).is_none(), "object still exists at id={}", id.0);
    }

    #[test]
    fn cap_delete_null_slot_ok() {
        let mut cspace = CSpace::new(4);
        // Deleting a null slot should be a no-op (no object to deallocate)
        assert!(super::cap_delete(&mut cspace, 0).is_ok());
    }

    #[test]
    fn cap_retype_untyped_to_frame() {
        super::super::object::init();
        for i in 0..256 {
            super::super::object::deallocate(super::super::object::KObjectId(i));
        }
        let mut cspace = CSpace::new(4);
        let frame = ruzt_hal::mem::PhysFrame::from_base(PhysAddr::new(0x4000)).unwrap();
        let untyped = CapSlot {
            cap_type: CapType::Untyped { phys: frame, size_bits: 12 },
            rights: CapRights::new(),
            badge: 0,
        };
        cspace.insert(0, untyped).unwrap();

        super::cap_retype(
            &mut cspace,
            0,
            1,
            CapType::Frame { phys: frame, size: FrameSize::Size4K },
        )
        .unwrap();

        assert_eq!(cspace.lookup(0), Err(ErrorCode::InvalidCap));
        let new_cap = cspace.lookup(1).unwrap();
        assert!(matches!(new_cap.cap_type, CapType::Frame { size: FrameSize::Size4K, .. }));
    }

    #[test]
    fn cap_retype_wrong_type_fails() {
        let mut cspace = CSpace::new(4);
        let slot = CapSlot {
            cap_type: CapType::Endpoint(EndpointId(1)),
            rights: CapRights::READ,
            badge: 0,
        };
        cspace.insert(0, slot).unwrap();

        assert_eq!(
            super::cap_retype(
                &mut cspace,
                0,
                1,
                CapType::Frame {
                    phys: ruzt_hal::mem::PhysFrame::from_base(PhysAddr::new(0x5000)).unwrap(),
                    size: FrameSize::Size4K,
                },
            ),
            Err(ErrorCode::InvalidCap)
        );
    }

    #[test]
    fn cap_retype_too_small_untyped() {
        let mut cspace = CSpace::new(4);
        let frame = ruzt_hal::mem::PhysFrame::from_base(PhysAddr::new(0x6000)).unwrap();
        let untyped = CapSlot {
            cap_type: CapType::Untyped { phys: frame, size_bits: 10 },
            rights: CapRights::new(),
            badge: 0,
        };
        cspace.insert(0, untyped).unwrap();

        assert_eq!(
            super::cap_retype(
                &mut cspace,
                0,
                1,
                CapType::Frame { phys: frame, size: FrameSize::Size4K },
            ),
            Err(ErrorCode::BadMessage)
        );
        // Untyped should be restored
        assert!(matches!(cspace.lookup(0).unwrap().cap_type, CapType::Untyped { .. }));
    }

    #[test]
    fn cap_mint_reduces_rights() {
        let mut cspace = CSpace::new(4);
        let slot = CapSlot {
            cap_type: CapType::Endpoint(EndpointId(1)),
            rights: CapRights::READ.union(CapRights::WRITE),
            badge: 0,
        };
        cspace.insert(0, slot).unwrap();

        super::cap_mint(
            &mut cspace,
            0,
            1,
            CapRights::READ,
            42,
        )
        .unwrap();

        let minted = cspace.lookup(1).unwrap();
        assert!(minted.rights.contains(CapRights::READ));
        assert!(!minted.rights.contains(CapRights::WRITE));
        assert_eq!(minted.badge, 42);
    }

    #[test]
    fn cap_mint_rights_violation() {
        let mut cspace = CSpace::new(4);
        let slot = CapSlot {
            cap_type: CapType::Endpoint(EndpointId(1)),
            rights: CapRights::READ,
            badge: 0,
        };
        cspace.insert(0, slot).unwrap();

        assert_eq!(
            super::cap_mint(
                &mut cspace,
                0,
                1,
                CapRights::WRITE,
                0,
            ),
            Err(ErrorCode::CapRightsViolation)
        );
    }

    #[test]
    fn cap_move_works() {
        let mut cspace = CSpace::new(4);
        let slot = CapSlot {
            cap_type: CapType::Endpoint(EndpointId(1)),
            rights: CapRights::READ,
            badge: 0,
        };
        cspace.insert(0, slot).unwrap();

        super::cap_move(&mut cspace, 0, 1).unwrap();
        assert_eq!(cspace.lookup(0), Err(ErrorCode::InvalidCap));
        assert_eq!(cspace.lookup(1).unwrap().cap_type, CapType::Endpoint(EndpointId(1)));
    }
}
