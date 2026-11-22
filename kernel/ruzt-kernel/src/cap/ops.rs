//! Capability operations — the kernel side of the `invoke` syscall.

use ruzt_abi::ErrorCode;
use ruzt_cap::CapRights;

use super::cspace::CSpace;

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
    /// Create a child kernel object from an Untyped capability.
    Retype {
        /// Source Untyped capability pointer.
        src_cptr: u64,
        /// Destination capability pointer for the new object.
        dest_cptr: u64,
        /// Wire tag for the kind of object to create.
        kind: u64,
        /// Size exponent for an Untyped child.
        size_bits: u64,
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
                src_cptr: _args.arg0,
                dest_cptr: _args.arg2,
                kind: _args.arg3,
                size_bits: _args.arg4,
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
