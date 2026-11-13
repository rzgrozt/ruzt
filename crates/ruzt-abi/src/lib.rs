//! Ruzt ABI — shared types between kernel and userland.
//!
//! This crate defines the vocabulary of IPC messages, capability operations,
//! and syscalls. Every type that crosses the kernel/user boundary uses
//! `#[repr(C)]` for a stable layout.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// x86_64 `syscall` instruction trap number.
///
/// Loaded into `rax` before executing the `syscall` instruction.
/// Both kernel and userland must agree on this value.
pub const SYS_SYSCALL: u32 = 0x80;

/// System-call numbers.
///
/// These values are loaded into `rax` (x86_64) or `x8` (AArch64)
/// before executing the trap instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum SyscallNumber {
    /// Invoke a capability (send an IPC message to an endpoint).
    Invoke = 0,
    /// Reserved for future use: reply to the last incoming message.
    _Reply = 1,
    /// Reserved for future use: yield the remaining time slice.
    _Yield = 2,
    /// Write one character to the debug console.
    DebugPutChar = 3,
    /// Syscall number not recognised.
    NotImplemented = 4,
}

impl From<u64> for SyscallNumber {
    fn from(value: u64) -> Self {
        match value {
            0 => Self::Invoke,
            1 => Self::_Reply,
            2 => Self::_Yield,
            3 => Self::DebugPutChar,
            _ => Self::NotImplemented,
        }
    }
}

/// Capability operation codes carried by the [`SyscallNumber::Invoke`] wire ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum CapOp {
    /// Send an IPC message through an endpoint.
    Send = 0,
    /// Receive an IPC message through an endpoint.
    Recv = 1,
    /// Signal a notification object.
    Signal = 2,
    /// Wait on a notification object.
    Wait = 3,
    /// Delete a capability.
    Delete = 4,
    /// Retype an untyped capability into a kernel object.
    Retype = 5,
    /// Mint a derived capability.
    Mint = 6,
    /// Move a capability between slots.
    Move = 7,
}

/// Rights that can be attached to a capability.
///
/// Four bits packed into a `u8`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct CapRights(u8);

impl CapRights {
    /// Read access.
    pub const READ: Self = Self(1 << 0);
    /// Write access.
    pub const WRITE: Self = Self(1 << 1);
    /// Grant (copy / mint) access.
    pub const GRANT: Self = Self(1 << 2);
    /// Reply access (endpoint-specific).
    pub const REPLY: Self = Self(1 << 3);

    /// Create a `CapRights` with all rights set.
    pub const fn new() -> Self {
        Self(0b1111)
    }

    /// Create an empty `CapRights`.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Check if all rights in `other` are set in `self`.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Union of two rights sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Intersection of two rights sets.
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
}

/// A capability reference that can be sent in an IPC message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct CapTransferSlot {
    /// Capability pointer (index into sender's CSpace).
    pub cptr: u64,
    /// Rights to transfer.
    pub rights: CapRights,
    /// Optional badge to mint onto the copy.
    pub badge: u64,
}

/// The fixed-size message format exchanged via IPC.
///
/// All fields are public so the kernel and userland can construct and
/// deconstruct messages without accessor overhead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct IpcMessage {
    /// User-defined message kind (endpoint-specific tag).
    pub label: u64,
    /// Valid bytes in `data`.
    pub length: u16,
    /// Number of valid entries in `caps` (0..=4).
    pub cap_count: u8,
    /// Message flags (reserved, must be zero).
    pub flags: u8,
    /// Inline payload.
    pub data: [u8; 56],
    /// Capability slots transferred with the message.
    pub caps: [CapTransferSlot; 4],
}

/// Register layout of the `syscall` / `sysret` fast path.
///
/// On x86_64 the fields map to `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`
/// respectively; `rax` holds the [`SyscallNumber`] on entry and the
/// [`ErrorCode`] on return.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct SyscallArgs {
    /// Syscall number (`rax` on x86_64).
    pub number: u64,
    /// First argument (`rdi` on x86_64).
    pub arg0: u64,
    /// Second argument (`rsi` on x86_64).
    pub arg1: u64,
    /// Third argument (`rdx` on x86_64).
    pub arg2: u64,
    /// Fourth argument (`r10` on x86_64).
    pub arg3: u64,
    /// Fifth argument (`r8` on x86_64).
    pub arg4: u64,
    /// Sixth argument (`r9` on x86_64).
    pub arg5: u64,
}

/// Error codes returned by kernel syscalls and capability operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorCode {
    /// Operation completed successfully.
    Ok = 0,
    /// Capability pointer did not refer to a valid capability.
    InvalidCap = 1,
    /// The capability did not grant the requested rights.
    CapRightsViolation = 2,
    /// Insufficient memory to complete the operation.
    NoMemory = 3,
    /// Malformed IPC message (bad length, too many caps, etc.).
    BadMessage = 4,
    /// Object or endpoint not found.
    NotFound = 5,
    /// Operation would block and the caller requested non-blocking mode.
    WouldBlock = 6,
    /// Syscall or operation not yet implemented.
    NotImplemented = 7,
}

impl ErrorCode {
    /// Return the error code as a `u64` for the register return convention.
    pub const fn as_u64(self) -> u64 {
        self as u64
    }

    /// Decode a syscall's `u64` register return into its success or error result.
    ///
    /// # Errors
    ///
    /// Returns the corresponding error for codes 1 through 7. Unknown values
    /// are reported as [`ErrorCode::NotImplemented`].
    pub const fn from_u64(value: u64) -> Result<(), ErrorCode> {
        match value {
            0 => Ok(()),
            1 => Err(Self::InvalidCap),
            2 => Err(Self::CapRightsViolation),
            3 => Err(Self::NoMemory),
            4 => Err(Self::BadMessage),
            5 => Err(Self::NotFound),
            6 => Err(Self::WouldBlock),
            7 => Err(Self::NotImplemented),
            _ => Err(Self::NotImplemented),
        }
    }
}

// Compile-time size checks for ABI stability.
const _: () = assert!(core::mem::size_of::<CapTransferSlot>() == 24);
// NOTE: IpcMessage is 168 bytes, exceeding the 128-byte cache-line target.
// The layout follows the spec exactly; reducing size would require
// shrinking fields (e.g. cptr/badge from u64 to u32).
const _: () = assert!(core::mem::size_of::<IpcMessage>() == 168);
const _: () = assert!(core::mem::size_of::<SyscallArgs>() == 56);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_rights_new_has_all() {
        let all = CapRights::new();
        assert!(all.contains(CapRights::READ));
        assert!(all.contains(CapRights::WRITE));
        assert!(all.contains(CapRights::GRANT));
        assert!(all.contains(CapRights::REPLY));
    }

    #[test]
    fn cap_rights_empty_is_empty() {
        let empty = CapRights::empty();
        assert!(!empty.contains(CapRights::READ));
        assert!(!empty.contains(CapRights::WRITE));
        assert!(!empty.contains(CapRights::GRANT));
        assert!(!empty.contains(CapRights::REPLY));
    }

    #[test]
    fn cap_rights_intersection() {
        let rw = CapRights::READ.union(CapRights::WRITE);
        let wg = CapRights::WRITE.union(CapRights::GRANT);
        let w = rw.intersection(wg);
        assert!(w.contains(CapRights::WRITE));
        assert!(!w.contains(CapRights::READ));
        assert!(!w.contains(CapRights::GRANT));
    }

    #[test]
    fn cap_rights_union() {
        let r = CapRights::READ;
        let w = CapRights::WRITE;
        let rw = r.union(w);
        assert!(rw.contains(CapRights::READ));
        assert!(rw.contains(CapRights::WRITE));
        assert!(!rw.contains(CapRights::GRANT));
        assert!(!rw.contains(CapRights::REPLY));
    }

    #[test]
    fn cap_op_wire_codes_are_stable() {
        // Given: every user-visible capability operation.
        // When: each operation is represented on the syscall wire.
        // Then: its discriminant matches the kernel's operation decoder.
        assert_eq!(CapOp::Send as u64, 0);
        assert_eq!(CapOp::Recv as u64, 1);
        assert_eq!(CapOp::Signal as u64, 2);
        assert_eq!(CapOp::Wait as u64, 3);
        assert_eq!(CapOp::Delete as u64, 4);
        assert_eq!(CapOp::Retype as u64, 5);
        assert_eq!(CapOp::Mint as u64, 6);
        assert_eq!(CapOp::Move as u64, 7);
    }

    #[test]
    fn error_code_round_trip() {
        assert_eq!(ErrorCode::Ok.as_u64(), 0);
        assert_eq!(ErrorCode::InvalidCap.as_u64(), 1);
        assert_eq!(ErrorCode::CapRightsViolation.as_u64(), 2);
        assert_eq!(ErrorCode::NoMemory.as_u64(), 3);
        assert_eq!(ErrorCode::BadMessage.as_u64(), 4);
        assert_eq!(ErrorCode::NotFound.as_u64(), 5);
        assert_eq!(ErrorCode::WouldBlock.as_u64(), 6);
        assert_eq!(ErrorCode::NotImplemented.as_u64(), 7);
    }

    #[test]
    fn error_code_from_u64_decodes_known_results() {
        // Given: every defined syscall return value.
        // When: each value is decoded at the user-space boundary.
        // Then: zero succeeds and each non-zero value preserves its error.
        assert_eq!(ErrorCode::from_u64(0), Ok(()));
        assert_eq!(ErrorCode::from_u64(1), Err(ErrorCode::InvalidCap));
        assert_eq!(
            ErrorCode::from_u64(2),
            Err(ErrorCode::CapRightsViolation)
        );
        assert_eq!(ErrorCode::from_u64(3), Err(ErrorCode::NoMemory));
        assert_eq!(ErrorCode::from_u64(4), Err(ErrorCode::BadMessage));
        assert_eq!(ErrorCode::from_u64(5), Err(ErrorCode::NotFound));
        assert_eq!(ErrorCode::from_u64(6), Err(ErrorCode::WouldBlock));
        assert_eq!(ErrorCode::from_u64(7), Err(ErrorCode::NotImplemented));
    }

    #[test]
    fn error_code_from_u64_rejects_unknown_value() {
        // Given: a value outside the defined syscall return range.
        // When: the value is decoded at the user-space boundary.
        // Then: it is reported as an unsupported operation.
        assert_eq!(
            ErrorCode::from_u64(u64::MAX),
            Err(ErrorCode::NotImplemented)
        );
    }

    #[test]
    fn ipc_message_default() {
        let msg = IpcMessage {
            label: 42,
            length: 8,
            cap_count: 1,
            flags: 0,
            data: [0; 56],
            caps: [CapTransferSlot {
                cptr: 3,
                rights: CapRights::READ,
                badge: 0xDEAD,
            }; 4],
        };
        assert_eq!(msg.label, 42);
        assert_eq!(msg.caps[0].cptr, 3);
    }
}
