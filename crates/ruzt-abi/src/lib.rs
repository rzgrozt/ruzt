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

/// Slot where the root process creates its console request capability.
pub const ROOTSRV_CONSOLE_REQUEST: u64 = 0;

/// Slot for the initial process's claimed PS/2 keyboard interrupt.
pub const ROOTSRV_KEYBOARD_IRQ: u64 = 1;

/// Capability slot granted to the initial process for the PS/2 data port.
pub const ROOTSRV_KEYBOARD_DATA: u64 = 2;

/// Capability slot granted to the initial process when a framebuffer is available.
pub const ROOTSRV_FRAMEBUFFER: u64 = 3;

/// Slot where the root process creates its console reply capability.
pub const ROOTSRV_CONSOLE_REPLY: u64 = 4;

/// Slot where the root process creates the console notification.
pub const ROOTSRV_CONSOLE_NOTIFICATION: u64 = 8;
/// Slot where the root process creates the frame to share with the console.
pub const ROOTSRV_CONSOLE_FRAME: u64 = 9;
/// RAM budget initially granted to the root process.
pub const ROOTSRV_UNTYPED: u64 = 10;
/// Read authority for the console service's termination status.
pub const ROOTSRV_CONSOLE_PROCESS: u64 = 13;
/// Authority to launch the console executable from the boot archive.
pub const ROOTSRV_CONSOLE_PROGRAM: u64 = 14;
/// Delegable authority for the console's UART data port.
pub const ROOTSRV_UART_DATA: u64 = 18;
/// Delegable authority for the console's UART status port.
pub const ROOTSRV_UART_STATUS: u64 = 19;
/// Boot authority to claim device interrupt lines.
pub const ROOTSRV_IRQ_CONTROL: u64 = 28;
/// Authority to configure the console UART's interrupt enable register.
pub const ROOTSRV_UART_IRQ_ENABLE: u64 = 29;
/// Authority to read the console UART's interrupt identification register.
pub const ROOTSRV_UART_IRQ_IDENTIFY: u64 = 30;
/// Self address-space capability installed at process startup.
pub const PROCESS_ADDRESS_SPACE: u64 = 15;
/// Base virtual address of the initial runtime heap.
pub const USER_HEAP_START: u64 = 0x4000_0000;
/// Bytes mapped at the heap base before entering user mode.
pub const USER_HEAP_INITIAL_BYTES: usize = 1024 * 1024;
/// Exclusive end of the virtual range reserved for the runtime heap.
pub const USER_HEAP_LIMIT: u64 = USER_HEAP_START + 16 * 1024 * 1024;

/// Byte length of a frame supported by the user mapping ABI.
pub const FRAME_BYTES: usize = 4096;

/// Largest supported radix of a retyped capability table.
pub const MAX_CNODE_RADIX: u8 = 8;

/// Maximum number of slot indices in one capability pointer.
pub const MAX_CPTR_DEPTH: usize = 7;
const CPTR_DEPTH_TAG: u8 = 0x80;

/// Encode a path from the caller's root capability table to a slot.
///
/// A single index uses its original root-slot number. Multi-level paths
/// contain two to seven indices, with the root index first and the leaf
/// index in the low byte. The high byte is 0x80 plus the number of indices.
pub fn cptr_path(indices: &[u8]) -> Result<u64, ErrorCode> {
    let depth = indices.len();
    if !(1..=MAX_CPTR_DEPTH).contains(&depth) {
        return Err(ErrorCode::InvalidCap);
    }
    let path = indices
        .iter()
        .fold(0u64, |path, &index| (path << 8) | u64::from(index));
    if depth == 1 {
        Ok(path)
    } else {
        Ok(u64::from(CPTR_DEPTH_TAG | depth as u8) << 56 | path)
    }
}

/// Validate a slot pointer's encoding and return its number of indices.
pub fn cptr_depth(cptr: u64) -> Result<usize, ErrorCode> {
    if cptr <= u64::from(u8::MAX) {
        return Ok(1);
    }
    let tag = (cptr >> 56) as u8;
    let depth = usize::from(tag & !CPTR_DEPTH_TAG);
    if tag & CPTR_DEPTH_TAG == 0 || !(2..=MAX_CPTR_DEPTH).contains(&depth) {
        return Err(ErrorCode::InvalidCap);
    }
    let payload = cptr & ((1u64 << 56) - 1);
    if payload >> (depth * 8) != 0 {
        return Err(ErrorCode::InvalidCap);
    }
    Ok(depth)
}

/// Boot console service protocol and capability slots.
pub mod console {
    /// Receive requests from the initial process.
    pub const REQUEST: u64 = 0;
    /// Send replies to the initial process.
    pub const REPLY: u64 = 1;
    /// Write to the UART data register.
    pub const UART_DATA: u64 = 2;
    /// Read the UART line status register.
    pub const UART_STATUS: u64 = 3;
    /// Empty slot where the console accepts its boot notification.
    pub const RECEIVED_NOTIFICATION: u64 = 4;
    /// Following slot where the console accepts its read-only frame.
    pub const RECEIVED_FRAME: u64 = 5;
    /// Slot where the console accepts an independently sized RAM budget.
    pub const RECEIVED_UNTYPED: u64 = 6;

    /// Write the inline payload to the console.
    pub const WRITE: u64 = 1;
    /// The console wrote the requested bytes.
    pub const WRITTEN: u64 = 2;
    /// The console did not recognize the request.
    pub const UNKNOWN_REQUEST: u64 = 3;
    /// Check that the boot grants were revoked and that a fresh frame cap can remap the page.
    pub const CHECK_REVOCATION: u64 = 4;
    /// Boot grants and mappings derived from the console budget were revoked.
    pub const REVOKED: u64 = 5;
    /// Write bytes from the transferred frame. The grants are a notification,
    /// a read-only frame, and an Untyped budget. The inline payload is a
    /// little-endian u16 byte count.
    pub const WRITE_SHARED: u64 = 6;
    /// Exercise two interrupts on a delegated UART line.
    pub const CHECK_IRQ: u64 = 7;
    /// A UART interrupt was received and acknowledged.
    pub const IRQ_CHECKED: u64 = 8;
}

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
    /// Terminate the calling user task with the status in `arg0`.
    Exit = 5,
    /// Wait on a list of endpoint, notification, IRQ, or process capabilities.
    ///
    /// `arg0` points to the array of `u64` capability pointers, `arg1`
    /// gives its length, and `arg2` points to a writable [`WaitEvent`] in
    /// a non-revocable mapping. `arg3` and `arg4` describe a contiguous
    /// capability receive window, as for [`CapOp::Recv`].
    WaitAny = 6,
    /// Wait like [`Self::WaitAny`], or return [`ErrorCode::TimedOut`].
    ///
    /// `arg5` is the absolute monotonic deadline in nanoseconds. A ready
    /// source can be polled with a deadline of zero. With an empty source
    /// list the call sleeps until the deadline and ignores buffer arguments.
    WaitAnyUntil = 7,
    /// Write the monotonic timestamp in nanoseconds to the `u64` at `arg0`.
    MonotonicTime = 8,
}

impl From<u64> for SyscallNumber {
    fn from(value: u64) -> Self {
        match value {
            0 => Self::Invoke,
            1 => Self::_Reply,
            2 => Self::_Yield,
            3 => Self::DebugPutChar,
            5 => Self::Exit,
            6 => Self::WaitAny,
            7 => Self::WaitAnyUntil,
            8 => Self::MonotonicTime,
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
    /// Receive an IPC message through an endpoint. For capability transfer,
    /// `arg3` is the first receiving slot and `arg4` is the slot capacity.
    /// Grants in one message must fit in the same capability table.
    /// The output buffer must be in a non-revocable mapping.
    Recv = 1,
    /// Signal a notification object.
    Signal = 2,
    /// Wait on a notification or a device interrupt.
    Wait = 3,
    /// Delete a capability.
    Delete = 4,
    /// Create a child object from an Untyped capability. `arg2` is the
    /// empty destination slot and `arg3` is a [`RetypeKind`]. For an Untyped
    /// child, `arg4` is the base-two exponent of its size in bytes. For a
    /// CNode, `arg4` is the base-two exponent of the number of slots.
    Retype = 5,
    /// Mint a derived capability.
    Mint = 6,
    /// Move a capability between slots.
    Move = 7,
    /// Read one byte from a port capability into the user pointer in `arg2`.
    ReadPort8 = 8,
    /// Copy a mapped framebuffer's layout into the user pointer in `arg2`.
    FramebufferInfo = 9,
    /// Write the byte in `arg2` to a port capability.
    WritePort8 = 10,
    /// Remove all capabilities derived from the invoked capability.
    Revoke = 11,
    /// Map the invoked frame at `arg2`. In `arg3`, 0 requests read-only and 1 requests read-write.
    MapFrame = 12,
    /// Remove the caller's mapping created with this frame capability.
    UnmapFrame = 13,
    /// Read a process's terminal status into the buffer in `arg2`. With
    /// `arg3` set to 0 this blocks until cleanup, or with 1 it polls.
    /// A blocking wait requires an output buffer in a non-revocable mapping.
    WaitProcess = 14,
    /// Launch this program in a fresh address space and capability space.
    /// `arg2` is the empty process status slot in the caller. `arg3` points
    /// to an [`IpcMessage`] containing only startup grants for child slots
    /// starting at zero. Each bit in `arg4` selects a startup endpoint that
    /// will close on child exit and requires full read, write and grant
    /// authority on the source endpoint. `arg5` is a writable Untyped slot
    /// that funds the child's private address-space pages.
    SpawnProgram = 15,
    /// Map zeroed private pages at `arg2` in the invoked address space.
    /// `arg3` is the page count and `arg4` selects read-only (0) or read-write (1).
    MapAnonymous = 16,
    /// Unmap a range of private pages created by `MapAnonymous`.
    /// `arg2` is the start address and `arg3` is the page count.
    UnmapAnonymous = 17,
    /// Extend the runtime heap with zeroed writable pages.
    /// `arg2` is the current heap end and `arg3` is the number of pages to add.
    GrowHeap = 18,
    /// Claim the hardware line in `arg3` into slot `arg2` using IRQ control.
    ClaimIrq = 19,
    /// Bind the invoked IRQ to the calling driver.
    BindIrq = 20,
    /// Re-arm the invoked IRQ after consuming its event and servicing the device.
    AckIrq = 21,
    /// Remove the caller's binding and mask the invoked IRQ.
    UnbindIrq = 22,
}

/// The process invoked `Exit`.
pub const PROCESS_EXITED: u32 = 0;
/// The kernel terminated the process on a user-mode exception.
pub const PROCESS_FAULTED: u32 = 1;

/// Termination status published after the process's resources are reclaimed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct ProcessStatus {
    /// One of the `PROCESS_*` termination kinds.
    pub kind: u32,
    /// Process exit code or architecture exception number.
    pub code: u32,
}

/// Maximum number of sources in one [`SyscallNumber::WaitAny`] call.
pub const MAX_WAIT_SOURCES: usize = 8;

/// The selected endpoint delivered a message.
pub const WAIT_MESSAGE: u64 = 1;
/// The selected notification was signalled and consumed.
pub const WAIT_NOTIFICATION: u64 = 2;
/// The selected IRQ was pending and is ready for the driver to handle.
pub const WAIT_IRQ: u64 = 3;
/// The selected endpoint was closed.
pub const WAIT_ENDPOINT_CLOSED: u64 = 4;
/// The selected process has been reaped and its status can be read.
pub const WAIT_PROCESS_EXITED: u64 = 5;

/// The first ready event in a caller's ordered wait list.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct WaitEvent {
    /// Zero-based index in the input list.
    pub index: u64,
    /// One of the `WAIT_*` event kinds.
    pub kind: u64,
    /// The received message for [`WAIT_MESSAGE`], empty for other kinds.
    pub message: IpcMessage,
}

const _: () = assert!(core::mem::size_of::<ProcessStatus>() == 8);

/// Objects that can be created by invoking an Untyped capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum RetypeKind {
    /// A zero-initialized 4 KiB RAM frame.
    Frame = 0,
    /// A synchronous IPC endpoint.
    Endpoint = 1,
    /// An initially unsignalled notification.
    Notification = 2,
    /// A smaller, naturally aligned Untyped RAM region.
    Untyped = 3,
    /// A capability table with up to 256 slots.
    CNode = 4,
}

impl TryFrom<u64> for RetypeKind {
    type Error = ErrorCode;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Frame),
            1 => Ok(Self::Endpoint),
            2 => Ok(Self::Notification),
            3 => Ok(Self::Untyped),
            4 => Ok(Self::CNode),
            _ => Err(ErrorCode::BadMessage),
        }
    }
}

/// Byte layout of an RGB framebuffer.
pub const FRAMEBUFFER_RGB: u32 = 1;
/// Byte layout of a BGR framebuffer.
pub const FRAMEBUFFER_BGR: u32 = 2;
/// Byte layout of a grayscale framebuffer.
pub const FRAMEBUFFER_GRAY8: u32 = 3;

/// Description of a boot framebuffer mapped into the caller's address space.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct FramebufferInfo {
    /// Base address of the user mapping.
    pub address: u64,
    /// Total byte length of the visible framebuffer, including row padding.
    pub byte_len: u64,
    /// Visible width in pixels.
    pub width: u32,
    /// Visible height in pixels.
    pub height: u32,
    /// Row pitch in bytes.
    pub pitch: u32,
    /// Number of bytes per pixel.
    pub bytes_per_pixel: u32,
    /// Pixel byte layout, one of the `FRAMEBUFFER_*` constants.
    pub format: u32,
    /// Reserved for ABI growth. Set to zero.
    pub reserved: u32,
}

const _: () = assert!(core::mem::size_of::<FramebufferInfo>() == 40);

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

    /// Encode the rights for a capability invocation.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Decode a rights mask, rejecting reserved bits.
    pub const fn from_bits(bits: u64) -> Option<Self> {
        if bits <= Self::new().0 as u64 {
            Some(Self(bits as u8))
        } else {
            None
        }
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
    /// Source slot on send or installed slot on receive.
    pub cptr: u64,
    /// Rights to transfer.
    pub rights: CapRights,
    /// Optional badge to mint onto the copy.
    pub badge: u64,
}

/// Maximum number of capabilities transferred with one message.
pub const IPC_CAP_SLOTS: usize = 4;

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
    pub caps: [CapTransferSlot; IPC_CAP_SLOTS],
}

impl Default for IpcMessage {
    fn default() -> Self {
        Self {
            label: 0,
            length: 0,
            cap_count: 0,
            flags: 0,
            data: [0; 56],
            caps: [CapTransferSlot {
                cptr: 0,
                rights: CapRights::empty(),
                badge: 0,
            }; IPC_CAP_SLOTS],
        }
    }
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
    /// The destination capability slot is already occupied.
    SlotOccupied = 8,
    /// The requested virtual address or frame capability already has a mapping.
    MappingExists = 9,
    /// The operation's monotonic deadline expired.
    TimedOut = 10,
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
    /// Returns the corresponding error for codes 1 through 10. Unknown values
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
            8 => Err(Self::SlotOccupied),
            9 => Err(Self::MappingExists),
            10 => Err(Self::TimedOut),
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
        assert_eq!(CapOp::ReadPort8 as u64, 8);
        assert_eq!(CapOp::FramebufferInfo as u64, 9);
        assert_eq!(CapOp::WritePort8 as u64, 10);
        assert_eq!(CapOp::Revoke as u64, 11);
        assert_eq!(CapOp::MapFrame as u64, 12);
        assert_eq!(CapOp::UnmapFrame as u64, 13);
        assert_eq!(CapOp::WaitProcess as u64, 14);
        assert_eq!(CapOp::SpawnProgram as u64, 15);
        assert_eq!(CapOp::MapAnonymous as u64, 16);
        assert_eq!(CapOp::UnmapAnonymous as u64, 17);
        assert_eq!(CapOp::GrowHeap as u64, 18);
        assert_eq!(CapOp::ClaimIrq as u64, 19);
        assert_eq!(CapOp::BindIrq as u64, 20);
        assert_eq!(CapOp::AckIrq as u64, 21);
        assert_eq!(CapOp::UnbindIrq as u64, 22);
    }

    #[test]
    fn retype_kind_uses_known_wire_codes() {
        assert_eq!(RetypeKind::try_from(0), Ok(RetypeKind::Frame));
        assert_eq!(RetypeKind::try_from(1), Ok(RetypeKind::Endpoint));
        assert_eq!(RetypeKind::try_from(2), Ok(RetypeKind::Notification));
        assert_eq!(RetypeKind::try_from(3), Ok(RetypeKind::Untyped));
        assert_eq!(RetypeKind::try_from(4), Ok(RetypeKind::CNode));
        assert_eq!(RetypeKind::try_from(5), Err(ErrorCode::BadMessage));
    }

    #[test]
    fn cptr_paths_preserve_root_slots_and_reject_noncanonical_encodings() {
        assert_eq!(cptr_path(&[200]), Ok(200));
        let path = cptr_path(&[0, 23, 255]).unwrap();
        assert_eq!(path, 0x8300_0000_0000_17ff);
        assert_eq!(cptr_depth(path), Ok(3));
        assert_eq!(cptr_depth(path | (1 << 24)), Err(ErrorCode::InvalidCap));
        assert_eq!(
            cptr_depth(0x8100_0000_0000_0001),
            Err(ErrorCode::InvalidCap)
        );
        assert_eq!(cptr_path(&[255; 7]).and_then(cptr_depth), Ok(7));
        assert_eq!(cptr_path(&[0; 8]), Err(ErrorCode::InvalidCap));
        assert_eq!(cptr_path(&[]), Err(ErrorCode::InvalidCap));
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
        assert_eq!(ErrorCode::SlotOccupied.as_u64(), 8);
        assert_eq!(ErrorCode::MappingExists.as_u64(), 9);
        assert_eq!(ErrorCode::TimedOut.as_u64(), 10);
    }

    #[test]
    fn error_code_from_u64_decodes_known_results() {
        // Given: every defined syscall return value.
        // When: each value is decoded at the user-space boundary.
        // Then: zero succeeds and each non-zero value preserves its error.
        assert_eq!(ErrorCode::from_u64(0), Ok(()));
        assert_eq!(ErrorCode::from_u64(1), Err(ErrorCode::InvalidCap));
        assert_eq!(ErrorCode::from_u64(2), Err(ErrorCode::CapRightsViolation));
        assert_eq!(ErrorCode::from_u64(3), Err(ErrorCode::NoMemory));
        assert_eq!(ErrorCode::from_u64(4), Err(ErrorCode::BadMessage));
        assert_eq!(ErrorCode::from_u64(5), Err(ErrorCode::NotFound));
        assert_eq!(ErrorCode::from_u64(6), Err(ErrorCode::WouldBlock));
        assert_eq!(ErrorCode::from_u64(7), Err(ErrorCode::NotImplemented));
        assert_eq!(ErrorCode::from_u64(8), Err(ErrorCode::SlotOccupied));
        assert_eq!(ErrorCode::from_u64(9), Err(ErrorCode::MappingExists));
        assert_eq!(ErrorCode::from_u64(10), Err(ErrorCode::TimedOut));
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
