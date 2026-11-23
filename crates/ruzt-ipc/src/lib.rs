#![no_std]
#![deny(unsafe_code)]

use ruzt_abi::{
    CapOp, CapRights, ErrorCode, IpcMessage, ProcessStatus, RetypeKind, SyscallNumber, WaitEvent,
};

pub fn send(endpoint_cptr: u64, message: &IpcMessage) -> Result<(), ErrorCode> {
    let return_value = {
        #[allow(unsafe_code)]
        // SAFETY: [Category 13 - Library contract] The immutable borrow keeps
        // the complete message readable for the synchronous `Send` operation.
        unsafe {
            ruzt_runtime::syscall::syscall(
                SyscallNumber::Invoke,
                endpoint_cptr,
                CapOp::Send as u64,
                message as *const IpcMessage as u64,
                0,
                0,
                0,
            )
        }
    };

    ErrorCode::from_u64(return_value)
}

pub fn recv(endpoint_cptr: u64, message: &mut IpcMessage) -> Result<(), ErrorCode> {
    recv_with_caps(endpoint_cptr, message, 0, 0)
}

/// Receive a message and accept up to `capacity` caps in slots starting at `first`.
///
/// The message buffer must be in a non-revocable mapping.
pub fn recv_with_caps(
    endpoint_cptr: u64,
    message: &mut IpcMessage,
    first: u64,
    capacity: u8,
) -> Result<(), ErrorCode> {
    let return_value = {
        #[allow(unsafe_code)]
        // SAFETY: [Categories 1 and 13 - aliasing and library contract] The
        // exclusive borrow keeps the complete message uniquely writable for
        // the synchronous `Recv` operation and prevents aliasing accesses.
        unsafe {
            ruzt_runtime::syscall::syscall(
                SyscallNumber::Invoke,
                endpoint_cptr,
                CapOp::Recv as u64,
                message as *mut IpcMessage as u64,
                first,
                u64::from(capacity),
                0,
            )
        }
    };

    ErrorCode::from_u64(return_value)
}

/// Set a notification or wake one of its waiters.
pub fn signal(notification: u64) -> Result<(), ErrorCode> {
    control(notification, CapOp::Signal, 0, 0, 0)
}

/// Block until the notification has been signalled.
pub fn wait(notification: u64) -> Result<(), ErrorCode> {
    control(notification, CapOp::Wait, 0, 0, 0)
}

/// Block until one of the supplied capabilities delivers an event.
///
/// Accepts endpoints, notifications, driver IRQs, and process status caps.
/// If several sources are ready, the first in the list wins. A returned
/// message, notification, or IRQ has already been consumed.
pub fn wait_any(sources: &[u64]) -> Result<WaitEvent, ErrorCode> {
    wait_any_with_caps(sources, 0, 0)
}

/// Wait for an event and accept grants in one contiguous receive window.
///
/// Each endpoint in the list uses the same window, as in [`recv_with_caps`].
/// Losing authority to any wait source cancels the wait.
pub fn wait_any_with_caps(
    sources: &[u64],
    first: u64,
    capacity: u8,
) -> Result<WaitEvent, ErrorCode> {
    let mut event = WaitEvent::default();
    #[allow(unsafe_code)]
    // SAFETY: The slice is readable and the local event is exclusively
    // writable for the duration of the call.
    let status = unsafe {
        ruzt_runtime::syscall::syscall(
            SyscallNumber::WaitAny,
            sources.as_ptr() as u64,
            sources.len() as u64,
            (&raw mut event) as u64,
            first,
            u64::from(capacity),
            0,
        )
    };
    ErrorCode::from_u64(status)?;
    Ok(event)
}

/// Derive a capability in an empty slot of the caller's capability space.
pub fn mint(source: u64, destination: u64, rights: CapRights, badge: u64) -> Result<(), ErrorCode> {
    control(
        source,
        CapOp::Mint,
        destination,
        u64::from(rights.bits()),
        badge,
    )
}

/// Move a capability to an empty slot in the same capability space.
pub fn move_cap(source: u64, destination: u64) -> Result<(), ErrorCode> {
    control(source, CapOp::Move, destination, 0, 0)
}

/// Delete the capability in this slot.
pub fn delete(cptr: u64) -> Result<(), ErrorCode> {
    control(cptr, CapOp::Delete, 0, 0, 0)
}

/// Revoke all descendants while keeping the invoked capability.
pub fn revoke(cptr: u64) -> Result<(), ErrorCode> {
    control(cptr, CapOp::Revoke, 0, 0, 0)
}

/// Create a child object in an empty slot, charging the invoked Untyped budget.
/// Use [`split_untyped`] or [`create_cnode`] for objects with an explicit size.
pub fn retype(untyped: u64, destination: u64, kind: RetypeKind) -> Result<(), ErrorCode> {
    control(untyped, CapOp::Retype, destination, kind as u64, 0)
}

/// Create a child capability table with `2^radix_bits` empty slots.
///
/// Access its contents using slot paths constructed with
/// [`ruzt_abi::cptr_path`].
pub fn create_cnode(untyped: u64, destination: u64, radix_bits: u8) -> Result<(), ErrorCode> {
    control(
        untyped,
        CapOp::Retype,
        destination,
        RetypeKind::CNode as u64,
        u64::from(radix_bits),
    )
}

/// Reserve a smaller Untyped budget in an empty slot.
///
/// Its size is `2^size_bits` bytes and must be at least one page.
pub fn split_untyped(untyped: u64, destination: u64, size_bits: u8) -> Result<(), ErrorCode> {
    control(
        untyped,
        CapOp::Retype,
        destination,
        RetypeKind::Untyped as u64,
        u64::from(size_bits),
    )
}

/// Map a shared frame into the caller at a page-aligned user address.
///
/// A capability has at most one mapping. Revoking or deleting it removes
/// that mapping. Callers must coordinate access with the other frame holders.
pub fn map_frame(cptr: u64, address: u64, writable: bool) -> Result<(), ErrorCode> {
    control(cptr, CapOp::MapFrame, address, u64::from(writable), 0)
}

/// Remove the caller's mapping made through this capability.
pub fn unmap_frame(cptr: u64) -> Result<(), ErrorCode> {
    control(cptr, CapOp::UnmapFrame, 0, 0, 0)
}

/// Map zeroed private memory at a page-aligned address using the process budget.
pub fn map_anonymous(
    address_space: u64,
    address: u64,
    pages: usize,
    writable: bool,
) -> Result<(), ErrorCode> {
    control(
        address_space,
        CapOp::MapAnonymous,
        address,
        pages as u64,
        u64::from(writable),
    )
}

/// Unmap each page in a range of previously allocated anonymous memory.
pub fn unmap_anonymous(address_space: u64, address: u64, pages: usize) -> Result<(), ErrorCode> {
    control(
        address_space,
        CapOp::UnmapAnonymous,
        address,
        pages as u64,
        0,
    )
}

/// Wait for a process to terminate and return its status after cleanup.
pub fn wait_process(cptr: u64) -> Result<ProcessStatus, ErrorCode> {
    process_status(cptr, false)
}

/// Launch a program with attenuated startup capabilities in consecutive slots.
///
/// The process status capability is installed at `status_slot`. Set a bit in
/// `close_on_exit` for each startup endpoint that should close on termination.
/// The child's private address-space pages come from `memory_budget`.
#[allow(unsafe_code)]
pub fn spawn_program(
    program: u64,
    status_slot: u64,
    grants: &IpcMessage,
    close_on_exit: u8,
    memory_budget: u64,
) -> Result<(), ErrorCode> {
    // SAFETY: The immutable borrow keeps the entire grant packet readable
    // throughout this synchronous syscall. The remaining arguments are scalar.
    let status = unsafe {
        ruzt_runtime::syscall::syscall(
            SyscallNumber::Invoke,
            program,
            CapOp::SpawnProgram as u64,
            status_slot,
            (grants as *const IpcMessage) as u64,
            u64::from(close_on_exit),
            memory_budget,
        )
    };
    ErrorCode::from_u64(status)
}

/// Read the terminal status or return `WouldBlock` while the process is live.
pub fn poll_process(cptr: u64) -> Result<ProcessStatus, ErrorCode> {
    process_status(cptr, true)
}

fn process_status(cptr: u64, nonblocking: bool) -> Result<ProcessStatus, ErrorCode> {
    let mut status = ProcessStatus::default();
    control(
        cptr,
        CapOp::WaitProcess,
        (&raw mut status) as u64,
        u64::from(nonblocking),
        0,
    )?;
    Ok(status)
}

#[allow(unsafe_code)]
fn control(cptr: u64, op: CapOp, arg2: u64, arg3: u64, arg4: u64) -> Result<(), ErrorCode> {
    // SAFETY: The wrappers supply the arguments required by each operation.
    let status = unsafe {
        ruzt_runtime::syscall::syscall(SyscallNumber::Invoke, cptr, op as u64, arg2, arg3, arg4, 0)
    };
    ErrorCode::from_u64(status)
}
