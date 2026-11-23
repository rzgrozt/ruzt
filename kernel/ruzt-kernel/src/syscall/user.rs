//! Capability invocations from scheduled user threads.

use core::mem::{offset_of, size_of};
use ruzt_abi::{
    CapOp, CapRights, CapTransferSlot, ErrorCode, FramebufferInfo, IpcMessage, ProcessStatus,
    RetypeKind, SyscallArgs, WaitEvent, IPC_CAP_SLOTS, MAX_WAIT_SOURCES,
};
use ruzt_cap::CapType;
use ruzt_hal::mem::PhysFrame;
use x86_64::instructions::port::{PortReadOnly, PortWriteOnly};

use super::user_mem;
use crate::cap::ops::{cap_delete, cap_mint, cap_move};
use crate::{ipc, keyboard, process, sched};

const DATA_OFFSET: usize = offset_of!(IpcMessage, data);
const LABEL_OFFSET: usize = offset_of!(IpcMessage, label);
const LENGTH_OFFSET: usize = offset_of!(IpcMessage, length);
const COUNT_OFFSET: usize = offset_of!(IpcMessage, cap_count);
const CAPS_OFFSET: usize = offset_of!(IpcMessage, caps);
const CPTR_OFFSET: usize = offset_of!(CapTransferSlot, cptr);
const RIGHTS_OFFSET: usize = offset_of!(CapTransferSlot, rights);
const BADGE_OFFSET: usize = offset_of!(CapTransferSlot, badge);

pub(crate) fn invoke(args: &SyscallArgs) -> Result<(), ErrorCode> {
    let operation = args.arg1;
    if operation == CapOp::Retype as u64 {
        let kind = RetypeKind::try_from(args.arg3)?;
        return sched::with_current_user(|process| {
            process.cspace.retype(args.arg0, args.arg2, kind, args.arg4)
        })
        .ok_or(ErrorCode::InvalidCap)?;
    }
    if operation == CapOp::MapFrame as u64 {
        let writable = match args.arg3 {
            0 => false,
            1 => true,
            _ => return Err(ErrorCode::BadMessage),
        };
        return sched::with_current_user(|process| {
            process.map_shared_frame(args.arg0, args.arg2, writable)
        })
        .ok_or(ErrorCode::InvalidCap)?;
    }
    if operation == CapOp::UnmapFrame as u64 {
        return sched::with_current_user(|process| process.unmap_shared_frame(args.arg0))
            .ok_or(ErrorCode::InvalidCap)?;
    }
    if operation == CapOp::Mint as u64
        || operation == CapOp::Move as u64
        || operation == CapOp::Delete as u64
        || operation == CapOp::Revoke as u64
    {
        let result = sched::with_current_user(|process| {
            let space = &mut process.cspace;
            match operation {
                op if op == CapOp::Mint as u64 => {
                    let rights = CapRights::from_bits(args.arg3).ok_or(ErrorCode::BadMessage)?;
                    cap_mint(space, args.arg0, args.arg2, rights, args.arg4)
                }
                op if op == CapOp::Move as u64 => cap_move(space, args.arg0, args.arg2),
                op if op == CapOp::Delete as u64 => cap_delete(space, args.arg0),
                _ => space.revoke(args.arg0),
            }
        })
        .ok_or(ErrorCode::InvalidCap)?;
        if result.is_ok()
            && (operation == CapOp::Revoke as u64 || operation == CapOp::Delete as u64)
        {
            sched::apply_capability_removals();
        }
        return result;
    }
    let (root, capability, authority, framebuffer) = sched::with_current_user(|process| {
        let capability = process.cspace.lookup(args.arg0)?;
        let authority = process.cspace.capability_id(args.arg0)?;
        Ok::<_, ErrorCode>((
            process.root(),
            capability,
            Some(authority),
            process.framebuffer,
        ))
    })
    .ok_or(ErrorCode::InvalidCap)??;
    // Capability lookup is complete and the scheduler lock is released before
    // any operation can block. User invocation currently runs on one CPU.
    match capability.cap_type {
        CapType::Endpoint(id) if args.arg1 == CapOp::Send as u64 => {
            require(capability.rights, CapRights::WRITE)?;
            ipc::send_packet(
                id,
                authority,
                read_packet(root, args.arg2, capability.rights)?,
            )
        }
        CapType::Endpoint(id) if args.arg1 == CapOp::Recv as u64 => {
            require(capability.rights, CapRights::READ)?;
            // Reject bad buffers before consuming a pending sender or blocking.
            validate_blocking_output(root, args.arg2, size_of::<IpcMessage>())?;
            let slots = receive_slots(args.arg3, args.arg4)?;
            let message = ipc::receive_packet(id, authority, slots)?;
            write_message(root, args.arg2, &message)
        }
        CapType::Process(id) if args.arg1 == CapOp::WaitProcess as u64 => {
            require(capability.rights, CapRights::READ)?;
            let nonblocking = match args.arg3 {
                0 => false,
                1 => true,
                _ => return Err(ErrorCode::BadMessage),
            };
            let length = size_of::<ProcessStatus>();
            if nonblocking {
                user_mem::validate_user_buffer(root, args.arg2, length, true)?;
            } else {
                validate_blocking_output(root, args.arg2, length)?;
            }
            let status = process::wait_for_status(id, authority, nonblocking)?;
            let mut bytes = [0; size_of::<ProcessStatus>()];
            bytes[..4].copy_from_slice(&status.kind.to_ne_bytes());
            bytes[4..].copy_from_slice(&status.code.to_ne_bytes());
            user_mem::write_user_buffer(root, args.arg2, &bytes)
        }
        CapType::Program(id) if args.arg1 == CapOp::SpawnProgram as u64 => {
            require(capability.rights, CapRights::WRITE)?;
            let grants = read_packet(root, args.arg3, capability.rights)?;
            process::spawn_program(
                crate::cap::object::KObjectId(id),
                args.arg2,
                grants,
                args.arg4,
                args.arg5,
            )
        }
        CapType::AddressSpace(id) if operation == CapOp::MapAnonymous as u64 => {
            require(capability.rights, CapRights::WRITE)?;
            let writable = match args.arg4 {
                0 => false,
                1 => true,
                _ => return Err(ErrorCode::BadMessage),
            };
            sched::with_current_user(|process| {
                process.map_anonymous(id, args.arg2, args.arg3, writable)
            })
            .ok_or(ErrorCode::InvalidCap)?
        }
        CapType::AddressSpace(id) if operation == CapOp::UnmapAnonymous as u64 => {
            require(capability.rights, CapRights::WRITE)?;
            sched::with_current_user(|process| process.unmap_anonymous(id, args.arg2, args.arg3))
                .ok_or(ErrorCode::InvalidCap)?
        }
        CapType::AddressSpace(id) if operation == CapOp::GrowHeap as u64 => {
            require(capability.rights, CapRights::WRITE)?;
            sched::with_current_user(|process| process.grow_heap(id, args.arg2, args.arg3))
                .ok_or(ErrorCode::InvalidCap)?
        }
        CapType::Notification(id) if args.arg1 == CapOp::Signal as u64 => {
            require(capability.rights, CapRights::WRITE)?;
            ErrorCode::from_u64(ipc::notification_signal(id))
        }
        CapType::Notification(id) if args.arg1 == CapOp::Wait as u64 => {
            require(capability.rights, CapRights::READ)?;
            ipc::wait_notification(id, authority)
        }
        CapType::Irq {
            irq_num: keyboard::IRQ,
        } if args.arg1 == CapOp::Wait as u64 => {
            require(capability.rights, CapRights::READ)?;
            keyboard::wait_irq(authority)
        }
        CapType::IoPort { port } if args.arg1 == CapOp::ReadPort8 as u64 => {
            require(capability.rights, CapRights::READ)?;
            user_mem::write_user_buffer_with(root, args.arg2, 1, || {
                #[allow(unsafe_code)]
                // SAFETY: The checked kernel-issued capability names the
                // hardware port. The caller does not supply the port number.
                let byte = unsafe { PortReadOnly::<u8>::new(port).read() };
                [byte]
            })
        }
        CapType::IoPort { port } if args.arg1 == CapOp::WritePort8 as u64 => {
            require(capability.rights, CapRights::WRITE)?;
            let byte = u8::try_from(args.arg2).map_err(|_| ErrorCode::BadMessage)?;
            #[allow(unsafe_code)]
            // SAFETY: The kernel-issued capability identifies an allowed
            // byte-wide port and grants permission to write it.
            unsafe {
                PortWriteOnly::new(port).write(byte)
            };
            Ok(())
        }
        CapType::Framebuffer if args.arg1 == CapOp::FramebufferInfo as u64 => {
            require(capability.rights, CapRights::WRITE)?;
            let info = framebuffer.ok_or(ErrorCode::InvalidCap)?;
            #[allow(unsafe_code)]
            // SAFETY: The C-layout integer fields occupy all 40 bytes.
            let bytes: [u8; size_of::<FramebufferInfo>()] = unsafe { core::mem::transmute(info) };
            user_mem::write_user_buffer(root, args.arg2, &bytes)
        }
        _ => Err(ErrorCode::InvalidCap),
    }
}

pub(crate) fn wait_any(args: &SyscallArgs) -> Result<(), ErrorCode> {
    let count = usize::try_from(args.arg1).map_err(|_| ErrorCode::BadMessage)?;
    if !(1..=MAX_WAIT_SOURCES).contains(&count) {
        return Err(ErrorCode::BadMessage);
    }
    let root = sched::with_current_user(|process| process.root()).ok_or(ErrorCode::InvalidCap)?;
    let mut cptrs = [0u8; size_of::<u64>() * MAX_WAIT_SOURCES];
    let cptrs = &mut cptrs[..count * size_of::<u64>()];
    user_mem::read_user_buffer(root, args.arg0, cptrs)?;
    validate_blocking_output(root, args.arg2, size_of::<WaitEvent>())?;
    let slots = receive_slots(args.arg3, args.arg4)?;
    let thread = sched::current_thread_id();
    let sources = sched::with_current_user(|user| {
        let mut sources = [None; MAX_WAIT_SOURCES];
        for (entry, bytes) in sources.iter_mut().zip(cptrs.chunks_exact(size_of::<u64>())) {
            let cptr = u64::from_ne_bytes(bytes.try_into().unwrap());
            let (authority, slot) = user.cspace.lookup_path(cptr)?;
            *entry = Some(ipc::wait::Source::new(authority, slot, thread)?);
        }
        Ok(sources)
    })
    .ok_or(ErrorCode::InvalidCap)??;
    let event = ipc::wait::wait_any(&sources, slots)?;
    let mut bytes = [0; size_of::<WaitEvent>()];
    bytes[offset_of!(WaitEvent, index)..][..8].copy_from_slice(&event.index.to_ne_bytes());
    bytes[offset_of!(WaitEvent, kind)..][..8].copy_from_slice(&event.kind.to_ne_bytes());
    bytes[offset_of!(WaitEvent, message)..][..size_of::<IpcMessage>()]
        .copy_from_slice(&encode_message(&event.message));
    user_mem::write_user_buffer(root, args.arg2, &bytes)
}

fn receive_slots(first: u64, capacity: u64) -> Result<ipc::ReceiveSlots, ErrorCode> {
    let capacity = usize::try_from(capacity).map_err(|_| ErrorCode::BadMessage)?;
    if capacity > IPC_CAP_SLOTS {
        return Err(ErrorCode::BadMessage);
    }
    // Revalidate at delivery so an edit cannot redirect incoming grants to a
    // different table while this thread waits.
    let cnode = if capacity > 0 && first > u64::from(u8::MAX) {
        sched::with_current_user(|user| user.cspace.receive_cnode(first))
            .ok_or(ErrorCode::InvalidCap)??
    } else {
        None
    };
    Ok(ipc::ReceiveSlots {
        first,
        capacity,
        cnode,
    })
}

fn validate_blocking_output(root: PhysFrame, address: u64, length: usize) -> Result<(), ErrorCode> {
    user_mem::validate_user_buffer(root, address, length, true)?;
    // A blocking call can complete in the kernel before the waiter resumes.
    // Its output cannot live in a frame another task can revoke.
    if sched::with_current_user(|process| process.buffer_is_stable(address, length))
        .ok_or(ErrorCode::InvalidCap)?
    {
        Ok(())
    } else {
        Err(ErrorCode::BadMessage)
    }
}

fn require(rights: CapRights, required: CapRights) -> Result<(), ErrorCode> {
    if rights.contains(required) {
        Ok(())
    } else {
        Err(ErrorCode::CapRightsViolation)
    }
}

fn read_packet(
    root: PhysFrame,
    address: u64,
    invocation_rights: CapRights,
) -> Result<ipc::Packet, ErrorCode> {
    let mut message = IpcMessage::default();
    // Read the fixed header and inline data without copying C-layout padding.
    let mut bytes = [0; DATA_OFFSET + 56];
    user_mem::read_user_buffer(root, address, &mut bytes)?;
    message.label = u64::from_le_bytes(bytes[LABEL_OFFSET..][..8].try_into().unwrap());
    message.length = u16::from_le_bytes(bytes[LENGTH_OFFSET..][..2].try_into().unwrap());
    message.cap_count = bytes[COUNT_OFFSET];
    let len = usize::from(message.length);
    let count = usize::from(message.cap_count);
    if len > message.data.len()
        || count > IPC_CAP_SLOTS
        || bytes[offset_of!(IpcMessage, flags)] != 0
    {
        return Err(ErrorCode::BadMessage);
    }
    message.data[..len].copy_from_slice(&bytes[DATA_OFFSET..][..len]);
    let mut packet = ipc::Packet::inline(message);
    if count == 0 {
        return Ok(packet);
    }
    require(invocation_rights, CapRights::GRANT)?;
    for index in 0..count {
        // The header range proved this is a lower-half address. Offsets in
        // the 168-byte message cannot overflow, and every read checks its pages.
        let base = address + cap_offset(index) as u64;
        let cptr = u64::from_le_bytes(read_wire(root, base + CPTR_OFFSET as u64)?);
        let [rights] = read_wire(root, base + RIGHTS_OFFSET as u64)?;
        let rights = CapRights::from_bits(u64::from(rights)).ok_or(ErrorCode::BadMessage)?;
        let badge = u64::from_le_bytes(read_wire(root, base + BADGE_OFFSET as u64)?);
        let grant = sched::with_current_user(|user| user.cspace.prepare_grant(cptr, rights, badge))
            .ok_or(ErrorCode::InvalidCap)??;
        packet.grants[index] = Some(grant);
        packet.message.caps[index] = CapTransferSlot {
            cptr,
            rights,
            badge,
        };
    }
    Ok(packet)
}

fn read_wire<const N: usize>(root: PhysFrame, address: u64) -> Result<[u8; N], ErrorCode> {
    let mut bytes = [0; N];
    user_mem::read_user_buffer(root, address, &mut bytes)?;
    Ok(bytes)
}

fn cap_offset(index: usize) -> usize {
    CAPS_OFFSET + index * size_of::<CapTransferSlot>()
}

fn write_message(root: PhysFrame, address: u64, message: &IpcMessage) -> Result<(), ErrorCode> {
    user_mem::write_user_buffer(root, address, &encode_message(message))
}

fn encode_message(message: &IpcMessage) -> [u8; size_of::<IpcMessage>()] {
    let mut bytes = [0; size_of::<IpcMessage>()];
    bytes[LABEL_OFFSET..][..8].copy_from_slice(&message.label.to_le_bytes());
    bytes[LENGTH_OFFSET..][..2].copy_from_slice(&message.length.to_le_bytes());
    bytes[COUNT_OFFSET] = message.cap_count;
    let len = usize::from(message.length);
    bytes[DATA_OFFSET..][..len].copy_from_slice(&message.data[..len]);
    for (index, cap) in message.caps[..usize::from(message.cap_count)]
        .iter()
        .enumerate()
    {
        let offset = cap_offset(index);
        bytes[offset + CPTR_OFFSET..][..8].copy_from_slice(&cap.cptr.to_le_bytes());
        bytes[offset + RIGHTS_OFFSET] = cap.rights.bits();
        bytes[offset + BADGE_OFFSET..][..8].copy_from_slice(&cap.badge.to_le_bytes());
    }
    bytes
}
