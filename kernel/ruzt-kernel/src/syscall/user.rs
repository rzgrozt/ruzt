//! Capability invocations from scheduled user threads.

use core::mem::{offset_of, size_of};
use ruzt_abi::{CapOp, CapRights, ErrorCode, FramebufferInfo, IpcMessage, SyscallArgs};
use ruzt_cap::CapType;
use ruzt_hal::mem::PhysFrame;
use x86_64::instructions::port::{PortReadOnly, PortWriteOnly};

use super::user_mem;
use crate::{ipc, keyboard, sched};

const DATA_OFFSET: usize = offset_of!(IpcMessage, data);
const LABEL_OFFSET: usize = offset_of!(IpcMessage, label);
const LENGTH_OFFSET: usize = offset_of!(IpcMessage, length);

pub(crate) fn invoke(args: &SyscallArgs) -> Result<(), ErrorCode> {
    let (root, capability, framebuffer) = sched::with_current_user(|process| {
        let capability = *process.cspace.lookup(args.arg0)?;
        Ok::<_, ErrorCode>((process.root, capability, process.framebuffer))
    })
    .ok_or(ErrorCode::InvalidCap)??;
    // Capability lookup is complete and the scheduler lock is released before
    // any operation can block. User invocation currently runs on one CPU.
    match capability.cap_type {
        CapType::Endpoint(id) if args.arg1 == CapOp::Send as u64 => {
            require(capability.rights, CapRights::WRITE)?;
            ipc::send_message(id, read_message(root, args.arg2)?)
        }
        CapType::Endpoint(id) if args.arg1 == CapOp::Recv as u64 => {
            require(capability.rights, CapRights::READ)?;
            // Reject bad buffers before consuming a pending sender or blocking.
            user_mem::validate_user_buffer(root, args.arg2, size_of::<IpcMessage>(), true)?;
            let message = ipc::receive_message(id)?;
            write_message(root, args.arg2, &message)
        }
        CapType::Irq {
            irq_num: keyboard::IRQ,
        } if args.arg1 == CapOp::Wait as u64 => {
            require(capability.rights, CapRights::READ)?;
            keyboard::wait_irq();
            Ok(())
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

fn require(rights: CapRights, required: CapRights) -> Result<(), ErrorCode> {
    if rights.contains(required) {
        Ok(())
    } else {
        Err(ErrorCode::CapRightsViolation)
    }
}

fn read_message(root: PhysFrame, address: u64) -> Result<IpcMessage, ErrorCode> {
    let mut message = IpcMessage::default();
    // Read the fixed header and inline data only. The C layout has padding
    // before the capability slots, which this operation never reads.
    let mut bytes = [0; DATA_OFFSET + 56];
    user_mem::read_user_buffer(root, address, &mut bytes)?;
    message.label = u64::from_le_bytes(bytes[LABEL_OFFSET..][..8].try_into().unwrap());
    message.length = u16::from_le_bytes(bytes[LENGTH_OFFSET..][..2].try_into().unwrap());
    let len = usize::from(message.length);
    if len > message.data.len()
        || bytes[offset_of!(IpcMessage, cap_count)] != 0
        || bytes[offset_of!(IpcMessage, flags)] != 0
    {
        return Err(ErrorCode::BadMessage);
    }
    message.data[..len].copy_from_slice(&bytes[DATA_OFFSET..][..len]);
    Ok(message)
}

fn write_message(root: PhysFrame, address: u64, message: &IpcMessage) -> Result<(), ErrorCode> {
    let mut bytes = [0; size_of::<IpcMessage>()];
    bytes[LABEL_OFFSET..][..8].copy_from_slice(&message.label.to_le_bytes());
    bytes[LENGTH_OFFSET..][..2].copy_from_slice(&message.length.to_le_bytes());
    let len = usize::from(message.length);
    bytes[DATA_OFFSET..][..len].copy_from_slice(&message.data[..len]);
    user_mem::write_user_buffer(root, address, &bytes)
}
