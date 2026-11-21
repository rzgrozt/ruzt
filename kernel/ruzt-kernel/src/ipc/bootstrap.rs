//! The single-process bootstrap endpoint, served by a kernel echo handler.

use core::mem::{offset_of, size_of};

use ruzt_abi::{CapOp, CapRights, ErrorCode, IpcMessage, SyscallArgs, ROOTSRV_BOOTSTRAP_ENDPOINT};
use ruzt_cap::{CapSlot, CapType, EndpointId};
use ruzt_hal::mem::PhysFrame;
use spin::Mutex;

use crate::cap::{cspace::CSpace, object};
use crate::syscall::user_mem::{read_user_buffer, write_user_buffer};

type MessageBytes = [u8; size_of::<IpcMessage>()];

struct Bootstrap {
    root: PhysFrame,
    cspace: CSpace,
    endpoint: EndpointId,
    reply: Option<MessageBytes>,
}

static BOOTSTRAP: Mutex<Option<Bootstrap>> = Mutex::new(None);

pub(crate) fn init(root: PhysFrame) {
    let mut cspace = CSpace::new(1);
    let endpoint = EndpointId(
        object::allocate(CapType::Endpoint(EndpointId(0)))
            .expect("Failed to allocate rootsrv endpoint")
            .0,
    );
    cspace
        .insert(
            ROOTSRV_BOOTSTRAP_ENDPOINT,
            CapSlot {
                cap_type: CapType::Endpoint(endpoint),
                rights: CapRights::READ.union(CapRights::WRITE),
                badge: 0,
            },
        )
        .expect("Failed to grant rootsrv endpoint");

    *BOOTSTRAP.lock() = Some(Bootstrap {
        root,
        cspace,
        endpoint,
        reply: None,
    });
}

pub(crate) fn invoke(args: &SyscallArgs) -> Result<(), ErrorCode> {
    let mut guard = BOOTSTRAP.lock();
    let bootstrap = guard.as_mut().ok_or(ErrorCode::InvalidCap)?;
    let slot = bootstrap.cspace.lookup(args.arg0)?;
    if slot.cap_type != CapType::Endpoint(bootstrap.endpoint) {
        return Err(ErrorCode::InvalidCap);
    }

    match args.arg1 {
        op if op == CapOp::Send as u64 => {
            if !slot.rights.contains(CapRights::WRITE) {
                return Err(ErrorCode::CapRightsViolation);
            }
            if bootstrap.reply.is_some() {
                return Err(ErrorCode::WouldBlock);
            }
            let mut request = [0; size_of::<IpcMessage>()];
            read_user_buffer(bootstrap.root, args.arg2, &mut request)?;
            bootstrap.reply = Some(echo_reply(&request)?);
        }
        op if op == CapOp::Recv as u64 => {
            if !slot.rights.contains(CapRights::READ) {
                return Err(ErrorCode::CapRightsViolation);
            }
            let reply = bootstrap.reply.as_ref().ok_or(ErrorCode::WouldBlock)?;
            write_user_buffer(bootstrap.root, args.arg2, reply)?;
            bootstrap.reply = None;
        }
        _ => return Err(ErrorCode::NotImplemented),
    }
    Ok(())
}

fn echo_reply(request: &MessageBytes) -> Result<MessageBytes, ErrorCode> {
    const LENGTH: usize = offset_of!(IpcMessage, length);
    const DATA: usize = offset_of!(IpcMessage, data);
    let length = u16::from_le_bytes([request[LENGTH], request[LENGTH + 1]]) as usize;
    if length > 56
        || request[offset_of!(IpcMessage, cap_count)] != 0
        || request[offset_of!(IpcMessage, flags)] != 0
    {
        return Err(ErrorCode::BadMessage);
    }

    // Echo the label and valid payload. Reserved fields and padding stay zero.
    let mut reply = [0; size_of::<IpcMessage>()];
    reply[..LENGTH + 2].copy_from_slice(&request[..LENGTH + 2]);
    reply[DATA..DATA + length].copy_from_slice(&request[DATA..DATA + length]);
    Ok(reply)
}
