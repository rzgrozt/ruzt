//! The single-process bootstrap endpoint, served by a kernel echo handler.

use core::mem::{offset_of, size_of};

use ruzt_abi::{
    CapOp, CapRights, ErrorCode, FramebufferInfo, IpcMessage, SyscallArgs,
    ROOTSRV_BOOTSTRAP_ENDPOINT, ROOTSRV_FRAMEBUFFER, ROOTSRV_KEYBOARD_DATA, ROOTSRV_KEYBOARD_IRQ,
};
use ruzt_cap::{CapSlot, CapType, EndpointId};
use ruzt_hal::mem::PhysFrame;
use x86_64::instructions::port::PortReadOnly;

use crate::cap::{cspace::CSpace, object};
use crate::keyboard;
use crate::syscall::user_mem::{read_user_buffer, write_user_buffer, write_user_buffer_with};

type MessageBytes = [u8; size_of::<IpcMessage>()];

pub(crate) struct Bootstrap {
    cspace: CSpace,
    endpoint: EndpointId,
    reply: Option<MessageBytes>,
    framebuffer: Option<FramebufferInfo>,
}

enum InvokeOutcome {
    Complete,
    WaitForKeyboard,
}

pub(crate) fn invoke(args: &SyscallArgs) -> Result<(), ErrorCode> {
    let outcome =
        crate::sched::with_current_user(|process| process.bootstrap.invoke(process.root, args))
            .ok_or(ErrorCode::InvalidCap)??;
    // The scheduler lock used for capability lookup has been released.
    if let InvokeOutcome::WaitForKeyboard = outcome {
        keyboard::wait_irq();
    }
    Ok(())
}

impl Bootstrap {
    pub(crate) fn new(framebuffer: Option<FramebufferInfo>) -> Self {
        let mut cspace = CSpace::new(2);
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
        for (index, cap_type) in [
            (
                ROOTSRV_KEYBOARD_IRQ,
                CapType::Irq {
                    irq_num: keyboard::IRQ,
                },
            ),
            (
                ROOTSRV_KEYBOARD_DATA,
                CapType::IoPort {
                    port: keyboard::DATA_PORT,
                },
            ),
        ] {
            cspace
                .insert(
                    index,
                    CapSlot {
                        cap_type,
                        rights: CapRights::READ,
                        badge: 0,
                    },
                )
                .expect("Failed to grant keyboard capability");
        }
        if framebuffer.is_some() {
            cspace
                .insert(
                    ROOTSRV_FRAMEBUFFER,
                    CapSlot {
                        cap_type: CapType::Framebuffer,
                        rights: CapRights::WRITE,
                        badge: 0,
                    },
                )
                .expect("Failed to grant the framebuffer capability");
        }

        Self {
            cspace,
            endpoint,
            reply: None,
            framebuffer,
        }
    }

    fn invoke(&mut self, root: PhysFrame, args: &SyscallArgs) -> Result<InvokeOutcome, ErrorCode> {
        let slot = *self.cspace.lookup(args.arg0)?;
        match slot.cap_type {
            CapType::Endpoint(id) if id == self.endpoint => self.echo(root, args, slot.rights)?,
            CapType::Irq {
                irq_num: keyboard::IRQ,
            } if args.arg1 == CapOp::Wait as u64 => {
                require_read(slot.rights)?;
                return Ok(InvokeOutcome::WaitForKeyboard);
            }
            CapType::IoPort { port } if args.arg1 == CapOp::ReadPort8 as u64 => {
                require_read(slot.rights)?;
                write_user_buffer_with(root, args.arg2, 1, || {
                    #[allow(unsafe_code)]
                    // SAFETY: The checked, kernel-issued capability names the
                    // port and grants read access. No caller controls the port.
                    let byte = unsafe { PortReadOnly::<u8>::new(port).read() };
                    [byte]
                })?;
            }
            CapType::Framebuffer if args.arg1 == CapOp::FramebufferInfo as u64 => {
                if !slot.rights.contains(CapRights::WRITE) {
                    return Err(ErrorCode::CapRightsViolation);
                }
                let info = self.framebuffer.ok_or(ErrorCode::InvalidCap)?;
                #[allow(unsafe_code)]
                // SAFETY: The C-layout integer fields occupy all 40 bytes.
                let bytes: [u8; size_of::<FramebufferInfo>()] =
                    unsafe { core::mem::transmute(info) };
                write_user_buffer(root, args.arg2, &bytes)?;
            }
            _ => return Err(ErrorCode::InvalidCap),
        }
        Ok(InvokeOutcome::Complete)
    }

    fn echo(
        &mut self,
        root: PhysFrame,
        args: &SyscallArgs,
        rights: CapRights,
    ) -> Result<(), ErrorCode> {
        match args.arg1 {
            op if op == CapOp::Send as u64 => {
                if !rights.contains(CapRights::WRITE) {
                    return Err(ErrorCode::CapRightsViolation);
                }
                if self.reply.is_some() {
                    return Err(ErrorCode::WouldBlock);
                }
                let mut request = [0; size_of::<IpcMessage>()];
                read_user_buffer(root, args.arg2, &mut request)?;
                self.reply = Some(echo_reply(&request)?);
            }
            op if op == CapOp::Recv as u64 => {
                require_read(rights)?;
                let reply = self.reply.as_ref().ok_or(ErrorCode::WouldBlock)?;
                write_user_buffer(root, args.arg2, reply)?;
                self.reply = None;
            }
            _ => return Err(ErrorCode::NotImplemented),
        }
        Ok(())
    }
}

fn require_read(rights: CapRights) -> Result<(), ErrorCode> {
    if rights.contains(CapRights::READ) {
        Ok(())
    } else {
        Err(ErrorCode::CapRightsViolation)
    }
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
