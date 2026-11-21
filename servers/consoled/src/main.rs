#![no_std]
#![no_main]

use ruzt_abi::{console, CapRights, ErrorCode, IpcMessage, ROOTSRV_FRAMEBUFFER};
use ruzt_driver_sdk::{read_port_u8, write_port_u8};

// TL16C550D §7.6.3, transmitter holding register empty.
const TRANSMITTER_READY: u8 = 1 << 5;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    ruzt_runtime::runtime_init(main)
}

fn main() -> ! {
    assert!(matches!(
        ruzt_driver_sdk::framebuffer_info(ROOTSRV_FRAMEBUFFER),
        Err(ErrorCode::InvalidCap)
    ));
    loop {
        let mut request = IpcMessage::default();
        match ruzt_ipc::recv_with_caps(
            console::REQUEST,
            &mut request,
            console::RECEIVED_NOTIFICATION,
            1,
        ) {
            Ok(()) => {}
            Err(ErrorCode::NotFound) => ruzt_runtime::syscall::exit(0),
            Err(
                ErrorCode::BadMessage
                | ErrorCode::SlotOccupied
                | ErrorCode::CapRightsViolation
                | ErrorCode::InvalidCap,
            ) => continue,
            Err(error) => panic!("console receive failed: {error:?}"),
        }
        #[cfg(feature = "qemu-fault-test")]
        if request.label == console::WRITE {
            // SAFETY: This test deliberately raises an instruction fault in
            // the guest's user mode. The task must never resume at this site.
            unsafe { core::arch::asm!("ud2", options(noreturn, nomem, nostack)) }
        }
        #[cfg(feature = "qemu-exit-test")]
        if request.label == console::WRITE {
            ruzt_runtime::syscall::exit(23);
        }
        let reply = IpcMessage {
            label: match (request.label, request.cap_count) {
                (console::WRITE, 0 | 1) => console_write(&request),
                (console::CHECK_REVOCATION, 0)
                    if ruzt_ipc::signal(console::RECEIVED_NOTIFICATION)
                        == Err(ErrorCode::InvalidCap) =>
                {
                    console::REVOKED
                }
                _ => {
                    if request.cap_count != 0 {
                        ruzt_ipc::delete(console::RECEIVED_NOTIFICATION)
                            .expect("discard unused grant");
                    }
                    console::UNKNOWN_REQUEST
                }
            },
            ..IpcMessage::default()
        };
        #[cfg(feature = "qemu-preemption-test")]
        if reply.label == console::REVOKED {
            uart_write(b"consoled: reply followed by CPU-bound loop\n");
        }
        ruzt_ipc::send(console::REPLY, &reply).expect("reply to console request");
        #[cfg(feature = "qemu-preemption-test")]
        if reply.label == console::REVOKED {
            loop {
                core::hint::spin_loop();
            }
        }
    }
}

fn console_write(request: &IpcMessage) -> u64 {
    if request.cap_count == 1 {
        let grant = request.caps[0];
        if grant.cptr != console::RECEIVED_NOTIFICATION
            || grant.rights != CapRights::WRITE
            || ruzt_ipc::wait(grant.cptr) != Err(ErrorCode::CapRightsViolation)
            || ruzt_ipc::signal(grant.cptr).is_err()
        {
            ruzt_ipc::delete(console::RECEIVED_NOTIFICATION).expect("discard invalid grant");
            return console::UNKNOWN_REQUEST;
        }
    }
    uart_write(&request.data[..usize::from(request.length)]);
    console::WRITTEN
}

fn uart_write(bytes: &[u8]) {
    for &byte in bytes {
        while read_port_u8(console::UART_STATUS).expect("read UART line status") & TRANSMITTER_READY
            == 0
        {
            core::hint::spin_loop();
        }
        write_port_u8(console::UART_DATA, byte).expect("write UART byte");
    }
}
