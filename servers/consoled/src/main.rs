#![no_std]
#![no_main]

use ruzt_abi::{console, CapRights, ErrorCode, IpcMessage, FRAME_BYTES, ROOTSRV_FRAMEBUFFER};
use ruzt_driver_sdk::{read_port_u8, write_port_u8};

// TL16C550D §7.6.3, transmitter holding register empty.
const TRANSMITTER_READY: u8 = 1 << 5;
const CONSOLE_BUFFER: u64 = 0x6000_0000;

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
            2,
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
        if request.label == console::WRITE_SHARED {
            // SAFETY: This test deliberately raises an instruction fault in
            // the guest's user mode. The task must never resume at this site.
            unsafe { core::arch::asm!("ud2", options(noreturn, nomem, nostack)) }
        }
        #[cfg(feature = "qemu-exit-test")]
        if request.label == console::WRITE_SHARED {
            ruzt_runtime::syscall::exit(23);
        }
        let label = match (request.label, request.cap_count) {
            (console::WRITE, 0) => {
                uart_write(&request.data[..usize::from(request.length)]);
                Ok(console::WRITTEN)
            }
            (console::WRITE_SHARED, 2) => write_shared(&request).map(|()| console::WRITTEN),
            (console::CHECK_REVOCATION, 1) => check_revocation().map(|()| console::REVOKED),
            _ => Err(ErrorCode::BadMessage),
        };
        if label.is_err() {
            for cap in &request.caps[..usize::from(request.cap_count)] {
                ruzt_ipc::delete(cap.cptr).expect("discard unused grant");
            }
        }
        let reply = IpcMessage {
            label: label.unwrap_or(console::UNKNOWN_REQUEST),
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

fn write_shared(request: &IpcMessage) -> Result<(), ErrorCode> {
    let notification = console::RECEIVED_NOTIFICATION;
    let frame = console::RECEIVED_FRAME;
    let length = usize::from(u16::from_le_bytes([request.data[0], request.data[1]]));
    if request.length != 2
        || length > FRAME_BYTES
        || request.caps[0].rights != CapRights::WRITE
        || request.caps[1].rights != CapRights::READ
        || ruzt_ipc::wait(notification) != Err(ErrorCode::CapRightsViolation)
        || ruzt_ipc::map_frame(frame, CONSOLE_BUFFER, true) != Err(ErrorCode::CapRightsViolation)
    {
        return Err(ErrorCode::BadMessage);
    }
    ruzt_ipc::map_frame(frame, CONSOLE_BUFFER, false)?;
    for offset in 0..length {
        // SAFETY: The address is inside the page mapped above. The boot
        // protocol keeps it mapped and the sender leaves the bytes untouched
        // until we reply. Volatile reads do not borrow the shared allocation.
        let byte = unsafe { ((CONSOLE_BUFFER as usize + offset) as *const u8).read_volatile() };
        uart_write_byte(byte);
    }
    ruzt_ipc::signal(notification)
}

fn check_revocation() -> Result<(), ErrorCode> {
    // The fresh read-only frame arrived in the former notification slot.
    // The old frame capability must be gone, and the old virtual address
    // must be available for the new capability to map.
    let fresh_frame = console::RECEIVED_NOTIFICATION;
    if ruzt_ipc::map_frame(console::RECEIVED_FRAME, CONSOLE_BUFFER, false)
        != Err(ErrorCode::InvalidCap)
    {
        return Err(ErrorCode::BadMessage);
    }
    ruzt_ipc::map_frame(fresh_frame, CONSOLE_BUFFER, false)?;
    ruzt_ipc::unmap_frame(fresh_frame)?;
    ruzt_ipc::delete(fresh_frame)
}

fn uart_write(bytes: &[u8]) {
    for &byte in bytes {
        uart_write_byte(byte);
    }
}

fn uart_write_byte(byte: u8) {
    while read_port_u8(console::UART_STATUS).expect("read UART line status") & TRANSMITTER_READY
        == 0
    {
        core::hint::spin_loop();
    }
    write_port_u8(console::UART_DATA, byte).expect("write UART byte");
}
