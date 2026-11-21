#![no_std]
#![no_main]

use ruzt_abi::{console, ErrorCode, IpcMessage, ROOTSRV_FRAMEBUFFER};
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
        ruzt_ipc::recv(console::REQUEST, &mut request).expect("receive console request");
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
            label: match request.label {
                console::WRITE => {
                    uart_write(&request.data[..usize::from(request.length)]);
                    console::WRITTEN
                }
                _ => console::UNKNOWN_REQUEST,
            },
            ..IpcMessage::default()
        };
        ruzt_ipc::send(console::REPLY, &reply).expect("reply to console request");
        #[cfg(feature = "qemu-preemption-test")]
        if reply.label == console::WRITTEN {
            for byte in b"consoled: entering CPU-bound test loop\n" {
                ruzt_runtime::debug_putchar(*byte);
            }
            loop {
                core::hint::spin_loop();
            }
        }
    }
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
