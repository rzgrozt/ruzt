#![no_std]
#![no_main]

use ruzt_abi::{CapRights, CapTransferSlot, ErrorCode, IpcMessage, ROOTSRV_BOOTSTRAP_ENDPOINT};
use ruzt_runtime::{debug_putchar, runtime_init};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    runtime_init(main)
}

const EMPTY_MESSAGE: IpcMessage = IpcMessage {
    label: 0,
    length: 0,
    cap_count: 0,
    flags: 0,
    data: [0; 56],
    caps: [CapTransferSlot {
        cptr: 0,
        rights: CapRights::empty(),
        badge: 0,
    }; 4],
};

fn write_line(text: &str) {
    for byte in text.bytes().chain(core::iter::once(b'\n')) {
        debug_putchar(byte);
    }
}

fn check_bootstrap_ipc() {
    let endpoint = ROOTSRV_BOOTSTRAP_ENDPOINT;
    let ungranted = endpoint + 1;
    let payload = b"rootsrv bootstrap";
    let mut request = EMPTY_MESSAGE;
    request.label = 42;
    request.length = payload.len() as u16;
    request.data[..payload.len()].copy_from_slice(payload);

    let mut reply = EMPTY_MESSAGE;
    assert_eq!(
        ruzt_ipc::recv(endpoint, &mut reply),
        Err(ErrorCode::WouldBlock)
    );
    assert_eq!(
        ruzt_ipc::send(ungranted, &request),
        Err(ErrorCode::InvalidCap)
    );
    ruzt_ipc::send(endpoint, &request).expect("bootstrap IPC send");
    assert_eq!(
        ruzt_ipc::send(endpoint, &request),
        Err(ErrorCode::WouldBlock)
    );
    assert_eq!(
        ruzt_ipc::recv(ungranted, &mut reply),
        Err(ErrorCode::InvalidCap)
    );
    ruzt_ipc::recv(endpoint, &mut reply).expect("bootstrap IPC receive");
    assert_eq!(reply, request);
    assert_eq!(
        ruzt_ipc::recv(endpoint, &mut reply),
        Err(ErrorCode::WouldBlock)
    );
    write_line("rootsrv: bootstrap IPC request and reply verified");
    write_line("rootsrv: ungranted endpoint rejected on send and receive");
}

fn main() -> ! {
    write_line("Hello from ring 3, rootsrv alive.");
    check_bootstrap_ipc();

    let mut iterations = 0_u64;
    loop {
        iterations += 1;
        if iterations == 10_000_000 {
            debug_putchar(b'.');
            iterations = 0;
        }
        core::hint::spin_loop();
    }
}
