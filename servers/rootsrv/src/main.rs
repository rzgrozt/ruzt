#![no_std]
#![no_main]

mod tile;

use ruzt_abi::{
    console, CapRights, ErrorCode, IpcMessage, ROOTSRV_CONSOLE_REPLY, ROOTSRV_CONSOLE_REQUEST,
    ROOTSRV_FRAMEBUFFER, ROOTSRV_KEYBOARD_DATA, ROOTSRV_KEYBOARD_IRQ,
};
use ruzt_runtime::{debug_putchar, runtime_init};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    runtime_init(main)
}

fn write_line(text: &str) {
    for byte in text.bytes().chain(core::iter::once(b'\n')) {
        debug_putchar(byte);
    }
}

fn greet_via_console() -> Result<(), ErrorCode> {
    let ungranted = u64::MAX;
    let payload = b"Hello from ring 3, rootsrv alive.\n";
    let mut request = IpcMessage::default();
    request.label = console::WRITE;
    request.length = payload.len() as u16;
    request.data[..payload.len()].copy_from_slice(payload);

    let mut reply = IpcMessage::default();
    assert_eq!(
        ruzt_ipc::send(ungranted, &request),
        Err(ErrorCode::InvalidCap)
    );
    assert_eq!(
        ruzt_ipc::recv(ungranted, &mut reply),
        Err(ErrorCode::InvalidCap)
    );
    assert_eq!(
        ruzt_ipc::recv(ROOTSRV_CONSOLE_REQUEST, &mut reply),
        Err(ErrorCode::CapRightsViolation)
    );
    assert_eq!(
        ruzt_ipc::send(ROOTSRV_CONSOLE_REPLY, &request),
        Err(ErrorCode::CapRightsViolation)
    );

    ruzt_ipc::send(ROOTSRV_CONSOLE_REQUEST, &request)?;
    ruzt_ipc::recv(ROOTSRV_CONSOLE_REPLY, &mut reply)?;
    assert_eq!(reply.label, console::WRITTEN);
    assert_eq!(reply.length, 0);
    write_line("rootsrv: console write acknowledged over IPC");
    write_line("rootsrv: console endpoint rights verified");
    Ok(())
}

fn check_revocation() {
    const CHILD: u64 = 5;
    const GRANDCHILD: u64 = 6;
    const MOVED: u64 = 7;
    let source = ROOTSRV_CONSOLE_REQUEST;
    let rights = CapRights::WRITE.union(CapRights::GRANT);
    ruzt_ipc::mint(source, CHILD, rights, 0).expect("derive console capability");
    ruzt_ipc::mint(CHILD, GRANDCHILD, CapRights::WRITE, 0).expect("derive attenuated capability");
    ruzt_ipc::move_cap(GRANDCHILD, MOVED).expect("move derived capability");
    ruzt_ipc::delete(CHILD).expect("delete intermediate capability");
    ruzt_ipc::revoke(source).expect("revoke console descendants");
    assert_eq!(
        ruzt_ipc::send(MOVED, &IpcMessage::default()),
        Err(ErrorCode::InvalidCap)
    );
    write_line("rootsrv: moved capability revoked transitively");
}

fn main() -> ! {
    check_revocation();
    match greet_via_console() {
        Ok(()) => {}
        Err(ErrorCode::NotFound) => write_line("rootsrv: console disconnected"),
        Err(error) => panic!("console IPC failed: {error:?}"),
    }

    assert_eq!(
        ruzt_driver_sdk::wait_irq(u64::MAX),
        Err(ErrorCode::InvalidCap)
    );
    assert_eq!(
        ruzt_driver_sdk::read_port_u8(ROOTSRV_KEYBOARD_IRQ),
        Err(ErrorCode::InvalidCap)
    );
    assert_eq!(
        ruzt_driver_sdk::write_port_u8(ROOTSRV_KEYBOARD_DATA, 0),
        Err(ErrorCode::CapRightsViolation)
    );
    assert!(matches!(
        ruzt_driver_sdk::framebuffer_info(ROOTSRV_KEYBOARD_IRQ),
        Err(ErrorCode::InvalidCap)
    ));
    let mut tile = match tile::Tile::from_capability(ROOTSRV_FRAMEBUFFER) {
        Ok(tile) => tile,
        Err(ErrorCode::InvalidCap) => None,
        Err(error) => panic!("framebuffer capability failed: {error:?}"),
    };
    if tile.is_some() {
        write_line("rootsrv: framebuffer tile drawn");
    }
    write_line("rootsrv: press Space to test keyboard input");
    loop {
        ruzt_driver_sdk::wait_irq(ROOTSRV_KEYBOARD_IRQ).expect("wait for PS/2 keyboard IRQ");
        let scancode =
            ruzt_driver_sdk::read_port_u8(ROOTSRV_KEYBOARD_DATA).expect("read PS/2 keyboard data");
        // The boot firmware configures translated set-1 scancodes.
        if scancode == 0x39 {
            if let Some(tile) = &mut tile {
                tile.toggle();
            }
            write_line("rootsrv: Space key received");
        }
    }
}
