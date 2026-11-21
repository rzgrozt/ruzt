#![no_std]
#![no_main]

mod tile;

use ruzt_abi::{
    console, CapRights, CapTransferSlot, ErrorCode, IpcMessage, FRAME_BYTES, ROOTSRV_CONSOLE_FRAME,
    ROOTSRV_CONSOLE_NOTIFICATION, ROOTSRV_CONSOLE_REPLY, ROOTSRV_CONSOLE_REQUEST,
    ROOTSRV_FRAMEBUFFER, ROOTSRV_KEYBOARD_DATA, ROOTSRV_KEYBOARD_IRQ,
};
use ruzt_runtime::{debug_putchar, runtime_init};

const CONSOLE_BUFFER: u64 = 0x5000_0000;
const GREETING: &[u8] = b"Hello from ring 3, rootsrv alive.\n";
const _: () = assert!(GREETING.len() <= FRAME_BYTES);

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
    let mut request = IpcMessage::default();
    let payload_len = (GREETING.len() as u16).to_le_bytes();
    request.label = console::WRITE_SHARED;
    request.length = payload_len.len() as u16;
    request.data[..payload_len.len()].copy_from_slice(&payload_len);
    request.cap_count = 2;
    request.caps[0] = CapTransferSlot {
        cptr: ROOTSRV_CONSOLE_NOTIFICATION,
        rights: CapRights::WRITE,
        badge: 0,
    };
    request.caps[1] = CapTransferSlot {
        cptr: ROOTSRV_CONSOLE_FRAME,
        rights: CapRights::READ,
        badge: 0,
    };

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

    let stack_page = (&raw const reply as u64) & !(FRAME_BYTES as u64 - 1);
    assert_eq!(
        ruzt_ipc::map_frame(ROOTSRV_CONSOLE_FRAME, stack_page, true),
        Err(ErrorCode::MappingExists)
    );
    ruzt_ipc::map_frame(ROOTSRV_CONSOLE_FRAME, CONSOLE_BUFFER, true)?;
    // SAFETY: The writable mapping is live and large enough for this payload.
    // The peer has not received a grant yet, and we never create a reference
    // into the shared page.
    unsafe {
        core::ptr::copy_nonoverlapping(
            GREETING.as_ptr(),
            CONSOLE_BUFFER as *mut u8,
            GREETING.len(),
        );
    }

    ruzt_ipc::send(ROOTSRV_CONSOLE_REQUEST, &request)?;
    ruzt_ipc::recv(ROOTSRV_CONSOLE_REPLY, &mut reply)?;
    assert_eq!(reply.label, console::WRITTEN);
    assert_eq!(reply.length, 0);
    ruzt_ipc::wait(ROOTSRV_CONSOLE_NOTIFICATION)?;
    write_line("rootsrv: console write acknowledged over IPC");
    write_line("rootsrv: console endpoint rights verified");

    ruzt_ipc::revoke(ROOTSRV_CONSOLE_NOTIFICATION)?;
    ruzt_ipc::revoke(ROOTSRV_CONSOLE_FRAME)?;
    let mut request = IpcMessage {
        label: console::CHECK_REVOCATION,
        cap_count: 1,
        ..IpcMessage::default()
    };
    request.caps[0] = CapTransferSlot {
        cptr: ROOTSRV_CONSOLE_FRAME,
        rights: CapRights::READ,
        badge: 0,
    };
    ruzt_ipc::send(ROOTSRV_CONSOLE_REQUEST, &request)?;
    ruzt_ipc::recv(ROOTSRV_CONSOLE_REPLY, &mut reply)?;
    assert_eq!(reply.label, console::REVOKED);
    write_line("rootsrv: notification transferred and revoked across capability spaces");
    write_line("rootsrv: shared frame mapped read-only by console and unmapped on revocation");
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
    let result = greet_via_console();
    ruzt_ipc::delete(ROOTSRV_CONSOLE_FRAME).expect("release boot console frame");
    match result {
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
