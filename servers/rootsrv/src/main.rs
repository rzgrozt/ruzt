#![no_std]
#![no_main]

mod tile;

use ruzt_abi::{
    console, CapRights, CapTransferSlot, ErrorCode, IpcMessage, RetypeKind, FRAME_BYTES,
    PROCESS_ADDRESS_SPACE, PROCESS_EXITED, PROCESS_FAULTED, ROOTSRV_CONSOLE_FRAME,
    ROOTSRV_CONSOLE_NOTIFICATION, ROOTSRV_CONSOLE_PROCESS, ROOTSRV_CONSOLE_PROGRAM,
    ROOTSRV_CONSOLE_REPLY, ROOTSRV_CONSOLE_REQUEST, ROOTSRV_FRAMEBUFFER, ROOTSRV_KEYBOARD_DATA,
    ROOTSRV_KEYBOARD_IRQ, ROOTSRV_UART_DATA, ROOTSRV_UART_STATUS, ROOTSRV_UNTYPED,
};
use ruzt_runtime::{debug_print, runtime_init};

const CONSOLE_BUFFER: u64 = 0x5000_0000;
const LOCAL_BUDGET: u64 = 11;
const CONSOLE_BUDGET: u64 = 12;
const SERVICE_BUDGET_BITS: u8 = 13;
const SESSION_BUDGET: u64 = 23;
const REQUEST_ENDPOINT: u64 = 16;
const REPLY_ENDPOINT: u64 = 17;
const PROGRAM_BUDGET: u64 = 20;
const PROGRAM_BUDGET_BITS: u8 = 21;
const PROGRAM_BUDGET_HALVES: [u64; 2] = [21, 22];
const EXIT_CHANNELS: u8 = (1 << console::REQUEST) | (1 << console::REPLY);
const GREETING: &[u8] = b"Hello from ring 3, rootsrv alive.\n";
const _: () = assert!(GREETING.len() <= FRAME_BYTES);

#[no_mangle]
pub extern "C" fn _start() -> ! {
    runtime_init(main)
}

fn write_line(text: &str) {
    debug_print(format_args!("{text}\n"));
}

fn greet_via_console() -> Result<(), ErrorCode> {
    let ungranted = u64::MAX;
    let mut request = IpcMessage::default();
    let payload_len = (GREETING.len() as u16).to_le_bytes();
    request.label = console::WRITE_SHARED;
    request.length = payload_len.len() as u16;
    request.data[..payload_len.len()].copy_from_slice(&payload_len);
    request.cap_count = 3;
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
    request.caps[2] = CapTransferSlot {
        cptr: CONSOLE_BUDGET,
        rights: CapRights::WRITE,
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
    ruzt_ipc::revoke(CONSOLE_BUDGET)?;
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
    write_line("rootsrv: console allocation and mapping revoked through its Untyped budget");
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

fn create_console_objects() {
    const COPY: u64 = 5;
    const PROBE: u64 = 6;
    let budget = LOCAL_BUDGET;
    assert_eq!(
        ruzt_ipc::retype(budget, ROOTSRV_CONSOLE_REQUEST, RetypeKind::Frame),
        Err(ErrorCode::SlotOccupied)
    );
    ruzt_ipc::mint(budget, COPY, CapRights::empty(), 0).expect("copy budget without write rights");
    assert_eq!(
        ruzt_ipc::retype(COPY, PROBE, RetypeKind::Frame),
        Err(ErrorCode::CapRightsViolation)
    );
    ruzt_ipc::delete(COPY).expect("delete attenuated budget copy");

    ruzt_ipc::mint(budget, COPY, CapRights::WRITE, 0).expect("copy writable budget");
    ruzt_ipc::retype(budget, ROOTSRV_CONSOLE_FRAME, RetypeKind::Frame)
        .expect("create console frame");
    ruzt_ipc::retype(COPY, ROOTSRV_CONSOLE_NOTIFICATION, RetypeKind::Notification)
        .expect("create console notification");
    assert_eq!(
        ruzt_ipc::retype(budget, PROBE, RetypeKind::Endpoint),
        Err(ErrorCode::NoMemory)
    );
    ruzt_ipc::delete(COPY).expect("delete writable budget copy");
}

fn reclaim_console_objects() {
    let budget = LOCAL_BUDGET;
    let frame = ROOTSRV_CONSOLE_FRAME;
    let notification = ROOTSRV_CONSOLE_NOTIFICATION;
    ruzt_ipc::revoke(budget).expect("revoke all console objects");
    assert_eq!(ruzt_ipc::signal(notification), Err(ErrorCode::InvalidCap));
    assert_eq!(
        ruzt_ipc::map_frame(frame, CONSOLE_BUFFER, false),
        Err(ErrorCode::InvalidCap)
    );

    ruzt_ipc::retype(budget, frame, RetypeKind::Frame).expect("reuse released Untyped page");
    ruzt_ipc::retype(budget, notification, RetypeKind::Endpoint)
        .expect("reuse the second Untyped page while the frame is live");
    ruzt_ipc::map_frame(frame, CONSOLE_BUFFER, false).expect("reuse released frame address");
    for offset in 0..FRAME_BYTES {
        // SAFETY: The replacement frame is mapped for reading and is private
        // until it is released below. No references into the page escape.
        let byte = unsafe { ((CONSOLE_BUFFER as usize + offset) as *const u8).read_volatile() };
        assert_eq!(byte, 0);
    }
    ruzt_ipc::delete(frame).expect("release replacement frame");
    ruzt_ipc::delete(notification).expect("release retyped endpoint");
    write_line("rootsrv: Untyped budget enforced and reclaimed after revocation");
}

fn start_console() {
    for slot in [REQUEST_ENDPOINT, REPLY_ENDPOINT] {
        ruzt_ipc::retype(ROOTSRV_UNTYPED, slot, RetypeKind::Endpoint)
            .expect("create fresh console endpoint");
    }
    ruzt_ipc::mint(
        REQUEST_ENDPOINT,
        ROOTSRV_CONSOLE_REQUEST,
        CapRights::WRITE.union(CapRights::GRANT),
        0,
    )
    .expect("grant the root server console send authority");
    ruzt_ipc::mint(REPLY_ENDPOINT, ROOTSRV_CONSOLE_REPLY, CapRights::READ, 0)
        .expect("grant the root server console receive authority");

    let launch = IpcMessage {
        cap_count: 4,
        caps: [
            CapTransferSlot {
                cptr: REQUEST_ENDPOINT,
                rights: CapRights::READ,
                badge: 0,
            },
            CapTransferSlot {
                cptr: REPLY_ENDPOINT,
                rights: CapRights::WRITE,
                badge: 0,
            },
            CapTransferSlot {
                cptr: ROOTSRV_UART_DATA,
                rights: CapRights::WRITE,
                badge: 0,
            },
            CapTransferSlot {
                cptr: ROOTSRV_UART_STATUS,
                rights: CapRights::READ,
                badge: 0,
            },
        ],
        ..IpcMessage::default()
    };
    assert_eq!(
        ruzt_ipc::spawn_program(
            ROOTSRV_UART_DATA,
            ROOTSRV_CONSOLE_PROCESS,
            &launch,
            EXIT_CHANNELS,
            PROGRAM_BUDGET,
        ),
        Err(ErrorCode::InvalidCap)
    );
    assert_eq!(
        ruzt_ipc::spawn_program(
            ROOTSRV_CONSOLE_PROGRAM,
            ROOTSRV_CONSOLE_REQUEST,
            &launch,
            EXIT_CHANNELS,
            PROGRAM_BUDGET,
        ),
        Err(ErrorCode::SlotOccupied)
    );
    assert_eq!(
        ruzt_ipc::spawn_program(
            ROOTSRV_CONSOLE_PROGRAM,
            ROOTSRV_CONSOLE_PROCESS,
            &launch,
            EXIT_CHANNELS | (1 << console::UART_DATA),
            PROGRAM_BUDGET,
        ),
        Err(ErrorCode::BadMessage)
    );
    assert_eq!(
        ruzt_ipc::spawn_program(
            ROOTSRV_CONSOLE_PROGRAM,
            ROOTSRV_CONSOLE_PROCESS,
            &launch,
            EXIT_CHANNELS,
            SESSION_BUDGET,
        ),
        Err(ErrorCode::NoMemory)
    );
    assert_eq!(
        ruzt_ipc::poll_process(ROOTSRV_CONSOLE_PROCESS),
        Err(ErrorCode::InvalidCap)
    );
    ruzt_ipc::spawn_program(
        ROOTSRV_CONSOLE_PROGRAM,
        ROOTSRV_CONSOLE_PROCESS,
        &launch,
        EXIT_CHANNELS,
        PROGRAM_BUDGET,
    )
    .expect("launch console with explicitly granted capabilities");
}

fn confirm_console_ready() -> Result<(), ErrorCode> {
    let request = IpcMessage {
        label: console::WRITE,
        ..IpcMessage::default()
    };
    let mut reply = IpcMessage::default();
    ruzt_ipc::send(ROOTSRV_CONSOLE_REQUEST, &request)?;
    ruzt_ipc::recv(ROOTSRV_CONSOLE_REPLY, &mut reply)?;
    if reply.label != console::WRITTEN {
        return Err(ErrorCode::BadMessage);
    }
    Ok(())
}

fn run_console() {
    ruzt_ipc::split_untyped(ROOTSRV_UNTYPED, PROGRAM_BUDGET, PROGRAM_BUDGET_BITS)
        .expect("reserve console address-space memory");
    ruzt_ipc::split_untyped(ROOTSRV_UNTYPED, SESSION_BUDGET, SERVICE_BUDGET_BITS + 1)
        .expect("reserve console session memory");
    for attempt in 0..2 {
        start_console();
        let ready = confirm_console_ready();
        if ready.is_ok() {
            assert_eq!(
                ruzt_ipc::split_untyped(
                    PROGRAM_BUDGET,
                    PROGRAM_BUDGET_HALVES[0],
                    PROGRAM_BUDGET_BITS - 1
                ),
                Err(ErrorCode::NoMemory)
            );
        }
        if attempt != 0 && ready.is_ok() {
            write_line("rootsrv: restarted console acknowledged IPC");
        }
        check_revocation();
        split_service_budgets();
        create_console_objects();
        let result = ready.and_then(|()| match ruzt_ipc::poll_process(ROOTSRV_CONSOLE_PROCESS) {
            Ok(_) => Err(ErrorCode::NotFound),
            Err(ErrorCode::WouldBlock) => greet_via_console(),
            Err(error) => Err(error),
        });
        reclaim_console_objects();
        ruzt_ipc::revoke(SESSION_BUDGET).expect("reclaim delegated budgets");
        split_service_budgets();
        ruzt_ipc::delete(LOCAL_BUDGET).expect("release the reclaimed local budget");
        ruzt_ipc::delete(CONSOLE_BUDGET).expect("release the reclaimed console budget");
        write_line("rootsrv: both delegated budgets reclaimed");

        match result {
            Ok(()) => return,
            Err(ErrorCode::NotFound) => write_line("rootsrv: console disconnected"),
            Err(error) => panic!("console IPC failed: {error:?}"),
        }
        let status = ruzt_ipc::wait_process(ROOTSRV_CONSOLE_PROCESS)
            .expect("wait for the console to be reaped");
        assert_eq!(ruzt_ipc::poll_process(ROOTSRV_CONSOLE_PROCESS), Ok(status));
        let reason = match status.kind {
            PROCESS_EXITED => "exit status",
            PROCESS_FAULTED => "fault vector",
            _ => panic!("unknown console termination kind"),
        };
        debug_print(format_args!(
            "rootsrv: reaped console reported {reason} {}\n",
            status.code
        ));
        verify_program_budget_reclaimed();

        for slot in [REQUEST_ENDPOINT, REPLY_ENDPOINT] {
            ruzt_ipc::revoke(slot).expect("revoke the old console channel");
            ruzt_ipc::delete(slot).expect("release the old console endpoint");
        }
        ruzt_ipc::delete(ROOTSRV_CONSOLE_PROCESS).expect("release old console status");
        if status.kind == PROCESS_EXITED && status.code == 0 {
            return;
        }
        if attempt == 0 {
            write_line("rootsrv: restarting console with fresh endpoints");
        }
    }
}

fn verify_program_budget_reclaimed() {
    for slot in PROGRAM_BUDGET_HALVES {
        ruzt_ipc::split_untyped(PROGRAM_BUDGET, slot, PROGRAM_BUDGET_BITS - 1)
            .expect("reclaim the console address-space budget");
    }
    for slot in PROGRAM_BUDGET_HALVES {
        ruzt_ipc::delete(slot).expect("return the reclaimed span to the program budget");
    }
    write_line("rootsrv: console address-space budget reclaimed");
}

fn main() -> ! {
    run_console();
    check_anonymous_memory();

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

fn check_anonymous_memory() {
    const BASE: u64 = 0x5a00_0000;
    const SECOND: u64 = BASE + FRAME_BYTES as u64;
    let space = PROCESS_ADDRESS_SPACE;
    ruzt_ipc::map_anonymous(space, SECOND, 1, true).expect("map one private page");
    // SAFETY: The page was mapped writable and belongs to this process.
    unsafe { (SECOND as *mut u8).write_volatile(0xa5) };
    assert_eq!(
        ruzt_ipc::map_anonymous(space, BASE, 2, true),
        Err(ErrorCode::MappingExists),
    );
    ruzt_ipc::map_anonymous(space, BASE, 1, true).expect("reuse address from rolled-back mapping");
    assert_eq!(
        ruzt_ipc::unmap_anonymous(space, BASE, 3),
        Err(ErrorCode::NotFound),
    );
    // SAFETY: The failed range operations preserved this existing mapping.
    assert_eq!(unsafe { (SECOND as *const u8).read_volatile() }, 0xa5);
    ruzt_ipc::unmap_anonymous(space, SECOND, 1).expect("unmap part of the private range");
    ruzt_ipc::map_anonymous(space, SECOND, 1, false).expect("remap as read-only");
    // SAFETY: The second page is mapped readable after remapping.
    assert_eq!(unsafe { (SECOND as *const u8).read_volatile() }, 0);
    ruzt_ipc::unmap_anonymous(space, BASE, 2).expect("return both private pages");
    write_line("rootsrv: anonymous memory rolled back and reused zeroed");
}

fn split_service_budgets() {
    assert_eq!(
        ruzt_ipc::split_untyped(SESSION_BUDGET, LOCAL_BUDGET, SERVICE_BUDGET_BITS + 1),
        Err(ErrorCode::BadMessage)
    );
    for budget in [LOCAL_BUDGET, CONSOLE_BUDGET] {
        ruzt_ipc::split_untyped(SESSION_BUDGET, budget, SERVICE_BUDGET_BITS)
            .expect("reserve a service RAM budget");
    }
    assert_eq!(
        ruzt_ipc::retype(SESSION_BUDGET, ROOTSRV_CONSOLE_FRAME, RetypeKind::Frame),
        Err(ErrorCode::NoMemory)
    );
}
