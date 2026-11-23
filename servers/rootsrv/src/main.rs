#![no_std]
#![no_main]

extern crate alloc;

mod tile;

use ruzt_abi::{
    console, CapRights, CapTransferSlot, ErrorCode, IpcMessage, PciAddress, RetypeKind,
    FRAME_BYTES, PROCESS_ADDRESS_SPACE, PROCESS_EXITED, PROCESS_FAULTED, ROOTSRV_CONSOLE_FRAME,
    ROOTSRV_CONSOLE_NOTIFICATION, ROOTSRV_CONSOLE_PROCESS, ROOTSRV_CONSOLE_PROGRAM,
    ROOTSRV_CONSOLE_REPLY, ROOTSRV_CONSOLE_REQUEST, ROOTSRV_FRAMEBUFFER, ROOTSRV_IRQ_CONTROL,
    ROOTSRV_KEYBOARD_DATA, ROOTSRV_KEYBOARD_IRQ, ROOTSRV_PCI_CONTROL, ROOTSRV_UART_DATA,
    ROOTSRV_UART_IRQ_ENABLE, ROOTSRV_UART_IRQ_IDENTIFY, ROOTSRV_UART_STATUS, ROOTSRV_UNTYPED,
    WAIT_ENDPOINT_CLOSED, WAIT_IRQ, WAIT_MESSAGE, WAIT_NOTIFICATION, WAIT_PROCESS_EXITED,
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
    let signal = ruzt_ipc::wait_any(&[ROOTSRV_CONSOLE_NOTIFICATION, ROOTSRV_CONSOLE_REPLY])?;
    if signal.kind == WAIT_ENDPOINT_CLOSED {
        return Err(ErrorCode::NotFound);
    }
    assert_eq!((signal.index, signal.kind), (0, WAIT_NOTIFICATION));
    let response = ruzt_ipc::wait_any(&[ROOTSRV_CONSOLE_REPLY, ROOTSRV_CONSOLE_NOTIFICATION])?;
    if response.kind == WAIT_ENDPOINT_CLOSED {
        return Err(ErrorCode::NotFound);
    }
    assert_eq!((response.index, response.kind), (0, WAIT_MESSAGE));
    reply = response.message;
    assert_eq!(reply.label, console::WRITTEN);
    assert_eq!(reply.length, 0);
    write_line("rootsrv: console write acknowledged over IPC");
    write_line("rootsrv: wait selected both console notification and reply");
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

fn run_console() -> bool {
    ruzt_ipc::split_untyped(ROOTSRV_UNTYPED, PROGRAM_BUDGET, PROGRAM_BUDGET_BITS)
        .expect("reserve console address-space memory");
    ruzt_ipc::split_untyped(ROOTSRV_UNTYPED, SESSION_BUDGET, SERVICE_BUDGET_BITS + 1)
        .expect("reserve console session memory");
    for attempt in 0..2 {
        start_console();
        let ready = confirm_console_ready();
        if ready.is_ok() {
            if ruzt_driver_sdk::read_port_u8(ROOTSRV_UART_IRQ_ENABLE).is_ok() {
                check_console_irq().expect("delegate and reclaim the console UART IRQ");
            }
            check_pci_mmio().expect("verify firmware-assigned PCI memory");
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
            Ok(()) => return true,
            Err(ErrorCode::NotFound) => write_line("rootsrv: console disconnected"),
            Err(error) => panic!("console IPC failed: {error:?}"),
        }
        let event = ruzt_ipc::wait_any(&[ROOTSRV_CONSOLE_PROCESS])
            .expect("wait for the console to be reaped");
        assert_eq!((event.index, event.kind), (0, WAIT_PROCESS_EXITED));
        let status = ruzt_ipc::poll_process(ROOTSRV_CONSOLE_PROCESS)
            .expect("read console status after the process event");
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
            return false;
        }
        if attempt == 0 {
            write_line("rootsrv: restarting console with fresh endpoints");
        }
    }
    false
}

fn check_console_irq() -> Result<(), ErrorCode> {
    const UART_CAP: u64 = 31;
    const VACANT: u64 = 24;
    const COM1_LINE: u32 = 4;
    let read_write = CapRights::READ.union(CapRights::WRITE);
    assert_eq!(
        ruzt_driver_sdk::claim_irq(ROOTSRV_UNTYPED, VACANT, COM1_LINE),
        Err(ErrorCode::InvalidCap)
    );
    ruzt_driver_sdk::claim_irq(ROOTSRV_IRQ_CONTROL, UART_CAP, COM1_LINE)?;
    assert_eq!(
        ruzt_driver_sdk::claim_irq(ROOTSRV_IRQ_CONTROL, VACANT, COM1_LINE),
        Err(ErrorCode::SlotOccupied)
    );

    let mut request = IpcMessage {
        label: console::CHECK_IRQ,
        cap_count: 3,
        ..IpcMessage::default()
    };
    for (cap, (cptr, rights)) in request.caps.iter_mut().zip([
        (UART_CAP, read_write),
        (ROOTSRV_UART_IRQ_ENABLE, read_write),
        (ROOTSRV_UART_IRQ_IDENTIFY, CapRights::READ),
    ]) {
        *cap = CapTransferSlot {
            cptr,
            rights,
            badge: 0,
        };
    }
    ruzt_ipc::send(ROOTSRV_CONSOLE_REQUEST, &request)?;
    let mut response = IpcMessage::default();
    ruzt_ipc::recv(ROOTSRV_CONSOLE_REPLY, &mut response)?;
    if response.label != console::IRQ_CHECKED {
        return Err(ErrorCode::BadMessage);
    }
    assert_eq!(
        ruzt_driver_sdk::bind_irq(UART_CAP),
        Err(ErrorCode::SlotOccupied)
    );
    assert_eq!(
        ruzt_driver_sdk::acknowledge_irq(UART_CAP),
        Err(ErrorCode::InvalidCap)
    );
    ruzt_ipc::revoke(UART_CAP)?;
    ruzt_driver_sdk::bind_irq(UART_CAP)?;
    ruzt_ipc::delete(UART_CAP)?;
    ruzt_driver_sdk::claim_irq(ROOTSRV_IRQ_CONTROL, VACANT, COM1_LINE)?;
    ruzt_driver_sdk::bind_irq(VACANT)?;
    ruzt_driver_sdk::unbind_irq(VACANT)?;
    ruzt_ipc::delete(VACANT)?;
    write_line("rootsrv: delegated UART IRQ delivered, re-armed and reclaimed");
    Ok(())
}

fn check_pci_mmio() -> Result<(), ErrorCode> {
    use ruzt_driver_sdk::{claim_pci_device, map_mmio, open_pci_bar, read_pci_config, unmap_mmio};
    const EDU_ID: u32 = 0x11e8_1234;
    const DEVICE: u64 = 33;
    const BAR: u64 = 34;
    const SPARE: u64 = 35;
    const WINDOW: u64 = 0x5200_0000;
    let mut found = None;
    for device in 0..32 {
        let address = PciAddress::new(0, device, 0).unwrap();
        if read_pci_config(ROOTSRV_PCI_CONTROL, address, 0)? == EDU_ID {
            found = Some(address);
            break;
        }
    }
    let Some(address) = found else { return Ok(()) };
    assert_eq!(
        read_pci_config(ROOTSRV_UNTYPED, address, 0),
        Err(ErrorCode::InvalidCap)
    );
    claim_pci_device(ROOTSRV_PCI_CONTROL, DEVICE, address)?;
    assert_eq!(
        claim_pci_device(ROOTSRV_PCI_CONTROL, SPARE, address),
        Err(ErrorCode::SlotOccupied)
    );
    assert_eq!(
        open_pci_bar(DEVICE, BAR, 0, 255, 2),
        Err(ErrorCode::BadMessage)
    );
    open_pci_bar(DEVICE, BAR, 0, 0, 2)?;

    let second_page = WINDOW + FRAME_BYTES as u64;
    ruzt_ipc::map_anonymous(PROCESS_ADDRESS_SPACE, second_page, 1, true)?;
    assert_eq!(map_mmio(BAR, WINDOW, true), Err(ErrorCode::MappingExists));
    ruzt_ipc::map_anonymous(PROCESS_ADDRESS_SPACE, WINDOW, 1, true)?;
    ruzt_ipc::unmap_anonymous(PROCESS_ADDRESS_SPACE, WINDOW, 2)?;
    let registers = map_mmio(BAR, WINDOW, true)?;
    // SAFETY: The EDU identity confirmed the device and BAR0 maps its registers.
    // Register 4 accepts a dword and returns its bitwise inversion on read.
    unsafe {
        assert_eq!(registers.read_u32(0)? & 0xffff, 0x00ed);
        registers.write_u32(4, 0x1234_5678)?;
        assert_eq!(registers.read_u32(4)?, !0x1234_5678);
    }
    // SAFETY: Asking the kernel to validate this mapped range as an output
    // buffer is intentional. MonotonicTime rejects device pages before writing.
    let status = unsafe {
        ruzt_runtime::syscall::syscall(
            ruzt_abi::SyscallNumber::MonotonicTime,
            WINDOW,
            0,
            0,
            0,
            0,
            0,
        )
    };
    assert_eq!(ErrorCode::from_u64(status), Err(ErrorCode::BadMessage));
    unmap_mmio(BAR)?;
    let mut request = IpcMessage {
        label: console::CHECK_MMIO,
        cap_count: 1,
        ..IpcMessage::default()
    };
    request.caps[0] = CapTransferSlot {
        cptr: BAR,
        rights: CapRights::READ,
        badge: 0,
    };
    ruzt_ipc::send(ROOTSRV_CONSOLE_REQUEST, &request)?;
    let mut response = IpcMessage::default();
    ruzt_ipc::recv(ROOTSRV_CONSOLE_REPLY, &mut response)?;
    assert_eq!(response.label, console::MMIO_CHECKED);

    ruzt_ipc::revoke(DEVICE)?;
    assert_eq!(map_mmio(BAR, WINDOW, false), Err(ErrorCode::InvalidCap));
    let request = IpcMessage {
        label: console::CHECK_MMIO_REVOKED,
        ..IpcMessage::default()
    };
    ruzt_ipc::send(ROOTSRV_CONSOLE_REQUEST, &request)?;
    ruzt_ipc::recv(ROOTSRV_CONSOLE_REPLY, &mut response)?;
    assert_eq!(response.label, console::MMIO_CHECKED);
    open_pci_bar(DEVICE, BAR, 0, 0, 1)?;
    check_pci_dma(DEVICE, BAR, address)?;
    ruzt_ipc::delete(BAR)?;
    ruzt_ipc::delete(DEVICE)?;
    claim_pci_device(ROOTSRV_PCI_CONTROL, SPARE, address)?;
    ruzt_ipc::delete(SPARE)?;
    write_line("rootsrv: PCI BAR mapped, delegated read-only, revoked and reclaimed");
    Ok(())
}

fn check_pci_dma(device: u64, bar: u64, address: PciAddress) -> Result<(), ErrorCode> {
    use ruzt_driver_sdk::{
        allocate_dma_buffer, bind_dma, map_dma_buffer, read_pci_config, unmap_dma_buffer, DMA_WRITE,
    };
    const BUDGET: u64 = 36;
    const BUFFER: u64 = 37;
    const SPARE: u64 = 38;
    const BUFFER_BITS: u8 = 13;
    const WINDOW: u64 = 0x5400_0000;
    const BUS_MASTER: u32 = 1 << 2;
    let shared = CapRights::READ.union(CapRights::WRITE);

    ruzt_ipc::split_untyped(ROOTSRV_UNTYPED, BUDGET, BUFFER_BITS)?;
    assert_eq!(
        allocate_dma_buffer(BUDGET, BUFFER, 11),
        Err(ErrorCode::BadMessage)
    );
    allocate_dma_buffer(BUDGET, BUFFER, BUFFER_BITS)?;
    assert_eq!(
        ruzt_ipc::retype(BUDGET, SPARE, RetypeKind::Frame),
        Err(ErrorCode::NoMemory)
    );
    ruzt_ipc::mint(BUFFER, SPARE, CapRights::READ, 0)?;
    assert_eq!(
        bind_dma(device, SPARE, DMA_WRITE),
        Err(ErrorCode::CapRightsViolation)
    );
    ruzt_ipc::delete(SPARE)?;

    let mut request = IpcMessage {
        label: console::CHECK_DMA,
        cap_count: 3,
        ..IpcMessage::default()
    };
    for (slot, cptr) in request.caps.iter_mut().zip([device, BUFFER, bar]) {
        *slot = CapTransferSlot {
            cptr,
            rights: shared,
            badge: 0,
        };
    }
    ruzt_ipc::send(ROOTSRV_CONSOLE_REQUEST, &request)?;
    let mut response = IpcMessage::default();
    ruzt_ipc::recv(ROOTSRV_CONSOLE_REPLY, &mut response)?;
    let transferred = match response.label {
        console::DMA_CHECKED => {
            assert_eq!(
                read_pci_config(ROOTSRV_PCI_CONTROL, address, 4)? & BUS_MASTER,
                BUS_MASTER
            );
            ruzt_ipc::revoke(BUFFER)?;
            let request = IpcMessage {
                label: console::CHECK_DMA_REVOKED,
                ..IpcMessage::default()
            };
            ruzt_ipc::send(ROOTSRV_CONSOLE_REQUEST, &request)?;
            ruzt_ipc::recv(ROOTSRV_CONSOLE_REPLY, &mut response)?;
            assert_eq!(response.label, console::DMA_CHECKED);
            true
        }
        console::DMA_UNAVAILABLE => false,
        _ => return Err(ErrorCode::BadMessage),
    };
    assert_eq!(
        read_pci_config(ROOTSRV_PCI_CONTROL, address, 4)? & BUS_MASTER,
        0
    );
    ruzt_ipc::delete(BUFFER)?;
    allocate_dma_buffer(BUDGET, SPARE, BUFFER_BITS)?;
    map_dma_buffer(SPARE, WINDOW, false)?;
    // SAFETY: The reallocated buffer is mapped read-only and unbound.
    unsafe {
        assert_eq!((WINDOW as *const u64).read_volatile(), 0);
        assert_eq!(
            ((WINDOW + FRAME_BYTES as u64) as *const u64).read_volatile(),
            0
        );
    }
    unmap_dma_buffer(SPARE)?;
    ruzt_ipc::delete(SPARE)?;
    ruzt_ipc::delete(BUDGET)?;
    if transferred {
        write_line("rootsrv: delegated DMA round trip, revocation and reclamation verified");
    }
    Ok(())
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
    ruzt_driver_sdk::claim_irq(ROOTSRV_IRQ_CONTROL, ROOTSRV_KEYBOARD_IRQ, 1)
        .expect("claim PS/2 keyboard IRQ");
    ruzt_driver_sdk::bind_irq(ROOTSRV_KEYBOARD_IRQ).expect("bind PS/2 keyboard IRQ");
    let mut console_is_open = run_console();
    check_cspace();
    check_anonymous_memory();
    check_heap_growth();

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
    let sources = [ROOTSRV_KEYBOARD_IRQ, ROOTSRV_CONSOLE_REPLY];
    loop {
        let count = 1 + usize::from(console_is_open);
        let event = ruzt_ipc::wait_any(&sources[..count]).expect("wait for keyboard or console");
        match event.kind {
            WAIT_ENDPOINT_CLOSED => console_is_open = false,
            WAIT_MESSAGE => {}
            WAIT_IRQ => {
                let scancode = ruzt_driver_sdk::read_port_u8(ROOTSRV_KEYBOARD_DATA)
                    .expect("read PS/2 keyboard data");
                ruzt_driver_sdk::acknowledge_irq(ROOTSRV_KEYBOARD_IRQ)
                    .expect("re-arm PS/2 keyboard IRQ");
                // The boot firmware configures translated set-1 scancodes.
                if scancode == 0x39 {
                    if let Some(tile) = &mut tile {
                        tile.toggle();
                    }
                    write_line("rootsrv: Space key received");
                }
            }
            kind => panic!("unexpected keyboard loop event {kind}"),
        }
    }
}

fn check_cspace() {
    use ruzt_abi::cptr_path;

    const BUDGET: u64 = 24;
    const TABLE: u8 = 25;
    const READER: u8 = 26;
    const COPY: u64 = 27;
    let table = u64::from(TABLE);
    let reader = u64::from(READER);
    let inner = cptr_path(&[TABLE, 0]).unwrap();
    let notification = cptr_path(&[TABLE, 0, 1]).unwrap();
    let read_path = cptr_path(&[READER, 0, 1]).unwrap();

    ruzt_ipc::split_untyped(ROOTSRV_UNTYPED, BUDGET, 13).expect("reserve two CNode pages");
    ruzt_ipc::create_cnode(BUDGET, table, 1).expect("create outer table");
    ruzt_ipc::create_cnode(BUDGET, inner, 1).expect("create nested table");
    assert_eq!(
        ruzt_ipc::retype(BUDGET, notification, RetypeKind::Notification),
        Err(ErrorCode::NoMemory)
    );
    ruzt_ipc::retype(ROOTSRV_UNTYPED, notification, RetypeKind::Notification)
        .expect("place notification in the nested table");
    ruzt_ipc::mint(table, reader, CapRights::READ, 0).expect("make a read-only view");
    assert_eq!(
        ruzt_ipc::delete(read_path),
        Err(ErrorCode::CapRightsViolation)
    );
    assert_eq!(ruzt_ipc::wait_any(&[]), Err(ErrorCode::BadMessage));
    assert_eq!(
        ruzt_ipc::wait_any(&[read_path; ruzt_abi::MAX_WAIT_SOURCES + 1]),
        Err(ErrorCode::BadMessage)
    );
    ruzt_ipc::signal(notification).expect("signal through a nested path");
    assert_eq!(
        ruzt_ipc::wait_any(&[read_path, u64::MAX]),
        Err(ErrorCode::InvalidCap)
    );
    let event = ruzt_ipc::wait_any_until(&[read_path], 0).expect("poll the ready notification");
    assert_eq!((event.index, event.kind), (0, WAIT_NOTIFICATION));
    check_deadlines(read_path);
    assert_eq!(
        ruzt_ipc::move_cap(table, cptr_path(&[TABLE, 1]).unwrap()),
        Err(ErrorCode::BadMessage)
    );
    ruzt_ipc::mint(notification, COPY, CapRights::WRITE, 0).expect("mint from nested slot");
    ruzt_ipc::revoke(notification).expect("revoke through a nested path");
    assert_eq!(ruzt_ipc::signal(COPY), Err(ErrorCode::InvalidCap));

    ruzt_ipc::revoke(BUDGET).expect("reclaim both CNodes and their slots");
    assert_eq!(ruzt_ipc::signal(notification), Err(ErrorCode::InvalidCap));
    assert_eq!(ruzt_ipc::signal(read_path), Err(ErrorCode::InvalidCap));
    for slot in [table, reader] {
        ruzt_ipc::retype(BUDGET, slot, RetypeKind::Endpoint).expect("reuse reclaimed CNode page");
        // Keep the first page reserved until both allocations have succeeded.
    }
    ruzt_ipc::revoke(BUDGET).expect("release test endpoints");
    ruzt_ipc::delete(BUDGET).expect("release the CNode budget");
    write_line("rootsrv: nested capability lookup, revocation and budgets verified");
}

fn check_deadlines(notification: u64) {
    use ruzt_runtime::syscall::{monotonic_ns, sleep_until};

    assert_eq!(
        ruzt_ipc::wait_any_until(&[notification], 0),
        Err(ErrorCode::TimedOut)
    );
    let deadline = monotonic_ns().expect("read the monotonic clock") + 30_000_000;
    assert_eq!(
        ruzt_ipc::wait_any_until(&[notification], deadline),
        Err(ErrorCode::TimedOut)
    );
    let after_wait = monotonic_ns().expect("read clock after the timed wait");
    assert!(after_wait >= deadline);

    let wake_at = after_wait + 30_000_000;
    sleep_until(wake_at).expect("sleep without any wait sources");
    assert!(monotonic_ns().expect("read clock after sleep") >= wake_at);
    write_line("rootsrv: timed wait and sleep woke at monotonic deadlines");
}

fn check_heap_growth() {
    use alloc::alloc::{alloc, dealloc, Layout};
    use ruzt_abi::{USER_HEAP_INITIAL_BYTES, USER_HEAP_START};

    let first_extension = USER_HEAP_START + USER_HEAP_INITIAL_BYTES as u64;
    assert_eq!(
        ruzt_ipc::map_anonymous(PROCESS_ADDRESS_SPACE, first_extension, 1, true),
        Err(ErrorCode::MappingExists),
    );
    // A page-aligned allocation larger than the entire bootstrap heap.
    let layout = Layout::from_size_align(
        USER_HEAP_INITIAL_BYTES + FRAME_BYTES - size_of::<usize>(),
        FRAME_BYTES * 2,
    )
    .unwrap();
    // SAFETY: The layout is valid and nonempty. The allocation is checked
    // before any access and released below with the same layout.
    let pointer = unsafe { alloc(layout) };
    assert!(!pointer.is_null());
    assert_eq!(pointer.addr() % layout.align(), 0);
    assert_eq!(
        ruzt_ipc::unmap_anonymous(PROCESS_ADDRESS_SPACE, first_extension, 1),
        Err(ErrorCode::NotFound),
    );
    // SAFETY: The successful allocation covers all of these bytes.
    unsafe {
        let last = pointer.add(layout.size() - 1);
        last.write_volatile(0xa5);
        assert_eq!(last.read_volatile(), 0xa5);
        dealloc(pointer, layout);
    }
    write_line("rootsrv: aligned allocation grew the runtime heap");
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
    let crossing = SECOND - 4;
    let earliest = ruzt_runtime::syscall::monotonic_ns().expect("read clock before split copy");
    assert_eq!(read_clock_at(crossing), Ok(()));
    // SAFETY: The syscall wrote the two aligned halves in writable private pages.
    let copied = unsafe {
        let low = (crossing as *const u32).read_volatile();
        let high = (SECOND as *const u32).read_volatile();
        u64::from(low) | (u64::from(high) << 32)
    };
    let latest = ruzt_runtime::syscall::monotonic_ns().expect("read clock after split copy");
    assert!((earliest..=latest).contains(&copied));

    ruzt_ipc::unmap_anonymous(space, SECOND, 1).expect("unmap part of the private range");
    ruzt_ipc::map_anonymous(space, SECOND, 1, false).expect("remap as read-only");
    // SAFETY: The first page stays writable across the second-page remap.
    unsafe { (crossing as *mut u32).write_volatile(u32::MAX) };
    assert_eq!(read_clock_at(crossing), Err(ErrorCode::BadMessage));
    // SAFETY: The first page stays mapped and should not have been modified.
    assert_eq!(
        unsafe { (crossing as *const u32).read_volatile() },
        u32::MAX
    );
    // SAFETY: The second page is mapped readable after remapping.
    assert_eq!(unsafe { (SECOND as *const u8).read_volatile() }, 0);
    ruzt_ipc::unmap_anonymous(space, BASE, 2).expect("return both private pages");
    write_line("rootsrv: anonymous memory rolled back and reused zeroed");
    write_line("rootsrv: syscall copy checked both pages before writing");
}

fn read_clock_at(address: u64) -> Result<(), ErrorCode> {
    // SAFETY: The caller supplies a controlled address in private pages. It
    // exercises the kernel's validation of the entire output range.
    let status = unsafe {
        ruzt_runtime::syscall::syscall(
            ruzt_abi::SyscallNumber::MonotonicTime,
            address,
            0,
            0,
            0,
            0,
            0,
        )
    };
    ErrorCode::from_u64(status)
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
