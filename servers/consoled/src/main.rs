#![no_std]
#![no_main]

#[cfg(any(feature = "qemu-fault-test", feature = "qemu-exit-test"))]
extern crate alloc;

mod dma;

use ruzt_abi::{
    console, CapRights, ErrorCode, IpcMessage, RetypeKind, FRAME_BYTES, PROCESS_ADDRESS_SPACE,
    ROOTSRV_FRAMEBUFFER, WAIT_ENDPOINT_CLOSED, WAIT_IRQ, WAIT_MESSAGE,
};
use ruzt_driver_sdk::{read_port_u8, write_port_u8};

// TL16C550D §7.6.3, transmitter holding register empty.
const TRANSMITTER_READY: u8 = 1 << 5;
const CONSOLE_BUFFER: u64 = 0x6000_0000;
const SCRATCH_BUFFER: u64 = CONSOLE_BUFFER + FRAME_BYTES as u64;
const SCRATCH_FRAME: u64 = 7;
const DEVICE_WINDOW: u64 = 0x6200_0000;

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
        let request = match ruzt_ipc::wait_any_with_caps(
            &[console::REQUEST],
            console::RECEIVED_NOTIFICATION,
            3,
        ) {
            Ok(event) if event.kind == WAIT_MESSAGE => event.message,
            Ok(event) if event.kind == WAIT_ENDPOINT_CLOSED => ruzt_runtime::syscall::exit(0),
            Ok(event) => panic!("unexpected console event {}", event.kind),
            Err(ErrorCode::InvalidCap) => ruzt_runtime::syscall::exit(1),
            Err(
                ErrorCode::BadMessage | ErrorCode::SlotOccupied | ErrorCode::CapRightsViolation,
            ) => {
                continue;
            }
            Err(error) => panic!("console receive failed: {error:?}"),
        };
        let label = match (request.label, request.cap_count) {
            (console::WRITE, 0) => {
                uart_write(&request.data[..usize::from(request.length)]);
                Ok(console::WRITTEN)
            }
            (console::WRITE_SHARED, 3) => write_shared(&request).map(|()| console::WRITTEN),
            (console::CHECK_REVOCATION, 1) => check_revocation().map(|()| console::REVOKED),
            (console::CHECK_IRQ, 3) => check_irq(&request).map(|()| console::IRQ_CHECKED),
            (console::CHECK_MMIO, 1) => {
                check_mmio(request.caps[0].cptr).map(|()| console::MMIO_CHECKED)
            }
            (console::CHECK_MMIO_REVOKED, 0) => {
                check_mmio_revoked().map(|()| console::MMIO_CHECKED)
            }
            (console::CHECK_DMA, 3) => dma::check(&request),
            (console::CHECK_DMA_REVOKED, 0) => dma::check_revoked().map(|()| console::DMA_CHECKED),
            #[cfg(feature = "qemu-pci-intx-test")]
            (console::CHECK_PCI_IRQ, 2) => check_pci_irq(&request).map(|()| console::PCI_IRQ_CHECKED),
            #[cfg(feature = "qemu-pci-intx-test")]
            (console::CHECK_PCI_IRQ_REVOKED, 0) => {
                assert_eq!(
                    ruzt_driver_sdk::bind_irq(console::RECEIVED_NOTIFICATION),
                    Err(ErrorCode::InvalidCap)
                );
                Ok(console::PCI_IRQ_CHECKED)
            }
            _ => Err(ErrorCode::BadMessage),
        };
        if label.is_err() {
            if (request.label, request.cap_count) == (console::WRITE_SHARED, 3) {
                ruzt_ipc::delete(SCRATCH_FRAME).expect("discard scratch frame");
            }
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
            run_preemption_test(&reply);
        }
        ruzt_ipc::send(console::REPLY, &reply).expect("reply to console request");
    }
}

#[cfg(feature = "qemu-preemption-test")]
fn run_preemption_test(reply: &IpcMessage) -> ! {
    const AC: u64 = 1 << 18;
    const DF: u64 = 1 << 10;
    let mut timestamp = 0u64;
    let (status, returned_flags): (u64, u64);
    // SAFETY: The syscall writes one u64 to our live stack. AC and DF are set
    // for the transition and cleared before control returns to Rust.
    unsafe {
        core::arch::asm!(
            "pushfq",
            "or qword ptr [rsp], {test_flags}",
            "popfq",
            "int 0x80",
            "pushfq",
            "pop {returned_flags}",
            "pushfq",
            "and qword ptr [rsp], {clear_flags}",
            "popfq",
            test_flags = const AC | DF,
            clear_flags = const !((AC | DF) as i32),
            returned_flags = lateout(reg) returned_flags,
            inlateout("rax") ruzt_abi::SyscallNumber::MonotonicTime as u64 => status,
            in("rdi") &mut timestamp,
        );
    }
    assert_eq!(ErrorCode::from_u64(status), Ok(()));
    assert_ne!(timestamp, 0);
    assert_eq!(returned_flags & (AC | DF), AC | DF);
    // Report both fixture markers while rootsrv is waiting for its reply.
    uart_write(b"consoled: syscall preserved user AC and DF\n");
    uart_write(b"consoled: reply followed by CPU-bound loop\n");
    ruzt_ipc::send(console::REPLY, reply).expect("reply to console request");

    // SAFETY: The loop touches no user data and never returns to Rust.
    unsafe {
        core::arch::asm!(
            "pushfq",
            "or qword ptr [rsp], {ac}",
            "popfq",
            "2: pause",
            "jmp 2b",
            ac = const AC,
            options(noreturn),
        )
    }
}

fn check_mmio(cap: u64) -> Result<(), ErrorCode> {
    use ruzt_driver_sdk::map_mmio;
    assert_eq!(
        map_mmio(cap, DEVICE_WINDOW, true),
        Err(ErrorCode::CapRightsViolation)
    );
    let registers = map_mmio(cap, DEVICE_WINDOW, false)?;
    // SAFETY: The supervisor grants the EDU register pages and waits for the
    // reply before revoking the capability. The ID is a readable dword.
    let identity = unsafe { registers.read_u32(0)? };
    if identity & 0xffff != 0x00ed {
        return Err(ErrorCode::BadMessage);
    }
    Ok(())
}

fn check_mmio_revoked() -> Result<(), ErrorCode> {
    assert_eq!(
        ruzt_driver_sdk::unmap_mmio(console::RECEIVED_NOTIFICATION),
        Err(ErrorCode::InvalidCap)
    );
    ruzt_ipc::map_anonymous(PROCESS_ADDRESS_SPACE, DEVICE_WINDOW, 2, true)?;
    ruzt_ipc::unmap_anonymous(PROCESS_ADDRESS_SPACE, DEVICE_WINDOW, 2)
}

fn check_irq(request: &IpcMessage) -> Result<(), ErrorCode> {
    // TL16C550D IER bit 1 enables THRE IRQs. IIR encodes THRE as 0b0010.
    const THRE_ENABLE: u8 = 1 << 1;
    const INTERRUPT_ID_MASK: u8 = 0x0f;
    let irq = request.caps[0].cptr;
    let enable = request.caps[1].cptr;
    let identify = request.caps[2].cptr;
    let prior_enable = read_port_u8(enable)?;
    write_port_u8(enable, 0)?;
    let probe = (|| {
        ruzt_driver_sdk::bind_irq(irq)?;
        assert_eq!(
            ruzt_driver_sdk::acknowledge_irq(irq),
            Err(ErrorCode::BadMessage)
        );
        for _ in 0..2 {
            write_port_u8(enable, THRE_ENABLE)?;
            let deadline = ruzt_runtime::syscall::monotonic_ns()? + 1_000_000_000;
            let event = ruzt_ipc::wait_any_until(&[irq], deadline)?;
            if event.kind != WAIT_IRQ || read_port_u8(identify)? & INTERRUPT_ID_MASK != 2 {
                return Err(ErrorCode::BadMessage);
            }
            write_port_u8(enable, 0)?;
            ruzt_driver_sdk::acknowledge_irq(irq)?;
        }
        Ok(())
    })();
    probe.and(write_port_u8(enable, prior_enable))?;
    ruzt_ipc::delete(enable)?;
    ruzt_ipc::delete(identify)?;
    // The supervisor revokes the remaining bound IRQ from its original cap.
    Ok(())
}

#[cfg(feature = "qemu-pci-intx-test")]
fn check_pci_irq(request: &IpcMessage) -> Result<(), ErrorCode> {
    use ruzt_driver_sdk::{acknowledge_irq, bind_irq, map_mmio, unmap_mmio};
    const STATUS: u64 = 0x24;
    const RAISE: u64 = 0x60;
    const CLEAR: u64 = 0x64;
    let irq = request.caps[0].cptr;
    let bar = request.caps[1].cptr;
    let registers = map_mmio(bar, DEVICE_WINDOW, true)?;
    let probe = (|| {
        bind_irq(irq)?;
        for bit in [1, 2] {
            // SAFETY: The test supervisor delegates the EDU BAR0 register
            // page. These offsets are its dword interrupt registers.
            unsafe {
                registers.write_u32(RAISE, bit)?;
                let deadline = ruzt_runtime::syscall::monotonic_ns()? + 1_000_000_000;
                let event = ruzt_ipc::wait_any_until(&[irq], deadline)?;
                if event.kind != WAIT_IRQ || registers.read_u32(STATUS)? != bit {
                    return Err(ErrorCode::BadMessage);
                }
                registers.write_u32(CLEAR, bit)?;
                // Read back the posted MMIO write before unmasking the pin.
                if registers.read_u32(STATUS)? != 0 {
                    return Err(ErrorCode::BadMessage);
                }
            }
            acknowledge_irq(irq)?;
        }
        Ok(())
    })();
    // SAFETY: Clear both test sources on the verified EDU BAR before unmapping.
    let clear = unsafe { registers.write_u32(CLEAR, 3) };
    let unmapped = unmap_mmio(bar);
    probe.and(clear).and(unmapped)?;
    ruzt_ipc::delete(bar)
}

fn write_shared(request: &IpcMessage) -> Result<(), ErrorCode> {
    let notification = console::RECEIVED_NOTIFICATION;
    let frame = console::RECEIVED_FRAME;
    let length = usize::from(u16::from_le_bytes([request.data[0], request.data[1]]));
    if request.length != 2
        || length > FRAME_BYTES
        || request.caps[0].rights != CapRights::WRITE
        || request.caps[1].rights != CapRights::READ
        || request.caps[2].rights != CapRights::WRITE
        || ruzt_ipc::wait(notification) != Err(ErrorCode::CapRightsViolation)
        || ruzt_ipc::map_frame(frame, CONSOLE_BUFFER, true) != Err(ErrorCode::CapRightsViolation)
    {
        return Err(ErrorCode::BadMessage);
    }
    ruzt_ipc::map_frame(frame, CONSOLE_BUFFER, false)?;
    ruzt_ipc::retype(console::RECEIVED_UNTYPED, SCRATCH_FRAME, RetypeKind::Frame)?;
    ruzt_ipc::map_frame(SCRATCH_FRAME, SCRATCH_BUFFER, true)?;
    run_shutdown_test();
    for offset in 0..length {
        // SAFETY: Both pages were mapped above. The boot sender waits for
        // our reply before changing the shared page or revoking either cap.
        unsafe {
            let byte = ((CONSOLE_BUFFER as usize + offset) as *const u8).read_volatile();
            ((SCRATCH_BUFFER as usize + offset) as *mut u8).write_volatile(byte);
        }
    }
    for offset in 0..length {
        // SAFETY: This is the same initialized scratch page and byte range.
        uart_write_byte(unsafe {
            ((SCRATCH_BUFFER as usize + offset) as *const u8).read_volatile()
        });
    }
    ruzt_ipc::signal(notification)
}

fn run_shutdown_test() {
    #[cfg(any(feature = "qemu-fault-test", feature = "qemu-exit-test"))]
    {
        let private_page = SCRATCH_BUFFER + FRAME_BYTES as u64;
        ruzt_ipc::map_anonymous(ruzt_abi::PROCESS_ADDRESS_SPACE, private_page, 1, true)
            .expect("map private memory to be reclaimed on exit");
        uart_write(b"consoled: delegated scratch and anonymous page mapped\n");
        check_heap_budget();
    }
    #[cfg(feature = "qemu-fault-test")]
    // SAFETY: This test deliberately raises a user instruction exception.
    unsafe {
        core::arch::asm!("ud2", options(noreturn, nomem, nostack))
    };
    #[cfg(all(feature = "qemu-exit-test", not(feature = "qemu-fault-test")))]
    ruzt_runtime::syscall::exit(23);
}

#[cfg(any(feature = "qemu-fault-test", feature = "qemu-exit-test"))]
fn check_heap_budget() {
    use core::hint::black_box;

    let mut initial = alloc::vec::Vec::new();
    black_box(&mut initial)
        .try_reserve_exact(ruzt_abi::USER_HEAP_INITIAL_BYTES - 64 * 1024)
        .expect("allocate most of the initial console heap");
    initial.push(0x69u8);

    let mut extra = alloc::vec::Vec::new();
    black_box(&mut extra)
        .try_reserve_exact(128 * 1024)
        .expect("grow the console heap");
    extra.push(0x96u8);
    let mut oversized = alloc::vec::Vec::<u8>::new();
    // An optimized build can elide a known, unused allocation.
    assert!(black_box(&mut oversized)
        .try_reserve_exact(2 * 1024 * 1024)
        .is_err());
    black_box(&mut extra)
        .try_reserve_exact(256 * 1024)
        .expect("grow after a rejected allocation");
    assert_eq!(black_box(initial.as_slice()), [0x69]);
    assert_eq!(black_box(extra.as_slice()), [0x96]);
    uart_write(b"consoled: runtime heap recovered after budget exhaustion\n");
}

fn check_revocation() -> Result<(), ErrorCode> {
    // The fresh read-only frame arrived in the former notification slot.
    // The old frame capability must be gone, and the old virtual address
    // must be available for the new capability to map.
    let fresh_frame = console::RECEIVED_NOTIFICATION;
    if ruzt_ipc::unmap_frame(console::RECEIVED_FRAME) != Err(ErrorCode::InvalidCap)
        || ruzt_ipc::unmap_frame(SCRATCH_FRAME) != Err(ErrorCode::InvalidCap)
    {
        return Err(ErrorCode::BadMessage);
    }
    for address in [CONSOLE_BUFFER, SCRATCH_BUFFER] {
        ruzt_ipc::map_frame(fresh_frame, address, false)?;
        ruzt_ipc::unmap_frame(fresh_frame)?;
    }
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
