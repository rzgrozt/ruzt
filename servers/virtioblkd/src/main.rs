#![no_std]
#![no_main]
#![deny(unsafe_code)]

#[allow(unsafe_code)]
mod hardware;

use ruzt_abi::{block, ErrorCode, IpcMessage};
use ruzt_runtime::{debug_print, runtime_init};
use ruzt_virtio::block::Error;

const SHARED: u64 = 9;

#[no_mangle]
#[allow(
    unsafe_code,
    reason = "the executable exports exactly one runtime entry point"
)]
pub extern "C" fn _start() -> ! {
    runtime_init(main)
}

fn main() -> ! {
    let mut device = hardware::initialize().expect("initialize isolated VirtIO block device");
    debug_print(format_args!(
        "virtioblkd: modern block queue ready, sectors={} read_only={} flush={}\n",
        device.sectors(),
        device.read_only(),
        device.supports_flush()
    ));
    let mut shared = None;
    #[cfg(feature = "qemu-restart-test")]
    let mut exit_on_write = false;
    loop {
        let mut message = IpcMessage::default();
        // The sole client establishes one reusable shared frame. Subsequent
        // requests carry no grants. DMA memory is never a syscall operand.
        ruzt_ipc::recv_with_caps(
            block::REQUEST,
            &mut message,
            SHARED,
            u8::from(shared.is_none()),
        )
        .expect("receive block request");
        #[cfg(feature = "qemu-restart-test")]
        if message.label == block::TEST_DELEGATE_DMA
            && message.length == 0
            && message.cap_count == 0
        {
            let mut reply = block::response(block::OK);
            reply.cap_count = 1;
            reply.caps[0] = ruzt_abi::CapTransferSlot {
                cptr: hardware::DMA,
                rights: ruzt_abi::CapRights::READ,
                badge: 0,
            };
            ruzt_ipc::send(block::REPLY, &reply).expect("delegate DMA for restart fixture");
            continue;
        }
        #[cfg(feature = "qemu-restart-test")]
        if message.label == block::TEST_EXIT && message.length == 0 && message.cap_count == 0 {
            ruzt_runtime::syscall::exit(23);
        }
        #[cfg(feature = "qemu-restart-test")]
        if message.label == block::TEST_EXIT_ON_WRITE
            && message.length == 0
            && message.cap_count == 0
        {
            exit_on_write = true;
            ruzt_ipc::send(block::REPLY, &block::response(block::OK))
                .expect("arm write-exit fixture");
            continue;
        }
        let attaching = message.label == block::ATTACH
            && shared.is_none()
            && message.cap_count == 1
            && message.length == 0
            && message.flags == 0;
        if !attaching && message.cap_count != 0 {
            // A rejected first request must not occupy the sole receive slot.
            ruzt_ipc::delete(SHARED).expect("discard unexpected block grant");
        }
        let response = if attaching {
            match hardware::SharedFrame::map(SHARED) {
                Ok(frame) => {
                    shared = Some(frame);
                    block::response(block::OK)
                }
                Err(_) => {
                    ruzt_ipc::delete(SHARED).expect("discard rejected shared frame");
                    block::response(block::BAD_REQUEST)
                }
            }
        } else if message.label == block::GEOMETRY
            && message.length == 0
            && message.cap_count == 0
            && message.flags == 0
        {
            block::geometry(
                device.sectors(),
                device.read_only(),
                device.supports_flush(),
            )
        } else {
            match block::Request::decode(&message) {
                Ok(request) if shared.is_some() || request.operation == block::FLUSH => {
                    let mut data = [0u8; 4096];
                    let bytes = usize::from(request.sectors) * 512;
                    let result = match request.operation {
                        block::READ => device.begin_read(request.sector, bytes),
                        block::WRITE => {
                            shared
                                .as_ref()
                                .unwrap()
                                .read(&mut data[..bytes])
                                .expect("copy block write input");
                            device.begin_write(request.sector, &data[..bytes])
                        }
                        block::FLUSH => device.begin_flush(),
                        _ => unreachable!(),
                    };
                    match result {
                        Ok(()) => {
                            #[cfg(feature = "qemu-restart-test")]
                            if exit_on_write && request.operation == block::WRITE {
                                ruzt_runtime::syscall::exit(24);
                            }
                            let deadline = ruzt_runtime::syscall::monotonic_ns()
                                .expect("read block deadline")
                                .saturating_add(5_000_000_000);
                            let completion = loop {
                                let output = if request.operation == block::READ {
                                    &mut data[..bytes]
                                } else {
                                    &mut []
                                };
                                match device.poll(output) {
                                    Ok(true) => break Ok(()),
                                    Ok(false) => {
                                        if ruzt_runtime::syscall::monotonic_ns()
                                            .expect("read block clock")
                                            >= deadline
                                        {
                                            // Exit lets the kernel stop and drain DMA.
                                            panic!("VirtIO block completion timed out");
                                        }
                                        // A completion can race with entering the wait.
                                        // Kernel IRQ notifications preserve that arrival.
                                        match ruzt_ipc::wait_any_until(&[hardware::IRQ], deadline) {
                                            Ok(_) => {
                                                ruzt_driver_sdk::acknowledge_irq(hardware::IRQ)
                                                    .expect("re-arm block IRQ")
                                            }
                                            Err(ErrorCode::TimedOut) => {}
                                            Err(error) => panic!("block IRQ failed: {error:?}"),
                                        }
                                    }
                                    Err(error @ (Error::Io | Error::Unsupported)) => {
                                        break Err(error)
                                    }
                                    Err(error) => panic!("block completion failed: {error:?}"),
                                }
                            };
                            if completion.is_ok() && request.operation == block::READ {
                                shared
                                    .as_ref()
                                    .unwrap()
                                    .write(&data[..bytes])
                                    .expect("copy block read output");
                            }
                            block::response(match completion {
                                Ok(()) => block::OK,
                                Err(Error::Io) => block::IO_ERROR,
                                Err(_) => block::UNSUPPORTED,
                            })
                        }
                        Err(Error::Bounds) => block::response(block::OUT_OF_RANGE),
                        Err(Error::ReadOnly) => block::response(block::READ_ONLY),
                        Err(Error::Unsupported) => block::response(block::UNSUPPORTED),
                        Err(error) => panic!("block submission failed: {error:?}"),
                    }
                }
                _ => block::response(block::BAD_REQUEST),
            }
        };
        ruzt_ipc::send(block::REPLY, &response).expect("send block response");
    }
}
