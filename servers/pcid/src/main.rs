#![no_std]
#![no_main]

use ruzt_abi::{pci, IpcMessage, PciAddress};
use ruzt_driver_sdk::read_pci_config;
use ruzt_runtime::{debug_print, runtime_init};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    runtime_init(main)
}

fn main() -> ! {
    #[cfg(feature = "qemu-restart-test")]
    assert_eq!(
        ruzt_driver_sdk::claim_pci_device(pci::CONTROL, 3, PciAddress::from_bits(0)),
        Err(ruzt_abi::ErrorCode::CapRightsViolation)
    );
    debug_print(format_args!("pcid: read-only PCI discovery ready\n"));
    loop {
        let mut request = IpcMessage::default();
        ruzt_ipc::recv(pci::REQUEST, &mut request).expect("receive PCI discovery request");
        #[cfg(feature = "qemu-restart-test")]
        if request.label == pci::TEST_EXIT && request.length == 0 && request.cap_count == 0 {
            ruzt_runtime::syscall::exit(23);
        }
        let response = discover(&request);
        ruzt_ipc::send(pci::REPLY, &response).expect("reply to PCI discovery client");
    }
}

fn discover(request: &IpcMessage) -> IpcMessage {
    if request.label != pci::NEXT || request.length != 2 || request.cap_count != 0 {
        return IpcMessage {
            label: pci::BAD_REQUEST,
            ..IpcMessage::default()
        };
    }
    let cursor = u16::from_le_bytes(request.data[..2].try_into().unwrap());
    if cursor > 256 {
        return IpcMessage {
            label: pci::BAD_REQUEST,
            ..IpcMessage::default()
        };
    }
    for function in cursor..256 {
        let address = PciAddress::from_bits(function);
        let vendor_device = read_pci_config(pci::CONTROL, address, 0).expect("read PCI identity");
        if vendor_device as u16 == 0xffff {
            continue;
        }
        let class_revision = read_pci_config(pci::CONTROL, address, 8).expect("read PCI class");
        return pci::Function {
            address,
            vendor_device,
            class_revision,
        }
        .message();
    }
    IpcMessage {
        label: pci::END,
        ..IpcMessage::default()
    }
}
