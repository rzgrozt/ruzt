//! Launch and supervise the read-only PCI discovery service.

use ruzt_abi::{pci, CapRights, CapTransferSlot, ErrorCode, IpcMessage, PciAddress, RetypeKind};
use ruzt_abi::{ROOTSRV_BOOT_PROGRAMS, ROOTSRV_PCI_CONTROL, ROOTSRV_UNTYPED};

const REQUEST: u64 = 51;
const REPLY: u64 = 52;
const PROGRAM: u64 = 53;
const STATUS: u64 = 54;
const MEMORY: u64 = 55;
#[cfg(feature = "qemu-pcid-test")]
const STALE_REQUEST: u64 = 57;

pub(super) fn start() -> Result<(), ErrorCode> {
    ruzt_ipc::open_boot_program(ROOTSRV_BOOT_PROGRAMS, "pcid", PROGRAM)?;
    ruzt_ipc::split_untyped(ROOTSRV_UNTYPED, MEMORY, 21)?;
    spawn()?;
    // The first request also verifies that startup and endpoint delegation
    // finished before the supervisor uses the discovery service.
    let _ = next(0)?;
    #[cfg(feature = "qemu-pcid-test")]
    verify_restart()?;
    super::write_line("rootsrv: supervised PCI discovery ready");
    Ok(())
}

fn spawn() -> Result<(), ErrorCode> {
    ruzt_ipc::retype(ROOTSRV_UNTYPED, REQUEST, RetypeKind::Endpoint)?;
    if let Err(error) = ruzt_ipc::retype(ROOTSRV_UNTYPED, REPLY, RetypeKind::Endpoint) {
        ruzt_ipc::delete(REQUEST)?;
        return Err(error);
    }
    let mut grants = IpcMessage {
        cap_count: 3,
        ..IpcMessage::default()
    };
    for (entry, (cptr, rights)) in grants.caps.iter_mut().zip([
        (REQUEST, CapRights::READ),
        (REPLY, CapRights::WRITE),
        (ROOTSRV_PCI_CONTROL, CapRights::READ),
    ]) {
        *entry = CapTransferSlot {
            cptr,
            rights,
            badge: 0,
        };
    }
    let result = ruzt_ipc::spawn_program(PROGRAM, STATUS, &grants, 3, MEMORY);
    if result.is_err() {
        ruzt_ipc::delete(REPLY)?;
        ruzt_ipc::delete(REQUEST)?;
    }
    result
}

fn next(cursor: u16) -> Result<Option<pci::Function>, ErrorCode> {
    let mut request = IpcMessage {
        label: pci::NEXT,
        length: 2,
        ..IpcMessage::default()
    };
    request.data[..2].copy_from_slice(&cursor.to_le_bytes());
    let response = exchange(&request)?;
    if response.label == pci::END && response.length == 0 && response.cap_count == 0 {
        return Ok(None);
    }
    let function = pci::Function::decode(&response)?;
    if function.address.bits() < cursor {
        return Err(ErrorCode::BadMessage);
    }
    Ok(Some(function))
}

fn exchange(request: &IpcMessage) -> Result<IpcMessage, ErrorCode> {
    match try_exchange(request) {
        Err(ErrorCode::NotFound) => {
            // Discovery only reads configuration. A request interrupted by
            // service exit can be retried once against a fresh instance.
            restart()?;
            try_exchange(request)
        }
        result => result,
    }
}

fn try_exchange(request: &IpcMessage) -> Result<IpcMessage, ErrorCode> {
    ruzt_ipc::send(REQUEST, request)?;
    let mut response = IpcMessage::default();
    ruzt_ipc::recv(REPLY, &mut response)?;
    Ok(response)
}

fn restart() -> Result<(), ErrorCode> {
    ruzt_ipc::wait_process(STATUS)?;
    for capability in [REQUEST, REPLY, STATUS] {
        ruzt_ipc::delete(capability)?;
    }
    spawn()?;
    super::write_line("rootsrv: PCI discovery service restarted");
    Ok(())
}

pub(super) fn find(vendor_device: u32) -> Result<Option<PciAddress>, ErrorCode> {
    let mut cursor = 0;
    while let Some(function) = next(cursor)? {
        if function.vendor_device == vendor_device {
            return Ok(Some(function.address));
        }
        cursor = function.address.bits() + 1;
    }
    Ok(None)
}

#[cfg(feature = "qemu-pcid-test")]
fn verify_restart() -> Result<(), ErrorCode> {
    assert!(next(256)?.is_none());
    let bad = IpcMessage {
        label: pci::NEXT,
        length: 1,
        ..IpcMessage::default()
    };
    assert_eq!(exchange(&bad)?.label, pci::BAD_REQUEST);
    ruzt_ipc::send(
        REQUEST,
        &IpcMessage {
            label: pci::TEST_EXIT,
            ..IpcMessage::default()
        },
    )?;
    let status = ruzt_ipc::wait_process(STATUS)?;
    assert_eq!(status.kind, ruzt_abi::PROCESS_EXITED);
    assert_eq!(status.code, 23);
    ruzt_ipc::mint(REQUEST, STALE_REQUEST, CapRights::WRITE, 0)?;
    for temporary in [58, 59] {
        ruzt_ipc::split_untyped(MEMORY, temporary, 20)?;
    }
    for temporary in [58, 59] {
        ruzt_ipc::delete(temporary)?;
    }
    // This exercises the same automatic retry used by ordinary discovery.
    let _ = next(0)?;
    assert_eq!(
        ruzt_ipc::send(STALE_REQUEST, &IpcMessage::default()),
        Err(ErrorCode::NotFound)
    );
    ruzt_ipc::delete(STALE_REQUEST)?;
    super::write_line("rootsrv: PCI discovery restarted with fresh endpoints and reclaimed memory");
    Ok(())
}
