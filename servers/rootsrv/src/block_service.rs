//! Exclusive block-device service with supervisor-owned endpoints and memory.
//! Native storage will be its client. Test writes require an explicit feature
//! and a disposable QEMU data disk, never the boot disk.

use ruzt_abi::{
    block, cptr_path, CapRights, CapTransferSlot, ErrorCode, IpcMessage, RetypeKind,
    ROOTSRV_BOOT_PROGRAMS, ROOTSRV_PCI_CONTROL, ROOTSRV_UNTYPED,
};

const TABLE: u64 = 46;
const REQUEST: u8 = 0;
const REPLY: u8 = 1;
const PROGRAM: u8 = 2;
const STATUS: u8 = 3;
const MEMORY: u8 = 4;
const DEVICE: u8 = 5;
const SHARED: u8 = 6;
const BUFFER: u64 = 0x5600_0000;

fn slot(index: u8) -> u64 {
    cptr_path(&[TABLE as u8, index]).unwrap()
}

pub(super) fn start() -> Result<(), ErrorCode> {
    let Some(address) = super::pci_service::find(0x1042_1af4)? else {
        return Ok(());
    };
    ruzt_ipc::create_cnode(ROOTSRV_UNTYPED, TABLE, 4)?;
    ruzt_driver_sdk::claim_pci_device(ROOTSRV_PCI_CONTROL, slot(DEVICE), address)?;
    ruzt_ipc::open_boot_program(ROOTSRV_BOOT_PROGRAMS, "virtioblkd", slot(PROGRAM))?;
    ruzt_ipc::split_untyped(ROOTSRV_UNTYPED, slot(MEMORY), 21)?;
    ruzt_ipc::retype(ROOTSRV_UNTYPED, slot(SHARED), RetypeKind::Frame)?;
    ruzt_ipc::map_frame(slot(SHARED), BUFFER, true)?;
    spawn()?;
    attach()?;
    let geometry = exchange(&IpcMessage {
        label: block::GEOMETRY,
        ..IpcMessage::default()
    })?;
    super::write_line("rootsrv: isolated VirtIO block service ready");
    #[cfg(feature = "qemu-block-test")]
    {
        verify_io(&geometry)?;
        verify_restart()?;
    }
    #[cfg(not(feature = "qemu-block-test"))]
    let _ = geometry;
    Ok(())
}

fn spawn() -> Result<(), ErrorCode> {
    ruzt_ipc::retype(ROOTSRV_UNTYPED, slot(REQUEST), RetypeKind::Endpoint)?;
    if let Err(error) = ruzt_ipc::retype(ROOTSRV_UNTYPED, slot(REPLY), RetypeKind::Endpoint) {
        ruzt_ipc::delete(slot(REQUEST))?;
        return Err(error);
    }
    let mut grants = IpcMessage {
        cap_count: 4,
        ..IpcMessage::default()
    };
    let reply_rights = CapRights::WRITE;
    // Only the fixture can transfer a deliberately retained DMA alias back
    // to its supervisor. Production reply authority is send-only.
    #[cfg(feature = "qemu-block-test")]
    let reply_rights = reply_rights.union(CapRights::GRANT);
    for (entry, (index, rights)) in grants.caps.iter_mut().zip([
        (REQUEST, CapRights::READ),
        (REPLY, reply_rights),
        (DEVICE, CapRights::READ.union(CapRights::WRITE)),
        (MEMORY, CapRights::WRITE),
    ]) {
        *entry = CapTransferSlot {
            cptr: slot(index),
            rights,
            badge: 0,
        };
    }
    let result = ruzt_ipc::spawn_program(slot(PROGRAM), slot(STATUS), &grants, 3, slot(MEMORY));
    if result.is_err() {
        ruzt_ipc::delete(slot(REPLY))?;
        ruzt_ipc::delete(slot(REQUEST))?;
    }
    result
}

fn attach() -> Result<IpcMessage, ErrorCode> {
    let geometry = try_exchange(&IpcMessage {
        label: block::GEOMETRY,
        ..IpcMessage::default()
    })?;
    if geometry.label != block::GEOMETRY_RESULT || geometry.length != 16 || geometry.cap_count != 0
    {
        return Err(ErrorCode::BadMessage);
    }
    let mut attach = IpcMessage {
        label: block::ATTACH,
        cap_count: 1,
        ..IpcMessage::default()
    };
    attach.caps[0] = CapTransferSlot {
        cptr: slot(SHARED),
        rights: CapRights::READ.union(CapRights::WRITE),
        badge: 0,
    };
    if try_exchange(&attach)? != block::response(block::OK) {
        return Err(ErrorCode::BadMessage);
    }
    Ok(geometry)
}

fn exchange(message: &IpcMessage) -> Result<IpcMessage, ErrorCode> {
    match try_exchange(message) {
        Err(ErrorCode::NotFound) => {
            ruzt_ipc::wait_process(slot(STATUS))?;
            // Remove resources the previous instance may have delegated before
            // it died, while retaining these supervisor-owned authorities.
            ruzt_ipc::revoke(slot(DEVICE))?;
            ruzt_ipc::revoke(slot(MEMORY))?;
            #[cfg(feature = "qemu-block-test")]
            verify_reclaimed_budget()?;
            for index in [REQUEST, REPLY, STATUS] {
                ruzt_ipc::delete(slot(index))?;
            }
            spawn()?;
            attach()?;
            super::write_line("rootsrv: block service restarted with fresh endpoints");
            if [block::READ, block::GEOMETRY].contains(&message.label) {
                try_exchange(message)
            } else {
                // A write may have reached the disk before its reply was lost.
                // Native storage must recover its transaction before retrying.
                Err(ErrorCode::NotFound)
            }
        }
        result => result,
    }
}

fn try_exchange(message: &IpcMessage) -> Result<IpcMessage, ErrorCode> {
    ruzt_ipc::send(slot(REQUEST), message)?;
    let mut response = IpcMessage::default();
    ruzt_ipc::recv(slot(REPLY), &mut response)?;
    Ok(response)
}

#[cfg(feature = "qemu-block-test")]
fn verify_io(geometry: &IpcMessage) -> Result<(), ErrorCode> {
    let sectors = u64::from_le_bytes(geometry.data[..8].try_into().unwrap());
    assert_eq!(sectors, 32768);
    assert_eq!(geometry.data[8..14], [0, 2, 0, 0, 8, 0]);
    assert_eq!(geometry.data[15], 1);
    let request = |operation, sector, count| {
        block::Request {
            operation,
            sector,
            sectors: count,
        }
        .message()
    };
    assert_eq!(
        exchange(&request(block::READ, sectors, 1))?,
        block::response(block::OUT_OF_RANGE)
    );
    assert_eq!(
        exchange(&request(block::WRITE, u64::MAX, 1))?,
        block::response(block::OUT_OF_RANGE)
    );
    assert_eq!(
        exchange(&request(block::READ, 0, 9))?,
        block::response(block::BAD_REQUEST)
    );
    assert_eq!(
        exchange(&IpcMessage::default())?,
        block::response(block::BAD_REQUEST)
    );
    if geometry.data[14] == 1 {
        assert_eq!(
            exchange(&request(block::WRITE, 32, 8))?,
            block::response(block::READ_ONLY)
        );
        assert_eq!(
            exchange(&request(block::READ, 16, 8))?,
            block::response(block::OK)
        );
        super::write_line("rootsrv: read-only block device rejected writes");
        return Ok(());
    }
    // Sector 16 is seeded by the host. Read it before writing to verify that a
    // second guest sees bytes acknowledged and flushed by the previous guest.
    assert_eq!(
        exchange(&request(block::READ, 16, 8))?,
        block::response(block::OK)
    );
    // SAFETY: The preceding read completed into the live shared page.
    let tag = unsafe { core::ptr::read_volatile(BUFFER as *const u8) } ^ pattern(0);
    assert!([0, 0xa5].contains(&tag));
    for index in 0..4096 {
        // SAFETY: The supervisor owns a live shared frame of exactly 4096 bytes.
        let byte = unsafe { core::ptr::read_volatile((BUFFER as usize + index) as *const u8) };
        assert_eq!(byte, pattern(index) ^ tag);
    }
    super::write_line("rootsrv: block read verified seeded persistent data");
    for iteration in 0..20 {
        for index in 0..4096 {
            // SAFETY: No request is pending while the supervisor fills its frame.
            unsafe {
                core::ptr::write_volatile(
                    (BUFFER as usize + index) as *mut u8,
                    pattern(index) ^ iteration,
                )
            };
        }
        assert_eq!(
            exchange(&request(block::WRITE, 32, 8))?,
            block::response(block::OK)
        );
        assert_eq!(
            exchange(&request(block::READ, 32, 8))?,
            block::response(block::OK)
        );
        for index in 0..4096 {
            // SAFETY: The previous response transferred ownership back to us.
            assert_eq!(
                unsafe { core::ptr::read_volatile((BUFFER as usize + index) as *const u8) },
                pattern(index) ^ iteration
            );
        }
    }
    // Leave the reboot marker deterministic and explicitly persist it.
    for index in 0..4096 {
        // SAFETY: The shared frame is live and there is no pending request.
        unsafe {
            core::ptr::write_volatile(
                (BUFFER as usize + index) as *mut u8,
                pattern(index) ^ tag ^ 0xa5,
            )
        };
    }
    assert_eq!(
        exchange(&request(block::WRITE, 16, 8))?,
        block::response(block::OK)
    );
    assert_eq!(
        exchange(&request(block::FLUSH, 0, 0))?,
        block::response(block::OK)
    );
    super::write_line("rootsrv: block writes, reads, queue wrap and durable flush verified");
    Ok(())
}

#[cfg(feature = "qemu-block-test")]
fn pattern(index: usize) -> u8 {
    (index as u8).wrapping_mul(31).wrapping_add(17)
}

#[cfg(feature = "qemu-block-test")]
fn verify_restart() -> Result<(), ErrorCode> {
    const STALE: u8 = 9;
    const DMA_COPY: u8 = 10;
    const REPLACEMENT: u8 = 11;
    const OLD_MAPPING: u64 = 0x5700_0000;
    ruzt_ipc::send(
        slot(REQUEST),
        &IpcMessage {
            label: block::TEST_DELEGATE_DMA,
            ..IpcMessage::default()
        },
    )?;
    let mut delegated = IpcMessage::default();
    ruzt_ipc::recv_with_caps(slot(REPLY), &mut delegated, slot(DMA_COPY), 1)?;
    assert_eq!(
        (
            delegated.label,
            delegated.length,
            delegated.cap_count,
            delegated.data[0]
        ),
        (block::RESULT, 1, 1, block::OK)
    );
    ruzt_driver_sdk::map_dma_buffer(slot(DMA_COPY), OLD_MAPPING, false)?;
    ruzt_ipc::mint(slot(REQUEST), slot(STALE), CapRights::WRITE, 0)?;
    ruzt_ipc::send(
        slot(REQUEST),
        &IpcMessage {
            label: block::TEST_EXIT,
            ..IpcMessage::default()
        },
    )?;
    let status = ruzt_ipc::wait_process(slot(STATUS))?;
    assert_eq!(status.kind, ruzt_abi::PROCESS_EXITED);
    assert_eq!(status.code, 23);
    let read = block::Request {
        operation: block::READ,
        sector: 16,
        sectors: 8,
    }
    .message();
    assert_eq!(exchange(&read)?, block::response(block::OK));
    assert_eq!(
        ruzt_driver_sdk::map_dma_buffer(slot(DMA_COPY), OLD_MAPPING, false),
        Err(ErrorCode::InvalidCap)
    );
    ruzt_ipc::retype(ROOTSRV_UNTYPED, slot(REPLACEMENT), RetypeKind::Frame)?;
    ruzt_ipc::map_frame(slot(REPLACEMENT), OLD_MAPPING, true)?;
    ruzt_ipc::delete(slot(REPLACEMENT))?;
    assert_eq!(
        ruzt_ipc::send(slot(STALE), &IpcMessage::default()),
        Err(ErrorCode::NotFound)
    );
    ruzt_ipc::delete(slot(STALE))?;
    super::write_line(
        "rootsrv: block driver restart reclaimed DMA and memory and read persisted data",
    );
    let geometry = exchange(&IpcMessage {
        label: block::GEOMETRY,
        ..IpcMessage::default()
    })?;
    if geometry.data[14] == 0 {
        assert_eq!(
            exchange(&IpcMessage {
                label: block::TEST_EXIT_ON_WRITE,
                ..IpcMessage::default()
            })?,
            block::response(block::OK)
        );
        let write = block::Request {
            operation: block::WRITE,
            sector: 64,
            sectors: 8,
        }
        .message();
        assert_eq!(exchange(&write), Err(ErrorCode::NotFound));
        assert_eq!(exchange(&read)?, block::response(block::OK));
        super::write_line(
            "rootsrv: in-flight block write exit recovered without replaying the write",
        );
    }
    Ok(())
}

#[cfg(feature = "qemu-block-test")]
fn verify_reclaimed_budget() -> Result<(), ErrorCode> {
    for temporary in [7, 8] {
        ruzt_ipc::split_untyped(slot(MEMORY), slot(temporary), 20)?;
    }
    for temporary in [7, 8] {
        ruzt_ipc::delete(slot(temporary))?;
    }
    Ok(())
}
