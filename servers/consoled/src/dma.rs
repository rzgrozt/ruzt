//! DMA delegation check for the supervisor's QEMU EDU fixture.

use ruzt_abi::{console, ErrorCode, IpcMessage, FRAME_BYTES, PROCESS_ADDRESS_SPACE};
use ruzt_driver_sdk::{
    bind_dma, map_dma_buffer, map_mmio, unbind_dma, unmap_dma_buffer, MmioRegion, DMA_READ,
    DMA_WRITE,
};
use ruzt_runtime::syscall::{monotonic_ns, sleep_until};

const BUFFER_WINDOW: u64 = 0x6400_0000;
const SOURCE: u64 = 0x80;
const DESTINATION: u64 = 0x88;
const COUNT: u64 = 0x90;
const COMMAND: u64 = 0x98;
const START: u64 = 1;
const FROM_DEVICE: u64 = 2;
const EDU_BUFFER: u64 = 0x40000;

pub(super) fn check(request: &IpcMessage) -> Result<u64, ErrorCode> {
    let [device, buffer, bar, _] = request.caps.map(|cap| cap.cptr);
    let iova = match bind_dma(device, buffer, DMA_READ) {
        Ok(iova) => iova,
        Err(ErrorCode::NotImplemented) => {
            for cptr in [device, buffer, bar] {
                ruzt_ipc::delete(cptr).expect("discard unused DMA grant");
            }
            return Ok(console::DMA_UNAVAILABLE);
        }
        Err(error) => return Err(error),
    };
    assert_eq!(
        bind_dma(device, buffer, DMA_READ | DMA_WRITE),
        Err(ErrorCode::SlotOccupied)
    );
    map_dma_buffer(buffer, BUFFER_WINDOW, true)?;
    // SAFETY: Deliberately exercise syscall buffer validation. This mapping
    // may change independently of the CPU, so the syscall must reject it.
    let status = unsafe {
        ruzt_runtime::syscall::syscall(
            ruzt_abi::SyscallNumber::MonotonicTime,
            BUFFER_WINDOW,
            0,
            0,
            0,
            0,
            0,
        )
    };
    assert_eq!(ErrorCode::from_u64(status), Err(ErrorCode::BadMessage));
    let registers = map_mmio(bar, super::DEVICE_WINDOW, true)?;
    let source = BUFFER_WINDOW as *mut u64;
    let destination = (BUFFER_WINDOW + FRAME_BYTES as u64) as *const u64;
    let payload = 0x0123_4567_89ab_cdef;
    // SAFETY: The supervisor keeps both mappings alive until the reply.
    // Only the driver writes the source and the destination stays idle.
    unsafe {
        assert_eq!(registers.read_u32(0)? & 0xffff, 0x00ed);
        source.write_volatile(payload);
        assert_eq!(destination.read_volatile(), 0);
    }
    transfer(&registers, iova, EDU_BUFFER, 0)?;
    transfer(
        &registers,
        EDU_BUFFER,
        iova + FRAME_BYTES as u64,
        FROM_DEVICE,
    )?;
    // SAFETY: The device request finished. Its read-only DMA lease cannot
    // write the destination, which remains mapped for the CPU.
    assert_eq!(unsafe { destination.read_volatile() }, 0);
    unbind_dma(device)?;
    assert_eq!(bind_dma(device, buffer, DMA_WRITE)?, iova);
    transfer(
        &registers,
        EDU_BUFFER,
        iova + FRAME_BYTES as u64,
        FROM_DEVICE,
    )?;
    // SAFETY: The command finished and the destination page is still mapped.
    assert_eq!(unsafe { destination.read_volatile() }, payload);
    // Keep the binding and CPU mapping live for the supervisor's revoke.
    Ok(console::DMA_CHECKED)
}

pub(super) fn check_revoked() -> Result<(), ErrorCode> {
    let buffer = console::RECEIVED_FRAME;
    assert_eq!(unmap_dma_buffer(buffer), Err(ErrorCode::InvalidCap));
    assert_eq!(
        unbind_dma(console::RECEIVED_NOTIFICATION),
        Err(ErrorCode::NotFound)
    );
    ruzt_ipc::map_anonymous(PROCESS_ADDRESS_SPACE, BUFFER_WINDOW, 2, true)?;
    ruzt_ipc::unmap_anonymous(PROCESS_ADDRESS_SPACE, BUFFER_WINDOW, 2)?;
    ruzt_ipc::delete(console::RECEIVED_UNTYPED)?;
    ruzt_ipc::delete(console::RECEIVED_NOTIFICATION)
}

fn transfer(
    registers: &MmioRegion,
    source: u64,
    destination: u64,
    direction: u64,
) -> Result<(), ErrorCode> {
    // SAFETY: The live window was identified as EDU. One operand is in its
    // on-device buffer and the other lies in the direction-checked DMA lease.
    unsafe {
        registers.write_u64(SOURCE, source)?;
        registers.write_u64(DESTINATION, destination)?;
        registers.write_u64(COUNT, size_of::<u64>() as u64)?;
        registers.write_u64(COMMAND, START | direction)?;
    }
    let deadline = monotonic_ns()?.saturating_add(1_000_000_000);
    loop {
        // SAFETY: The supervisor retains the EDU grant through the reply.
        if unsafe { registers.read_u64(COMMAND)? } & START == 0 {
            return Ok(());
        }
        let now = monotonic_ns()?;
        if now >= deadline {
            return Err(ErrorCode::TimedOut);
        }
        sleep_until(now.saturating_add(1_000_000).min(deadline))?;
    }
}
