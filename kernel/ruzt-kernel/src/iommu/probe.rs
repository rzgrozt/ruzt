//! Test an unassigned device against the live remapping hardware.

use ruzt_abi::{ErrorCode, PciAddress};
use ruzt_hal::mem::PhysFrame;
use ruzt_hal_x86_64::{mapper, vtd};

const EDU_ID: u32 = 0x11e8_1234;
const DMA_SOURCE: usize = 0x80;
const DMA_DESTINATION: usize = 0x88;
const DMA_SIZE: usize = 0x90;
const DMA_COMMAND: usize = 0x98;
const DEVICE_BUFFER: u64 = 0x40000;

#[allow(unsafe_code)]
pub(super) fn verify(unit: &vtd::Unit, scope: &super::Scope) -> Result<(), ErrorCode> {
    let (address, registers) = locate_edu()?;
    if !scope.covers(address) {
        return Err(ErrorCode::InvalidCap);
    }
    let scratch = crate::mm::frame::allocate().ok_or(ErrorCode::NoMemory)?;
    let physical = scratch.base.as_u64();
    if physical >= 1 << 28 {
        crate::mm::frame::deallocate(scratch);
        return Err(ErrorCode::BadMessage);
    }
    // SAFETY: The frame is owned by this probe. EDU reads only its first
    // four bytes into its on-device buffer and cannot reach other RAM.
    unsafe { mapper::zero_frame(scratch) };
    let _ = unit.take_fault(address.bits(), physical);
    // SAFETY: The EDU function is still exclusively held by the boot probe,
    // and the live remapper denies all transactions from this requester.
    unsafe {
        ruzt_hal_x86_64::pci::set_bus_master(address.bits(), true);
        write(registers, DMA_SOURCE, physical);
        write(registers, DMA_DESTINATION, DEVICE_BUFFER);
        write(registers, DMA_SIZE, 4);
        write(registers, DMA_COMMAND, 1);
    }
    let completed = wait_for_dma(registers);
    // SAFETY: The probe owns both PCI configuration and the device aperture.
    unsafe { ruzt_hal_x86_64::pci::set_bus_master(address.bits(), false) };
    crate::mm::frame::deallocate(scratch);
    if !completed {
        return Err(ErrorCode::TimedOut);
    }
    if !unit.take_fault(address.bits(), physical) {
        return Err(ErrorCode::BadMessage);
    }
    crate::serial_println!("VT-d rejected an unassigned EDU DMA request");
    Ok(())
}

fn locate_edu() -> Result<(PciAddress, u64), ErrorCode> {
    for slot in 0..32 {
        let address = PciAddress::new(0, slot, 0).unwrap();
        if crate::pci::read_config(address, 0)? != EDU_ID {
            continue;
        }
        let (bars, _) = crate::pci::probe(address)?;
        crate::pci::prepare_physmap(&bars)?;
        let bar = bars[0].ok_or(ErrorCode::NotFound)?;
        if bar.bytes < PhysFrame::SIZE as u64 {
            return Err(ErrorCode::BadMessage);
        }
        let alias =
            mapper::with_mapper(|mapper| mapper.physmap_alias(bar.base, PhysFrame::SIZE as u64))
                .ok_or(ErrorCode::NotFound)?;
        return Ok((address, alias.as_u64()));
    }
    Err(ErrorCode::NotFound)
}

#[allow(unsafe_code)]
fn wait_for_dma(registers: u64) -> bool {
    // The QEMU fixture's device uses a virtual 100 ms DMA timer. Bound the
    // probe even on a device that stops responding before interrupts start.
    // SAFETY: RDTSC is available on every supported QEMU x86-64 CPU.
    let limit = unsafe { core::arch::x86_64::_rdtsc() }.wrapping_add(6_000_000_000);
    loop {
        // SAFETY: This is the validated qword-aligned EDU command register.
        let command =
            unsafe { core::ptr::read_volatile((registers as usize + DMA_COMMAND) as *const u64) };
        if command & 1 == 0 {
            return true;
        }
        if unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(limit) < 1 << 63 {
            return false;
        }
        core::hint::spin_loop();
    }
}

#[allow(unsafe_code)]
unsafe fn write(registers: u64, offset: usize, word: u64) {
    // SAFETY: The caller owns the mapped EDU window and selects a valid
    // qword DMA register.
    unsafe { core::ptr::write_volatile((registers as usize + offset) as *mut u64, word) };
}
