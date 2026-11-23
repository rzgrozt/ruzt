//! Default-deny PCI DMA translation.

use alloc::vec::Vec;
use ruzt_abi::PciAddress;
use ruzt_hal::boot::{BootInfo, FirmwareTables, MemoryRegionKind};
use ruzt_hal::mem::{PhysFrame, VirtAddr};
use ruzt_hal_x86_64::{mapper, vtd};
use spin::{Mutex, Once};

use crate::{acpi, mm::frame};

mod domain;
pub(crate) use domain::{bind, detach_revoked, detach_thread, unbind};

#[cfg(feature = "qemu-vtd-test")]
mod probe;

const DMAR_HEADER: usize = 48;
const INCLUDE_ALL: u8 = 1;
const DRHD: u16 = 0;
const RMRR: u16 = 1;
const ATSR: u16 = 2;
const SATC: u16 = 5;

#[derive(Debug, Eq, PartialEq)]
struct Remapper {
    base: u64,
    host_bits: u8,
    scope: Scope,
}

#[derive(Debug, Eq, PartialEq)]
enum Scope {
    All,
    Endpoints(Vec<PciAddress>),
}

impl Scope {
    fn covers(&self, address: PciAddress) -> bool {
        match self {
            Self::All => true,
            Self::Endpoints(endpoints) => endpoints.contains(&address),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum Error {
    Firmware(acpi::Error),
    BadDmar,
    UnsupportedTopology,
    BadRegisters,
    NoMemory,
    CacheMaintenance,
    Hardware(vtd::Error),
}

struct Controller {
    unit: vtd::Unit,
    root: PhysFrame,
    scope: Scope,
    host_bits: u8,
    domains: Mutex<domain::Domains>,
}

static CONTROLLER: Once<Controller> = Once::new();

pub(crate) fn init(boot: &BootInfo) {
    match start(boot) {
        Ok(Some(controller)) => {
            CONTROLLER.call_once(|| controller);
            crate::serial_println!("VT-d DMA translation enabled with an empty root table");
        }
        Ok(None) => {}
        Err(error) => crate::serial_println!("VT-d DMA translation unavailable: {error:?}"),
    }
}

#[cfg(feature = "qemu-vtd-test")]
pub(crate) fn verify_unassigned_device() {
    let controller = CONTROLLER
        .get()
        .expect("VT-d is required by the QEMU fixture");
    probe::verify(&controller.unit, &controller.scope)
        .expect("verify VT-d blocks an unassigned requester");
}

fn start(boot: &BootInfo) -> Result<Option<Controller>, Error> {
    let FirmwareTables::Acpi { rsdp_addr } = boot.firmware_tables else {
        return Ok(None);
    };
    let firmware = acpi::Firmware::new(boot.memory_map);
    let Some(dmar) = firmware
        .find(rsdp_addr.as_u64(), *b"DMAR")
        .map_err(Error::Firmware)?
    else {
        return Ok(None);
    };
    let remapper = parse_dmar(&dmar)?;
    let page = PhysFrame::SIZE as u64;
    let end = remapper.base + page;
    if boot.memory_map.iter().any(|region| {
        remapper.base < region.end.as_u64()
            && region.start.as_u64() < end
            && region.kind != MemoryRegionKind::Reserved
    }) {
        return Err(Error::BadRegisters);
    }
    let regs = mapper::with_mapper(|mapper| {
        let alias = mapper
            .physmap_alias(remapper.base, page)
            .ok_or(Error::BadRegisters)?;
        #[allow(unsafe_code)]
        // SAFETY: DMAR identifies this aligned MMIO page, and it overlaps
        // no allocatable memory or boot-owned data. No aliases have been issued.
        unsafe { mapper.make_device_physmap_uncached(remapper.base, page) }
            .map_err(|_| Error::BadRegisters)?;
        Ok(alias)
    })?;
    #[allow(unsafe_code)]
    // SAFETY: This boot-owned VT-d register page is mapped uncached.
    let unit = unsafe { vtd::Unit::inspect(regs) }.map_err(Error::Hardware)?;
    let root = frame::allocate().ok_or(Error::NoMemory)?;
    if root.base.as_u64() >= 1 << remapper.host_bits {
        frame::deallocate(root);
        return Err(Error::BadRegisters);
    }
    #[allow(unsafe_code)]
    // SAFETY: The allocator returned fresh direct-mapped RAM.
    unsafe {
        mapper::zero_frame(root)
    };
    if let Err(error) = frame_alias(root).and_then(|alias| publish(alias, unit.coherent())) {
        frame::deallocate(root);
        return Err(error);
    }
    #[allow(unsafe_code)]
    // SAFETY: Every root entry is empty, visible to hardware, and therefore
    // denies DMA. The allocator keeps the table even on a hardware timeout.
    unsafe { unit.enable(root) }.map_err(Error::Hardware)?;
    Ok(Some(Controller {
        unit,
        root,
        scope: remapper.scope,
        host_bits: remapper.host_bits,
        domains: Mutex::new(domain::Domains::new()),
    }))
}

fn frame_alias(frame: PhysFrame) -> Result<VirtAddr, Error> {
    mapper::with_mapper(|mapper| mapper.physmap_alias(frame.base.as_u64(), PhysFrame::SIZE as u64))
        .ok_or(Error::BadRegisters)
}

fn publish(alias: VirtAddr, coherent: bool) -> Result<(), Error> {
    if !coherent {
        flush_frame(alias)?;
    }
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    Ok(())
}

#[allow(unsafe_code)]
fn flush_frame(alias: VirtAddr) -> Result<(), Error> {
    let features = core::arch::x86_64::__cpuid(1);
    let line = ((features.ebx >> 8) & 0xff) as usize * 8;
    if features.edx & (1 << 19) == 0 || !line.is_power_of_two() || line > PhysFrame::SIZE {
        return Err(Error::CacheMaintenance);
    }
    for offset in (0..PhysFrame::SIZE).step_by(line) {
        // SAFETY: The address lies in the fresh frame and CPUID confirms CLFSH.
        unsafe {
            core::arch::asm!("clflush [{address}]", address = in(reg) alias.as_u64() + offset as u64,
                options(nostack, preserves_flags));
        }
    }
    Ok(())
}

fn parse_dmar(bytes: &[u8]) -> Result<Remapper, Error> {
    let host_bits = bytes
        .get(36)
        .copied()
        .and_then(|bits| bits.checked_add(1))
        .filter(|bits| (32..=52).contains(bits))
        .ok_or(Error::BadDmar)?;
    let mut structures = bytes.get(DMAR_HEADER..).ok_or(Error::BadDmar)?;
    let mut remapper = None;
    while !structures.is_empty() {
        let header = structures.get(..4).ok_or(Error::BadDmar)?;
        let kind = u16::from_le_bytes(header[..2].try_into().unwrap());
        let length = usize::from(u16::from_le_bytes(header[2..].try_into().unwrap()));
        if !(4..=structures.len()).contains(&length) {
            return Err(Error::BadDmar);
        }
        let structure = &structures[..length];
        match kind {
            DRHD => {
                if length < 16 {
                    return Err(Error::BadDmar);
                }
                let base = u64::from_le_bytes(structure[8..16].try_into().unwrap());
                // This backend supports one segment-zero remapping unit.
                if structure[4] & !INCLUDE_ALL != 0
                    || structure[5] != 0
                    || structure[6..8] != [0, 0]
                    || remapper.is_some()
                {
                    return Err(Error::UnsupportedTopology);
                }
                if base < 0x10_0000 || base >= 1 << host_bits || base % PhysFrame::SIZE as u64 != 0
                {
                    return Err(Error::BadRegisters);
                }
                let scope = parse_scope(structure[4], &structure[16..])?;
                remapper = Some(Remapper {
                    base,
                    host_bits,
                    scope,
                });
            }
            RMRR | ATSR | SATC => return Err(Error::UnsupportedTopology),
            _ => {}
        }
        structures = &structures[length..];
    }
    remapper.ok_or(Error::UnsupportedTopology)
}

fn parse_scope(flags: u8, mut entries: &[u8]) -> Result<Scope, Error> {
    let all = flags & INCLUDE_ALL != 0;
    let mut endpoints = Vec::new();
    while !entries.is_empty() {
        let header = entries.get(..6).ok_or(Error::BadDmar)?;
        let length = usize::from(header[1]);
        if length < 8 || length % 2 != 0 || length > entries.len() {
            return Err(Error::BadDmar);
        }
        match header[0] {
            1 if !all && length == 8 => {
                let address =
                    PciAddress::new(header[5], entries[6], entries[7]).ok_or(Error::BadDmar)?;
                if endpoints.contains(&address) {
                    return Err(Error::BadDmar);
                }
                endpoints.try_reserve(1).map_err(|_| Error::NoMemory)?;
                endpoints.push(address);
            }
            3 | 4 => {} // Interrupt-only scopes do not grant DMA coverage.
            _ => return Err(Error::UnsupportedTopology),
        }
        entries = &entries[length..];
    }
    if all {
        Ok(Scope::All)
    } else if endpoints.is_empty() {
        Err(Error::UnsupportedTopology)
    } else {
        Ok(Scope::Endpoints(endpoints))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_segment_zero_catch_all_and_rejects_unhandled_topologies() {
        let mut table = [0; DMAR_HEADER + 16 + 24];
        table[36] = 39;
        table[DMAR_HEADER + 2] = 16;
        table[DMAR_HEADER + 4] = 1;
        table[DMAR_HEADER + 8..DMAR_HEADER + 16].copy_from_slice(&0xfed9_0000u64.to_le_bytes());
        assert_eq!(
            parse_dmar(&table[..DMAR_HEADER + 16]),
            Ok(Remapper {
                base: 0xfed9_0000,
                host_bits: 40,
                scope: Scope::All,
            })
        );
        assert_eq!(parse_dmar(&table[..DMAR_HEADER + 15]), Err(Error::BadDmar));
        table[DMAR_HEADER + 16] = RMRR as u8;
        table[DMAR_HEADER + 18] = 24;
        assert_eq!(parse_dmar(&table), Err(Error::UnsupportedTopology));
        table[DMAR_HEADER + 4] = 0;
        assert_eq!(
            parse_dmar(&table[..DMAR_HEADER + 16]),
            Err(Error::UnsupportedTopology)
        );
    }

    #[test]
    fn records_direct_pci_requesters_from_scoped_units() {
        let entry = [1, 8, 0, 0, 0, 0, 3, 1];
        assert_eq!(
            parse_scope(0, &entry),
            Ok(Scope::Endpoints(alloc::vec![
                PciAddress::new(0, 3, 1).unwrap()
            ]))
        );
        assert_eq!(parse_scope(1, &entry), Err(Error::UnsupportedTopology));
        assert_eq!(parse_scope(0, &entry[..7]), Err(Error::BadDmar));
    }
}
