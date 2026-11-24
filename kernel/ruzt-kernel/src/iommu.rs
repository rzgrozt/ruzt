//! Default-deny PCI DMA translation.

use alloc::vec::Vec;
use ruzt_abi::PciAddress;
use ruzt_hal::boot::{BootInfo, FirmwareTables, MemoryRegionKind};
use ruzt_hal::mem::{PhysFrame, VirtAddr};
use ruzt_hal_x86_64::{irq::IoApicRemapping, mapper, vtd};
use spin::{Mutex, Once};

use crate::{acpi, mm::frame};

mod domain;
pub(crate) use domain::{bind, detach_revoked, detach_thread, unbind};

#[cfg(feature = "qemu-vtd-test")]
mod probe;

const DMAR_HEADER: usize = 48;
const INTERRUPT_REMAP: u8 = 1;
const X2APIC_OPT_OUT: u8 = 1 << 1;
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
    interrupts: Option<InterruptTopology>,
}

#[derive(Debug, Eq, PartialEq)]
struct InterruptTopology {
    x2apic_opt_out: bool,
    ioapics: [Option<u16>; 256],
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
    Hardware(vtd::Error),
}

struct Controller {
    unit: vtd::Unit,
    root: PhysFrame,
    scope: Scope,
    interrupts: Option<InterruptTopology>,
    host_bits: u8,
    domains: Mutex<domain::Domains>,
}

impl Controller {
    fn protects_requester(&self, address: PciAddress) -> bool {
        address.bits() >> 8 == 0 && self.scope.covers(address) && self.unit.can_drain()
    }
}

static CONTROLLER: Once<Controller> = Once::new();
static MMIO_PAGE: Once<u64> = Once::new();
static INTERRUPT_TABLE: Once<vtd::InterruptTable> = Once::new();

pub(crate) fn overlaps_mmio(start: u64, end: u64) -> bool {
    MMIO_PAGE
        .get()
        .is_some_and(|&base| start < base + PhysFrame::SIZE as u64 && base < end)
}

/// Whether an unassigned requester is covered by active default-deny DMA.
pub(crate) fn permits_pci_handoff(address: PciAddress) -> bool {
    // Successful translation enable drained pre-remapping requests on this
    // unit. A function without a device lease has no live DMA context.
    CONTROLLER
        .get()
        .is_some_and(|controller| controller.protects_requester(address))
}

pub(crate) fn prepare_ioapic_remapping(
    ioapic_ids: impl IntoIterator<Item = u8>,
    x2apic: bool,
) -> Option<IoApicRemapping> {
    let controller = CONTROLLER.get()?;
    let firmware = controller.interrupts.as_ref()?;
    if (x2apic && firmware.x2apic_opt_out)
        || !controller.unit.supports_interrupt_remapping(x2apic)
        || ioapic_ids
            .into_iter()
            .any(|id| firmware.ioapics[usize::from(id)].is_none())
    {
        return None;
    }
    let table = match INTERRUPT_TABLE.try_call_once(|| allocate_interrupt_table(controller, x2apic))
    {
        Ok(table) => table,
        Err(error) => {
            crate::serial_println!("VT-d interrupt table unavailable: {error:?}");
            return None;
        }
    };
    Some(IoApicRemapping {
        table,
        sources: &firmware.ioapics,
    })
}

fn allocate_interrupt_table(
    controller: &'static Controller,
    x2apic: bool,
) -> Result<vtd::InterruptTable, Error> {
    let frame = frame::allocate().ok_or(Error::NoMemory)?;
    let alias = frame_alias(frame);
    match alias {
        #[allow(unsafe_code)]
        Ok(alias) if frame.base.as_u64() < 1 << controller.host_bits => {
            // SAFETY: The allocator owns this frame and the physmap covers
            // it. It stays pinned after allocation even if activation fails.
            Ok(unsafe {
                mapper::zero_frame(frame);
                vtd::InterruptTable::new(&controller.unit, frame, alias, x2apic)
            })
        }
        _ => {
            frame::deallocate(frame);
            Err(Error::BadRegisters)
        }
    }
}

pub(crate) fn init(boot: &BootInfo) {
    match start(boot) {
        Ok(Some(controller)) => {
            let queued = controller.unit.uses_queued_invalidation();
            CONTROLLER.call_once(|| controller);
            if queued {
                crate::serial_println!("VT-d queued invalidation enabled");
            }
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
    // Global DMA invalidation submits three descriptors. Exercise wraparound
    // of the 256-entry ring before the guest starts binding DMA buffers.
    if controller.unit.uses_queued_invalidation() {
        for _ in 0..86 {
            controller
                .unit
                .invalidate_all()
                .expect("wrap the VT-d queue");
        }
    }
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
            && !matches!(
                region.kind,
                MemoryRegionKind::Reserved | MemoryRegionKind::Mmio
            )
    }) {
        return Err(Error::BadRegisters);
    }
    // Keep the remapping aperture private even if initialization fails later.
    MMIO_PAGE.call_once(|| remapper.base);
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
    let mut unit = unsafe { vtd::Unit::inspect(regs) }.map_err(Error::Hardware)?;
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
    if let Err(error) = frame_alias(root).and_then(|alias| publish(alias, &unit)) {
        frame::deallocate(root);
        return Err(error);
    }
    let queue = if unit.supports_queued_invalidation() {
        match allocate_queue(remapper.host_bits) {
            Ok(memory) => Some(memory),
            Err(error) => {
                frame::deallocate(root);
                return Err(error);
            }
        }
    } else {
        None
    };
    #[allow(unsafe_code)]
    // SAFETY: The visible root table is empty. The queue pages, if required,
    // are private and contiguous. All frames stay pinned on hardware failure.
    unsafe { unit.enable(root, queue) }.map_err(Error::Hardware)?;
    Ok(Some(Controller {
        unit,
        root,
        scope: remapper.scope,
        interrupts: remapper.interrupts,
        host_bits: remapper.host_bits,
        domains: Mutex::new(domain::Domains::new()),
    }))
}

fn allocate_queue(host_bits: u8) -> Result<(PhysFrame, VirtAddr), Error> {
    let pages = vtd::INVALIDATION_PAGES;
    let bytes = (pages * PhysFrame::SIZE) as u64;
    let base = frame::allocate_contiguous(pages).ok_or(Error::NoMemory)?;
    let start = base.base.as_u64();
    let alias = mapper::with_mapper(|mapper| mapper.physmap_alias(start, bytes))
        .filter(|_| start + bytes <= 1 << host_bits);
    let Some(alias) = alias else {
        frame::deallocate_contiguous(base, pages);
        return Err(Error::BadRegisters);
    };
    #[allow(unsafe_code)]
    // SAFETY: The allocator owns this contiguous range and the physmap covers it.
    unsafe {
        (alias.as_u64() as *mut u8).write_bytes(0, bytes as usize)
    };
    Ok((base, alias))
}

fn frame_alias(frame: PhysFrame) -> Result<VirtAddr, Error> {
    mapper::with_mapper(|mapper| mapper.physmap_alias(frame.base.as_u64(), PhysFrame::SIZE as u64))
        .ok_or(Error::BadRegisters)
}

#[allow(unsafe_code)]
fn publish(alias: VirtAddr, unit: &vtd::Unit) -> Result<(), Error> {
    // SAFETY: Only the allocator's private, aligned remapping pages reach here.
    unsafe { unit.publish_frame(alias) }.map_err(Error::Hardware)
}

fn parse_dmar(bytes: &[u8]) -> Result<Remapper, Error> {
    let host_bits = bytes
        .get(36)
        .copied()
        .and_then(|bits| bits.checked_add(1))
        .filter(|bits| (32..=52).contains(bits))
        .ok_or(Error::BadDmar)?;
    let mut structures = bytes.get(DMAR_HEADER..).ok_or(Error::BadDmar)?;
    let flags = bytes[37];
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
                let (scope, ioapics) = parse_scope(structure[4], &structure[16..])?;
                let interrupts = ioapics
                    .filter(|_| flags & INTERRUPT_REMAP != 0)
                    .map(|ioapics| InterruptTopology {
                        x2apic_opt_out: flags & X2APIC_OPT_OUT != 0,
                        ioapics,
                    });
                remapper = Some(Remapper {
                    base,
                    host_bits,
                    scope,
                    interrupts,
                });
            }
            RMRR | ATSR | SATC => return Err(Error::UnsupportedTopology),
            _ => {}
        }
        structures = &structures[length..];
    }
    remapper.ok_or(Error::UnsupportedTopology)
}

type IoApicSources = [Option<u16>; 256];

fn parse_scope(flags: u8, mut entries: &[u8]) -> Result<(Scope, Option<IoApicSources>), Error> {
    let all = flags & INCLUDE_ALL != 0;
    let mut endpoints = Vec::new();
    let mut ioapics = [None; 256];
    let mut complete = true;
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
            3 if length == 8 => {
                let id = usize::from(header[4]);
                let source = PciAddress::new(header[5], entries[6], entries[7])
                    .ok_or(Error::BadDmar)?
                    .bits();
                if ioapics[id].is_some() || ioapics.contains(&Some(source)) {
                    return Err(Error::BadDmar);
                }
                ioapics[id] = Some(source);
            }
            3 => complete = false, // Resolving a bridged requester requires PCI topology.
            4 => {}                // HPET is unused.
            _ => return Err(Error::UnsupportedTopology),
        }
        entries = &entries[length..];
    }
    if endpoints
        .iter()
        .any(|address| ioapics.contains(&Some(address.bits())))
    {
        return Err(Error::BadDmar);
    }
    let scope = if all {
        Scope::All
    } else if endpoints.is_empty() {
        return Err(Error::UnsupportedTopology);
    } else {
        Scope::Endpoints(endpoints)
    };
    Ok((scope, complete.then_some(ioapics)))
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
                interrupts: None,
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
            parse_scope(0, &entry).map(|(scope, _)| scope),
            Ok(Scope::Endpoints(alloc::vec![
                PciAddress::new(0, 3, 1).unwrap()
            ]))
        );
        assert_eq!(parse_scope(1, &entry), Err(Error::UnsupportedTopology));
        assert_eq!(parse_scope(0, &entry[..7]), Err(Error::BadDmar));
    }

    #[test]
    fn keeps_ioapic_requester_ids_separate_from_dma_coverage() {
        let endpoint = [1, 8, 0, 0, 0, 0, 3, 1];
        let ioapic = [3, 8, 0, 0, 2, 0xff, 0, 0];
        let (dma, sources) = parse_scope(0, &[endpoint, ioapic].concat()).unwrap();
        assert!(dma.covers(PciAddress::new(0, 3, 1).unwrap()));
        assert!(!dma.covers(PciAddress::new(0xff, 0, 0).unwrap()));
        assert_eq!(sources.unwrap()[2], Some(0xff00));
        assert_eq!(
            parse_scope(INCLUDE_ALL, &[ioapic, ioapic].concat()),
            Err(Error::BadDmar)
        );
        let bridged = [3, 10, 0, 0, 2, 0, 3, 0, 4, 0];
        assert_eq!(parse_scope(INCLUDE_ALL, &bridged), Ok((Scope::All, None)));
        let alias = [3, 8, 0, 0, 2, 0, 3, 1];
        assert_eq!(
            parse_scope(0, &[endpoint, alias].concat()),
            Err(Error::BadDmar)
        );
    }
}
