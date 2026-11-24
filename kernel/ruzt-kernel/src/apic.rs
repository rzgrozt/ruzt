//! Discover and validate ACPI interrupt routing before replacing the PIC.

use alloc::vec::Vec;
use ruzt_abi::{ErrorCode, IRQ_ACTIVE_LOW, IRQ_LEVEL_TRIGGERED};
use ruzt_hal::boot::{BootInfo, FirmwareTables, MemoryRegionKind};
use ruzt_hal::mem::{PhysFrame, VirtAddr};
use ruzt_hal_x86_64::{
    apic::{Input, IoApic, LocalApic},
    irq::{self, CASCADE, ISA_IRQ_COUNT, KEYBOARD, TIMER},
    mapper, pic,
};
use spin::Once;

use crate::acpi;

const MADT_HEADER: usize = 44;
const PCAT_COMPATIBLE: u32 = 1;
const PAGE: u64 = PhysFrame::SIZE as u64;

static MMIO_PAGES: Once<Vec<u64>> = Once::new();
static TOPOLOGY: Once<Topology> = Once::new();

#[derive(Debug, PartialEq, Eq)]
enum Error {
    Firmware(acpi::Error),
    InvalidTable,
    UnusableController,
    NoMemory,
}

#[derive(Clone, Copy)]
struct Descriptor {
    id: u8,
    base: u64,
    first_gsi: u32,
}

struct Madt {
    local: u64,
    pcat_compatible: bool,
    processors: [bool; 255],
    controllers: Vec<Descriptor>,
    overrides: [Option<Route>; ISA_IRQ_COUNT],
    nmi: Vec<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Route {
    gsi: u32,
    low: bool,
    level: bool,
}

impl Route {
    fn parse(gsi: u32, flags: u16) -> Result<Self, Error> {
        let polarity = flags & 3;
        let trigger = (flags >> 2) & 3;
        if flags & !0xf != 0 || polarity == 2 || trigger == 2 {
            return Err(Error::InvalidTable);
        }
        Ok(Self {
            gsi,
            low: polarity == 3,
            level: trigger == 3,
        })
    }
}

impl Madt {
    fn parse(table: &[u8]) -> Result<Self, Error> {
        let header = table.get(..MADT_HEADER).ok_or(Error::InvalidTable)?;
        let mut result = Self {
            local: u64::from(dword(&header[36..])),
            pcat_compatible: dword(&header[40..]) & PCAT_COMPATIBLE != 0,
            processors: [false; 255],
            controllers: Vec::new(),
            overrides: [None; ISA_IRQ_COUNT],
            nmi: Vec::new(),
        };
        let mut override_local = false;
        let mut records = &table[MADT_HEADER..];
        while !records.is_empty() {
            let header = records.get(..2).ok_or(Error::InvalidTable)?;
            let size = usize::from(header[1]);
            let record = records
                .get(..size)
                .filter(|record| record.len() >= 2)
                .ok_or(Error::InvalidTable)?;
            records = &records[size..];
            match header[0] {
                0 if size == 8 => result.processor(u32::from(record[3]), dword(&record[4..]))?,
                1 if size == 12 => result.controller(record)?,
                2 if size == 10 && record[2] == 0 => {
                    let line = usize::from(record[3]);
                    let route = Route::parse(dword(&record[4..]), word(&record[8..]))?;
                    if line >= ISA_IRQ_COUNT
                        || line == CASCADE
                        || result.overrides[line].is_some()
                        || result
                            .overrides
                            .iter()
                            .flatten()
                            .any(|other| other.gsi == route.gsi)
                    {
                        return Err(Error::InvalidTable);
                    }
                    result.overrides[line] = Some(route);
                }
                3 if size == 8 => {
                    let route = Route::parse(dword(&record[4..]), word(&record[2..]))?;
                    result.nmi.try_reserve(1).map_err(|_| Error::NoMemory)?;
                    result.nmi.push(route.gsi);
                }
                5 if size == 12 && !override_local => {
                    override_local = true;
                    result.local = u64::from_le_bytes(record[4..12].try_into().unwrap());
                }
                9 if size == 16 => result.processor(dword(&record[4..]), dword(&record[8..]))?,
                0 | 1 | 2 | 3 | 5 | 9 => return Err(Error::InvalidTable),
                _ => {}
            }
        }
        if result.controllers.is_empty()
            || result
                .controllers
                .iter()
                .any(|controller| controller.base == result.local)
        {
            return Err(Error::UnusableController);
        }
        Ok(result)
    }

    fn processor(&mut self, id: u32, flags: u32) -> Result<(), Error> {
        if flags & 1 != 0 {
            if let Some(enabled) = self.processors.get_mut(id as usize) {
                if core::mem::replace(enabled, true) {
                    return Err(Error::InvalidTable);
                }
            }
        }
        Ok(())
    }

    fn controller(&mut self, record: &[u8]) -> Result<(), Error> {
        let id = record[2];
        let base = u64::from(dword(&record[4..]));
        if self
            .controllers
            .iter()
            .any(|unit| unit.id == id || unit.base == base)
        {
            return Err(Error::InvalidTable);
        }
        self.controllers
            .try_reserve(1)
            .map_err(|_| Error::NoMemory)?;
        self.controllers.push(Descriptor {
            id,
            base,
            first_gsi: dword(&record[8..]),
        });
        Ok(())
    }

    fn routes(&self) -> impl Iterator<Item = (usize, Route)> + '_ {
        (0..ISA_IRQ_COUNT).filter_map(|line| {
            if line == CASCADE {
                return None;
            }
            let route = match self.overrides[line] {
                Some(route) => route,
                None => {
                    let gsi = line as u32;
                    // A firmware override takes a pin away from its identity
                    // alias even when the legacy line numbers differ.
                    if self
                        .overrides
                        .iter()
                        .flatten()
                        .any(|other| other.gsi == gsi)
                    {
                        return None;
                    }
                    Route {
                        gsi,
                        low: false,
                        level: false,
                    }
                }
            };
            (!self.nmi.contains(&route.gsi)).then_some((line, route))
        })
    }
}

struct Controller {
    first: u32,
    end: u32,
    hardware: IoApic,
}

struct Topology {
    controllers: Vec<Controller>,
    overrides: [Option<Route>; ISA_IRQ_COUNT],
    nmi: Vec<u32>,
    cpus: CpuTopology,
}

pub(crate) struct CpuTopology {
    pub(crate) enabled: [bool; 255],
    pub(crate) bsp: u8,
    pub(crate) local_physical: u64,
    pub(crate) local_alias: Option<VirtAddr>,
}

pub(crate) fn cpu_topology() -> Option<&'static CpuTopology> {
    TOPOLOGY.get().map(|topology| &topology.cpus)
}

pub(crate) fn reserve_gsi(gsi: u32, flags: u64) -> Result<u32, ErrorCode> {
    if gsi < ISA_IRQ_COUNT as u32 || flags & !(IRQ_ACTIVE_LOW | IRQ_LEVEL_TRIGGERED) != 0 {
        return Err(ErrorCode::BadMessage);
    }
    let topology = TOPOLOGY.get().ok_or(ErrorCode::NotFound)?;
    if topology.nmi.contains(&gsi)
        || topology.overrides.iter().flatten().any(|route| route.gsi == gsi)
    {
        return Err(ErrorCode::BadMessage);
    }
    let route = Route {
        gsi,
        low: flags & IRQ_ACTIVE_LOW != 0,
        level: flags & IRQ_LEVEL_TRIGGERED != 0,
    };
    let input = find_input(&topology.controllers, route).ok_or(ErrorCode::NotFound)?;
    #[allow(unsafe_code)]
    // SAFETY: The syscall transaction serializes route changes with IF clear.
    // The validated topology identifies a unique non-ISA, non-NMI pin.
    let line = unsafe { irq::reserve_gsi(gsi, input) };
    line.map_err(crate::irq::hardware_error)
}

pub(crate) fn init(boot: &BootInfo) {
    match start(boot) {
        Ok(true) => {
            crate::serial_println!("Local APIC and I/O APIC interrupt routing enabled");
            return;
        }
        Ok(false) => {}
        Err(error) => crate::serial_println!("APIC interrupt routing unavailable ({error:?})"),
    }
    #[allow(unsafe_code)]
    // SAFETY: APIC discovery failed before changing delivery. This is the
    // boot CPU, with interrupts disabled and the legacy IDT installed.
    unsafe {
        pic::init()
    };
    crate::serial_println!("8259 PIC interrupt routing enabled");
}

pub(crate) fn overlaps_mmio(start: u64, end: u64) -> bool {
    MMIO_PAGES
        .get()
        .is_some_and(|pages| pages.iter().any(|&base| start < base + PAGE && base < end))
}

fn start(boot: &BootInfo) -> Result<bool, Error> {
    let FirmwareTables::Acpi { rsdp_addr } = boot.firmware_tables else {
        return Ok(false);
    };
    let firmware = acpi::Firmware::new(boot.memory_map);
    let Some(table) = firmware
        .find(rsdp_addr.as_u64(), *b"APIC")
        .map_err(Error::Firmware)?
    else {
        return Ok(false);
    };
    let madt = Madt::parse(&table)?;
    let (base, x2) = LocalApic::location().ok_or(Error::UnusableController)?;
    if base != madt.local {
        return Err(Error::UnusableController);
    }
    let mut pages = Vec::new();
    pages
        .try_reserve_exact(madt.controllers.len() + 1)
        .map_err(|_| Error::NoMemory)?;
    for base in core::iter::once(madt.local).chain(madt.controllers.iter().map(|unit| unit.base)) {
        if !valid_register_page(boot, base) {
            return Err(Error::UnusableController);
        }
        pages.push(base);
    }
    // These apertures are firmware-owned even if a later hardware check fails.
    MMIO_PAGES.call_once(|| pages);

    let local_alias = if x2 {
        None
    } else {
        Some(map_register_page(madt.local)?)
    };
    #[allow(unsafe_code)]
    // SAFETY: The alias is mapped uncached unless CPUID/MSR identified x2APIC.
    let local = unsafe { LocalApic::inspect(local_alias) }.ok_or(Error::UnusableController)?;
    if !madt.processors[usize::from(local.id())] {
        return Err(Error::UnusableController);
    }
    let controllers = inspect_controllers(&madt.controllers)?;
    let mut inputs = [None; ISA_IRQ_COUNT];
    for (line, route) in madt.routes() {
        inputs[line] = find_input(&controllers, route);
        if inputs[line].is_none() && madt.overrides[line].is_some() {
            return Err(Error::UnusableController);
        }
    }
    if inputs[TIMER].is_none() || inputs[KEYBOARD].is_none() {
        return Err(Error::UnusableController);
    }

    let bsp = local.id();
    let remapping = crate::iommu::prepare_ioapic_remapping(
        controllers.iter().map(|unit| unit.hardware.id()),
        x2,
    );
    let remapped = remapping.is_some();
    #[allow(unsafe_code)]
    // SAFETY: All controller mappings and routes were validated before
    // changing delivery. The matching gates are installed and IF is clear.
    unsafe {
        irq::install_apic(
            local,
            controllers.iter().map(|unit| unit.hardware),
            inputs,
            madt.pcat_compatible,
            remapping,
        )
    };
    if remapped {
        crate::serial_println!("VT-d I/O APIC interrupt remapping enabled");
    }
    TOPOLOGY.call_once(|| Topology {
        controllers,
        overrides: madt.overrides,
        nmi: madt.nmi,
        cpus: CpuTopology {
            enabled: madt.processors,
            bsp,
            local_physical: base,
            local_alias,
        },
    });
    Ok(true)
}

fn valid_register_page(boot: &BootInfo, base: u64) -> bool {
    base >= 0x10_0000
        && base < 1 << 52
        && base % PAGE == 0
        && !crate::iommu::overlaps_mmio(base, base + PAGE)
        && !boot.memory_map.iter().any(|region| {
            base < region.end.as_u64()
                && region.start.as_u64() < base + PAGE
                && !matches!(
                    region.kind,
                    MemoryRegionKind::Reserved | MemoryRegionKind::Mmio
                )
        })
}

fn map_register_page(base: u64) -> Result<VirtAddr, Error> {
    mapper::with_mapper(|mapper| {
        let alias = mapper
            .physmap_alias(base, PAGE)
            .ok_or(Error::UnusableController)?;
        #[allow(unsafe_code)]
        // SAFETY: The caller validated this firmware-owned register page.
        // No device mappings exist this early in boot.
        unsafe { mapper.make_device_physmap_uncached(base, PAGE) }
            .map_err(|_| Error::UnusableController)?;
        Ok(alias)
    })
}

fn inspect_controllers(descriptors: &[Descriptor]) -> Result<Vec<Controller>, Error> {
    let mut controllers: Vec<Controller> = Vec::new();
    controllers
        .try_reserve_exact(descriptors.len())
        .map_err(|_| Error::NoMemory)?;
    for descriptor in descriptors {
        let alias = map_register_page(descriptor.base)?;
        #[allow(unsafe_code)]
        // SAFETY: The MADT identified the I/O APIC page, the alias is
        // uncached, and the boot CPU exclusively accesses its registers.
        let hardware =
            unsafe { IoApic::inspect(alias, descriptor.id) }.ok_or(Error::UnusableController)?;
        let first = descriptor.first_gsi;
        let end = first
            .checked_add(u32::from(hardware.pin_count()))
            .ok_or(Error::InvalidTable)?;
        if controllers
            .iter()
            .any(|unit| first < unit.end && unit.first < end)
        {
            return Err(Error::InvalidTable);
        }
        controllers.push(Controller {
            first,
            end,
            hardware,
        });
    }
    Ok(controllers)
}

fn find_input(units: &[Controller], route: Route) -> Option<Input> {
    let unit = units
        .iter()
        .find(|unit| (unit.first..unit.end).contains(&route.gsi))?;
    unit.hardware
        .input((route.gsi - unit.first) as u8, route.low, route.level)
}

fn word(bytes: &[u8]) -> u16 {
    u16::from_le_bytes(bytes[..2].try_into().unwrap())
}

fn dword(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes[..4].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> Vec<u8> {
        let mut table = alloc::vec![0; MADT_HEADER];
        table[36..40].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
        table[40] = 1;
        table.extend([0, 8, 1, 0, 1, 0, 0, 0]); // enabled BSP
        table.extend([1, 12, 3, 0, 0, 0, 0xc0, 0xfe, 0, 0, 0, 0]);
        table.extend([2, 10, 0, 0, 2, 0, 0, 0, 0, 0]); // IRQ0 on GSI2
        table.extend([2, 10, 0, 5, 10, 0, 0, 0, 15, 0]); // active-low level
        table.extend([3, 8, 0, 0, 9, 0, 0, 0]); // reserve GSI9 for NMI
        table
    }

    #[test]
    fn routes_isa_overrides_without_exposing_shared_pins() {
        let topology = Madt::parse(&table()).unwrap();
        assert!(topology.pcat_compatible && topology.processors[0]);
        let routes: Vec<_> = topology.routes().collect();
        assert_eq!(
            routes[0],
            (
                TIMER,
                Route {
                    gsi: 2,
                    low: false,
                    level: false
                }
            )
        );
        assert!(routes.contains(&(
            5,
            Route {
                gsi: 10,
                low: true,
                level: true
            }
        )));
        assert!(!routes.iter().any(|(line, _)| matches!(*line, 2 | 9 | 10)));
    }

    #[test]
    fn rejects_bad_record_lengths_and_duplicate_firmware_routes() {
        let mut truncated = table();
        truncated.pop();
        assert!(matches!(Madt::parse(&truncated), Err(Error::InvalidTable)));
        let mut duplicate = table();
        duplicate.extend([2, 10, 0, 7, 10, 0, 0, 0, 0, 0]);
        assert!(matches!(Madt::parse(&duplicate), Err(Error::InvalidTable)));
        assert_eq!(Route::parse(5, 2), Err(Error::InvalidTable));
        assert_eq!(Route::parse(5, 8), Err(Error::InvalidTable));
    }
}
