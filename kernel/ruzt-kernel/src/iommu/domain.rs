//! Legacy VT-d context and second-stage page tables for PCI DMA leases.

use alloc::vec::Vec;
use ruzt_abi::{ErrorCode, PciAddress, DMA_IOVA_BASE};
use ruzt_hal::mem::{PhysFrame, VirtAddr};
use ruzt_hal_x86_64::{mapper, pci, vtd};

use super::{frame_alias, publish, Controller, CONTROLLER};
use crate::cap::{
    cspace::CapabilityPath,
    object::{DmaPin, PciPin},
};
use crate::{mm::frame, sched::ThreadId};

const PAGE_BYTES: usize = PhysFrame::SIZE;
const TABLE_ENTRIES: usize = PAGE_BYTES / size_of::<u64>();
const DIRECTORY_SPAN: usize = PAGE_BYTES * TABLE_ENTRIES;
const PRESENT: u64 = 1;
const READ_WRITE: u64 = 3;
const SNOOP: u64 = 1 << 11;

type DeviceAuthority = (CapabilityPath, PciPin);
type BufferAuthority = (CapabilityPath, DmaPin);

struct TablePage {
    frame: PhysFrame,
    alias: VirtAddr,
}

impl TablePage {
    fn allocate(host_bits: u8) -> Result<Self, ErrorCode> {
        let frame = frame::allocate().ok_or(ErrorCode::NoMemory)?;
        if frame.base.as_u64() >= 1 << host_bits {
            frame::deallocate(frame);
            return Err(ErrorCode::NoMemory);
        }
        let Ok(alias) = frame_alias(frame) else {
            frame::deallocate(frame);
            return Err(ErrorCode::NoMemory);
        };
        #[allow(unsafe_code)]
        // SAFETY: This page is freshly allocated and privately owned.
        unsafe {
            mapper::zero_frame(frame)
        };
        Ok(Self { frame, alias })
    }

    fn physical(&self) -> u64 {
        self.frame.base.as_u64()
    }

    fn store(&self, index: usize, value: u64) {
        store(self.alias, index, value);
    }
}

impl Drop for TablePage {
    fn drop(&mut self) {
        // A page is dropped before publication or after successful context
        // removal and IOTLB drain. Published bus context pages stay allocated.
        #[allow(unsafe_code)]
        // SAFETY: No remapping walk can reach the frame and it is still owned.
        unsafe {
            mapper::zero_frame(self.frame)
        };
        frame::deallocate(self.frame);
    }
}

#[allow(unsafe_code)]
fn store(alias: VirtAddr, index: usize, value: u64) {
    assert!(index < TABLE_ENTRIES);
    let address = alias.as_u64() + (index * size_of::<u64>()) as u64;
    // SAFETY: The index is within a live translation table; all CPU writers
    // serialize under the domain lock. Hardware may concurrently read it.
    unsafe { core::ptr::write_volatile(address as *mut u64, value) };
}

fn publish_table(alias: VirtAddr, unit: &vtd::Unit) -> Result<(), ErrorCode> {
    publish(alias, unit).map_err(|_| ErrorCode::NotImplemented)
}

struct Translation {
    tables: Vec<TablePage>,
    levels: u8,
}

impl Translation {
    fn new(controller: &Controller, buffer: &DmaPin, permissions: u64) -> Result<Self, ErrorCode> {
        let levels = controller
            .unit
            .page_table_levels()
            .ok_or(ErrorCode::NotImplemented)?;
        let directories = usize::from(levels - 1);
        let size = buffer.pages * PAGE_BYTES;
        let base = buffer.base.base.as_u64();
        if base + size as u64 > 1 << controller.host_bits {
            return Err(ErrorCode::BadMessage);
        }
        const { assert!(DMA_IOVA_BASE as usize % DIRECTORY_SPAN == 0) };
        let start = DMA_IOVA_BASE as usize / DIRECTORY_SPAN;
        let count = size.div_ceil(DIRECTORY_SPAN);
        if start + count > TABLE_ENTRIES {
            return Err(ErrorCode::BadMessage);
        }
        let mut tables = Vec::new();
        tables
            .try_reserve_exact(directories + count)
            .map_err(|_| ErrorCode::NoMemory)?;
        for _ in 0..directories + count {
            tables.push(TablePage::allocate(controller.host_bits)?);
        }
        // The whole IOVA range lies in the same page directory. Entries
        // outside the contiguous buffer stay zero, including in its last PT.
        for parent in 1..directories {
            tables[parent].store(0, tables[parent - 1].physical() | READ_WRITE);
        }
        for (table, index) in tables[directories..].iter().zip(start..) {
            tables[0].store(index, table.physical() | READ_WRITE);
        }
        let flags = permissions
            | if controller.unit.snoop_control() {
                SNOOP
            } else {
                0
            };
        for page in 0..buffer.pages {
            let physical = base + (page * PAGE_BYTES) as u64;
            tables[directories + page / TABLE_ENTRIES]
                .store(page % TABLE_ENTRIES, physical | flags);
        }
        for page in &tables {
            publish_table(page.alias, &controller.unit)?;
        }
        Ok(Self { tables, levels })
    }

    fn root(&self) -> u64 {
        self.tables[usize::from(self.levels - 2)].physical()
    }
}

struct Binding {
    thread: ThreadId,
    device: DeviceAuthority,
    buffer: BufferAuthority,
    translation: Translation,
    id: u16,
    retiring: bool,
}

impl Binding {
    fn address(&self) -> PciAddress {
        self.device.1.address
    }

    fn revoked(&self) -> bool {
        self.retiring || !self.device.0.is_live() || !self.buffer.0.is_live()
    }

    fn context_index(&self) -> usize {
        usize::from(self.address().bits() as u8) * 2
    }

    fn retire(&mut self, context: &TablePage, unit: &vtd::Unit) -> Result<(), ErrorCode> {
        self.retiring = true;
        let disabled = bus_master(self.address(), false);
        let index = self.context_index();
        context.store(index, 0);
        publish_table(context.alias, unit)?;
        invalidate(unit)?;
        if !disabled {
            return Err(ErrorCode::NotFound);
        }
        Ok(())
    }
}

pub(super) struct Domains {
    // DMA assignments are currently limited to directly attached bus-zero
    // endpoints. The bus-zero root entry references this page permanently.
    context: Option<TablePage>,
    bindings: Vec<Binding>,
}

impl Domains {
    pub(super) const fn new() -> Self {
        Self {
            context: None,
            bindings: Vec::new(),
        }
    }

    fn retire(&mut self, unit: &vtd::Unit, index: usize) -> Result<(), ErrorCode> {
        self.bindings[index].retire(self.context.as_ref().expect("live VT-d context"), unit)?;
        self.bindings.swap_remove(index);
        Ok(())
    }
}

pub(crate) fn bind(
    thread: ThreadId,
    device: DeviceAuthority,
    buffer: BufferAuthority,
    permissions: u64,
) -> Result<(), ErrorCode> {
    let controller = CONTROLLER.get().ok_or(ErrorCode::NotImplemented)?;
    let address = device.1.address;
    if !controller.protects_requester(address) {
        return Err(ErrorCode::NotImplemented);
    }
    let mut domains = controller.domains.lock();
    if domains
        .bindings
        .iter()
        .any(|binding| binding.address() == address || binding.buffer.1.id == buffer.1.id)
    {
        return Err(ErrorCode::SlotOccupied);
    }
    let command = crate::pci::read_config(address, 4)?;
    if command == u32::MAX || command & (1 << 2) != 0 {
        return Err(ErrorCode::NotFound);
    }
    let id = (1..controller.unit.domain_count())
        .map(|id| id as u16)
        .find(|id| domains.bindings.iter().all(|binding| binding.id != *id))
        .ok_or(ErrorCode::NoMemory)?;
    let translation = Translation::new(controller, &buffer.1, permissions)?;
    domains
        .bindings
        .try_reserve(1)
        .map_err(|_| ErrorCode::NoMemory)?;
    if domains.context.is_none() {
        let context = TablePage::allocate(controller.host_bits)?;
        publish_table(context.alias, &controller.unit)?;
        let root = frame_alias(controller.root).map_err(|_| ErrorCode::NotImplemented)?;
        store(root, 0, context.physical() | PRESENT);
        domains.context = Some(context);
        publish_table(root, &controller.unit)?;
    }
    // Retain both device and buffer before publishing the present bit. If
    // removing the context later fails, all frames and the lease stay pinned.
    let binding = Binding {
        thread,
        device,
        buffer,
        translation,
        id,
        retiring: false,
    };
    let index = binding.context_index();
    let high = (u64::from(id) << 8) | u64::from(binding.translation.levels - 2);
    let low = binding.translation.root() | PRESENT;
    let active = domains.bindings.len();
    domains.bindings.push(binding);
    let context = domains
        .context
        .as_ref()
        .expect("installed VT-d context table");
    context.store(index + 1, high);
    context.store(index, low);
    let result = publish_table(context.alias, &controller.unit)
        .and_then(|()| invalidate(&controller.unit))
        .and_then(|()| {
            if bus_master(address, true) {
                Ok(())
            } else {
                Err(ErrorCode::NotFound)
            }
        });
    if result.is_err() {
        let _ = domains.retire(&controller.unit, active);
    }
    result
}

pub(crate) fn unbind(thread: ThreadId, address: PciAddress) -> Result<(), ErrorCode> {
    let controller = CONTROLLER.get().ok_or(ErrorCode::NotImplemented)?;
    let mut domains = controller.domains.lock();
    let index = domains
        .bindings
        .iter()
        .position(|binding| binding.thread == thread && binding.address() == address)
        .ok_or(ErrorCode::NotFound)?;
    domains.retire(&controller.unit, index)
}

pub(crate) fn detach_thread(thread: ThreadId) {
    detach_matching(|binding| binding.thread == thread);
}

pub(crate) fn detach_revoked() {
    detach_matching(Binding::revoked);
}

fn detach_matching(matches: impl Fn(&Binding) -> bool) {
    let Some(controller) = CONTROLLER.get() else {
        return;
    };
    let mut domains = controller.domains.lock();
    for index in (0..domains.bindings.len()).rev() {
        if matches(&domains.bindings[index]) {
            let address = domains.bindings[index].address();
            if let Err(error) = domains.retire(&controller.unit, index) {
                crate::serial_println!(
                    "DMA lease for PCI requester {:04x} remains pinned ({error:?})",
                    address.bits()
                );
            }
        }
    }
}

fn invalidate(unit: &vtd::Unit) -> Result<(), ErrorCode> {
    unit.invalidate_all().map_err(|error| match error {
        vtd::Error::TimedOut => ErrorCode::TimedOut,
        _ => ErrorCode::NotImplemented,
    })
}

#[allow(unsafe_code)]
fn bus_master(address: PciAddress, enabled: bool) -> bool {
    // SAFETY: The domain registry retains an exclusive function lease.
    // Bus mastering is enabled only after publishing and syncing translation.
    unsafe { pci::set_bus_master(address.bits(), enabled) }
}
