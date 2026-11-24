//! Kernel object table — every capability references a stable entry here.

use ruzt_abi::{ErrorCode, PciAddress, ProcessStatus, RetypeKind, MAX_CNODE_RADIX};
use ruzt_cap::{AddressSpaceId, CapType, EndpointId, FrameSize, NotificationId, ProcessId};
use ruzt_hal::mem::{PhysAddr, PhysFrame};
use ruzt_hal_x86_64::mapper::{self, UserPageFrames};
use ruzt_hal_x86_64::pci::MemoryBar;
use spin::Mutex;

use super::region::FreePages;
use crate::mm::frame;

/// Maximum number of kernel objects in the table.
pub(super) const MAX_OBJECTS: usize = 256;
const _: () = assert!(MAX_OBJECTS.is_power_of_two());

/// Opaque handle for a kernel object entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct KObjectId(pub u64);

/// A kernel object stored in the global table.
///
/// All variants are `Copy` so the table can be initialised with `[None; N]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelObject {
    /// Empty slot.
    Null,
    /// IPC endpoint. Waiters live in the scheduler.
    Endpoint {
        /// The process that owns the endpoint's lifetime has exited.
        closed: bool,
    },
    /// Async notification object.
    Notification {
        /// Whether a signal arrived while nobody was waiting.
        state: bool,
    },
    /// A live process or its persistent terminal status.
    Process {
        /// Set once, after the scheduler reaps the process.
        status: Option<ProcessStatus>,
    },
    /// Executable image from the trusted boot archive.
    Program {
        /// Display name for diagnostics.
        name: &'static str,
        /// Immutable executable bytes from the boot archive.
        image: &'static [u8],
    },
    /// Thread control block.
    Thread {
        /// Index into the scheduler's thread array.
        thread_id: usize,
    },
    /// Address space (page table root).
    AddressSpace {
        /// Physical frame holding the top-level page table.
        root_page_table: PhysFrame,
    },
    /// Physical frame.
    Frame {
        /// Physical frame backing this mapping.
        phys: PhysFrame,
    },
    /// Capability table node whose slots are managed by the derivation tree.
    CNode {
        /// Number of bits used to index into this node.
        radix_bits: u8,
    },
    /// Untyped physical memory.
    Untyped {
        /// Physical frame where the untyped region starts.
        phys: PhysFrame,
        /// Size of the region as a power-of-two exponent.
        size_bits: u8,
    },
    /// IRQ handler.
    Irq {
        /// Hardware IRQ line number.
        irq_num: u32,
    },
    /// An IRQ backed by one PCI MSI message.
    MsiIrq {
        /// Logical IRQ number.
        irq_num: u32,
        /// Keeps the exclusive PCI function leased through interrupt teardown.
        device: KObjectId,
    },
    /// An exclusive lease on a firmware-configured PCI function.
    PciDevice {
        /// PCI bus, device and function.
        address: PciAddress,
        /// Assignments validated against boot and other device resources.
        bars: crate::pci::Bars,
    },
    /// A page-aligned portion of a PCI memory BAR.
    Mmio {
        /// Holds the device lease even when the original device cap is deleted.
        device: KObjectId,
        /// Physical register range.
        range: MemoryBar,
    },
    /// Contiguous, page-aligned memory reserved from a user Untyped region.
    DmaBuffer {
        /// First frame of the allocation.
        base: PhysFrame,
        /// Number of consecutive frames.
        pages: usize,
    },
}

const INDEX_BITS: u32 = MAX_OBJECTS.trailing_zeros();
const INDEX_MASK: u64 = MAX_OBJECTS as u64 - 1;
const MAX_GENERATION: u64 = u64::MAX >> INDEX_BITS;

#[derive(Clone, Copy)]
struct UntypedAllocation {
    region: KObjectId,
    first: usize,
    count: usize,
}

struct Entry {
    generation: u64,
    object: Option<KernelObject>,
    references: usize,
    backing: Option<UntypedAllocation>,
    free_pages: Option<FreePages>,
}

impl Entry {
    const EMPTY: Self = Self {
        generation: 0,
        object: None,
        references: 0,
        backing: None,
        free_pages: None,
    };

    fn matches(&self, id: KObjectId) -> bool {
        self.generation == id.0 >> INDEX_BITS
    }

    fn take(&mut self) -> Option<(KernelObject, Option<UntypedAllocation>)> {
        let object = self.object.take()?;
        if let Some(pages) = self.free_pages.take() {
            assert!(pages.is_all_free(), "live pages retain the Untyped region");
        }
        Some((object, self.backing.take()))
    }
}

impl KObjectId {
    pub(super) fn index(self) -> usize {
        (self.0 & INDEX_MASK) as usize
    }
}

/// Global object table protected by a spinlock.
static TABLE: Mutex<[Entry; MAX_OBJECTS]> = Mutex::new([const { Entry::EMPTY }; MAX_OBJECTS]);

/// Initialise the object table and the kernel-only CSpace.
pub fn init() {
    super::cspace::init_kernel_cspace();
    #[cfg(test)]
    {
        let mut table = TABLE.lock();
        for entry in table.iter_mut() {
            if let Some((object, backing)) = entry.take() {
                // Host tests never reserve or retype actual physical RAM.
                assert!(backing.is_none());
                destroy(object, None);
            }
            entry.references = 0;
        }
    }
}

/// Allocate a kernel object and return its generation-qualified identity.
pub fn allocate(cap_type: CapType) -> Result<KObjectId, ErrorCode> {
    allocate_with(|| kernel_object_from_cap_type(cap_type))
}

pub(crate) fn allocate_program(
    name: &'static str,
    image: &'static [u8],
) -> Result<KObjectId, ErrorCode> {
    allocate_with(|| Ok(KernelObject::Program { name, image }))
}

pub(super) fn allocate_irq(irq_num: u32) -> Result<KObjectId, ErrorCode> {
    if !ruzt_hal_x86_64::irq::is_device_irq(irq_num) {
        return Err(ErrorCode::BadMessage);
    }
    let mut table = TABLE.lock();
    let object = KernelObject::Irq { irq_num };
    if table.iter().any(|entry| entry.object == Some(object)) {
        return Err(ErrorCode::SlotOccupied);
    }
    let id = vacant_id(&table[..])?;
    let entry = &mut table[id.index()];
    entry.object = Some(object);
    entry.generation += 1;
    Ok(id)
}

pub(super) fn allocate_gsi(gsi: u32, flags: u64) -> Result<(KObjectId, u32), ErrorCode> {
    let mut table = TABLE.lock();
    let id = vacant_id(&table[..])?;
    let irq_num = crate::apic::reserve_gsi(gsi, flags)?;
    let entry = &mut table[id.index()];
    entry.object = Some(KernelObject::Irq { irq_num });
    entry.generation += 1;
    Ok((id, irq_num))
}

pub(super) fn allocate_msi(device: KObjectId) -> Result<(KObjectId, u32), ErrorCode> {
    let mut table = TABLE.lock();
    if table.iter().any(|entry| {
        matches!(entry.object, Some(KernelObject::MsiIrq { device: live, .. }) if live == device)
    }) {
        return Err(ErrorCode::SlotOccupied);
    }
    let id = vacant_id(&table[..])?;
    let parent = &mut table[device.index()];
    if !parent.matches(device) {
        return Err(ErrorCode::InvalidCap);
    }
    let Some(KernelObject::PciDevice { address, .. }) = parent.object else {
        return Err(ErrorCode::InvalidCap);
    };
    let references = parent.references.checked_add(1).ok_or(ErrorCode::NoMemory)?;
    let irq_num = crate::irq::reserve_msi(address)?;
    parent.references = references;
    let entry = &mut table[id.index()];
    entry.object = Some(KernelObject::MsiIrq { irq_num, device });
    entry.generation += 1;
    Ok((id, irq_num))
}

pub(super) fn allocate_pci_device(address: PciAddress) -> Result<KObjectId, ErrorCode> {
    let mut table = TABLE.lock();
    if table.iter().any(|entry| {
        matches!(entry.object, Some(KernelObject::PciDevice { address: live, .. }) if live == address)
    }) {
        return Err(ErrorCode::SlotOccupied);
    }
    let id = vacant_id(&table[..])?;
    let bars = crate::pci::probe(address)?;
    for entry in table.iter() {
        if let Some(KernelObject::PciDevice { bars: claimed, .. }) = entry.object {
            if bars.iter().flatten().any(|bar| {
                claimed
                    .iter()
                    .flatten()
                    .any(|other| crate::pci::overlaps(*bar, *other))
            }) {
                return Err(ErrorCode::MappingExists);
            }
        }
    }
    crate::pci::prepare_physmap(&bars)?;
    let entry = &mut table[id.index()];
    entry.object = Some(KernelObject::PciDevice { address, bars });
    entry.generation += 1;
    Ok(id)
}

pub(super) fn allocate_mmio(
    device: KObjectId,
    bar: usize,
    first: u64,
    pages: u64,
) -> Result<KObjectId, ErrorCode> {
    let mut table = TABLE.lock();
    let id = vacant_id(&table[..])?;
    let parent = &mut table[device.index()];
    if !parent.matches(device) {
        return Err(ErrorCode::InvalidCap);
    }
    let Some(KernelObject::PciDevice { bars, .. }) = parent.object else {
        return Err(ErrorCode::InvalidCap);
    };
    let range = bar_subrange(
        bars.get(bar)
            .copied()
            .flatten()
            .ok_or(ErrorCode::NotFound)?,
        first,
        pages,
    )?;
    parent.references = parent
        .references
        .checked_add(1)
        .ok_or(ErrorCode::NoMemory)?;
    let entry = &mut table[id.index()];
    entry.object = Some(KernelObject::Mmio { device, range });
    entry.generation += 1;
    Ok(id)
}

fn bar_subrange(bar: MemoryBar, first: u64, pages: u64) -> Result<MemoryBar, ErrorCode> {
    let page = PhysFrame::SIZE as u64;
    let bar_pages = bar.bytes / page;
    if pages == 0 || first.checked_add(pages).is_none_or(|end| end > bar_pages) {
        return Err(ErrorCode::BadMessage);
    }
    Ok(MemoryBar {
        base: bar.base + first * page,
        bytes: pages * page,
    })
}

/// Register a descriptor for a user-owned page table root.
pub(crate) fn register_address_space(root: PhysFrame) -> Result<AddressSpaceId, ErrorCode> {
    allocate_with(|| {
        Ok(KernelObject::AddressSpace {
            root_page_table: root,
        })
    })
    .map(|id| AddressSpaceId(id.0))
}

const PAGE_BITS: u8 = PhysFrame::SIZE.trailing_zeros() as u8;
const MAX_UNTYPED_BITS: u8 = PAGE_BITS + 12;

fn frame_at(base: PhysFrame, index: usize) -> PhysFrame {
    let address = base.base.as_u64() + (index as u64 * PhysFrame::SIZE as u64);
    PhysFrame::from_base(PhysAddr::new(address)).expect("aligned Untyped page")
}

pub(super) fn allocate_untyped(size_bits: u8) -> Result<(KObjectId, CapType), ErrorCode> {
    if !(PAGE_BITS..=MAX_UNTYPED_BITS).contains(&size_bits) {
        return Err(ErrorCode::BadMessage);
    }
    let pages = 1 << (size_bits - PAGE_BITS);
    let free_pages = FreePages::new(pages)?;
    let mut table = TABLE.lock();
    let id = vacant_id(&table[..])?;
    let phys = frame::allocate_untyped(pages).ok_or(ErrorCode::NoMemory)?;
    let entry = &mut table[id.index()];
    entry.object = Some(KernelObject::Untyped { phys, size_bits });
    entry.free_pages = Some(free_pages);
    entry.generation += 1;
    Ok((id, CapType::Untyped { phys, size_bits }))
}

fn allocate_with(
    build: impl FnOnce() -> Result<KernelObject, ErrorCode>,
) -> Result<KObjectId, ErrorCode> {
    let mut table = TABLE.lock();
    let id = vacant_id(&table[..])?;
    let entry = &mut table[id.index()];
    entry.object = Some(build()?);
    entry.generation += 1;
    Ok(id)
}

fn vacant_id(table: &[Entry]) -> Result<KObjectId, ErrorCode> {
    table
        .iter()
        .enumerate()
        .find(|(_, entry)| entry.object.is_none() && entry.generation < MAX_GENERATION)
        .map(|(index, entry)| KObjectId(((entry.generation + 1) << INDEX_BITS) | index as u64))
        .ok_or(ErrorCode::NoMemory)
}

pub(super) fn retype(
    region: KObjectId,
    kind: RetypeKind,
    requested_size_bits: u64,
) -> Result<(KObjectId, CapType), ErrorCode> {
    let mut table = TABLE.lock();
    let id = vacant_id(&table[..])?;
    let parent = &mut table[region.index()];
    if !parent.matches(region) {
        return Err(ErrorCode::InvalidCap);
    }
    let Some(KernelObject::Untyped {
        phys,
        size_bits: parent_bits,
    }) = parent.object
    else {
        return Err(ErrorCode::InvalidCap);
    };
    let size_bits = match kind {
        RetypeKind::Untyped => {
            let bits = u8::try_from(requested_size_bits).map_err(|_| ErrorCode::BadMessage)?;
            if !(PAGE_BITS..parent_bits).contains(&bits) {
                return Err(ErrorCode::BadMessage);
            }
            bits
        }
        RetypeKind::DmaBuffer => {
            let bits = u8::try_from(requested_size_bits).map_err(|_| ErrorCode::BadMessage)?;
            if !(PAGE_BITS..=parent_bits).contains(&bits) {
                return Err(ErrorCode::BadMessage);
            }
            bits
        }
        RetypeKind::CNode if requested_size_bits <= u64::from(MAX_CNODE_RADIX) => PAGE_BITS,
        _ if requested_size_bits == 0 => PAGE_BITS,
        _ => return Err(ErrorCode::BadMessage),
    };
    let count = 1 << (size_bits - PAGE_BITS);
    let free_pages = if kind == RetypeKind::Untyped {
        Some(FreePages::new(count)?)
    } else {
        None
    };
    let references = parent
        .references
        .checked_add(1)
        .ok_or(ErrorCode::NoMemory)?;
    let first = parent
        .free_pages
        .as_mut()
        .expect("Untyped page map")
        .take(count)
        .ok_or(ErrorCode::NoMemory)?;
    let phys = frame_at(phys, first);
    let (object, cap_type) = match kind {
        RetypeKind::Frame => {
            // SAFETY: The page belongs to the region and has no live objects or aliases.
            unsafe { ruzt_hal_x86_64::mapper::zero_frame(phys) };
            (
                KernelObject::Frame { phys },
                CapType::Frame {
                    phys,
                    size: FrameSize::Size4K,
                },
            )
        }
        RetypeKind::DmaBuffer => {
            scrub_dma_buffer(phys, count);
            (
                KernelObject::DmaBuffer {
                    base: phys,
                    pages: count,
                },
                CapType::DmaBuffer(id.0),
            )
        }
        RetypeKind::Endpoint => (
            KernelObject::Endpoint { closed: false },
            CapType::Endpoint(EndpointId(id.0)),
        ),
        RetypeKind::Notification => (
            KernelObject::Notification { state: false },
            CapType::Notification(NotificationId(id.0)),
        ),
        RetypeKind::Untyped => (
            KernelObject::Untyped { phys, size_bits },
            CapType::Untyped { phys, size_bits },
        ),
        RetypeKind::CNode => {
            let radix_bits = requested_size_bits as u8;
            (
                KernelObject::CNode { radix_bits },
                CapType::CNode {
                    radix_bits,
                    ptr: id.0,
                },
            )
        }
    };
    parent.references = references;
    let entry = &mut table[id.index()];
    entry.object = Some(object);
    entry.free_pages = free_pages;
    // This reference keeps the whole parent extent reserved until the child
    // object, including any mappings through it, has been destroyed.
    entry.backing = Some(UntypedAllocation {
        region,
        first,
        count,
    });
    entry.generation += 1;
    Ok((id, cap_type))
}

/// Return the object identified by this live generation.
pub fn get(id: KObjectId) -> Option<KernelObject> {
    let table = TABLE.lock();
    let entry = &table[id.index()];
    if entry.matches(id) {
        entry.object
    } else {
        None
    }
}

pub(crate) fn close_endpoint(id: KObjectId) {
    update(id, |object| {
        if let KernelObject::Endpoint { closed } = object {
            *closed = true;
        }
    });
}

/// Remove a kernel object and release its storage.
pub fn deallocate(id: KObjectId) {
    let object = {
        let mut table = TABLE.lock();
        let entry = &mut table[id.index()];
        if entry.matches(id) && entry.references == 0 {
            entry.take()
        } else {
            None
        }
    };
    if let Some((object, backing)) = object {
        destroy(object, backing);
    }
}

pub(super) fn retain(id: KObjectId) -> Result<(), ErrorCode> {
    let mut table = TABLE.lock();
    let entry = &mut table[id.index()];
    if !entry.matches(id) || entry.object.is_none() {
        return Err(ErrorCode::InvalidCap);
    }
    entry.references = entry.references.checked_add(1).ok_or(ErrorCode::NoMemory)?;
    Ok(())
}

/// Release an object reference and report whether it was the last one.
pub(super) fn release(id: KObjectId) -> bool {
    let object = {
        let mut table = TABLE.lock();
        let entry = &mut table[id.index()];
        assert!(entry.matches(id) && entry.references != 0);
        entry.references -= 1;
        if entry.references == 0 {
            entry.take()
        } else {
            None
        }
    };
    if let Some((object, backing)) = object {
        destroy(object, backing);
        true
    } else {
        false
    }
}

/// Keeps mapped RAM alive until after its last page table alias is removed.
pub(crate) struct FramePin {
    id: KObjectId,
    pub(crate) phys: PhysFrame,
}

impl FramePin {
    pub(super) fn new(id: KObjectId) -> Result<Self, ErrorCode> {
        // The caller holds the derivation lock and already has a reference
        // through the live capability, so the object cannot disappear here.
        let Some(KernelObject::Frame { phys }) = get(id) else {
            return Err(ErrorCode::InvalidCap);
        };
        retain(id)?;
        Ok(Self { id, phys })
    }
}

impl Drop for FramePin {
    fn drop(&mut self) {
        release(self.id);
    }
}

/// Keeps a device lease alive until the last associated mapping is removed.
pub(crate) struct MmioPin {
    id: KObjectId,
    pub(crate) range: MemoryBar,
}

impl MmioPin {
    pub(super) fn new(id: KObjectId) -> Result<Self, ErrorCode> {
        let Some(KernelObject::Mmio { range, .. }) = get(id) else {
            return Err(ErrorCode::InvalidCap);
        };
        retain(id)?;
        Ok(Self { id, range })
    }
}

impl Drop for MmioPin {
    fn drop(&mut self) {
        release(self.id);
    }
}

pub(crate) struct DmaPin {
    pub(crate) id: KObjectId,
    pub(crate) base: PhysFrame,
    pub(crate) pages: usize,
}

impl DmaPin {
    pub(super) fn new(id: KObjectId) -> Result<Self, ErrorCode> {
        let Some(KernelObject::DmaBuffer { base, pages }) = get(id) else {
            return Err(ErrorCode::InvalidCap);
        };
        retain(id)?;
        Ok(Self { id, base, pages })
    }
}

impl Drop for DmaPin {
    fn drop(&mut self) {
        release(self.id);
    }
}

pub(crate) struct PciPin {
    id: KObjectId,
    pub(crate) address: PciAddress,
}

impl PciPin {
    pub(super) fn new(id: KObjectId) -> Result<Self, ErrorCode> {
        let Some(KernelObject::PciDevice { address, .. }) = get(id) else {
            return Err(ErrorCode::InvalidCap);
        };
        retain(id)?;
        Ok(Self { id, address })
    }
}

impl Drop for PciPin {
    fn drop(&mut self) {
        release(self.id);
    }
}

/// Keeps the Untyped allocator alive for every private page of an address space.
pub(crate) struct UntypedBudget(KObjectId);

impl UntypedBudget {
    pub(super) fn new(id: KObjectId) -> Result<Self, ErrorCode> {
        // The live CSpace node pins the object across the type check.
        if !matches!(get(id), Some(KernelObject::Untyped { .. })) {
            return Err(ErrorCode::InvalidCap);
        }
        retain(id)?;
        Ok(Self(id))
    }

    pub(crate) fn page_count(&self) -> usize {
        let Some(KernelObject::Untyped { size_bits, .. }) = get(self.0) else {
            unreachable!("budget retains its source Untyped object");
        };
        1 << (size_bits - PAGE_BITS)
    }
}

// SAFETY: The region owns exclusive allocator frames held under the object
// table lock. A released page is scrubbed before its bit becomes available.
unsafe impl UserPageFrames for UntypedBudget {
    fn allocate(&self) -> Option<PhysFrame> {
        let mut table = TABLE.lock();
        let entry = &mut table[self.0.index()];
        assert!(entry.matches(self.0));
        let Some(KernelObject::Untyped { phys, .. }) = entry.object else {
            unreachable!("budget retains its source Untyped object");
        };
        let page = entry
            .free_pages
            .as_mut()
            .expect("Untyped page map")
            .take(1)?;
        Some(frame_at(phys, page))
    }

    unsafe fn deallocate(&self, frame: PhysFrame) {
        let mut table = TABLE.lock();
        let entry = &mut table[self.0.index()];
        assert!(entry.matches(self.0));
        let Some(KernelObject::Untyped { phys, size_bits }) = entry.object else {
            unreachable!("budget retains its source Untyped object");
        };
        let offset = frame
            .base
            .as_u64()
            .checked_sub(phys.base.as_u64())
            .expect("frame belongs to its Untyped region");
        assert!(offset < 1 << size_bits && offset % PhysFrame::SIZE as u64 == 0);
        // SAFETY: The caller owns this page with no live mappings, and the
        // checked address is in the retained region.
        unsafe { mapper::zero_frame(frame) };
        entry
            .free_pages
            .as_mut()
            .expect("Untyped page map")
            .put((offset >> PAGE_BITS) as usize, 1);
    }
}

impl Drop for UntypedBudget {
    fn drop(&mut self) {
        release(self.0);
    }
}

/// Owns the process's reference while the kernel can still publish its status.
pub(crate) struct ProcessExitPublisher(KObjectId);

impl ProcessExitPublisher {
    pub(crate) fn new() -> Result<(ProcessId, Self), ErrorCode> {
        let id = allocate_with(|| Ok(KernelObject::Process { status: None }))?;
        if let Err(error) = retain(id) {
            deallocate(id);
            return Err(error);
        }
        Ok((ProcessId(id.0), Self(id)))
    }

    pub(crate) fn publish(self, status: ProcessStatus) {
        update(self.0, |object| {
            let KernelObject::Process { status: stored } = object else {
                unreachable!("exit publisher owns a process object");
            };
            assert!(stored.replace(status).is_none());
        });
        crate::sched::wake_process_waiters(self.0);
    }
}

impl Drop for ProcessExitPublisher {
    fn drop(&mut self) {
        release(self.0);
    }
}

fn destroy(object: KernelObject, backing: Option<UntypedAllocation>) {
    match object {
        KernelObject::Frame { phys } => {
            // SAFETY: The final reference is gone, including every mapping,
            // and the page is still reserved in the parent region.
            unsafe { ruzt_hal_x86_64::mapper::zero_frame(phys) };
        }
        KernelObject::DmaBuffer { base, pages } => scrub_dma_buffer(base, pages),
        KernelObject::Untyped { phys, size_bits } => {
            if backing.is_none() {
                frame::deallocate_contiguous(phys, 1 << (size_bits - PAGE_BITS));
            }
        }
        KernelObject::Irq { irq_num } => {
            crate::irq::release(irq_num);
        }
        KernelObject::MsiIrq { irq_num, device } => {
            if crate::irq::release(irq_num) {
                release(device);
            } else {
                crate::serial_println!("PCI device lease remains pinned after MSI teardown failed");
            }
        }
        KernelObject::Mmio { device, .. } => {
            release(device);
        }
        _ => {}
    }
    if let Some(allocation) = backing {
        {
            let mut table = TABLE.lock();
            let region = &mut table[allocation.region.index()];
            assert!(region.matches(allocation.region));
            region
                .free_pages
                .as_mut()
                .expect("Untyped page map")
                .put(allocation.first, allocation.count);
        }
        release(allocation.region);
    }
}

#[allow(unsafe_code)]
fn scrub_dma_buffer(base: PhysFrame, pages: usize) {
    for page in 0..pages {
        // SAFETY: These pages are reserved in their Untyped region and no
        // CPU mapping or active DMA binding can reference them at this point.
        unsafe { mapper::zero_frame(frame_at(base, page)) };
    }
}

/// Set the signal state of a live notification.
pub fn set_notification_state(id: KObjectId, new_state: bool) {
    update(id, |object| {
        if let KernelObject::Notification { state } = object {
            *state = new_state;
        }
    });
}

fn update(id: KObjectId, f: impl FnOnce(&mut KernelObject)) {
    let mut table = TABLE.lock();
    let entry = &mut table[id.index()];
    if entry.matches(id) {
        if let Some(object) = &mut entry.object {
            f(object);
        }
    }
}

/// Convert a [`CapType`] into the corresponding [`KernelObject`] variant.
fn kernel_object_from_cap_type(cap_type: CapType) -> Result<KernelObject, ErrorCode> {
    match cap_type {
        CapType::Null => Err(ErrorCode::InvalidCap),
        CapType::Endpoint(_) => Ok(KernelObject::Endpoint { closed: false }),
        CapType::Notification(_) => Ok(KernelObject::Notification { state: false }),
        CapType::Thread(thread_id) => Ok(KernelObject::Thread {
            thread_id: thread_id.0 as usize,
        }),
        CapType::AddressSpace(_) => Err(ErrorCode::InvalidCap),
        CapType::Frame { .. } | CapType::Untyped { .. } => Err(ErrorCode::InvalidCap),
        CapType::Process(_) | CapType::Program(_) => Err(ErrorCode::InvalidCap),
        #[cfg(test)]
        CapType::CNode { radix_bits, .. } => Ok(KernelObject::CNode { radix_bits }),
        #[cfg(not(test))]
        CapType::CNode { .. } => Err(ErrorCode::InvalidCap),
        CapType::Irq { .. } | CapType::IrqControl => Err(ErrorCode::InvalidCap),
        CapType::PciControl | CapType::PciDevice(_) | CapType::Mmio(_) | CapType::DmaBuffer(_) => {
            Err(ErrorCode::InvalidCap)
        }
        // Boot device capabilities are only provisioned at process creation.
        CapType::IoPort { .. } | CapType::Framebuffer => Err(ErrorCode::NotImplemented),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn deallocate_works() {
        let _state = crate::isolated_kernel_state();
        let id = allocate(CapType::Endpoint(EndpointId(0))).unwrap();
        assert!(get(id).is_some());
        deallocate(id);
        assert!(get(id).is_none());
    }

    #[test]
    fn stale_handle_cannot_read_or_change_a_reused_slot() {
        let _state = crate::isolated_kernel_state();
        let old = allocate(CapType::Endpoint(EndpointId(0))).unwrap();
        deallocate(old);
        let new = allocate(CapType::Endpoint(EndpointId(0))).unwrap();

        assert_eq!(old.index(), new.index());
        assert_ne!(old, new);
        assert_eq!(get(old), None);
        close_endpoint(old);
        deallocate(old);
        assert_eq!(get(new), Some(KernelObject::Endpoint { closed: false }));
    }

    #[test]
    fn allocate_endpoint() {
        let _state = crate::isolated_kernel_state();
        let id = allocate(CapType::Endpoint(EndpointId(0))).unwrap();
        let obj = get(id).unwrap();
        assert!(matches!(obj, KernelObject::Endpoint { closed: false }));
    }

    #[test]
    fn deallocate_endpoint() {
        let _state = crate::isolated_kernel_state();
        let id = allocate(CapType::Endpoint(EndpointId(0))).unwrap();
        deallocate(id);
        assert!(get(id).is_none());
    }

    #[test]
    fn allocate_notification() {
        let _state = crate::isolated_kernel_state();
        let id = allocate(CapType::Notification(NotificationId(0))).unwrap();
        let obj = get(id).unwrap();
        assert!(matches!(obj, KernelObject::Notification { state: false }));
    }

    #[test]
    fn allocate_null_fails() {
        let _state = crate::isolated_kernel_state();
        assert_eq!(allocate(CapType::Null), Err(ErrorCode::InvalidCap));
    }

    #[test]
    fn raw_descriptors_cannot_allocate_ram_objects() {
        let _state = crate::isolated_kernel_state();
        let phys = PhysFrame::from_base(PhysAddr::new(0x1000)).unwrap();
        assert_eq!(
            allocate(CapType::Frame {
                phys,
                size: FrameSize::Size4K
            }),
            Err(ErrorCode::InvalidCap)
        );
        assert_eq!(
            allocate(CapType::Untyped {
                phys,
                size_bits: 12
            }),
            Err(ErrorCode::InvalidCap)
        );
    }

    #[test]
    fn live_mmio_pin_keeps_the_pci_device_lease() {
        let _state = crate::isolated_kernel_state();
        let device = allocate_with(|| {
            let mut bars = [None; ruzt_hal_x86_64::pci::BAR_COUNT];
            bars[0] = Some(MemoryBar {
                base: 0xfea0_0000,
                bytes: 8192,
            });
            Ok(KernelObject::PciDevice {
                address: PciAddress::new(0, 4, 0).unwrap(),
                bars,
            })
        })
        .unwrap();
        assert_eq!(allocate_mmio(device, 0, 0, 0), Err(ErrorCode::BadMessage));
        assert_eq!(
            allocate_mmio(device, 0, u64::MAX, 2),
            Err(ErrorCode::BadMessage)
        );
        assert_eq!(allocate_mmio(device, 0, 1, 2), Err(ErrorCode::BadMessage));
        let mmio = allocate_mmio(device, 0, 1, 1).unwrap();
        let pin = MmioPin::new(mmio).unwrap();
        assert_eq!(
            pin.range,
            MemoryBar {
                base: 0xfea0_1000,
                bytes: 4096
            }
        );
        deallocate(device);
        deallocate(mmio);
        assert!(get(device).is_some());
        drop(pin);
        assert_eq!(get(mmio), None);
        assert_eq!(get(device), None);
    }

    #[test]
    fn allocate_and_deallocate_many() {
        let _state = crate::isolated_kernel_state();
        let mut ids = Vec::with_capacity(16);
        for _ in 0..16 {
            ids.push(allocate(CapType::Endpoint(EndpointId(0))).unwrap());
        }
        for id in ids {
            deallocate(id);
            assert!(get(id).is_none());
        }
    }
}
