//! Kernel object table — every capability references a stable entry here.

use alloc::vec::Vec;
use ruzt_abi::{ErrorCode, ProcessStatus, RetypeKind};
use ruzt_cap::{CapType, EndpointId, FrameSize, NotificationId, ProcessId, NULL_SLOT};
use ruzt_hal::mem::{PhysAddr, PhysFrame};
use spin::Mutex;

use crate::mm::frame;

/// Maximum number of kernel objects in the table.
const MAX_OBJECTS: usize = 256;
const _: () = assert!(MAX_OBJECTS.is_power_of_two());

/// Opaque handle for a kernel object entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct KObjectId(pub u64);

/// A kernel object stored in the global table.
///
/// All variants are `Copy` so the table can be initialised with `[None; N]`.
///
/// # Safety
/// `Sync` is implemented manually because the enum contains a raw pointer
/// (`*mut CapSlot`). All access to the table is gated by `spin::Mutex`, so
/// the pointer is never shared across threads unsafely.
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
    /// Capability table node.
    CNode {
        /// Raw pointer to the heap-allocated slot array.
        slots: *mut ruzt_cap::CapSlot,
        /// Number of bits used to index into this node.
        radix_bits: u8,
        /// Number of slots (`1 << radix_bits`).
        count: usize,
    },
    /// Untyped physical memory.
    Untyped {
        /// Physical frame where the untyped region starts.
        phys: PhysFrame,
        /// Size of the region as a power-of-two exponent.
        size_bits: u8,
        /// A set bit identifies a page still available for retyping.
        free_pages: u64,
    },
    /// IRQ handler.
    Irq {
        /// Hardware IRQ line number.
        irq_num: u32,
    },
}

// SAFETY: All access to `KernelObject` values is gated by `spin::Mutex`, so
// the raw pointer inside `CNode` is never shared across threads unsafely.
unsafe impl Send for KernelObject {}
unsafe impl Sync for KernelObject {}

const INDEX_BITS: u32 = MAX_OBJECTS.trailing_zeros();
const INDEX_MASK: u64 = MAX_OBJECTS as u64 - 1;
const MAX_GENERATION: u64 = u64::MAX >> INDEX_BITS;

#[derive(Clone, Copy)]
struct UntypedAllocation {
    region: KObjectId,
    mask: u64,
}

#[derive(Clone, Copy)]
struct Entry {
    generation: u64,
    object: Option<KernelObject>,
    references: usize,
    backing: Option<UntypedAllocation>,
}

impl Entry {
    const EMPTY: Self = Self {
        generation: 0,
        object: None,
        references: 0,
        backing: None,
    };

    fn matches(&self, id: KObjectId) -> bool {
        self.generation == id.0 >> INDEX_BITS
    }

    fn take(&mut self) -> Option<(KernelObject, Option<UntypedAllocation>)> {
        self.object
            .take()
            .map(|object| (object, self.backing.take()))
    }
}

impl KObjectId {
    fn index(self) -> usize {
        (self.0 & INDEX_MASK) as usize
    }
}

/// Global object table protected by a spinlock.
static TABLE: Mutex<[Entry; MAX_OBJECTS]> = Mutex::new([Entry::EMPTY; MAX_OBJECTS]);

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

const PAGE_BITS: u8 = PhysFrame::SIZE.trailing_zeros() as u8;
const MAX_UNTYPED_BITS: u8 = PAGE_BITS + 6;

fn available_page_mask(size_bits: u8) -> u64 {
    let pages = 1 << (size_bits - PAGE_BITS);
    u64::MAX >> (u64::BITS - pages)
}

fn find_aligned_run(free: u64, size_bits: u8, parent_bits: u8) -> Option<(u32, u64)> {
    let pages = 1 << (size_bits - PAGE_BITS);
    let extent = available_page_mask(size_bits);
    let parent_pages = 1 << (parent_bits - PAGE_BITS);
    (0..parent_pages).step_by(pages).find_map(|index| {
        let mask = extent << index;
        (free & mask == mask).then_some((index as u32, mask))
    })
}

pub(super) fn allocate_untyped(size_bits: u8) -> Result<(KObjectId, CapType), ErrorCode> {
    if !(PAGE_BITS..=MAX_UNTYPED_BITS).contains(&size_bits) {
        return Err(ErrorCode::BadMessage);
    }
    let pages = 1 << (size_bits - PAGE_BITS);
    let id = allocate_with(|| {
        let phys = frame::allocate_untyped(pages).ok_or(ErrorCode::NoMemory)?;
        Ok(KernelObject::Untyped {
            phys,
            size_bits,
            free_pages: available_page_mask(size_bits),
        })
    })?;
    let Some(KernelObject::Untyped { phys, .. }) = get(id) else {
        unreachable!("new Untyped object must exist");
    };
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
        free_pages,
    }) = &mut parent.object
    else {
        return Err(ErrorCode::InvalidCap);
    };
    let size_bits = match kind {
        RetypeKind::Untyped => {
            let bits = u8::try_from(requested_size_bits).map_err(|_| ErrorCode::BadMessage)?;
            if !(PAGE_BITS..*parent_bits).contains(&bits) {
                return Err(ErrorCode::BadMessage);
            }
            bits
        }
        _ if requested_size_bits == 0 => PAGE_BITS,
        _ => return Err(ErrorCode::BadMessage),
    };
    let (index, mask) =
        find_aligned_run(*free_pages, size_bits, *parent_bits).ok_or(ErrorCode::NoMemory)?;
    let references = parent
        .references
        .checked_add(1)
        .ok_or(ErrorCode::NoMemory)?;
    let addr = phys.base.as_u64() + (u64::from(index) << PAGE_BITS);
    let phys = PhysFrame::from_base(PhysAddr::new(addr)).expect("aligned Untyped page");
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
        RetypeKind::Endpoint => (
            KernelObject::Endpoint { closed: false },
            CapType::Endpoint(EndpointId(id.0)),
        ),
        RetypeKind::Notification => (
            KernelObject::Notification { state: false },
            CapType::Notification(NotificationId(id.0)),
        ),
        RetypeKind::Untyped => (
            KernelObject::Untyped {
                phys,
                size_bits,
                free_pages: available_page_mask(size_bits),
            },
            CapType::Untyped { phys, size_bits },
        ),
    };
    *free_pages &= !mask;
    parent.references = references;
    let entry = &mut table[id.index()];
    entry.object = Some(object);
    // This reference keeps the whole parent extent reserved until the child
    // object, including any mappings through it, has been destroyed.
    entry.backing = Some(UntypedAllocation { region, mask });
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

pub(super) fn release(id: KObjectId) {
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
        KernelObject::CNode { slots, count, .. } => {
            // SAFETY: This is the unique boxed slice from CNode allocation.
            unsafe {
                drop(alloc::boxed::Box::from_raw(
                    core::ptr::slice_from_raw_parts_mut(slots, count),
                ))
            };
        }
        KernelObject::Frame { phys } => {
            // SAFETY: The final reference is gone, including every mapping,
            // and the page is still reserved in the parent region.
            unsafe { ruzt_hal_x86_64::mapper::zero_frame(phys) };
        }
        KernelObject::Untyped {
            phys,
            size_bits,
            free_pages,
        } => {
            assert_eq!(free_pages, available_page_mask(size_bits));
            if backing.is_none() {
                frame::deallocate_contiguous(phys, 1 << (size_bits - PAGE_BITS));
            }
        }
        _ => {}
    }
    if let Some(allocation) = backing {
        update(allocation.region, |region| {
            let KernelObject::Untyped { free_pages, .. } = region else {
                unreachable!("object backing is Untyped");
            };
            assert_eq!(*free_pages & allocation.mask, 0);
            *free_pages |= allocation.mask;
        });
        release(allocation.region);
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
        CapType::AddressSpace(_) => Ok(KernelObject::AddressSpace {
            root_page_table: crate::mm::frame::allocate().ok_or(ErrorCode::NoMemory)?,
        }),
        CapType::Frame { .. } | CapType::Untyped { .. } => Err(ErrorCode::InvalidCap),
        CapType::Process(_) | CapType::Program(_) => Err(ErrorCode::InvalidCap),
        CapType::CNode { radix_bits, .. } => {
            let count = 1usize
                .checked_shl(u32::from(radix_bits))
                .ok_or(ErrorCode::BadMessage)?;
            let mut slots = Vec::new();
            slots
                .try_reserve_exact(count)
                .map_err(|_| ErrorCode::NoMemory)?;
            slots.resize(count, NULL_SLOT);
            let ptr = alloc::boxed::Box::into_raw(slots.into_boxed_slice()).cast();
            Ok(KernelObject::CNode {
                slots: ptr,
                radix_bits,
                count,
            })
        }
        CapType::Irq { irq_num } => Ok(KernelObject::Irq { irq_num }),
        // Boot device capabilities are only provisioned at process creation.
        CapType::IoPort { .. } | CapType::Framebuffer => Err(ErrorCode::NotImplemented),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delegated_region_uses_only_naturally_aligned_free_pages() {
        assert_eq!(find_aligned_run(0b0110, 13, 14), None);
        assert_eq!(find_aligned_run(0b1110, 13, 14), Some((2, 0b1100)));
        assert_eq!(find_aligned_run(1 << 63, 12, 18), Some((63, 1 << 63)));
    }

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
    fn allocate_cnode() {
        let _state = crate::isolated_kernel_state();
        let id = allocate(CapType::CNode {
            radix_bits: 4,
            ptr: 0,
        })
        .unwrap();
        let obj = get(id).unwrap();
        if let KernelObject::CNode {
            radix_bits, count, ..
        } = obj
        {
            assert_eq!(radix_bits, 4);
            assert_eq!(count, 16);
        } else {
            panic!("expected CNode");
        }
        deallocate(id);
        assert!(get(id).is_none());
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
