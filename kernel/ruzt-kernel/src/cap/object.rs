//! Kernel object table — every capability references a stable entry here.

use alloc::vec::Vec;
use ruzt_abi::ErrorCode;
use ruzt_cap::{CapType, NULL_SLOT};
use ruzt_hal::mem::PhysFrame;
use spin::Mutex;

/// Maximum number of kernel objects in the table.
const MAX_OBJECTS: usize = 256;
const _: () = assert!(MAX_OBJECTS.is_power_of_two());

/// Opaque handle for a kernel object entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct KObjectId(pub u64);

/// Opaque handle for an address space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct AddressSpaceId(pub u64);

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
        /// The peer of a boot channel has exited.
        closed: bool,
    },
    /// Async notification object.
    Notification {
        /// Whether a signal arrived while nobody was waiting.
        state: bool,
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
    /// Mapped physical frame.
    Frame {
        /// Physical frame backing this mapping.
        phys: PhysFrame,
        /// Address spaces that have this frame mapped.
        mapped_in: [AddressSpaceId; 4],
        /// Number of valid entries in `mapped_in`.
        mapped_count: u8,
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
struct Entry {
    generation: u64,
    object: Option<KernelObject>,
    references: usize,
}

impl Entry {
    const EMPTY: Self = Self {
        generation: 0,
        object: None,
        references: 0,
    };

    fn matches(&self, id: KObjectId) -> bool {
        self.generation == id.0 >> INDEX_BITS
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
    {
        let mut table = TABLE.lock();
        for entry in table.iter_mut() {
            if let Some(object) = entry.object.take() {
                destroy(object);
            }
            entry.references = 0;
        }
    }
}

/// Allocate a kernel object and return its generation-qualified identity.
pub fn allocate(cap_type: CapType) -> Result<KObjectId, ErrorCode> {
    let mut table = TABLE.lock();
    let (index, entry) = table
        .iter_mut()
        .enumerate()
        .find(|(_, entry)| entry.object.is_none() && entry.generation < MAX_GENERATION)
        .ok_or(ErrorCode::NoMemory)?;
    entry.object = Some(kernel_object_from_cap_type(cap_type)?);
    entry.generation += 1;
    Ok(KObjectId((entry.generation << INDEX_BITS) | index as u64))
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
            entry.object.take()
        } else {
            None
        }
    };
    if let Some(object) = object {
        destroy(object);
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
            entry.object.take()
        } else {
            None
        }
    };
    if let Some(object) = object {
        destroy(object);
    }
}

fn destroy(object: KernelObject) {
    if let KernelObject::CNode { slots, count, .. } = object {
        // SAFETY: This is the unique boxed slice from CNode allocation.
        unsafe {
            drop(alloc::boxed::Box::from_raw(
                core::ptr::slice_from_raw_parts_mut(slots, count),
            ))
        };
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
        CapType::Frame { phys, size: _ } => Ok(KernelObject::Frame {
            phys,
            mapped_in: [AddressSpaceId(0); 4],
            mapped_count: 0,
        }),
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
        CapType::Untyped { phys, size_bits } => Ok(KernelObject::Untyped { phys, size_bits }),
        CapType::Irq { irq_num } => Ok(KernelObject::Irq { irq_num }),
        // Boot device capabilities are only provisioned at process creation.
        CapType::IoPort { .. } | CapType::Framebuffer => Err(ErrorCode::NotImplemented),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruzt_cap::{EndpointId, NotificationId};
    use ruzt_hal::mem::PhysAddr;

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
    fn allocate_frame() {
        let _state = crate::isolated_kernel_state();
        let frame = ruzt_hal::mem::PhysFrame::from_base(PhysAddr::new(0x1000)).unwrap();
        let id = allocate(CapType::Frame {
            phys: frame,
            size: ruzt_cap::FrameSize::Size4K,
        })
        .unwrap();
        let obj = get(id).unwrap();
        assert!(matches!(obj, KernelObject::Frame { .. }));
    }

    #[test]
    fn allocate_untyped() {
        let _state = crate::isolated_kernel_state();
        let frame = ruzt_hal::mem::PhysFrame::from_base(PhysAddr::new(0x2000)).unwrap();
        let id = allocate(CapType::Untyped {
            phys: frame,
            size_bits: 12,
        })
        .unwrap();
        let obj = get(id).unwrap();
        assert!(matches!(obj, KernelObject::Untyped { size_bits: 12, .. }));
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
