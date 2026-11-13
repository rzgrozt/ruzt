//! Kernel object table — every capability references a stable entry here.

use alloc::vec::Vec;
use core::mem;
use spin::Mutex;
use ruzt_abi::ErrorCode;
use ruzt_cap::{CapType, NULL_SLOT};
use ruzt_hal::mem::PhysFrame;

/// Maximum number of kernel objects in the table.
const MAX_OBJECTS: usize = 256;

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
    /// IPC endpoint.
    Endpoint {
        /// Thread waiting to send (blocked).
        blocked_sender: Option<usize>,
        /// Thread waiting to receive (blocked).
        blocked_receiver: Option<usize>,
    },
    /// Async notification object.
    Notification {
        /// Current signal state.
        state: bool,
        /// Thread waiting on this notification.
        blocked_waiter: Option<usize>,
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

/// Global object table protected by a spinlock.
static TABLE: Mutex<[Option<KernelObject>; MAX_OBJECTS]> = Mutex::new([None; MAX_OBJECTS]);

/// One-time table initialisation.
pub fn init() {
    let mut guard = TABLE.lock();
    for entry in guard.iter_mut() {
        *entry = None;
    }
    super::cspace::init_kernel_cspace();
}

/// Allocate a free table slot and store the initial kernel object derived from
/// `cap_type`.
///
/// Returns the [`KObjectId`] of the newly created entry.
pub fn allocate(cap_type: CapType) -> Result<KObjectId, ErrorCode> {
    let mut guard = TABLE.lock();
    let obj = kernel_object_from_cap_type(cap_type)?;
    for (i, entry) in guard.iter_mut().enumerate() {
        if entry.is_none() {
            *entry = Some(obj);
            return Ok(KObjectId(i as u64));
        }
    }
    Err(ErrorCode::NoMemory)
}

/// Return a copy of the kernel object at `id`, or `None` if the slot is empty.
pub fn get(id: KObjectId) -> Option<KernelObject> {
    let guard = TABLE.lock();
    guard.get(id.0 as usize).and_then(|opt| *opt)
}

/// Zero the slot at `id` and, if it was a CNode, reclaim the heap-allocated
/// slot array.
pub fn deallocate(id: KObjectId) {
    let mut guard = TABLE.lock();
    if let Some(entry) = guard.get_mut(id.0 as usize) {
        if let Some(obj) = entry {
            if let KernelObject::CNode { slots, count, .. } = obj {
                // SAFETY: ptr was allocated via Vec::with_capacity, count is
                // correct. We reconstruct the Vec to drop it properly.
                unsafe {
                    let _ = Vec::from_raw_parts(*slots, 0, *count);
                }
            }
            *entry = None;
        }
    }
}

/// Set the blocked sender on an Endpoint object.
pub fn set_blocked_sender(id: KObjectId, sender_id: usize) {
    let mut guard = TABLE.lock();
    if let Some(Some(KernelObject::Endpoint { ref mut blocked_sender, .. })) =
        guard.get_mut(id.0 as usize)
    {
        *blocked_sender = Some(sender_id);
    }
}

/// Clear the blocked sender on an Endpoint object.
pub fn clear_blocked_sender(id: KObjectId) {
    let mut guard = TABLE.lock();
    if let Some(Some(KernelObject::Endpoint { ref mut blocked_sender, .. })) =
        guard.get_mut(id.0 as usize)
    {
        *blocked_sender = None;
    }
}

/// Set the blocked receiver on an Endpoint object.
pub fn set_blocked_receiver(id: KObjectId, receiver_id: usize) {
    let mut guard = TABLE.lock();
    if let Some(Some(KernelObject::Endpoint { ref mut blocked_receiver, .. })) =
        guard.get_mut(id.0 as usize)
    {
        *blocked_receiver = Some(receiver_id);
    }
}

/// Clear the blocked receiver on an Endpoint object.
pub fn clear_blocked_receiver(id: KObjectId) {
    let mut guard = TABLE.lock();
    if let Some(Some(KernelObject::Endpoint { ref mut blocked_receiver, .. })) =
        guard.get_mut(id.0 as usize)
    {
        *blocked_receiver = None;
    }
}

/// Set the signal state of a Notification object.
pub fn set_notification_state(id: KObjectId, new_state: bool) {
    let mut guard = TABLE.lock();
    if let Some(Some(KernelObject::Notification { state, .. })) =
        guard.get_mut(id.0 as usize)
    {
        *state = new_state;
    }
}

/// Set the blocked waiter on a Notification object.
pub fn set_blocked_waiter(id: KObjectId, waiter_id: usize) {
    let mut guard = TABLE.lock();
    if let Some(Some(KernelObject::Notification { ref mut blocked_waiter, .. })) =
        guard.get_mut(id.0 as usize)
    {
        *blocked_waiter = Some(waiter_id);
    }
}

/// Clear the blocked waiter on a Notification object.
pub fn clear_blocked_waiter(id: KObjectId) {
    let mut guard = TABLE.lock();
    if let Some(Some(KernelObject::Notification { ref mut blocked_waiter, .. })) =
        guard.get_mut(id.0 as usize)
    {
        *blocked_waiter = None;
    }
}

/// Convert a [`CapType`] into the corresponding [`KernelObject`] variant.
fn kernel_object_from_cap_type(cap_type: CapType) -> Result<KernelObject, ErrorCode> {
    match cap_type {
        CapType::Null => Err(ErrorCode::InvalidCap),
        CapType::Endpoint(_) => Ok(KernelObject::Endpoint {
            blocked_sender: None,
            blocked_receiver: None,
        }),
        CapType::Notification(_) => Ok(KernelObject::Notification {
            state: false,
            blocked_waiter: None,
        }),
        CapType::Thread(thread_id) => Ok(KernelObject::Thread {
            thread_id: thread_id.0 as usize,
        }),
        CapType::AddressSpace(_) => Ok(KernelObject::AddressSpace {
            root_page_table: crate::mm::frame::allocate()
                .ok_or(ErrorCode::NoMemory)?,
        }),
        CapType::Frame { phys, size: _ } => Ok(KernelObject::Frame {
            phys,
            mapped_in: [AddressSpaceId(0); 4],
            mapped_count: 0,
        }),
        CapType::CNode { radix_bits, .. } => {
            let count = 1usize << (radix_bits as usize);
            let mut slots = Vec::with_capacity(count);
            slots.resize(count, NULL_SLOT);
            let ptr = slots.as_mut_ptr();
            mem::forget(slots);
            Ok(KernelObject::CNode {
                slots: ptr,
                radix_bits,
                count,
            })
        }
        CapType::Untyped { phys, size_bits } => Ok(KernelObject::Untyped {
            phys,
            size_bits,
        }),
        CapType::Irq { irq_num } => Ok(KernelObject::Irq { irq_num }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruzt_cap::{EndpointId, NotificationId};
    use ruzt_hal::mem::PhysAddr;

    #[test]
    fn deallocate_works() {
        init();
        let id = allocate(CapType::Endpoint(EndpointId(0))).unwrap();
        assert!(get(id).is_some());
        deallocate(id);
        assert!(get(id).is_none());
    }

    #[test]
    fn allocate_endpoint() {
        let id = allocate(CapType::Endpoint(EndpointId(0))).unwrap();
        let obj = get(id).unwrap();
        assert!(matches!(obj, KernelObject::Endpoint { blocked_sender: None, blocked_receiver: None }));
    }

    #[test]
    fn deallocate_endpoint() {
        let id = allocate(CapType::Endpoint(EndpointId(0))).unwrap();
        deallocate(id);
        assert!(get(id).is_none());
    }

    #[test]
    fn allocate_notification() {
        let id = allocate(CapType::Notification(NotificationId(0))).unwrap();
        let obj = get(id).unwrap();
        assert!(matches!(obj, KernelObject::Notification { state: false, blocked_waiter: None }));
    }

    #[test]
    fn allocate_null_fails() {
        assert_eq!(allocate(CapType::Null), Err(ErrorCode::InvalidCap));
    }

    #[test]
    fn allocate_frame() {
        let frame = ruzt_hal::mem::PhysFrame::from_base(PhysAddr::new(0x1000)).unwrap();
        let id = allocate(CapType::Frame { phys: frame, size: ruzt_cap::FrameSize::Size4K }).unwrap();
        let obj = get(id).unwrap();
        assert!(matches!(obj, KernelObject::Frame { .. }));
    }

    #[test]
    fn allocate_untyped() {
        let frame = ruzt_hal::mem::PhysFrame::from_base(PhysAddr::new(0x2000)).unwrap();
        let id = allocate(CapType::Untyped { phys: frame, size_bits: 12 }).unwrap();
        let obj = get(id).unwrap();
        assert!(matches!(obj, KernelObject::Untyped { size_bits: 12, .. }));
    }

    #[test]
    fn allocate_cnode() {
        let id = allocate(CapType::CNode { radix_bits: 4, ptr: 0 }).unwrap();
        let obj = get(id).unwrap();
        if let KernelObject::CNode { radix_bits, count, .. } = obj {
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
        init();
        for i in 0..256 {
            deallocate(KObjectId(i as u64));
        }
        let mut ids = Vec::with_capacity(16);
        for _ in 0..16 {
            ids.push(allocate(CapType::Endpoint(EndpointId(0))).unwrap());
        }
        for id in ids {
            deallocate(id);
        }
        for i in 0..16 {
            assert!(get(KObjectId(i)).is_none());
        }
    }
}
