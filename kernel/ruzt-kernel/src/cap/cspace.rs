//! CSpace — capability namespace for a single process.

use alloc::vec::Vec;
use ruzt_abi::ErrorCode;
use ruzt_cap::{CapSlot, CapType, NULL_SLOT};

/// A capability table node (CNode) owning a heap-allocated slot array.
pub struct CapSlotCNode {
    /// All slots in this node.
    slots: Vec<CapSlot>,
    /// Number of bits used to index into this node.
    radix_bits: u8,
}

/// A process's capability namespace.
///
/// For Phase 2, only a single root CNode is supported (no multi-level lookup).
pub struct CSpace {
    /// The root CNode of this CSpace.
    root: CapSlotCNode,
}

use spin::Mutex;

/// Global kernel CSpace used for the kernel-internal IPC self-test.
static KERNEL_CSPACE: Mutex<Option<CSpace>> = Mutex::new(None);

/// Initialise the global kernel CSpace.
pub fn init_kernel_cspace() {
    let mut guard = KERNEL_CSPACE.lock();
    *guard = Some(CSpace::new(6));
}

/// Return a lock guard on the global kernel CSpace.
pub fn kernel_cspace() -> spin::MutexGuard<'static, Option<CSpace>> {
    KERNEL_CSPACE.lock()
}

impl CSpace {
    /// Create a new CSpace with a root CNode of `radix_bits` depth.
    ///
    /// All slots are initialised to [`NULL_SLOT`].
    pub fn new(radix_bits: u8) -> Self {
        let count = 1usize << (radix_bits as usize);
        let mut slots = Vec::with_capacity(count);
        slots.resize(count, NULL_SLOT);
        Self {
            root: CapSlotCNode { slots, radix_bits },
        }
    }

    /// Resolve a single-level cptr to a capability slot.
    ///
    /// Returns [`ErrorCode::InvalidCap`] if the cptr is out of bounds or the
    /// slot is empty (`Null`).
    pub fn lookup(&self, cptr: u64) -> Result<&CapSlot, ErrorCode> {
        let slot = self
            .root
            .slots
            .get(cptr as usize)
            .ok_or(ErrorCode::InvalidCap)?;
        if matches!(slot.cap_type, CapType::Null) {
            return Err(ErrorCode::InvalidCap);
        }
        Ok(slot)
    }

    /// Resolve a single-level cptr to a mutable capability slot.
    ///
    /// Returns [`ErrorCode::InvalidCap`] if the cptr is out of bounds or the
    /// slot is empty (`Null`).
    pub fn lookup_mut(&mut self, cptr: u64) -> Result<&mut CapSlot, ErrorCode> {
        let slot = self
            .root
            .slots
            .get_mut(cptr as usize)
            .ok_or(ErrorCode::InvalidCap)?;
        if matches!(slot.cap_type, CapType::Null) {
            return Err(ErrorCode::InvalidCap);
        }
        Ok(slot)
    }

    /// Overwrite the slot at `cptr` with `slot`.
    pub fn insert(&mut self, cptr: u64, slot: CapSlot) -> Result<(), ErrorCode> {
        let s = self
            .root
            .slots
            .get_mut(cptr as usize)
            .ok_or(ErrorCode::InvalidCap)?;
        *s = slot;
        Ok(())
    }

    /// Replace the slot at `cptr` with [`NULL_SLOT`] and return the old value.
    pub fn delete(&mut self, cptr: u64) -> Result<CapSlot, ErrorCode> {
        let s = self
            .root
            .slots
            .get_mut(cptr as usize)
            .ok_or(ErrorCode::InvalidCap)?;
        let old = *s;
        *s = NULL_SLOT;
        Ok(old)
    }

    /// Find the first empty slot and return its cptr.
    pub fn alloc_slot(&mut self) -> Result<u64, ErrorCode> {
        for (i, slot) in self.root.slots.iter().enumerate() {
            if matches!(slot.cap_type, CapType::Null) {
                return Ok(i as u64);
            }
        }
        Err(ErrorCode::NoMemory)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruzt_cap::{CapRights, CapSlot, EndpointId, FrameSize};
    use ruzt_hal::mem::PhysAddr;

    #[test]
    fn cspace_new_all_null() {
        let cspace = CSpace::new(4);
        for i in 0..16 {
            assert_eq!(cspace.lookup(i), Err(ErrorCode::InvalidCap));
        }
    }

    #[test]
    fn cspace_insert_and_lookup() {
        let mut cspace = CSpace::new(4);
        let slot = CapSlot {
            cap_type: CapType::Endpoint(EndpointId(7)),
            rights: CapRights::READ,
            badge: 0,
        };
        cspace.insert(3, slot).unwrap();
        let found = cspace.lookup(3).unwrap();
        assert_eq!(found.cap_type, CapType::Endpoint(EndpointId(7)));
        assert_eq!(found.rights, CapRights::READ);
    }

    #[test]
    fn cspace_delete_returns_old() {
        let mut cspace = CSpace::new(4);
        let slot = CapSlot {
            cap_type: CapType::Endpoint(EndpointId(7)),
            rights: CapRights::READ,
            badge: 0,
        };
        cspace.insert(3, slot).unwrap();
        let old = cspace.delete(3).unwrap();
        assert_eq!(old.cap_type, CapType::Endpoint(EndpointId(7)));
        assert_eq!(cspace.lookup(3), Err(ErrorCode::InvalidCap));
    }

    #[test]
    fn cspace_lookup_empty_returns_invalid_cap() {
        let cspace = CSpace::new(4);
        assert_eq!(cspace.lookup(5), Err(ErrorCode::InvalidCap));
    }

    #[test]
    fn cspace_lookup_out_of_bounds() {
        let cspace = CSpace::new(4);
        assert_eq!(cspace.lookup(100), Err(ErrorCode::InvalidCap));
    }

    #[test]
    fn cspace_alloc_slot() {
        let mut cspace = CSpace::new(4);
        let cptr = cspace.alloc_slot().unwrap();
        assert_eq!(cptr, 0);
        cspace.insert(0, CapSlot {
            cap_type: CapType::Endpoint(EndpointId(1)),
            rights: CapRights::READ,
            badge: 0,
        }).unwrap();
        let cptr2 = cspace.alloc_slot().unwrap();
        assert_eq!(cptr2, 1);
    }

    #[test]
    fn cspace_alloc_slot_full() {
        let mut cspace = CSpace::new(2);
        for i in 0..4 {
            cspace.insert(i, CapSlot {
                cap_type: CapType::Endpoint(EndpointId(i as u64)),
                rights: CapRights::READ,
                badge: 0,
            }).unwrap();
        }
        assert_eq!(cspace.alloc_slot(), Err(ErrorCode::NoMemory));
    }

    #[test]
    fn cspace_retype_untyped_to_frame() {
        let mut cspace = CSpace::new(4);
        let frame = ruzt_hal::mem::PhysFrame::from_base(PhysAddr::new(0x3000)).unwrap();
        let untyped = CapSlot {
            cap_type: CapType::Untyped { phys: frame, size_bits: 12 },
            rights: CapRights::new(),
            badge: 0,
        };
        cspace.insert(0, untyped).unwrap();

        let old = cspace.delete(0).unwrap();
        assert!(matches!(old.cap_type, CapType::Untyped { size_bits: 12, .. }));

        let new_slot = CapSlot {
            cap_type: CapType::Frame { phys: frame, size: FrameSize::Size4K },
            rights: CapRights::READ,
            badge: 0,
        };
        cspace.insert(0, new_slot).unwrap();
        let found = cspace.lookup(0).unwrap();
        assert!(matches!(found.cap_type, CapType::Frame { size: FrameSize::Size4K, .. }));
    }
}
