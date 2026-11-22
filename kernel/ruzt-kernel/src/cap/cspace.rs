//! Per-process slots and the kernel-wide capability derivation tree.

use alloc::{collections::BTreeMap, vec::Vec};
use ruzt_abi::{ErrorCode, RetypeKind, IPC_CAP_SLOTS};
use ruzt_cap::{CapRights, CapSlot, CapType, NULL_SLOT};
use spin::Mutex;

use super::object::{self, FramePin, KObjectId, UntypedBudget};

/// A capability identity that survives moves between slots.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct CapabilityId(u64);

#[derive(Clone, Copy)]
pub(crate) struct CapGrant {
    source: CapabilityId,
    rights: CapRights,
    badge: u64,
}

pub(crate) fn is_live(id: CapabilityId) -> bool {
    DERIVATIONS.lock().nodes.contains_key(&id)
}

#[derive(Clone, Copy)]
struct Node {
    slot: CapSlot,
    object: Option<KObjectId>,
    parent: Option<CapabilityId>,
}

struct DerivationTree {
    nodes: BTreeMap<CapabilityId, Node>,
    next: u64,
}

impl DerivationTree {
    fn install(&mut self, node: Node) -> Result<CapabilityId, ErrorCode> {
        let id = CapabilityId(self.next);
        let next = self.next.checked_add(1).ok_or(ErrorCode::NoMemory)?;
        if let Some(object) = node.object {
            object::retain(object)?;
        }
        self.nodes.insert(id, node);
        self.next = next;
        Ok(id)
    }

    fn remove(&mut self, id: CapabilityId) -> Option<CapSlot> {
        let node = self.nodes.remove(&id)?;
        // Deleting a cap leaves its children live. Link them to the nearest
        // surviving ancestor so revocation still reaches them.
        for child in self.nodes.values_mut() {
            if child.parent == Some(id) {
                child.parent = node.parent;
            }
        }
        if let Some(object) = node.object {
            object::release(object);
        }
        Some(node.slot)
    }

    fn derive(
        &mut self,
        source: CapabilityId,
        rights: CapRights,
        badge: u64,
    ) -> Result<CapabilityId, ErrorCode> {
        let parent = self.validate_grant(CapGrant {
            source,
            rights,
            badge,
        })?;
        self.install(Node {
            slot: CapSlot {
                rights,
                badge,
                ..parent.slot
            },
            object: parent.object,
            parent: Some(source),
        })
    }

    fn validate_grant(&self, grant: CapGrant) -> Result<Node, ErrorCode> {
        let &parent = self.nodes.get(&grant.source).ok_or(ErrorCode::InvalidCap)?;
        let rights = grant.rights;
        let badge = grant.badge;
        let can_grant = parent.slot.rights.contains(CapRights::GRANT.union(rights));
        let can_badge = parent.slot.badge == 0 || parent.slot.badge == badge;
        if !can_grant || !can_badge {
            return Err(ErrorCode::CapRightsViolation);
        }
        Ok(parent)
    }

    fn revoke(&mut self, source: CapabilityId) {
        // Remove one immediate child at a time. Removing it reparents its
        // own children, so this visits the entire subtree without recursion.
        while let Some(id) = self
            .nodes
            .iter()
            .find_map(|(&id, node)| (node.parent == Some(source)).then_some(id))
        {
            self.remove(id);
        }
    }
}

static DERIVATIONS: Mutex<DerivationTree> = Mutex::new(DerivationTree {
    nodes: BTreeMap::new(),
    next: 1,
});

/// A process's capability namespace, initially a single CNode.
pub struct CSpace {
    slots: Vec<Option<CapabilityId>>,
}

static KERNEL_CSPACE: Mutex<Option<CSpace>> = Mutex::new(None);

/// Initialise the capability space of the kernel IPC diagnostic.
pub fn init_kernel_cspace() {
    *KERNEL_CSPACE.lock() = Some(CSpace::new(6));
}

/// Return the locked kernel diagnostic capability space.
pub fn kernel_cspace() -> spin::MutexGuard<'static, Option<CSpace>> {
    KERNEL_CSPACE.lock()
}

impl CSpace {
    /// Create a root CNode with 2^radix_bits slots.
    pub fn new(radix_bits: u8) -> Self {
        Self::try_new(radix_bits).expect("allocate CSpace")
    }

    pub(crate) fn try_new(radix_bits: u8) -> Result<Self, ErrorCode> {
        let count = 1usize
            .checked_shl(u32::from(radix_bits))
            .ok_or(ErrorCode::BadMessage)?;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(count)
            .map_err(|_| ErrorCode::NoMemory)?;
        slots.resize(count, None);
        Ok(Self { slots })
    }

    fn index(&self, cptr: u64) -> Result<usize, ErrorCode> {
        let index = usize::try_from(cptr).map_err(|_| ErrorCode::InvalidCap)?;
        if index < self.slots.len() {
            Ok(index)
        } else {
            Err(ErrorCode::InvalidCap)
        }
    }

    fn vacant(&self, index: usize, tree: &DerivationTree) -> Result<(), ErrorCode> {
        match self.slots[index] {
            Some(id) if tree.nodes.contains_key(&id) => Err(ErrorCode::SlotOccupied),
            _ => Ok(()),
        }
    }

    pub(crate) fn capability_id(&self, cptr: u64) -> Result<CapabilityId, ErrorCode> {
        let id = self.slots[self.index(cptr)?].ok_or(ErrorCode::InvalidCap)?;
        if is_live(id) {
            Ok(id)
        } else {
            Err(ErrorCode::InvalidCap)
        }
    }

    /// Resolve a live slot to its descriptor.
    pub fn lookup(&self, cptr: u64) -> Result<CapSlot, ErrorCode> {
        let id = self.slots[self.index(cptr)?].ok_or(ErrorCode::InvalidCap)?;
        DERIVATIONS
            .lock()
            .nodes
            .get(&id)
            .map(|node| node.slot)
            .ok_or(ErrorCode::InvalidCap)
    }

    pub(crate) fn shared_frame(
        &self,
        cptr: u64,
        rights: CapRights,
    ) -> Result<(CapabilityId, FramePin), ErrorCode> {
        let id = self.slots[self.index(cptr)?].ok_or(ErrorCode::InvalidCap)?;
        let tree = DERIVATIONS.lock();
        let node = tree.nodes.get(&id).ok_or(ErrorCode::InvalidCap)?;
        let object = node.object.ok_or(ErrorCode::InvalidCap)?;
        if !matches!(node.slot.cap_type, CapType::Frame { .. }) {
            return Err(ErrorCode::InvalidCap);
        }
        if !node.slot.rights.contains(rights) {
            return Err(ErrorCode::CapRightsViolation);
        }
        Ok((id, FramePin::new(object)?))
    }

    pub(crate) fn untyped_budget(&self, cptr: u64) -> Result<UntypedBudget, ErrorCode> {
        let id = self.slots[self.index(cptr)?].ok_or(ErrorCode::InvalidCap)?;
        let tree = DERIVATIONS.lock();
        let node = tree.nodes.get(&id).ok_or(ErrorCode::InvalidCap)?;
        if !matches!(node.slot.cap_type, CapType::Untyped { .. }) {
            return Err(ErrorCode::InvalidCap);
        }
        if !node.slot.rights.contains(CapRights::WRITE) {
            return Err(ErrorCode::CapRightsViolation);
        }
        UntypedBudget::new(node.object.ok_or(ErrorCode::InvalidCap)?)
    }

    pub(crate) fn provision_untyped(&mut self, cptr: u64, size_bits: u8) -> Result<(), ErrorCode> {
        let (object, cap_type) = object::allocate_untyped(size_bits)?;
        let result = self.install(
            cptr,
            CapSlot {
                cap_type,
                rights: CapRights::WRITE.union(CapRights::GRANT),
                badge: 0,
            },
            Some(object),
        );
        if result.is_err() {
            object::deallocate(object);
        }
        result
    }

    pub(crate) fn retype(
        &mut self,
        cptr: u64,
        destination: u64,
        kind: RetypeKind,
        size_bits: u64,
    ) -> Result<(), ErrorCode> {
        let source = self.slots[self.index(cptr)?].ok_or(ErrorCode::InvalidCap)?;
        let dest = self.index(destination)?;
        let mut tree = DERIVATIONS.lock();
        let node = tree.nodes.get(&source).ok_or(ErrorCode::InvalidCap)?;
        if !matches!(node.slot.cap_type, CapType::Untyped { .. }) {
            return Err(ErrorCode::InvalidCap);
        }
        if !node.slot.rights.contains(CapRights::WRITE) {
            return Err(ErrorCode::CapRightsViolation);
        }
        let region = node.object.ok_or(ErrorCode::InvalidCap)?;
        self.vacant(dest, &tree)?;

        let (object, cap_type) = object::retype(region, kind, size_bits)?;
        let mut rights = CapRights::WRITE.union(CapRights::GRANT);
        if kind != RetypeKind::Untyped {
            rights = rights.union(CapRights::READ);
        }
        let installed = tree.install(Node {
            slot: CapSlot {
                cap_type,
                rights,
                badge: 0,
            },
            object: Some(object),
            parent: Some(source),
        });
        match installed {
            Ok(id) => {
                self.slots[dest] = Some(id);
                Ok(())
            }
            Err(error) => {
                object::deallocate(object);
                Err(error)
            }
        }
    }

    /// Install a capability issued by the kernel at boot.
    pub fn insert(&mut self, cptr: u64, slot: CapSlot) -> Result<(), ErrorCode> {
        let object = match slot.cap_type {
            CapType::Endpoint(id) => Some(KObjectId(id.0)),
            CapType::Notification(id) => Some(KObjectId(id.0)),
            CapType::Process(id) => Some(KObjectId(id.0)),
            CapType::Program(id) => Some(KObjectId(id)),
            CapType::Thread(id) => Some(KObjectId(id.0)),
            CapType::AddressSpace(id) => Some(KObjectId(id.0)),
            CapType::CNode { ptr, .. } => Some(KObjectId(ptr)),
            CapType::Irq { .. } | CapType::IoPort { .. } | CapType::Framebuffer => None,
            CapType::Null | CapType::Frame { .. } | CapType::Untyped { .. } => {
                return Err(ErrorCode::InvalidCap)
            }
        };
        self.install(cptr, slot, object)
    }

    fn install(
        &mut self,
        cptr: u64,
        slot: CapSlot,
        object: Option<KObjectId>,
    ) -> Result<(), ErrorCode> {
        let index = self.index(cptr)?;
        let mut tree = DERIVATIONS.lock();
        self.vacant(index, &tree)?;
        self.slots[index] = Some(tree.install(Node {
            slot,
            object,
            parent: None,
        })?);
        Ok(())
    }

    /// Delete the slot. Object storage is reclaimed after its last reference.
    pub fn delete(&mut self, cptr: u64) -> Result<CapSlot, ErrorCode> {
        let index = self.index(cptr)?;
        let Some(id) = self.slots[index].take() else {
            return Ok(NULL_SLOT);
        };
        Ok(DERIVATIONS.lock().remove(id).unwrap_or(NULL_SLOT))
    }

    pub(super) fn move_cap(&mut self, source: u64, dest: u64) -> Result<(), ErrorCode> {
        let source_index = self.index(source)?;
        let dest_index = self.index(dest)?;
        let id = self.slots[source_index].ok_or(ErrorCode::InvalidCap)?;
        let tree = DERIVATIONS.lock();
        if !tree.nodes.contains_key(&id) {
            return Err(ErrorCode::InvalidCap);
        }
        self.vacant(dest_index, &tree)?;
        self.slots[dest_index] = self.slots[source_index].take();
        Ok(())
    }

    pub(crate) fn derive(
        &mut self,
        source: CapabilityId,
        dest: u64,
        rights: CapRights,
        badge: u64,
    ) -> Result<(), ErrorCode> {
        let index = self.index(dest)?;
        let mut tree = DERIVATIONS.lock();
        self.vacant(index, &tree)?;
        self.slots[index] = Some(tree.derive(source, rights, badge)?);
        Ok(())
    }

    pub(crate) fn revoke(&mut self, source: u64) -> Result<(), ErrorCode> {
        let id = self.capability_id(source)?;
        DERIVATIONS.lock().revoke(id);
        Ok(())
    }

    pub(crate) fn revoke_all_descendants(&mut self) {
        let mut tree = DERIVATIONS.lock();
        for id in self.slots.iter().flatten() {
            tree.revoke(*id);
        }
    }

    pub(crate) fn prepare_grant(
        &self,
        source: u64,
        rights: CapRights,
        badge: u64,
    ) -> Result<CapGrant, ErrorCode> {
        let grant = CapGrant {
            source: self.capability_id(source)?,
            rights,
            badge,
        };
        DERIVATIONS.lock().validate_grant(grant)?;
        Ok(grant)
    }

    pub(crate) fn accept_grants(
        &mut self,
        first: u64,
        grants: &[Option<CapGrant>],
    ) -> Result<(), ErrorCode> {
        if grants.is_empty() {
            return Ok(());
        }
        if grants.len() > IPC_CAP_SLOTS {
            return Err(ErrorCode::BadMessage);
        }
        let first = self.index(first)?;
        let end = first
            .checked_add(grants.len())
            .filter(|&end| end <= self.slots.len())
            .ok_or(ErrorCode::InvalidCap)?;
        let mut tree = DERIVATIONS.lock();
        for index in first..end {
            self.vacant(index, &tree)?;
        }

        let mut installed = [None; IPC_CAP_SLOTS];
        for (slot, grant) in installed.iter_mut().zip(grants) {
            let result = grant
                .ok_or(ErrorCode::BadMessage)
                .and_then(|grant| tree.derive(grant.source, grant.rights, grant.badge));
            match result {
                Ok(id) => *slot = Some(id),
                Err(error) => {
                    for id in installed.iter().flatten() {
                        tree.remove(*id);
                    }
                    return Err(error);
                }
            }
        }
        self.slots[first..end].copy_from_slice(&installed[..grants.len()]);
        Ok(())
    }

    /// Find the first usable slot, including slots invalidated by revocation.
    pub fn alloc_slot(&self) -> Result<u64, ErrorCode> {
        let tree = DERIVATIONS.lock();
        self.slots
            .iter()
            .position(|slot| slot.is_none_or(|id| !tree.nodes.contains_key(&id)))
            .map(|index| index as u64)
            .ok_or(ErrorCode::NoMemory)
    }

    pub(crate) fn require_vacant(&self, cptr: u64) -> Result<(), ErrorCode> {
        self.vacant(self.index(cptr)?, &DERIVATIONS.lock())
    }
}

impl Drop for CSpace {
    fn drop(&mut self) {
        let mut tree = DERIVATIONS.lock();
        for id in self.slots.iter().flatten() {
            tree.remove(*id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruzt_cap::EndpointId;

    fn endpoint(space: &mut CSpace, cptr: u64) -> KObjectId {
        let id = object::allocate(CapType::Endpoint(EndpointId(0))).unwrap();
        space
            .insert(
                cptr,
                CapSlot {
                    cap_type: CapType::Endpoint(EndpointId(id.0)),
                    rights: CapRights::new(),
                    badge: 0,
                },
            )
            .unwrap();
        id
    }

    #[test]
    fn copies_pin_objects_until_the_last_space_is_dropped() {
        let _state = crate::isolated_kernel_state();
        let mut a = CSpace::new(1);
        let mut b = CSpace::new(1);
        let object = endpoint(&mut a, 0);
        b.derive(a.capability_id(0).unwrap(), 0, CapRights::READ, 42)
            .unwrap();
        drop(a);
        assert!(object::get(object).is_some());
        assert_eq!(b.lookup(0).unwrap().badge, 42);
        drop(b);
        assert!(object::get(object).is_none());
    }

    #[test]
    fn revoke_reaches_moved_grandchildren_after_deleting_their_parent() {
        let _state = crate::isolated_kernel_state();
        let mut a = CSpace::new(2);
        let mut b = CSpace::new(2);
        let object = endpoint(&mut a, 0);
        let original = a.capability_id(0).unwrap();
        let rights = CapRights::GRANT.union(CapRights::READ);
        b.derive(original, 0, rights, 0).unwrap();
        let child = b.capability_id(0).unwrap();
        b.derive(child, 1, CapRights::READ, 7).unwrap();
        b.move_cap(1, 2).unwrap();
        b.delete(0).unwrap();
        b.derive(original, 3, CapRights::READ, 8).unwrap();

        a.revoke(0).unwrap();
        assert_eq!(b.lookup(2), Err(ErrorCode::InvalidCap));
        assert_eq!(b.lookup(3), Err(ErrorCode::InvalidCap));
        b.derive(original, 2, CapRights::READ, 0).unwrap();
        assert!(object::get(object).is_some());
        assert_eq!(a.lookup(0).unwrap().rights, CapRights::new());
    }

    #[test]
    fn occupied_slots_and_failed_rights_checks_leave_both_caps_live() {
        let _state = crate::isolated_kernel_state();
        let mut space = CSpace::new(2);
        endpoint(&mut space, 0);
        endpoint(&mut space, 1);
        let authority = space.capability_id(0).unwrap();
        assert_eq!(space.move_cap(0, 1), Err(ErrorCode::SlotOccupied));
        assert_eq!(space.move_cap(0, u64::MAX), Err(ErrorCode::InvalidCap));
        assert_eq!(space.capability_id(0), Ok(authority));
        assert_eq!(
            space.derive(authority, 1, CapRights::READ, 0),
            Err(ErrorCode::SlotOccupied)
        );
        space.derive(authority, 2, CapRights::READ, 0).unwrap();
        let restricted = space.capability_id(2).unwrap();
        assert_eq!(
            space.derive(restricted, 3, CapRights::READ, 0),
            Err(ErrorCode::CapRightsViolation)
        );
        assert_eq!(space.alloc_slot(), Ok(3));
    }

    #[test]
    fn derivation_cannot_expand_rights_or_replace_a_badge() {
        let _state = crate::isolated_kernel_state();
        let mut space = CSpace::new(2);
        endpoint(&mut space, 0);
        let rights = CapRights::READ.union(CapRights::GRANT);
        space
            .derive(space.capability_id(0).unwrap(), 1, rights, 42)
            .unwrap();
        let child = space.capability_id(1).unwrap();
        assert_eq!(
            space.derive(child, 2, CapRights::WRITE, 42),
            Err(ErrorCode::CapRightsViolation)
        );
        assert_eq!(
            space.derive(child, 2, CapRights::READ, 7),
            Err(ErrorCode::CapRightsViolation)
        );
        space.derive(child, 2, CapRights::READ, 42).unwrap();
        assert_eq!(space.lookup(2).unwrap().badge, 42);
    }

    #[test]
    fn batch_receive_rolls_back_if_a_queued_grant_is_revoked() {
        let _state = crate::isolated_kernel_state();
        let mut sender = CSpace::new(2);
        let mut receiver = CSpace::new(2);
        let first = endpoint(&mut sender, 0);
        endpoint(&mut sender, 1);
        sender
            .derive(
                sender.capability_id(1).unwrap(),
                2,
                CapRights::READ.union(CapRights::GRANT),
                0,
            )
            .unwrap();
        let grants = [
            Some(sender.prepare_grant(0, CapRights::READ, 0).unwrap()),
            Some(sender.prepare_grant(2, CapRights::READ, 0).unwrap()),
        ];
        sender.revoke(1).unwrap();
        assert_eq!(
            receiver.accept_grants(0, &grants),
            Err(ErrorCode::InvalidCap)
        );
        assert_eq!(receiver.lookup(0), Err(ErrorCode::InvalidCap));
        assert_eq!(receiver.lookup(1), Err(ErrorCode::InvalidCap));
        sender.delete(0).unwrap();
        assert_eq!(object::get(first), None);
    }
}
