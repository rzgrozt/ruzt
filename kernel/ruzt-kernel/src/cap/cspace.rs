//! Per-process capability tables and the kernel-wide derivation tree.

use alloc::{collections::BTreeMap, vec::Vec};
use core::ops::Bound::{Excluded, Unbounded};
use ruzt_abi::{
    cptr_depth, ErrorCode, PciAddress, RetypeKind, IPC_CAP_SLOTS, MAX_CNODE_RADIX, MAX_CPTR_DEPTH,
};
use ruzt_cap::{CapRights, CapSlot, CapType, NULL_SLOT};
use spin::Mutex;

use super::object::{
    self, DmaPin, FramePin, KObjectId, MmioPin, PciPin, UntypedBudget, MAX_OBJECTS,
};

/// A capability identity that survives moves between slots.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct CapabilityId(u64);

/// The authorities exercised while traversing a slot path.
#[derive(Clone, Copy)]
pub(crate) struct CapabilityPath([u64; MAX_CPTR_DEPTH]);

impl CapabilityPath {
    pub(crate) fn leaf(&self) -> CapabilityId {
        CapabilityId(self.0[0])
    }

    pub(crate) fn is_live(&self) -> bool {
        let tree = DERIVATIONS.lock();
        self.0
            .iter()
            .all(|&id| id == 0 || tree.nodes.contains_key(&CapabilityId(id)))
    }
}

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
    owner: u64,
}

impl Node {
    fn cnode(self) -> Option<KObjectId> {
        match self.slot.cap_type {
            CapType::CNode { .. } => self.object,
            _ => None,
        }
    }

    fn visible_to(self, owner: u64) -> bool {
        self.owner == owner || self.slot.rights.contains(CapRights::GRANT)
    }
}

struct DerivationTree {
    nodes: BTreeMap<CapabilityId, Node>,
    cnodes: BTreeMap<KObjectId, Vec<Option<CapabilityId>>>,
    next: u64,
    next_space: u64,
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
        let (slot, retired) = self.remove_one(id)?;
        if let Some(cnode) = retired {
            self.drain_cnodes(cnode);
        }
        Some(slot)
    }

    fn remove_one(&mut self, id: CapabilityId) -> Option<(CapSlot, Option<KObjectId>)> {
        let node = self.nodes.remove(&id)?;
        // Deleting a cap leaves its children live. Link them to the nearest
        // surviving ancestor so revocation still reaches them.
        for child in self.nodes.values_mut() {
            if child.parent == Some(id) {
                child.parent = node.parent;
            }
        }
        let destroyed = node.object.is_some_and(object::release);
        Some((node.slot, node.cnode().filter(|_| destroyed)))
    }

    fn drain_cnodes(&mut self, first: KObjectId) {
        // Each retired CNode enters the worklist once. New CNodes cannot
        // be installed while the caller holds the derivation lock.
        let mut pending = [first; MAX_OBJECTS];
        let mut len = 1;
        while len > 0 {
            len -= 1;
            let slots = self.cnodes.remove(&pending[len]).expect("retired CNode");
            for id in slots.into_iter().flatten() {
                if let Some((_, Some(cnode))) = self.remove_one(id) {
                    pending[len] = cnode;
                    len += 1;
                }
            }
        }
    }

    fn grant_node(&self, grant: CapGrant, owner: u64) -> Result<Node, ErrorCode> {
        let parent = self.validate_grant(grant)?;
        Ok(Node {
            slot: CapSlot {
                rights: grant.rights,
                badge: grant.badge,
                ..parent.slot
            },
            parent: Some(grant.source),
            owner,
            ..parent
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

    fn require_acyclic(&self, dest: Option<KObjectId>, node: Node) -> Result<(), ErrorCode> {
        let (Some(dest), Some(source)) = (dest, node.cnode()) else {
            return Ok(());
        };
        // All CNodes have different live object-table indices. Mark each
        // one at discovery so the worklist fits even when aliases converge.
        let mut pending = [source; MAX_OBJECTS];
        let mut visited = [false; MAX_OBJECTS];
        visited[source.index()] = true;
        let mut len = 1;
        while len > 0 {
            len -= 1;
            let current = pending[len];
            if current == dest {
                return Err(ErrorCode::BadMessage);
            }
            for child in self.cnodes[&current]
                .iter()
                .flatten()
                .filter_map(|id| self.nodes.get(id)?.cnode())
            {
                if !visited[child.index()] {
                    visited[child.index()] = true;
                    pending[len] = child;
                    len += 1;
                }
            }
        }
        Ok(())
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

    fn owned_after(&self, owner: u64, previous: CapabilityId) -> Option<CapabilityId> {
        self.nodes
            .range((Excluded(previous), Unbounded))
            .find_map(|(&id, node)| (node.owner == owner).then_some(id))
    }
}

static DERIVATIONS: Mutex<DerivationTree> = Mutex::new(DerivationTree {
    nodes: BTreeMap::new(),
    cnodes: BTreeMap::new(),
    next: 1,
    next_space: 1,
});

#[derive(Clone, Copy)]
struct SlotAddress {
    cnode: Option<KObjectId>,
    index: usize,
}

/// A process's capability namespace with an implicit root table.
pub struct CSpace {
    slots: Vec<Option<CapabilityId>>,
    id: u64,
}

fn empty_slots(radix_bits: u64) -> Result<Vec<Option<CapabilityId>>, ErrorCode> {
    if radix_bits > u64::from(MAX_CNODE_RADIX) {
        return Err(ErrorCode::BadMessage);
    }
    let count = 1 << radix_bits;
    let mut slots = Vec::new();
    slots
        .try_reserve_exact(count)
        .map_err(|_| ErrorCode::NoMemory)?;
    slots.resize(count, None);
    Ok(slots)
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
        let slots = empty_slots(u64::from(radix_bits))?;
        let mut tree = DERIVATIONS.lock();
        let id = tree.next_space;
        tree.next_space = id.checked_add(1).ok_or(ErrorCode::NoMemory)?;
        Ok(Self { slots, id })
    }

    fn slots<'a>(
        &'a self,
        tree: &'a DerivationTree,
        cnode: Option<KObjectId>,
    ) -> &'a [Option<CapabilityId>] {
        match cnode {
            Some(cnode) => &tree.cnodes[&cnode],
            None => &self.slots,
        }
    }

    fn slot_mut<'a>(
        &'a mut self,
        tree: &'a mut DerivationTree,
        address: SlotAddress,
    ) -> &'a mut Option<CapabilityId> {
        let slots = match address.cnode {
            Some(cnode) => tree.cnodes.get_mut(&cnode).expect("resolved CNode"),
            None => &mut self.slots,
        };
        &mut slots[address.index]
    }

    fn resolve(
        &self,
        tree: &DerivationTree,
        cptr: u64,
        writable: bool,
    ) -> Result<SlotAddress, ErrorCode> {
        self.resolve_with(tree, cptr, writable, |_, _| {})
    }

    fn resolve_with(
        &self,
        tree: &DerivationTree,
        cptr: u64,
        writable: bool,
        mut visit: impl FnMut(usize, CapabilityId),
    ) -> Result<SlotAddress, ErrorCode> {
        let depth = cptr_depth(cptr)?;
        let rights = if writable {
            CapRights::READ.union(CapRights::WRITE)
        } else {
            CapRights::READ
        };
        let mut cnode = None;
        for level in (1..depth).rev() {
            let index = ((cptr >> (level * 8)) as u8) as usize;
            let (id, node) = self.live_node(tree, SlotAddress { cnode, index })?;
            cnode = Some(node.cnode().ok_or(ErrorCode::InvalidCap)?);
            if !node.slot.rights.contains(rights) {
                return Err(ErrorCode::CapRightsViolation);
            }
            visit(level, id);
        }
        let index = cptr as u8 as usize;
        if index >= self.slots(tree, cnode).len() {
            return Err(ErrorCode::InvalidCap);
        }
        Ok(SlotAddress { cnode, index })
    }

    pub(crate) fn lookup_path(&self, cptr: u64) -> Result<(CapabilityPath, CapSlot), ErrorCode> {
        let tree = DERIVATIONS.lock();
        self.lookup_path_locked(&tree, cptr)
    }

    fn lookup_path_locked(
        &self,
        tree: &DerivationTree,
        cptr: u64,
    ) -> Result<(CapabilityPath, CapSlot), ErrorCode> {
        let mut path = [0; MAX_CPTR_DEPTH];
        let address = self.resolve_with(tree, cptr, false, |level, id| path[level] = id.0)?;
        let (id, node) = self.live_node(tree, address)?;
        path[0] = id.0;
        Ok((CapabilityPath(path), node.slot))
    }

    pub(crate) fn device_mmio(
        &self,
        cptr: u64,
        rights: CapRights,
    ) -> Result<(CapabilityPath, MmioPin), ErrorCode> {
        let tree = DERIVATIONS.lock();
        let (path, cap) = self.lookup_path_locked(&tree, cptr)?;
        let CapType::Mmio(id) = cap.cap_type else {
            return Err(ErrorCode::InvalidCap);
        };
        if !cap.rights.contains(rights) {
            return Err(ErrorCode::CapRightsViolation);
        }
        Ok((path, MmioPin::new(KObjectId(id))?))
    }

    pub(crate) fn dma_buffer(
        &self,
        cptr: u64,
        rights: CapRights,
    ) -> Result<(CapabilityPath, DmaPin), ErrorCode> {
        let tree = DERIVATIONS.lock();
        let (path, cap) = self.lookup_path_locked(&tree, cptr)?;
        let CapType::DmaBuffer(id) = cap.cap_type else {
            return Err(ErrorCode::InvalidCap);
        };
        if !cap.rights.contains(rights) {
            return Err(ErrorCode::CapRightsViolation);
        }
        Ok((path, DmaPin::new(KObjectId(id))?))
    }

    pub(crate) fn pci_device(&self, cptr: u64) -> Result<(CapabilityPath, PciPin), ErrorCode> {
        let tree = DERIVATIONS.lock();
        let (path, cap) = self.lookup_path_locked(&tree, cptr)?;
        let CapType::PciDevice(id) = cap.cap_type else {
            return Err(ErrorCode::InvalidCap);
        };
        if !cap.rights.contains(CapRights::WRITE) {
            return Err(ErrorCode::CapRightsViolation);
        }
        Ok((path, PciPin::new(KObjectId(id))?))
    }

    fn live_node(
        &self,
        tree: &DerivationTree,
        address: SlotAddress,
    ) -> Result<(CapabilityId, Node), ErrorCode> {
        let id = self
            .slots(tree, address.cnode)
            .get(address.index)
            .copied()
            .flatten()
            .ok_or(ErrorCode::InvalidCap)?;
        let node = *tree.nodes.get(&id).ok_or(ErrorCode::InvalidCap)?;
        // Sharing a CNode cannot expose capabilities that their holders
        // could not grant directly.
        if !node.visible_to(self.id) {
            return Err(ErrorCode::CapRightsViolation);
        }
        Ok((id, node))
    }

    fn lookup_node(
        &self,
        tree: &DerivationTree,
        cptr: u64,
    ) -> Result<(CapabilityId, Node), ErrorCode> {
        self.live_node(tree, self.resolve(tree, cptr, false)?)
    }

    fn vacant(&self, address: SlotAddress, tree: &DerivationTree) -> Result<(), ErrorCode> {
        match self.slots(tree, address.cnode)[address.index] {
            Some(id) if tree.nodes.contains_key(&id) => Err(ErrorCode::SlotOccupied),
            _ => Ok(()),
        }
    }

    pub(crate) fn capability_id(&self, cptr: u64) -> Result<CapabilityId, ErrorCode> {
        self.lookup_node(&DERIVATIONS.lock(), cptr)
            .map(|(id, _)| id)
    }

    /// Resolve a live slot to its descriptor.
    pub fn lookup(&self, cptr: u64) -> Result<CapSlot, ErrorCode> {
        self.lookup_node(&DERIVATIONS.lock(), cptr)
            .map(|(_, node)| node.slot)
    }

    pub(crate) fn shared_frame(
        &self,
        cptr: u64,
        rights: CapRights,
    ) -> Result<(CapabilityId, FramePin), ErrorCode> {
        let tree = DERIVATIONS.lock();
        let (id, node) = self.lookup_node(&tree, cptr)?;
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
        let tree = DERIVATIONS.lock();
        let (_, node) = self.lookup_node(&tree, cptr)?;
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
        let mut tree = DERIVATIONS.lock();
        let (source, node) = self.lookup_node(&tree, cptr)?;
        let dest = self.resolve(&tree, destination, true)?;
        if !matches!(node.slot.cap_type, CapType::Untyped { .. }) {
            return Err(ErrorCode::InvalidCap);
        }
        if !node.slot.rights.contains(CapRights::WRITE) {
            return Err(ErrorCode::CapRightsViolation);
        }
        let region = node.object.ok_or(ErrorCode::InvalidCap)?;
        self.vacant(dest, &tree)?;

        let cnode_slots = if kind == RetypeKind::CNode {
            Some(empty_slots(size_bits)?)
        } else {
            None
        };
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
            owner: self.id,
        });
        match installed {
            Ok(id) => {
                if let Some(slots) = cnode_slots {
                    tree.cnodes.insert(object, slots);
                }
                *self.slot_mut(&mut tree, dest) = Some(id);
                Ok(())
            }
            Err(error) => {
                object::deallocate(object);
                Err(error)
            }
        }
    }

    pub(crate) fn claim_irq(
        &mut self,
        control: u64,
        destination: u64,
        irq_num: u32,
    ) -> Result<(), ErrorCode> {
        self.allocate_device_object(control, destination, |cap| {
            if cap != CapType::IrqControl {
                return Err(ErrorCode::InvalidCap);
            }
            let object = object::allocate_irq(irq_num)?;
            Ok((
                object,
                CapType::Irq {
                    irq_num,
                    id: object.0,
                },
            ))
        })
    }

    pub(crate) fn claim_pci_device(
        &mut self,
        control: u64,
        destination: u64,
        address: PciAddress,
    ) -> Result<(), ErrorCode> {
        self.allocate_device_object(control, destination, |cap| {
            if cap != CapType::PciControl {
                return Err(ErrorCode::InvalidCap);
            }
            let object = object::allocate_pci_device(address)?;
            Ok((object, CapType::PciDevice(object.0)))
        })
    }

    pub(crate) fn open_pci_bar(
        &mut self,
        source: u64,
        destination: u64,
        bar: usize,
        first: u64,
        pages: u64,
    ) -> Result<(), ErrorCode> {
        self.allocate_device_object(source, destination, |cap| {
            let CapType::PciDevice(device) = cap else {
                return Err(ErrorCode::InvalidCap);
            };
            let object = object::allocate_mmio(KObjectId(device), bar, first, pages)?;
            Ok((object, CapType::Mmio(object.0)))
        })
    }

    fn allocate_device_object(
        &mut self,
        cptr: u64,
        destination: u64,
        allocate: impl FnOnce(CapType) -> Result<(KObjectId, CapType), ErrorCode>,
    ) -> Result<(), ErrorCode> {
        let mut tree = DERIVATIONS.lock();
        let (source, node) = self.lookup_node(&tree, cptr)?;
        if !node.slot.rights.contains(CapRights::WRITE) {
            return Err(ErrorCode::CapRightsViolation);
        }
        let destination = self.resolve(&tree, destination, true)?;
        self.vacant(destination, &tree)?;
        let (object, cap_type) = allocate(node.slot.cap_type)?;
        let node = Node {
            slot: CapSlot {
                cap_type,
                rights: CapRights::READ
                    .union(CapRights::WRITE)
                    .union(CapRights::GRANT),
                badge: 0,
            },
            object: Some(object),
            parent: Some(source),
            owner: self.id,
        };
        match tree.install(node) {
            Ok(id) => {
                *self.slot_mut(&mut tree, destination) = Some(id);
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
            CapType::IrqControl
            | CapType::PciControl
            | CapType::IoPort { .. }
            | CapType::Framebuffer => None,
            CapType::Null
            | CapType::Irq { .. }
            | CapType::PciDevice(_)
            | CapType::Mmio(_)
            | CapType::DmaBuffer(_)
            | CapType::Frame { .. }
            | CapType::Untyped { .. } => return Err(ErrorCode::InvalidCap),
        };
        self.install(cptr, slot, object)
    }

    fn install(
        &mut self,
        cptr: u64,
        slot: CapSlot,
        object: Option<KObjectId>,
    ) -> Result<(), ErrorCode> {
        let mut tree = DERIVATIONS.lock();
        let dest = self.resolve(&tree, cptr, true)?;
        self.vacant(dest, &tree)?;
        let node = Node {
            slot,
            object,
            parent: None,
            owner: self.id,
        };
        if let Some(cnode) = node.cnode() {
            if !tree.cnodes.contains_key(&cnode) {
                return Err(ErrorCode::InvalidCap);
            }
        }
        tree.require_acyclic(dest.cnode, node)?;
        let id = tree.install(node)?;
        *self.slot_mut(&mut tree, dest) = Some(id);
        Ok(())
    }

    /// Delete the slot. Object storage is reclaimed after its last reference.
    pub fn delete(&mut self, cptr: u64) -> Result<CapSlot, ErrorCode> {
        let mut tree = DERIVATIONS.lock();
        let address = self.resolve(&tree, cptr, true)?;
        if let Some(id) = self.slots(&tree, address.cnode)[address.index] {
            if tree
                .nodes
                .get(&id)
                .is_some_and(|node| !node.visible_to(self.id))
            {
                return Err(ErrorCode::CapRightsViolation);
            }
        }
        let Some(id) = self.slot_mut(&mut tree, address).take() else {
            return Ok(NULL_SLOT);
        };
        Ok(tree.remove(id).unwrap_or(NULL_SLOT))
    }

    pub(super) fn move_cap(&mut self, source: u64, dest: u64) -> Result<(), ErrorCode> {
        let mut tree = DERIVATIONS.lock();
        let source = self.resolve(&tree, source, true)?;
        let (id, node) = self.live_node(&tree, source)?;
        let dest = self.resolve(&tree, dest, true)?;
        self.vacant(dest, &tree)?;
        tree.require_acyclic(dest.cnode, node)?;
        *self.slot_mut(&mut tree, source) = None;
        *self.slot_mut(&mut tree, dest) = Some(id);
        Ok(())
    }

    pub(super) fn mint(
        &mut self,
        source: u64,
        dest: u64,
        rights: CapRights,
        badge: u64,
    ) -> Result<(), ErrorCode> {
        let mut tree = DERIVATIONS.lock();
        let (source, _) = self.lookup_node(&tree, source)?;
        self.install_grant(
            &mut tree,
            dest,
            CapGrant {
                source,
                rights,
                badge,
            },
        )
    }

    #[cfg(test)]
    pub(crate) fn derive(
        &mut self,
        source: CapabilityId,
        dest: u64,
        rights: CapRights,
        badge: u64,
    ) -> Result<(), ErrorCode> {
        let mut tree = DERIVATIONS.lock();
        self.install_grant(
            &mut tree,
            dest,
            CapGrant {
                source,
                rights,
                badge,
            },
        )
    }

    fn install_grant(
        &mut self,
        tree: &mut DerivationTree,
        dest: u64,
        grant: CapGrant,
    ) -> Result<(), ErrorCode> {
        let dest = self.resolve(tree, dest, true)?;
        self.vacant(dest, tree)?;
        let node = tree.grant_node(grant, self.id)?;
        tree.require_acyclic(dest.cnode, node)?;
        let id = tree.install(node)?;
        *self.slot_mut(tree, dest) = Some(id);
        Ok(())
    }

    pub(crate) fn revoke(&mut self, source: u64) -> Result<(), ErrorCode> {
        let mut tree = DERIVATIONS.lock();
        let address = self.resolve(&tree, source, true)?;
        let (id, _) = self.live_node(&tree, address)?;
        tree.revoke(id);
        Ok(())
    }

    pub(crate) fn revoke_all_descendants(&mut self) {
        let mut tree = DERIVATIONS.lock();
        // A move into a shared CNode does not change who installed the cap.
        // Reap this space's derivations wherever its slots now reside.
        let mut previous = CapabilityId(0);
        while let Some(id) = tree.owned_after(self.id, previous) {
            tree.revoke(id);
            previous = id;
        }
    }

    pub(crate) fn prepare_grant(
        &self,
        source: u64,
        rights: CapRights,
        badge: u64,
    ) -> Result<CapGrant, ErrorCode> {
        let tree = DERIVATIONS.lock();
        let grant = CapGrant {
            source: self.lookup_node(&tree, source)?.0,
            rights,
            badge,
        };
        tree.validate_grant(grant)?;
        Ok(grant)
    }

    pub(crate) fn accept_grants(
        &mut self,
        first: u64,
        expected_cnode: Option<KObjectId>,
        grants: &[Option<CapGrant>],
    ) -> Result<(), ErrorCode> {
        if grants.is_empty() {
            return Ok(());
        }
        if grants.len() > IPC_CAP_SLOTS {
            return Err(ErrorCode::BadMessage);
        }
        let mut tree = DERIVATIONS.lock();
        let first = self.resolve(&tree, first, true)?;
        if first.cnode != expected_cnode {
            return Err(ErrorCode::InvalidCap);
        }
        let end = first
            .index
            .checked_add(grants.len())
            .filter(|&end| end <= self.slots(&tree, first.cnode).len())
            .ok_or(ErrorCode::InvalidCap)?;
        for index in first.index..end {
            self.vacant(SlotAddress { index, ..first }, &tree)?;
        }

        let mut installed = [None; IPC_CAP_SLOTS];
        for (slot, grant) in installed.iter_mut().zip(grants) {
            let result = (|| {
                let node = tree.grant_node(grant.ok_or(ErrorCode::BadMessage)?, self.id)?;
                tree.require_acyclic(first.cnode, node)?;
                tree.install(node)
            })();
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
        for (index, id) in (first.index..end).zip(installed) {
            *self.slot_mut(&mut tree, SlotAddress { index, ..first }) = id;
        }
        Ok(())
    }

    pub(crate) fn receive_cnode(&self, first: u64) -> Result<Option<KObjectId>, ErrorCode> {
        let tree = DERIVATIONS.lock();
        Ok(self.resolve(&tree, first, true)?.cnode)
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
        let tree = DERIVATIONS.lock();
        self.vacant(self.resolve(&tree, cptr, true)?, &tree)
    }
}

impl Drop for CSpace {
    fn drop(&mut self) {
        let mut tree = DERIVATIONS.lock();
        let mut previous = CapabilityId(0);
        while let Some(id) = tree.owned_after(self.id, previous) {
            tree.remove(id);
            previous = id;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruzt_abi::cptr_path;
    use ruzt_cap::EndpointId;

    fn cnode(space: &mut CSpace, cptr: u64, radix_bits: u8) -> KObjectId {
        let object = object::allocate(CapType::CNode { radix_bits, ptr: 0 }).unwrap();
        DERIVATIONS
            .lock()
            .cnodes
            .insert(object, empty_slots(u64::from(radix_bits)).unwrap());
        space
            .insert(
                cptr,
                CapSlot {
                    cap_type: CapType::CNode {
                        radix_bits,
                        ptr: object.0,
                    },
                    rights: CapRights::new(),
                    badge: 0,
                },
            )
            .unwrap();
        object
    }

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
            receiver.accept_grants(0, None, &grants),
            Err(ErrorCode::InvalidCap)
        );
        assert_eq!(receiver.lookup(0), Err(ErrorCode::InvalidCap));
        assert_eq!(receiver.lookup(1), Err(ErrorCode::InvalidCap));
        sender.delete(0).unwrap();
        assert_eq!(object::get(first), None);
    }

    #[test]
    fn cnode_cycles_fail_and_final_references_drain_nested_tables() {
        let _state = crate::isolated_kernel_state();
        let mut space = CSpace::new(2);
        let child = cptr_path(&[0, 1]).unwrap();
        let leaf = cptr_path(&[0, 1, 0]).unwrap();
        let outer = cnode(&mut space, 0, 1);
        let inner = cnode(&mut space, child, 1);
        assert_eq!(space.move_cap(0, leaf), Err(ErrorCode::BadMessage));
        assert_eq!(
            space.mint(child, cptr_path(&[0, 1, 1]).unwrap(), CapRights::READ, 0),
            Err(ErrorCode::BadMessage)
        );
        let endpoint = endpoint(&mut space, leaf);
        space.delete(0).unwrap();
        assert_eq!(space.lookup(leaf), Err(ErrorCode::InvalidCap));
        for object in [outer, inner, endpoint] {
            assert_eq!(object::get(object), None);
        }
    }

    #[test]
    fn shared_cnode_views_preserve_slot_rights_and_exit_ownership() {
        let _state = crate::isolated_kernel_state();
        let mut owner = CSpace::new(2);
        let mut peer = CSpace::new(2);
        cnode(&mut owner, 0, 2);
        cnode(&mut owner, cptr_path(&[0, 0]).unwrap(), 2);
        let id = owner.capability_id(0).unwrap();
        peer.derive(id, 0, CapRights::READ, 0).unwrap();
        peer.derive(id, 1, CapRights::READ.union(CapRights::WRITE), 0)
            .unwrap();

        let owned = cptr_path(&[0, 0, 0]).unwrap();
        let peer_rw = cptr_path(&[1, 0, 0]).unwrap();
        let original = endpoint(&mut owner, owned);
        let (owner_path, _) = owner.lookup_path(owned).unwrap();
        let (peer_path, _) = peer.lookup_path(owned).unwrap();
        assert!(peer_path.is_live());
        assert_eq!(
            peer.lookup(owned).unwrap().cap_type,
            CapType::Endpoint(EndpointId(original.0))
        );
        assert_eq!(peer.move_cap(owned, 2), Err(ErrorCode::CapRightsViolation));

        let private = cptr_path(&[0, 0, 1]).unwrap();
        owner.mint(owned, private, CapRights::READ, 0).unwrap();
        assert_eq!(
            peer.lookup(cptr_path(&[1, 0, 1]).unwrap()),
            Err(ErrorCode::CapRightsViolation)
        );
        assert_eq!(
            peer.delete(cptr_path(&[1, 0, 1]).unwrap()),
            Err(ErrorCode::CapRightsViolation)
        );
        peer.mint(peer_rw, 2, CapRights::READ, 0).unwrap();
        peer.revoke_all_descendants();
        assert!(owner.lookup(owned).is_ok());
        owner.revoke_all_descendants();
        assert!(owner_path.is_live());
        assert!(!peer_path.is_live());
        assert_eq!(peer.lookup(2), Err(ErrorCode::InvalidCap));
        assert_eq!(peer.lookup(peer_rw), Err(ErrorCode::InvalidCap));
    }

    #[test]
    fn receiving_into_cnodes_checks_cycles_boundaries_and_retargeting() {
        let _state = crate::isolated_kernel_state();
        let mut space = CSpace::new(2);
        let table = cnode(&mut space, 0, 1);
        cnode(&mut space, 1, 1);
        endpoint(&mut space, 2);
        let grant = space.prepare_grant(2, CapRights::READ, 1).unwrap();
        let cycle = space.prepare_grant(0, CapRights::READ, 0).unwrap();
        let first = cptr_path(&[0, 0]).unwrap();
        let last = cptr_path(&[0, 1]).unwrap();
        assert_eq!(space.receive_cnode(first), Ok(Some(table)));
        assert_eq!(
            space.accept_grants(last, Some(table), &[Some(grant), Some(grant)]),
            Err(ErrorCode::InvalidCap)
        );
        assert_eq!(
            space.accept_grants(first, Some(table), &[Some(grant), Some(cycle)]),
            Err(ErrorCode::BadMessage)
        );
        assert_eq!(space.lookup(first), Err(ErrorCode::InvalidCap));
        space.move_cap(0, 3).unwrap();
        space.move_cap(1, 0).unwrap();
        assert_eq!(
            space.accept_grants(first, Some(table), &[Some(grant)]),
            Err(ErrorCode::InvalidCap)
        );
        space
            .accept_grants(
                cptr_path(&[3, 0]).unwrap(),
                Some(table),
                &[Some(grant), Some(grant)],
            )
            .unwrap();
        assert_eq!(space.lookup(cptr_path(&[3, 1]).unwrap()).unwrap().badge, 1);
    }
}
