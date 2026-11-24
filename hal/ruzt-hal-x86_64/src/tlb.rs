//! Local x86 invalidation and the mapper's synchronous SMP hooks.

use ruzt_hal::mem::{PhysFrame, VirtAddr};
use spin::Once;
use x86_64::{
    instructions::tlb,
    registers::control::{Cr3, Cr4, Cr4Flags},
    VirtAddr as X64VirtAddr,
};

/// A page-table change to synchronize with other logical CPUs.
#[derive(Clone, Copy)]
pub enum Invalidation {
    /// A shared supervisor address, including a possible global entry.
    Page(VirtAddr),
    /// All translations, including global entries and paging-structure caches.
    All,
    /// Non-global translations and paging-structure caches of a user root.
    User(PhysFrame),
    /// Confirm a root being destroyed has no active CPU references.
    Inactive(PhysFrame),
}

pub(crate) struct Hooks {
    pub(crate) remote: fn(Invalidation),
    pub(crate) poll: fn(),
}

pub(crate) static HOOKS: Once<Hooks> = Once::new();

/// Install the kernel's IPI transport before additional CPUs use the mapper.
///
/// The mapper serializes remote requests and waits for completion. The
/// polling hook must service only pending local invalidations without
/// acquiring the mapper lock. Both hooks run with interrupts disabled.
pub fn install(remote: fn(Invalidation), poll: fn()) {
    HOOKS.call_once(|| Hooks { remote, poll });
}

/// Perform one change's local invalidation or check with interrupts disabled.
pub fn apply_local(request: Invalidation) {
    let flags = Cr4::read();
    assert!(
        !flags.contains(Cr4Flags::PCID),
        "TLB shootdown requires PCID disabled"
    );
    let current = || Cr3::read().0.start_address().as_u64();
    match request {
        Invalidation::Page(address) => tlb::flush(X64VirtAddr::new(address.as_u64())),
        Invalidation::All if flags.contains(Cr4Flags::PAGE_GLOBAL) => {
            // SAFETY: Changing PGE invalidates global entries as well as
            // non-global ones. Restore every other CR4 setting unchanged.
            unsafe {
                Cr4::write(flags - Cr4Flags::PAGE_GLOBAL);
                Cr4::write(flags);
            }
        }
        Invalidation::All => tlb::flush_all(),
        Invalidation::User(root) => {
            // User mappings are non-global. A later CR3 load flushes an
            // inactive root before any CPU can use it.
            if current() == root.base.as_u64() {
                tlb::flush_all();
            }
        }
        Invalidation::Inactive(root) => {
            assert_ne!(
                current(),
                root.base.as_u64(),
                "destroying an active user root"
            );
        }
    }
}

pub(crate) fn synchronize(request: Invalidation) {
    apply_local(request);
    if let Some(hooks) = HOOKS.get() {
        (hooks.remote)(request);
    }
}
