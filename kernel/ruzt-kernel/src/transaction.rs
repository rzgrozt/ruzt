//! Serialization between kernel operations that check and update shared state.

use spin::{Mutex, MutexGuard};

static KERNEL: Mutex<()> = Mutex::new(());

/// Held from capability lookup or event delivery through the state update.
/// Acquire before the scheduler, capability, device, and mapper locks.
pub(crate) struct Transaction(Option<MutexGuard<'static, ()>>);

/// Enter with local interrupts disabled. A contending CPU must still service
/// synchronous TLB requests from the lock holder.
pub(crate) fn enter() -> Transaction {
    #[cfg(not(test))]
    debug_assert!(!x86_64::instructions::interrupts::are_enabled());
    loop {
        if let Some(guard) = KERNEL.try_lock() {
            return Transaction(Some(guard));
        }
        #[cfg(not(test))]
        crate::smp::poll_local_shootdown();
        core::hint::spin_loop();
    }
}

impl Transaction {
    /// Release after publishing the waiter under the scheduler lock. The
    /// callback switches contexts and returns only once this thread runs
    /// again. Reacquire before inspecting the completion or retrying a wait.
    pub(crate) fn park(&mut self, switch: impl FnOnce()) {
        drop(self.0.take().expect("parking requires a live transaction"));
        switch();
        *self = enter();
    }
}
