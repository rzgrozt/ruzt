//! PIT-based timer for x86_64.

use core::sync::atomic::{AtomicU64, Ordering};
use ruzt_hal::time::Timer;

/// Each PIT tick ≈ 10 ms = 10_000_000 ns.
const NS_PER_TICK: u64 = 10_000_000;

/// Global tick counter incremented by the timer ISR.
static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Stored deadline for one-shot timer emulation.
static DEADLINE: AtomicU64 = AtomicU64::new(0);

/// x86_64 timer (PIT-based — LAPIC timer will replace this later).
pub struct X86_64Timer;

impl Timer for X86_64Timer {
    fn now_monotonic_ns() -> u64 {
        TICK_COUNT.load(Ordering::Relaxed) * NS_PER_TICK
    }

    fn set_oneshot_ns(deadline_ns: u64) {
        DEADLINE.store(deadline_ns, Ordering::Relaxed);
    }
}

/// Called by the timer ISR on each PIT tick (~10 ms).
pub fn increment_tick() {
    TICK_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Returns `true` if the deadline set by [`Timer::set_oneshot_ns`] has passed.
///
/// Not a true hardware one-shot — this is a polling check sufficient
/// to satisfy the trait contract until LAPIC timer programming arrives.
pub fn is_deadline_passed() -> bool {
    X86_64Timer::now_monotonic_ns() >= DEADLINE.load(Ordering::Relaxed)
}
