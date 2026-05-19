//! ARM Generic Timer for aarch64.

use core::sync::atomic::{AtomicU64, Ordering};
use ruzt_hal::time::Timer;

/// Global tick counter incremented by the timer ISR.
static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Stored deadline for one-shot timer emulation.
static DEADLINE: AtomicU64 = AtomicU64::new(u64::MAX);

/// Read CNTFRQ_EL0 (counter frequency).
pub fn get_counter_frequency() -> u64 {
    let freq: u64;
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq); }
    freq
}

/// Read CNTPCT_EL0 (physical counter value).
pub fn read_counter() -> u64 {
    let cnt: u64;
    unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) cnt); }
    cnt
}

/// aarch64 timer (ARM Generic Timer — CNTPCT_EL0 / CNTFRQ_EL0).
pub struct AArch64Timer;

impl Timer for AArch64Timer {
    fn now_monotonic_ns() -> u64 {
        let freq = get_counter_frequency();
        let count = read_counter();
        if freq == 0 {
            return 0;
        }
        count * 1_000_000_000 / freq
    }

    fn set_oneshot_ns(deadline_ns: u64) {
        DEADLINE.store(deadline_ns, Ordering::Relaxed);
    }
}

/// Called by the timer ISR on each tick.
pub fn increment_tick() {
    TICK_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Returns `true` if the deadline set by [`Timer::set_oneshot_ns`] has passed.
///
/// Not a true hardware one-shot — this is a polling check sufficient
/// to satisfy the trait contract until GIC timer programming arrives.
pub fn is_deadline_passed() -> bool {
    AArch64Timer::now_monotonic_ns() >= DEADLINE.load(Ordering::Relaxed)
}
