//! Stub timer for x86_64.

use ruzt_hal::time::Timer;

/// x86_64 timer (stub — LAPIC timer implementation pending scheduler task).
pub struct X86_64Timer;

impl Timer for X86_64Timer {
    fn now_monotonic_ns() -> u64 {
        todo!("LAPIC timer now_monotonic_ns")
    }
    fn set_oneshot_ns(_deadline_ns: u64) {
        todo!("LAPIC timer set_oneshot_ns")
    }
}
