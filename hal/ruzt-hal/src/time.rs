//! Timer abstraction.
//!
//! SOURCE: Design Report §8 — Timer trait

/// A monotonic hardware timer.
// SOURCE: Design Report §8 — Timer trait skeleton
pub trait Timer {
    /// Returns a monotonically increasing timestamp in nanoseconds since boot.
    fn now_monotonic_ns() -> u64;
    /// Programs a one-shot interrupt to fire at `deadline_ns` nanoseconds from boot.
    fn set_oneshot_ns(deadline_ns: u64);
}
