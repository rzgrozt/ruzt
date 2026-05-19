//! Console output abstraction.
//!
//! SOURCE: Design Report §8 — Console trait

/// A write-only byte stream — the lowest-level kernel console output.
///
/// Implemented by the HAL backend (e.g., UART for serial, framebuffer for VGA).
// SOURCE: Design Report §8 — Console trait skeleton
pub trait Console: Send + Sync {
    /// Write raw bytes to the console. Must not block indefinitely.
    fn write_bytes(&self, bytes: &[u8]);
}
