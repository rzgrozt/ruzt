//! Memory management subsystem.

pub mod frame;
pub mod heap;

/// Re-export frame allocator internals for integration tests.
#[cfg(test)]
pub use frame::BitmapAllocator;
