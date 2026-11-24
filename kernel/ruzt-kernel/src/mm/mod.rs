//! Memory management subsystem.

pub(crate) mod entry_stack;
pub(crate) mod exception_stack;
pub mod frame;
pub mod heap;

/// Re-export frame allocator internals for integration tests.
#[cfg(test)]
pub use frame::BitmapAllocator;
