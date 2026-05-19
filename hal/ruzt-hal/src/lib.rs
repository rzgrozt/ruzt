#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Ruzt Hardware Abstraction Layer — trait surface.
//!
//! This crate contains exclusively traits and shared value types.
//! No implementations. No `unsafe`. No arch-specific code.
//! Every HAL backend (`ruzt-hal-x86_64`, `ruzt-hal-aarch64`) must satisfy
//! the contracts defined here.

pub mod boot;
pub mod cpu;
pub mod io;
pub mod irq;
pub mod mem;
pub mod time;

#[cfg(test)]
mod mock {
    use super::*;
    use mem::{FrameAllocator, MapError, Mapper, PageFlags, PhysAddr, PhysFrame, VirtAddr};

    // -- Mock FrameAllocator --
    struct MockAllocator;
    impl FrameAllocator for MockAllocator {
        fn allocate(&mut self) -> Option<PhysFrame> { None }
        fn allocate_contiguous(&mut self, _count: usize) -> Option<PhysFrame> { None }
        fn deallocate(&mut self, _frame: PhysFrame) {}
    }

    // -- Mock Mapper --
    struct MockMapper;
    impl Mapper for MockMapper {
        fn map(
            &mut self,
            _virt: VirtAddr,
            _phys: PhysFrame,
            flags: PageFlags,
        ) -> Result<(), MapError> {
            if flags.contains(PageFlags::WRITABLE | PageFlags::EXECUTABLE) {
                return Err(MapError::WriteExecute);
            }
            Ok(())
        }
        fn unmap(&mut self, _virt: VirtAddr) -> Result<PhysFrame, MapError> {
            Err(MapError::AlreadyMapped)
        }
        fn translate(&self, _virt: VirtAddr) -> Option<PhysAddr> { None }
        fn flush(&mut self, _virt: VirtAddr) {}
        fn flush_all_smp(&mut self) {}
    }

    // -- Mock CpuOps --
    struct MockGuard;
    impl Drop for MockGuard { fn drop(&mut self) {} }
    impl cpu::InterruptGuard for MockGuard {}
    struct MockCpu;
    impl cpu::CpuOps for MockCpu {
        type Guard = MockGuard;
        fn cpu_id() -> u32 { 0 }
        fn cpu_idle() {}
        fn enable_interrupts() {}
        fn disable_interrupts() -> MockGuard { MockGuard }
    }

    // -- Mock Console --
    struct MockConsole;
    impl io::Console for MockConsole {
        fn write_bytes(&self, _bytes: &[u8]) {}
    }

    // -- Mock Timer --
    struct MockTimer;
    impl time::Timer for MockTimer {
        fn now_monotonic_ns() -> u64 { 0 }
        fn set_oneshot_ns(_deadline_ns: u64) {}
    }

    // -- Mock IrqController --
    struct MockIrqCtrl;
    impl irq::IrqController for MockIrqCtrl {
        fn enable(_irq: irq::IrqNumber) {}
        fn disable(_irq: irq::IrqNumber) {}
        fn route(_irq: irq::IrqNumber, _cpu: u32) {}
        fn end_of_interrupt(_irq: irq::IrqNumber) {}
    }

    #[test]
    fn wx_violation_is_rejected() {
        let mut mapper = MockMapper;
        let frame = PhysFrame::from_base(PhysAddr::new(0x1000)).unwrap();
        let result = mapper.map(
            VirtAddr::new(0xdead_0000),
            frame,
            PageFlags::WRITABLE | PageFlags::EXECUTABLE,
        );
        assert_eq!(result, Err(MapError::WriteExecute));
    }

    #[test]
    fn phys_frame_rejects_unaligned() {
        assert!(PhysFrame::from_base(PhysAddr::new(0x1001)).is_none());
        assert!(PhysFrame::from_base(PhysAddr::new(0x1000)).is_some());
    }
}
