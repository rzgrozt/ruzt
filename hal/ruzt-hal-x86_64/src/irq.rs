//! 8259A PIC-based interrupt controller for x86_64.

use core::sync::atomic::{AtomicU8, Ordering};
use ruzt_hal::irq::{IrqController, IrqNumber};
use x86_64::instructions::port::Port;

const MASTER_DATA: u16 = 0x21;
const SLAVE_DATA: u16 = 0xA1;

/// Current master PIC mask (bit = 1 means masked / disabled).
///
/// Initial value `0xFC` matches the state programmed by [`crate::pic::init`]
/// (IRQ0 timer and IRQ1 keyboard are unmasked; all other master IRQs masked).
static MASTER_MASK: AtomicU8 = AtomicU8::new(0xFC);

/// Current slave PIC mask (bit = 1 means masked / disabled).
///
/// Initial value `0xFF` matches the state programmed by [`crate::pic::init`]
/// (all slave IRQs are masked after init).
static SLAVE_MASK: AtomicU8 = AtomicU8::new(0xFF);

/// x86_64 interrupt controller (PIC-based — APIC will replace this later).
pub struct X86_64IrqController;

impl IrqController for X86_64IrqController {
    fn enable(irq: IrqNumber) {
        let irq = irq.0 as u8;
        if irq < 8 {
            let mut port = Port::<u8>::new(MASTER_DATA);
            let mask = MASTER_MASK.load(Ordering::Relaxed) & !(1 << irq);
            MASTER_MASK.store(mask, Ordering::Relaxed);
            unsafe { port.write(mask); }
        } else if irq < 16 {
            let irq = irq - 8;
            let mut port = Port::<u8>::new(SLAVE_DATA);
            let mask = SLAVE_MASK.load(Ordering::Relaxed) & !(1 << irq);
            SLAVE_MASK.store(mask, Ordering::Relaxed);
            unsafe { port.write(mask); }
        }
    }

    fn disable(irq: IrqNumber) {
        let irq = irq.0 as u8;
        if irq < 8 {
            let mut port = Port::<u8>::new(MASTER_DATA);
            let mask = MASTER_MASK.load(Ordering::Relaxed) | (1 << irq);
            MASTER_MASK.store(mask, Ordering::Relaxed);
            unsafe { port.write(mask); }
        } else if irq < 16 {
            let irq = irq - 8;
            let mut port = Port::<u8>::new(SLAVE_DATA);
            let mask = SLAVE_MASK.load(Ordering::Relaxed) | (1 << irq);
            SLAVE_MASK.store(mask, Ordering::Relaxed);
            unsafe { port.write(mask); }
        }
    }

    fn route(_irq: IrqNumber, _cpu: u32) {
        // PIC does not support per-CPU routing; APIC impl will replace this.
    }

    fn end_of_interrupt(irq: IrqNumber) {
        crate::pic::send_eoi(irq.0 as u8);
    }
}
