//! 8259A Programmable Interrupt Controller (PIC) driver.

use x86_64::instructions::port::PortWriteOnly;

const MASTER_CMD: u16 = 0x20;
const MASTER_DATA: u16 = 0x21;
const SLAVE_CMD: u16 = 0xA0;
const SLAVE_DATA: u16 = 0xA1;

const ICW1_INIT: u8 = 0x11;
const ICW4_8086: u8 = 0x01;

/// Remap the PIC so IRQ0–7 map to vectors 32–39 and IRQ8–15 map to vectors 40–47,
/// then mask all interrupts except IRQ0 (timer) and IRQ1 (keyboard).
///
/// # Safety
/// Must be called exactly once during early boot, before interrupts are enabled.
pub unsafe fn init() {
    // SAFETY: I/O ports 0x20, 0x21, 0xA0, 0xA1 are the 8259A PIC ports.
    // These writes follow the exact 8259A initialisation sequence.
    unsafe {
        PortWriteOnly::new(MASTER_CMD).write(ICW1_INIT);
        PortWriteOnly::new(SLAVE_CMD).write(ICW1_INIT);

        PortWriteOnly::new(MASTER_DATA).write(0x20u8);
        PortWriteOnly::new(SLAVE_DATA).write(0x28u8);

        PortWriteOnly::new(MASTER_DATA).write(0x04u8);
        PortWriteOnly::new(SLAVE_DATA).write(0x02u8);

        PortWriteOnly::new(MASTER_DATA).write(ICW4_8086);
        PortWriteOnly::new(SLAVE_DATA).write(ICW4_8086);

        PortWriteOnly::new(MASTER_DATA).write(0xFFu8);
        PortWriteOnly::new(SLAVE_DATA).write(0xFFu8);

        PortWriteOnly::new(MASTER_DATA).write(0xFCu8);
    }
}

/// Send End-of-Interrupt for the given IRQ.
pub fn send_eoi(irq: u8) {
    // Safety: I/O ports 0x20 and 0xA0 are the PIC command ports.
    // Writing 0x20 sends EOI. This is safe when called from the
    // interrupt handler for the corresponding IRQ.
    unsafe {
        if irq >= 8 {
            PortWriteOnly::new(SLAVE_CMD).write(0x20u8);
        }
        PortWriteOnly::new(MASTER_CMD).write(0x20u8);
    }
}
