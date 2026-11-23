//! 8259A Programmable Interrupt Controller (PIC) driver.

use x86_64::instructions::port::{Port, PortWriteOnly};

const MASTER_CMD: u16 = 0x20;
const MASTER_DATA: u16 = 0x21;
const SLAVE_CMD: u16 = 0xA0;
const SLAVE_DATA: u16 = 0xA1;

const ICW1_INIT: u8 = 0x11;
const ICW4_8086: u8 = 0x01;
const CASCADE: u8 = 2;

/// Number of lines across the two cascaded PICs.
pub const IRQ_COUNT: usize = 16;

/// Whether a line can be delegated to a user device driver.
pub const fn is_device_irq(line: u32) -> bool {
    line > 0 && line < IRQ_COUNT as u32 && line != CASCADE as u32
}

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

/// Change a device IRQ mask and keep the slave cascade enabled as needed.
/// Call with interrupts disabled on the boot CPU.
pub(crate) fn set_enabled(line: u32, enabled: bool) {
    if line >= IRQ_COUNT as u32 || line == u32::from(CASCADE) {
        return;
    }
    let line = line as u8;
    // SAFETY: Both data ports are the PIC interrupt mask registers.
    unsafe {
        let mut master = Port::<u8>::new(MASTER_DATA);
        if line < 8 {
            let mask = master.read();
            master.write(with_mask(mask, line, enabled));
        } else {
            let mut slave = Port::<u8>::new(SLAVE_DATA);
            let mask = with_mask(slave.read(), line - 8, enabled);
            slave.write(mask);
            let mask_master = master.read();
            master.write(with_mask(mask_master, CASCADE, mask != u8::MAX));
        }
    }
}

const fn with_mask(mask: u8, line: u8, enabled: bool) -> u8 {
    if enabled {
        mask & !(1 << line)
    } else {
        mask | (1 << line)
    }
}

/// Detect a spurious IRQ7 or IRQ15 and acknowledge only the cascade when needed.
/// Call before acting on the line.
pub fn dismiss_spurious(line: u8) -> bool {
    let command = match line {
        7 => MASTER_CMD,
        15 => SLAVE_CMD,
        _ => return false,
    };
    // SAFETY: OCW3 selects the in-service register on the specified PIC.
    let spurious = unsafe {
        let mut port = Port::<u8>::new(command);
        port.write(0x0b);
        port.read() & 0x80 == 0
    };
    if spurious && line == 15 {
        send_eoi(CASCADE);
    }
    spurious
}
