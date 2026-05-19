//! 8253/8254 Programmable Interval Timer (PIT) driver.

use x86_64::instructions::port::PortWriteOnly;

const PIT_CMD: u16 = 0x43;
const PIT_CH0: u16 = 0x40;

/// PIT oscillator frequency in Hz (1.193182 MHz).
// Verified against OSDev Wiki: https://wiki.osdev.org/PIT
const _PIT_FREQUENCY: u32 = 1_193_182;

/// Desired tick rate in Hz.
const _DESIRED_HZ: u32 = 100;

/// Divisor for ~10 ms ticks.
// 1_193_182 / 100 = 11_931.82; round to nearest integer.
const DIVISOR: u16 = 11_932;

/// Configure PIT channel 0 for ~10 ms ticks in rate-generator mode.
///
/// # Safety
/// Must be called exactly once after PIC initialisation and before
/// interrupts are enabled.
pub unsafe fn init() {
    // SAFETY: I/O ports 0x43 and 0x40 are the 8253/8254 PIT command and
    // channel-0 data ports. These writes configure channel 0 in rate-generator
    // mode with the correct divisor.
    unsafe {
        PortWriteOnly::new(PIT_CMD).write(0x34u8);

        PortWriteOnly::new(PIT_CH0).write((DIVISOR & 0xFF) as u8);
        PortWriteOnly::new(PIT_CH0).write((DIVISOR >> 8) as u8);
    }
}
