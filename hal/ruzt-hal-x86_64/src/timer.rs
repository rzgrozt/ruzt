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
/// Must be called exactly once after IRQ routing is initialized and before
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

/// Delay using the independent PIT channel 2 one-shot during AP startup.
///
/// # Safety
/// Call on the boot CPU with exclusive access to the PIT and speaker ports.
/// Keep interrupts disabled. The firmware routes IRQ0 separately on channel 0.
pub unsafe fn startup_delay_us(microseconds: u16) -> bool {
    use x86_64::instructions::port::Port;
    let ticks = (u64::from(microseconds) * u64::from(_PIT_FREQUENCY)).div_ceil(1_000_000);
    let Ok(ticks) = u16::try_from(ticks) else {
        return false;
    };
    if ticks == 0 {
        return true;
    }
    let mut control = Port::<u8>::new(0x61);
    // SAFETY: The caller owns all these legacy timers during CPU startup.
    unsafe {
        let saved = control.read();
        control.write(saved & !3);
        PortWriteOnly::new(PIT_CMD).write(0xb0u8); // Channel 2, mode 0.
        let mut count = PortWriteOnly::new(0x42);
        count.write(ticks as u8);
        count.write((ticks >> 8) as u8);
        control.write((saved & !2) | 1);
        for _ in 0..1_000_000 {
            if control.read() & (1 << 5) != 0 {
                control.write(saved);
                return true;
            }
            core::hint::spin_loop();
        }
        control.write(saved);
    }
    false
}
