//! PL011 UART console implementation of [`Console`] for QEMU virt machine.

use ruzt_hal::io::Console;

const UART_BASE: usize = 0x0900_0000;
const UARTFR: *const u32 = (UART_BASE + 0x018) as *const u32;
const UARTDR: *mut u32 = (UART_BASE + 0x000) as *mut u32;
const TXFF: u32 = 1 << 5;

/// PL011 UART console for aarch64 QEMU `virt` machine.
pub struct Pl011Uart;

impl Pl011Uart {
    /// Initialise the underlying UART.
    pub fn init() {
        // PL011 on QEMU virt is pre-initialised.
    }
}

impl Console for Pl011Uart {
    fn write_bytes(&self, bytes: &[u8]) {
        for &byte in bytes {
            while unsafe { core::ptr::read_volatile(UARTFR) } & TXFF != 0 {
                core::hint::spin_loop();
            }
            unsafe { core::ptr::write_volatile(UARTDR, byte as u32); }
        }
    }
}
