//! COM1 serial console implementation of [`Console`].

use ruzt_hal::io::Console;
use spin::Mutex;
use uart_16550::SerialPort;

/// COM1 base I/O port address.
const COM1: u16 = 0x3F8;

/// Global COM1 serial port protected by a spinlock.
static COM1_PORT: Mutex<SerialPort> = Mutex::new(unsafe { SerialPort::new(COM1) });

/// x86_64 serial console backed by COM1.
pub struct SerialConsole;

impl SerialConsole {
    /// Initialise the underlying UART. Must be called once before any output.
    pub fn init() {
        COM1_PORT.lock().init();
    }
}

impl Console for SerialConsole {
    fn write_bytes(&self, bytes: &[u8]) {
        let mut port = COM1_PORT.lock();
        for &byte in bytes {
            port.send(byte);
        }
    }
}
