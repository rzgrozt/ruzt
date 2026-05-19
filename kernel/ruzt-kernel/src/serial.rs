//! Serial port I/O via COM1.

use core::fmt;
use spin::{Lazy, Mutex};
use uart_16550::SerialPort;
use x86_64::instructions::interrupts;

/// COM1 base I/O port address.
const COM1: u16 = 0x3F8;

/// Global serial port handle protected by a spinlock.
///
/// Call `SERIAL1.lock().init()` once during early boot before any I/O.
pub static SERIAL1: Lazy<Mutex<SerialPort>> = Lazy::new(|| {
    #[allow(unsafe_code)]
    // Safety: COM1 (0x3F8) is the well-known base port for the primary
    // serial port on IBM PC-compatible hardware.
    Mutex::new(unsafe { SerialPort::new(COM1) })
});

/// Prints to the serial console without a trailing newline.
#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::serial::_print(format_args!($($arg)*))
    };
}

/// Prints to the serial console with a trailing newline.
#[macro_export]
macro_rules! serial_println {
    () => ($crate::serial_print!("\n"));
    ($($arg:tt)*) => {
        $crate::serial_print!("{}\n", format_args!($($arg)*))
    };
}

/// Internal helper used by `serial_print!` / `serial_println!`.
#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    interrupts::without_interrupts(|| {
        let mut serial = SERIAL1.lock();
        struct Writer<'a>(&'a mut SerialPort);
        impl<'a> fmt::Write for Writer<'a> {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                for byte in s.bytes() {
                    self.0.send(byte);
                }
                Ok(())
            }
        }
        let _ = fmt::Write::write_fmt(&mut Writer(&mut serial), args);
    });
}
