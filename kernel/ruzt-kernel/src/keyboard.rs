//! PS/2 keyboard scancode handling.

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use x86_64::instructions::port::PortReadOnly;

static SCANCODE_READY: AtomicBool = AtomicBool::new(false);
static SCANCODE: AtomicU8 = AtomicU8::new(0);

/// Called from the keyboard ISR (vector 33).
/// Reads the scancode from port 0x60 and stores it in a global buffer.
#[allow(unsafe_code)]
pub fn on_interrupt() {
    let scancode: u8 = unsafe { PortReadOnly::new(0x60).read() };

    // Ignore release scancodes (bit 7 set).
    if scancode < 0x80 {
        SCANCODE.store(scancode, Ordering::Relaxed);
        SCANCODE_READY.store(true, Ordering::Relaxed);
    }
}

/// Try to read a scancode from the interrupt buffer.
/// Returns `Some(scancode)` if a new scancode has arrived since the last call.
pub fn try_read() -> Option<u8> {
    if SCANCODE_READY.swap(false, Ordering::Relaxed) {
        Some(SCANCODE.load(Ordering::Relaxed))
    } else {
        None
    }
}

/// Convert a press scancode (set 1, US QWERTY) to an ASCII character.
/// Returns `None` for scancodes with no mapping.
pub fn scancode_to_ascii(scancode: u8) -> Option<char> {
    const TABLE: [u8; 128] = [
        // 0x00-0x07
        0,    0,    b'1', b'2', b'3', b'4', b'5', b'6',
        // 0x08-0x0F
        b'7', b'8', b'9', b'0', 0,    0,    b'\x08', 0,
        // 0x10-0x17
        b'q', b'w', b'e', b'r', b't', b'y', b'u', b'i',
        // 0x18-0x1F
        b'o', b'p', 0,    0,    b'\n', 0,    b'a', b's',
        // 0x20-0x27
        b'd', b'f', b'g', b'h', b'j', b'k', b'l', 0,
        // 0x28-0x2F
        0,    0,    0,    0,    b'z', b'x', b'c', b'v',
        // 0x30-0x37
        b'b', b'n', b'm', 0,    0,    0,    0,    0,
        // 0x38-0x3F
        0,    b' ', 0,    0,    0,    0,    0,    0,
        // 0x40-0x47
        0,    0,    0,    0,    0,    0,    0,    0,
        // 0x48-0x4F
        0,    0,    0,    0,    0,    0,    0,    0,
        // 0x50-0x57
        0,    0,    0,    0,    0,    0,    0,    0,
        // 0x58-0x5F
        0,    0,    0,    0,    0,    0,    0,    0,
        // 0x60-0x67
        0,    0,    0,    0,    0,    0,    0,    0,
        // 0x68-0x6F
        0,    0,    0,    0,    0,    0,    0,    0,
        // 0x70-0x77
        0,    0,    0,    0,    0,    0,    0,    0,
        // 0x78-0x7F
        0,    0,    0,    0,    0,    0,    0,    0,
    ];

    if scancode < 128 {
        let ascii = TABLE[scancode as usize];
        if ascii != 0 {
            Some(ascii as char)
        } else {
            None
        }
    } else {
        None
    }
}
