//! VGA text-mode buffer (80x25) output.

use core::fmt;
use core::ptr;
use spin::{Lazy, Mutex};

const BUFFER_WIDTH: usize = 80;
const BUFFER_HEIGHT: usize = 25;
const COLOR_CODE: u8 = 0x0A;

#[derive(Clone, Copy)]
#[repr(C)]
struct ScreenChar {
    ascii_character: u8,
    color_code: u8,
}

#[repr(transparent)]
struct Buffer {
    chars: [[ScreenChar; BUFFER_WIDTH]; BUFFER_HEIGHT],
}

struct Writer {
    column_position: usize,
    color_code: u8,
    buffer: *mut Buffer,
}

#[allow(unsafe_code)]
// Safety: The VGA buffer at 0xb8000 is a globally-mapped MMIO region
// with no thread-local state. It is safe to send across threads.
unsafe impl Send for Writer {}

impl Writer {
    #[allow(unsafe_code)]
    // Safety: 0xb8000 is the well-known VGA text buffer address.
    fn new() -> Self {
        Self {
            column_position: 0,
            color_code: COLOR_CODE,
            buffer: 0xb8000 as *mut Buffer,
        }
    }

    fn write_byte(&mut self, byte: u8) {
        match byte {
            b'\n' => self.new_line(),
            byte => {
                if self.column_position >= BUFFER_WIDTH {
                    self.new_line();
                }
                let row = BUFFER_HEIGHT - 1;
                let col = self.column_position;
                let color_code = self.color_code;
                #[allow(unsafe_code)]
                // Safety: self.buffer points to the VGA text buffer which
                // is always mapped and writable in kernel address space.
                let char_ptr = unsafe { &mut (*self.buffer).chars[row][col] };
                #[allow(unsafe_code)]
                // Safety: char_ptr is within the mapped VGA buffer.
                unsafe {
                    ptr::write_volatile(
                        char_ptr,
                        ScreenChar { ascii_character: byte, color_code },
                    );
                }
                self.column_position += 1;
            }
        }
    }

    fn new_line(&mut self) {
        for row in 1..BUFFER_HEIGHT {
            for col in 0..BUFFER_WIDTH {
                #[allow(unsafe_code)]
                // Safety: self.buffer points to the VGA text buffer.
                let src = unsafe { &(*self.buffer).chars[row][col] };
                #[allow(unsafe_code)]
                // Safety: src is within the mapped VGA buffer.
                let character = unsafe { ptr::read_volatile(src) };
                #[allow(unsafe_code)]
                // Safety: self.buffer points to the VGA text buffer.
                let dst = unsafe { &mut (*self.buffer).chars[row - 1][col] };
                #[allow(unsafe_code)]
                // Safety: dst is within the mapped VGA buffer.
                unsafe {
                    ptr::write_volatile(dst, character);
                }
            }
        }
        self.clear_row(BUFFER_HEIGHT - 1);
        self.column_position = 0;
    }

    fn clear_row(&mut self, row: usize) {
        let blank = ScreenChar {
            ascii_character: b' ',
            color_code: self.color_code,
        };
        for col in 0..BUFFER_WIDTH {
            #[allow(unsafe_code)]
            // Safety: self.buffer points to the VGA text buffer.
            let ptr = unsafe { &mut (*self.buffer).chars[row][col] };
            #[allow(unsafe_code)]
            // Safety: ptr is within the mapped VGA buffer.
            unsafe {
                ptr::write_volatile(ptr, blank);
            }
        }
    }

    fn write_string(&mut self, s: &str) {
        for byte in s.bytes() {
            let byte = if (0x20..=0x7e).contains(&byte) || byte == b'\n' {
                byte
            } else {
                0xfe
            };
            self.write_byte(byte);
        }
    }
}

impl fmt::Write for Writer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_string(s);
        Ok(())
    }
}

static VGA_WRITER: Lazy<Mutex<Writer>> = Lazy::new(|| {
    Mutex::new(Writer::new())
});

/// Prints to the VGA text buffer without a trailing newline.
#[macro_export]
macro_rules! vga_print {
    ($($arg:tt)*) => {
        $crate::vga::_vga_print(format_args!($($arg)*))
    };
}

/// Prints to the VGA text buffer with a trailing newline.
#[macro_export]
macro_rules! vga_println {
    () => ($crate::vga_print!("\n"));
    ($($arg:tt)*) => {
        $crate::vga_print!("{}\n", format_args!($($arg)*))
    };
}

#[doc(hidden)]
pub fn _vga_print(args: fmt::Arguments) {
    use x86_64::instructions::interrupts;
    interrupts::without_interrupts(|| {
        let mut writer = VGA_WRITER.lock();
        let _ = fmt::Write::write_fmt(&mut *writer, args);
    });
}
