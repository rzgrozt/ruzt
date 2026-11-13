use core::fmt::{self, Write};
use core::panic::PanicInfo;

use crate::debug_putchar;

struct DebugWriter;

impl Write for DebugWriter {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        for byte in text.bytes() {
            debug_putchar(byte);
        }
        Ok(())
    }
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    let _ = write!(DebugWriter, "PANIC: {info}\n");

    loop {
        core::hint::spin_loop();
    }
}
