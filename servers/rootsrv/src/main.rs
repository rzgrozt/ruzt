#![no_std]
#![no_main]

use ruzt_runtime::{debug_putchar, runtime_init};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    runtime_init(main)
}

fn main() -> ! {
    for &byte in b"Hello from ring 3, rootsrv alive.\n" {
        debug_putchar(byte);
    }

    let mut iterations = 0_u64;
    loop {
        iterations += 1;
        if iterations == 10_000_000 {
            debug_putchar(b'.');
            iterations = 0;
        }
        core::hint::spin_loop();
    }
}
