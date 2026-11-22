#![no_std]
#![deny(unsafe_code)]

pub mod allocator;
pub mod panic;
pub mod syscall;

pub use syscall::debug_putchar;

/// Write formatted text to the kernel debug console.
pub fn debug_print(args: core::fmt::Arguments<'_>) {
    use core::fmt::Write;

    struct DebugWriter;

    impl Write for DebugWriter {
        fn write_str(&mut self, text: &str) -> core::fmt::Result {
            for byte in text.bytes() {
                debug_putchar(byte);
            }
            Ok(())
        }
    }

    let _ = DebugWriter.write_fmt(args);
}

pub fn runtime_init(main: fn() -> !) -> ! {
    allocator::init();
    main();

    #[allow(
        unreachable_code,
        reason = "the runtime contract requires a terminal spin after its diverging entry point"
    )]
    loop {
        core::hint::spin_loop();
    }
}
