#![no_std]
#![deny(unsafe_code)]

pub mod allocator;
pub mod panic;
pub mod syscall;

pub use syscall::debug_putchar;

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
