use core::panic::PanicInfo;

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    crate::debug_print(format_args!("PANIC: {info}\n"));

    crate::syscall::exit(1)
}
