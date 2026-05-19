#![no_std]
#![no_main]

use bootloader_api::{config::Mapping, entry_point, BootInfo as RawBootInfo, BootloaderConfig};
#[cfg(not(test))]
use ruzt_hal::cpu::CpuOps;

pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut c = BootloaderConfig::new_default();
    c.mappings.physical_memory = Some(Mapping::Dynamic);
    c.kernel_stack_size = 256 * 1024;
    c
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

fn kernel_main(raw_boot_info: &'static mut RawBootInfo) -> ! {
    // SAFETY: Called exactly once at kernel entry, before any concurrent code.
    let boot_info = unsafe { ruzt_hal_x86_64::boot::normalize(raw_boot_info) };
    ruzt_kernel::main(boot_info)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    ruzt_kernel::serial_println!("PANIC: {}", info);
    loop {
        ruzt_hal_x86_64::cpu::X86_64Cpu::cpu_idle();
    }
}
