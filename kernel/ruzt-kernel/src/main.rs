#![no_std]
#![no_main]

use bootloader_api::{config::Mapping, entry_point, BootInfo as RawBootInfo, BootloaderConfig};
#[cfg(not(test))]
use ruzt_hal::cpu::CpuOps;

pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    const SUPERVISOR_START: u64 = 0xffff_8000_0000_0000;
    let mut c = BootloaderConfig::new_default();
    // The pinned BIOS loader's early stack cannot hold the ASLR RNG state.
    c.mappings.aslr = cfg!(feature = "uefi-kaslr");
    // The pinned loader can shift a randomized physmap past its reservation
    // when the physical span is an exact multiple of a PML4 slot.
    c.mappings.physical_memory = Some(if c.mappings.aslr {
        Mapping::FixedAddress(SUPERVISOR_START)
    } else {
        Mapping::Dynamic
    });
    // Reserve the last supervisor PML4 slot for the kernel heap.
    c.mappings.dynamic_range_start = Some(SUPERVISOR_START);
    c.mappings.dynamic_range_end =
        Some(ruzt_kernel::mm::heap::HEAP_START - ruzt_hal::mem::PhysFrame::SIZE as u64);
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
