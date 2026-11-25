//! Kernel IBT and the system-wide policy for user shadow stacks.

use core::sync::atomic::{AtomicBool, Ordering};

static INSTRUMENTED: AtomicBool = AtomicBool::new(false);
static USER_SHADOW_STACK: AtomicBool = AtomicBool::new(false);
static CPU_SHADOW_STACK: [AtomicBool; crate::smp::SCHEDULER_SLOTS] =
    [const { AtomicBool::new(false) }; crate::smp::SCHEDULER_SLOTS];

/// Record whether the bootloader's kernel ELF carries the linked IBT property.
///
/// # Safety
/// The boot information must be the trusted bootloader handoff and its kernel
/// ELF range must be pinned and mapped in the physical-memory map.
#[allow(unsafe_code)]
pub unsafe fn configure(boot: &bootloader_api::BootInfo) {
    let image = boot
        .physical_memory_offset
        .into_option()
        .and_then(|offset| {
            let start = offset.checked_add(boot.kernel_addr)?;
            let len = usize::try_from(boot.kernel_len).ok()?;
            if len == 0 || len > isize::MAX as usize {
                return None;
            }
            let address = x86_64::VirtAddr::try_new(start).ok()?;
            x86_64::VirtAddr::try_new(start.checked_add(len as u64 - 1)?).ok()?;
            // SAFETY: The trusted loader keeps the original ELF live and maps its
            // physical range. Above, both endpoints and the length were checked.
            Some(unsafe { core::slice::from_raw_parts(address.as_ptr::<u8>(), len) })
        });
    INSTRUMENTED.store(
        image.is_some_and(crate::elf::has_kernel_ibt),
        Ordering::Release,
    );
}

#[allow(unsafe_code)]
pub(crate) fn init_cpu(slot: usize) -> bool {
    // SAFETY: Each caller has installed its IDT and has interrupts disabled.
    // The linker emits the IBT AND property only for an instrumented image.
    let features =
        unsafe { ruzt_hal_x86_64::cet::init(INSTRUMENTED.load(Ordering::Acquire)) };
    CPU_SHADOW_STACK[slot].store(features.user_shadow_stack, Ordering::Release);
    features.supervisor_ibt
}

pub(crate) fn finish_smp() {
    // Any registered scheduler CPU may run a user thread. Publish one
    // immutable policy after registration completes and before loading users.
    let enabled = crate::smp::scheduler_slots()
        .all(|slot| CPU_SHADOW_STACK[slot].load(Ordering::Acquire));
    USER_SHADOW_STACK.store(enabled, Ordering::Release);
    crate::serial_println!("x86 CET user shadow stacks enabled: {enabled}");
}

pub(crate) fn user_shadow_stack_enabled() -> bool {
    USER_SHADOW_STACK.load(Ordering::Acquire)
}
