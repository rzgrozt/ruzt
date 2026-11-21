//! PS/2 keyboard scancode handling.

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use x86_64::instructions::port::PortReadOnly;

static SCANCODE_READY: AtomicBool = AtomicBool::new(false);
static SCANCODE: AtomicU8 = AtomicU8::new(0);
static USER_DRIVER: spin::Once<crate::sched::ThreadId> = spin::Once::new();
static IRQ_PENDING: AtomicBool = AtomicBool::new(false);

pub(crate) const IRQ: u32 = 1;
pub(crate) const DATA_PORT: u16 = 0x60;

/// Route the keyboard interrupt to the initial user process.
pub(crate) fn enable_user_driver(thread: crate::sched::ThreadId) {
    USER_DRIVER.call_once(|| thread);
}

/// Sleep until the driver has an interrupt to handle.
/// Called from the syscall interrupt gate with interrupts disabled.
pub(crate) fn wait_irq() {
    while !IRQ_PENDING.swap(false, Ordering::Relaxed) {
        // This check and the scheduler's blocked transition are atomic
        // with respect to this CPU's keyboard IRQ.
        #[cfg(feature = "qemu-rootsrv-test")]
        {
            static PROBE: spin::Once<()> = spin::Once::new();
            PROBE.call_once(|| crate::serial_println!("rootsrv thread waiting for keyboard IRQ"));
        }
        crate::sched::block_current(crate::sched::ThreadState::BlockedIrq(IRQ));
    }
}

/// Called from the keyboard ISR (vector 33).
/// For the boot-time user driver, only records the interrupt.
#[allow(unsafe_code)]
pub fn on_interrupt() {
    if let Some(&thread) = USER_DRIVER.get() {
        // The controller drops the IRQ line when the driver reads the byte.
        // On the edge-triggered PIC, no other interrupt arrives for that byte.
        IRQ_PENDING.store(true, Ordering::Relaxed);
        crate::sched::wake_irq(thread, IRQ);
        return;
    }

    // SAFETY: The kernel echo task owns the PS/2 data port without a user driver.
    let scancode: u8 = unsafe { PortReadOnly::new(DATA_PORT).read() };

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
