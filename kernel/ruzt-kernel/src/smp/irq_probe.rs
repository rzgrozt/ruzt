//! Synchronous vector status queries on the CPU that receives device IRQs.

use core::sync::atomic::{fence, AtomicBool, AtomicU16, Ordering};

use ruzt_hal_x86_64::{apic::Ipi, irq};

use super::{apic, shootdown};

const NO_REQUEST: u16 = 256;
static REQUEST: AtomicU16 = AtomicU16::new(NO_REQUEST);
static IDLE: AtomicBool = AtomicBool::new(false);

pub(super) fn install() {
    irq::install_vector_probe(probe_remote);
}

#[allow(unsafe_code)]
fn probe_remote(vector: u8) -> bool {
    let bsp = apic::cpu_topology().expect("device APIC topology").bsp;
    // Device route transactions serialize all publishers. Keep the route
    // masked and owned until the receiving CPU has sampled its LAPIC.
    assert_eq!(REQUEST.load(Ordering::Acquire), NO_REQUEST);
    REQUEST.store(u16::from(vector), Ordering::Release);
    fence(Ordering::SeqCst);
    // SAFETY: The transaction holds IF clear, and the BSP installed its IDT
    // before bringing this CPU online.
    assert!(
        unsafe { irq::send_ipi(bsp, Ipi::LapicProbe) },
        "could not send LAPIC probe"
    );
    for _ in 0..50_000_000 {
        if REQUEST.load(Ordering::Acquire) == NO_REQUEST {
            return IDLE.load(Ordering::Relaxed);
        }
        // The BSP can hold the mapper while it answers the query.
        shootdown::poll_local();
        core::hint::spin_loop();
    }
    panic!("boot CPU did not answer its LAPIC probe");
}

#[allow(unsafe_code)]
pub(super) fn poll_boot() {
    let Ok(vector) = u8::try_from(REQUEST.load(Ordering::Acquire)) else {
        return;
    };
    // SAFETY: Both the interrupt gate and the polling sites run with IF
    // clear. The HAL refuses to sample any CPU other than the boot CPU.
    if let Some(idle) = unsafe { irq::local_boot_vector_idle(vector) } {
        IDLE.store(idle, Ordering::Relaxed);
        REQUEST.store(NO_REQUEST, Ordering::Release);
    }
}

#[allow(unsafe_code)]
pub(crate) fn handle() {
    // SAFETY: This is the dedicated fixed-IPI entry with interrupts disabled.
    unsafe { irq::finish_ipi() };
    poll_boot();
}
