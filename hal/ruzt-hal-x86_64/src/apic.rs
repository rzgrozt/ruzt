//! Local and I/O APIC register access on the boot CPU.

use ruzt_hal::mem::VirtAddr;
use x86_64::registers::model_specific::Msr;

const APIC_BASE_MSR: u32 = 0x1b;
const GLOBAL_ENABLE: u64 = 1 << 11;
const X2APIC_MODE: u64 = 1 << 10;
const APIC_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const VERSION: usize = 0x30;
const LVT_MASK: u32 = 1 << 16;
const REDIRECTION_START: u8 = 0x10;
const REDIRECTION_MASK: u32 = 1 << 16;
const ICR: usize = 0x300;
const ICR_DESTINATION: usize = 0x310;
const DELIVERY_PENDING: u32 = 1 << 12;

/// Vector used for LAPIC spurious delivery. This vector needs no EOI.
pub const SPURIOUS_VECTOR: u8 = 0xff;
/// Fixed-vector interprocessor interrupt for the secondary CPU mailbox.
pub const WAKE_VECTOR: u8 = 0xf0;
/// Fixed-vector interprocessor interrupt for address-space invalidation.
pub const TLB_VECTOR: u8 = 0xf1;
/// Fixed-vector interprocessor interrupt for inspecting the boot CPU's LAPIC.
pub const LAPIC_PROBE_VECTOR: u8 = 0xf2;

/// A physical unicast command sent over the local APIC.
pub enum Ipi {
    /// Put a secondary into the wait-for-SIPI state.
    Init,
    /// Start at the given 4 KiB real-mode address index.
    Startup(u8),
    /// Interrupt a CPU whose kernel IDT is live.
    Wake,
    /// Service a published TLB invalidation.
    Tlb,
    /// Check a device vector on the CPU that receives it.
    LapicProbe,
}

/// The boot CPU's local interrupt controller.
pub struct LocalApic {
    registers: LocalRegisters,
    id: u8,
    max_lvt: u32,
}

enum LocalRegisters {
    Xapic(u64),
    X2apic,
}

impl LocalRegisters {
    fn read(&self, offset: usize) -> u32 {
        match *self {
            // SAFETY: Construction requires the live uncached LAPIC page.
            Self::Xapic(base) => unsafe {
                ((base as usize + offset) as *const u32).read_volatile()
            },
            // SAFETY: x2APIC mode was checked and these MSRs are readable.
            Self::X2apic => unsafe { Msr::new(0x800 + (offset / 16) as u32).read() as u32 },
        }
    }

    fn write(&self, offset: usize, value: u32) {
        match *self {
            // SAFETY: The register is aligned, writable and belongs to this CPU.
            Self::Xapic(base) => unsafe {
                ((base as usize + offset) as *mut u32).write_volatile(value);
            },
            // SAFETY: x2APIC mode was checked and these MSRs are writable.
            Self::X2apic => unsafe {
                Msr::new(0x800 + (offset / 16) as u32).write(u64::from(value))
            },
        }
    }
}

impl LocalApic {
    /// Report the enabled local APIC's physical base and whether it uses MSRs.
    pub fn location() -> Option<(u64, bool)> {
        let features = core::arch::x86_64::__cpuid(1);
        if features.edx & (1 << 9) == 0 {
            return None;
        }
        // SAFETY: CPUID reports a local APIC. This runs on the boot CPU in ring 0.
        let base = unsafe { Msr::new(APIC_BASE_MSR).read() };
        (base & GLOBAL_ENABLE != 0).then_some((base & APIC_ADDRESS_MASK, base & X2APIC_MODE != 0))
    }

    /// Inspect the boot processor's active local APIC.
    ///
    /// # Safety
    /// Call on the boot CPU with interrupts disabled. Use a live, uncached
    /// alias of the xAPIC register page, or `None` in active x2APIC mode.
    pub unsafe fn inspect(alias: Option<VirtAddr>) -> Option<Self> {
        let registers = match alias {
            Some(alias) => LocalRegisters::Xapic(alias.as_u64()),
            None => LocalRegisters::X2apic,
        };
        let version = registers.read(VERSION);
        let id = match registers {
            LocalRegisters::Xapic(_) => registers.read(0x20) >> 24,
            LocalRegisters::X2apic => registers.read(0x20),
        };
        let max_lvt = (version >> 16) & 0xff;
        if !(0x10..0xff).contains(&(version as u8)) || max_lvt < 3 || id >= 0xff {
            return None;
        }
        Some(Self {
            registers,
            id: id as u8,
            max_lvt,
        })
    }

    pub(crate) fn enable(&self) {
        // Leave the local timer and LINT inputs masked. The PIT will arrive
        // through the I/O APIC, with no second delivery from the 8259 PIC.
        for (index, register) in [0x320, 0x350, 0x360, 0x370, 0x340, 0x330, 0x2f0]
            .into_iter()
            .enumerate()
        {
            if index as u32 <= self.max_lvt {
                self.registers.write(register, LVT_MASK);
            }
        }
        self.registers.write(0x80, 0);
        // EOI broadcast stays enabled for level-triggered I/O APIC lines.
        self.registers
            .write(0xf0, (1 << 8) | u32::from(SPURIOUS_VECTOR));
    }

    /// Physical destination ID usable by a legacy I/O APIC.
    pub fn id(&self) -> u8 {
        self.id
    }

    pub(crate) fn current_id(&self) -> u8 {
        match self.registers {
            LocalRegisters::Xapic(_) => (self.registers.read(0x20) >> 24) as u8,
            LocalRegisters::X2apic => self.registers.read(0x20) as u8,
        }
    }

    /// Match the BSP's APIC mode and enable local delivery on a secondary.
    ///
    /// # Safety
    /// Call on this secondary with interrupts disabled and a live IDT.
    /// The optional xAPIC alias is the validated uncached hardware page.
    pub unsafe fn init_secondary(physical: u64, alias: Option<VirtAddr>) -> Option<Self> {
        let (base, extended) = Self::location()?;
        if base != physical || (extended && alias.is_some()) {
            return None;
        }
        if !extended && alias.is_none() {
            if core::arch::x86_64::__cpuid(1).ecx & (1 << 21) == 0 {
                return None;
            }
            // SAFETY: The CPU reports x2APIC and already runs with the APIC enabled.
            unsafe {
                let mut msr = Msr::new(APIC_BASE_MSR);
                msr.write(msr.read() | X2APIC_MODE);
            }
        }
        // SAFETY: This CPU now uses the mode named by the validated alias.
        let local = unsafe { Self::inspect(alias) }?;
        local.enable();
        Some(local)
    }

    pub(crate) fn send_ipi(&self, destination: u8, message: Ipi) -> bool {
        let low = match message {
            Ipi::Init => (5 << 8) | (1 << 14) | (1 << 15),
            Ipi::Startup(vector) => (6 << 8) | u32::from(vector),
            Ipi::Wake => u32::from(WAKE_VECTOR),
            Ipi::Tlb => u32::from(TLB_VECTOR),
            Ipi::LapicProbe => u32::from(LAPIC_PROBE_VECTOR),
        };
        match self.registers {
            LocalRegisters::Xapic(_) => {
                if !self.icr_idle() {
                    return false;
                }
                self.registers.write(ICR_DESTINATION, u32::from(destination) << 24);
                self.registers.write(ICR, low);
                self.icr_idle()
            }
            LocalRegisters::X2apic => {
                // SAFETY: x2APIC is enabled and the command uses physical unicast.
                unsafe { Msr::new(0x830).write((u64::from(destination) << 32) | u64::from(low)) };
                true
            }
        }
    }

    fn icr_idle(&self) -> bool {
        for _ in 0..1_000_000 {
            if self.registers.read(ICR) & DELIVERY_PENDING == 0 {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }

    pub(crate) fn end_of_interrupt(&self) {
        self.registers.write(0xb0, 0);
    }

    pub(crate) fn vector_idle(&self, vector: u8) -> bool {
        let offset = usize::from(vector / 32) * 16;
        let bit = 1 << (vector % 32);
        // The caller has disabled local interrupts, so IRR cannot move into ISR.
        self.registers.read(0x200 + offset) & bit == 0
            && self.registers.read(0x100 + offset) & bit == 0
    }
}

/// An I/O APIC register window and its hardware-reported pin count.
#[derive(Clone, Copy)]
pub struct IoApic {
    registers: u64,
    pins: u8,
    id: u8,
}

impl IoApic {
    /// Inspect an I/O APIC and verify the firmware-reported identity.
    ///
    /// # Safety
    /// The alias must cover the live uncached page for this I/O APIC. The
    /// caller owns and serializes the selector/data register pair.
    pub unsafe fn inspect(alias: VirtAddr, id: u8) -> Option<Self> {
        let mut unit = Self {
            registers: alias.as_u64(),
            pins: 0,
            id,
        };
        let version = unit.read(1);
        let max_pin = ((version >> 16) & 0xff) as u8;
        if !matches!(version as u8, 0x11..=0xfe)
            || max_pin >= 120
            || (unit.read(0) >> 24) as u8 != id
        {
            return None;
        }
        unit.pins = max_pin + 1;
        Some(unit)
    }

    /// Count of implemented redirection entries.
    pub fn pin_count(self) -> u8 {
        self.pins
    }

    /// The firmware and hardware identifier of this I/O APIC.
    pub fn id(self) -> u8 {
        self.id
    }

    fn select(self, index: u8) {
        // SAFETY: Construction requires a live uncached IOREGSEL page.
        unsafe { (self.registers as *mut u32).write_volatile(u32::from(index)) };
    }

    fn read(self, index: u8) -> u32 {
        self.select(index);
        // SAFETY: The selector names a register and accesses are serialized.
        unsafe { ((self.registers + 0x10) as *const u32).read_volatile() }
    }

    fn write(self, index: u8, value: u32) {
        self.select(index);
        // SAFETY: The selector names a writable redirection register.
        unsafe { ((self.registers + 0x10) as *mut u32).write_volatile(value) };
    }

    pub(crate) fn mask_all(self) {
        for pin in 0..self.pins {
            let index = REDIRECTION_START + 2 * pin;
            self.write(index, self.read(index) | REDIRECTION_MASK);
        }
        // Read back the last update before changing the delivery format.
        self.read(REDIRECTION_START + 2 * (self.pins - 1));
    }

    /// Resolve one firmware-described hardware input to a kernel route.
    pub fn input(self, pin: u8, low: bool, level: bool) -> Option<Input> {
        (pin < self.pins).then(|| Input {
            unit: self,
            register: REDIRECTION_START + 2 * pin,
            flags: (u32::from(low) << 13) | (u32::from(level) << 15),
        })
    }
}

/// A physical I/O APIC input and its firmware-specified signal mode.
#[derive(Clone, Copy)]
pub struct Input {
    unit: IoApic,
    register: u8,
    flags: u32,
}

impl Input {
    pub(crate) fn controller_id(self) -> u8 {
        self.unit.id()
    }

    pub(crate) fn level_triggered(self) -> bool {
        self.flags & (1 << 15) != 0
    }

    pub(crate) fn configure(self, vector: u8, destination: u8, remap_index: Option<u8>) {
        // These indices fit in the low 15 bits of the RTE's remapping index.
        // Keep the same vector and trigger mode in the RTE and IRTE for EOI.
        let high = match remap_index {
            Some(index) => (1 << 16) | (u32::from(index) << 17),
            None => u32::from(destination) << 24,
        };
        self.unit.write(self.register + 1, high);
        self.unit.write(
            self.register,
            REDIRECTION_MASK | self.flags | u32::from(vector),
        );
    }

    pub(crate) fn set_enabled(self, enabled: bool) {
        let old = self.unit.read(self.register);
        let new = if enabled {
            old & !REDIRECTION_MASK
        } else {
            old | REDIRECTION_MASK
        };
        self.unit.write(self.register, new);
    }

    pub(crate) fn delivery_idle(self) -> bool {
        let entry = self.unit.read(self.register);
        let pending = (1 << 12) | (1 << 14); // Delivery status and remote IRR.
        entry & (REDIRECTION_MASK | pending) == REDIRECTION_MASK
    }
}
