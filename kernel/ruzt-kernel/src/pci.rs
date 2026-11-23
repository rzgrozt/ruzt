//! Firmware-assigned PCI resources eligible for user-space mapping.

use ruzt_abi::{ErrorCode, PciAddress};
use ruzt_hal::boot::{Framebuffer, MemoryRegion};
use ruzt_hal::mem::{Mapper, PhysFrame, VirtAddr};
use ruzt_hal_x86_64::{
    mapper,
    pci::{MemoryBar, BAR_COUNT},
};
use spin::Once;

pub(crate) type Bars = [Option<MemoryBar>; BAR_COUNT];

struct Policy {
    memory: &'static [MemoryRegion],
    framebuffer: Option<MemoryBar>,
}

static POLICY: Once<Policy> = Once::new();

pub(crate) fn init(memory: &'static [MemoryRegion], framebuffer: Option<&Framebuffer>) {
    POLICY.call_once(|| Policy {
        memory,
        framebuffer: framebuffer.and_then(|framebuffer| {
            if framebuffer.buffer.is_empty() {
                return None;
            }
            let page = PhysFrame::SIZE as u64;
            let address = framebuffer.buffer.as_ptr() as u64;
            let start = address & !(page - 1);
            let end = (address + framebuffer.buffer.len() as u64).next_multiple_of(page);
            Some(mapper::with_mapper(|mapper| {
                let mut base = u64::MAX;
                let mut top = 0;
                for page_address in (start..end).step_by(PhysFrame::SIZE) {
                    let physical = mapper
                        .translate(VirtAddr::new(page_address))
                        .expect("boot framebuffer mapping")
                        .as_u64();
                    base = base.min(physical);
                    top = top.max(physical + page);
                }
                MemoryBar {
                    base,
                    bytes: top - base,
                }
            }))
        }),
    });
}

pub(crate) fn read_config(address: PciAddress, offset: u8) -> Result<u32, ErrorCode> {
    if offset % 4 != 0 {
        return Err(ErrorCode::BadMessage);
    }
    #[allow(unsafe_code)]
    // SAFETY: This is the x86 boot CPU. Its syscall gate keeps interrupts
    // disabled throughout the configuration transaction.
    Ok(unsafe { ruzt_hal_x86_64::pci::read_config(address.bits(), offset) })
}

pub(crate) fn probe(address: PciAddress) -> Result<Bars, ErrorCode> {
    let policy = POLICY.get().ok_or(ErrorCode::NotFound)?;
    // The boot framebuffer may still be scanning out through a VGA device.
    if policy.framebuffer.is_some() && read_config(address, 8)? >> 16 == 0x0300 {
        return Err(ErrorCode::NotFound);
    }
    let allow_handoff = crate::iommu::permits_pci_handoff(address);
    #[allow(unsafe_code)]
    // SAFETY: The object table granted exclusive probe access after checking
    // that the function has no live lease. No other CPU or driver uses config.
    // The handoff flag requires a live remapper that denies this requester.
    let mut bars = unsafe { ruzt_hal_x86_64::pci::probe_bars(address.bits(), allow_handoff) }
        .ok_or(ErrorCode::NotFound)?;
    for bar in &mut bars {
        *bar = bar.filter(|bar| allowed(*bar, policy));
    }
    if bars.iter().flatten().next().is_none() {
        return Err(ErrorCode::NotFound);
    }
    for (index, bar) in bars.iter().enumerate() {
        if let Some(bar) = bar {
            if bars[..index]
                .iter()
                .flatten()
                .any(|prior| overlaps(*prior, *bar))
            {
                return Err(ErrorCode::BadMessage);
            }
        }
    }
    Ok(bars)
}

pub(crate) fn prepare_physmap(bars: &Bars) -> Result<(), ErrorCode> {
    mapper::with_mapper(|mapper| {
        for bar in bars.iter().flatten() {
            #[allow(unsafe_code)]
            // SAFETY: Boot and device leases were checked for overlap, and
            // interrupts stay disabled as this new lease is installed.
            unsafe { mapper.make_device_physmap_uncached(bar.base, bar.bytes) }.map_err(
                |error| match error {
                    ruzt_hal::mem::MapError::FrameAllocationFailed => ErrorCode::NoMemory,
                    _ => ErrorCode::BadMessage,
                },
            )?;
        }
        Ok(())
    })
}

pub(crate) fn overlaps(a: MemoryBar, b: MemoryBar) -> bool {
    a.base < b.base + b.bytes && b.base < a.base + a.bytes
}

fn allowed(bar: MemoryBar, policy: &Policy) -> bool {
    let page = PhysFrame::SIZE as u64;
    let Some(end) = bar.base.checked_add(bar.bytes) else {
        return false;
    };
    // No byte of a mapping may share a page with another resource.
    if bar.base < 0x10_0000
        || end > 1 << 52
        || bar.bytes == 0
        || bar.base % page != 0
        || bar.bytes % page != 0
        || crate::apic::overlaps_mmio(bar.base, end)
        || crate::iommu::overlaps_mmio(bar.base, end)
    {
        return false;
    }
    // Protect the fixed x86 interrupt-controller and chipset control window
    // even when old firmware omits it from its memory map.
    if overlaps(
        bar,
        MemoryBar {
            base: 0xfec0_0000,
            bytes: 0x40_0000,
        },
    ) {
        return false;
    }
    !policy
        .memory
        .iter()
        .any(|region| bar.base < region.end.as_u64() && region.start.as_u64() < end)
        && !policy.framebuffer.is_some_and(|fb| overlaps(bar, fb))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruzt_hal::{boot::MemoryRegionKind, mem::PhysAddr};

    #[test]
    fn prevents_overlaps_with_ram_firmware_framebuffer_and_interrupt_registers() {
        static MEMORY: &[MemoryRegion] = &[
            MemoryRegion {
                start: PhysAddr::new(0x1000000),
                end: PhysAddr::new(0x100_0000 + 4097),
                kind: MemoryRegionKind::Usable,
            },
            MemoryRegion {
                start: PhysAddr::new(0xfff0_0000),
                end: PhysAddr::new(0x1_0000_0000),
                kind: MemoryRegionKind::Reserved,
            },
        ];
        let policy = Policy {
            memory: MEMORY,
            framebuffer: Some(MemoryBar {
                base: 0xfd00_0000,
                bytes: 8192,
            }),
        };
        for base in [
            0x100_1000,
            0xfff0_0000,
            0xfd00_1000,
            0xfee0_0000,
            0,
            u64::MAX - 4095,
        ] {
            assert!(!allowed(MemoryBar { base, bytes: 4096 }, &policy));
        }
        assert!(!allowed(
            MemoryBar {
                base: 0xfea0_0000,
                bytes: 2048
            },
            &policy
        ));
        assert!(allowed(
            MemoryBar {
                base: 0xfea0_0000,
                bytes: 0x10_0000
            },
            &policy
        ));
    }
}
