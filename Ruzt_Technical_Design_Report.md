# Ruzt
## A Privacy-First, Rust-Native Microkernel Operating System
### Technical Design Report & Implementation Guide — v0.3

> *"Some clueless person is gonna build an entire system on Rust."*
> — Linus Torvalds
>
> This report is for that person.

---

**Document note.** This is the source-of-truth design report for Ruzt. Read Section 1 and the phase roadmap in Section 3, then return to the relevant sections as development progresses. The code examples illustrate the design.

**v0.3 additions:** Sections 25–34 are new, covering the subsystems absent from v0.2: power management, audio, USB, Wi-Fi, GPU/graphics API, user authentication and session lock, structured logging, internationalisation and input methods, camera/microphone privacy, and PKI/certificate trust.

---

## Table of Contents

1.  Project Philosophy & North Star
2.  Architectural Decisions (Locked-in)
3.  The Realistic Multi-Year Roadmap
4.  Repository Layout & Workspace Structure
5.  Toolchain & Bootstrap
6.  Bootloader & Early Boot (x86_64 and aarch64)
7.  The Kernel Core — `ruzt-kernel`
8.  The Hardware Abstraction Layer
9.  User-Space Drivers
10. Storage, Filesystem & Full-Disk Encryption
11. Networking Stack & Isolation
12. POSIX Shim — `libruzt-posix`
13. Init System, Service Management & the Supervision Tree
14. Display Server, Compositor & GUI Stack (Smithay-based)
15. Package Management & Reproducible Builds
16. Security Architecture Deep Dive
17. Robustness & Crash-Only Design
18. Privacy Architecture
19. Aesthetic & UX Design System
20. Development Workflow
21. Testing, Fuzzing & Formal Verification
22. Contribution Model & Governance
23. Mobile & Future Form Factors
24. Power Management — `powerd` & Energy Subsystem *(new)*
25. Audio — `audiod` & the Capability-Gated Media Graph *(new)*
26. USB Subsystem — `usbhostd` & Device Class Isolation *(new)*
27. Wi-Fi & Wireless Networking *(new)*
28. GPU & Graphics API Stack *(new)*
29. User Authentication, Multi-User & Session Lock *(new)*
30. Logging — `logd` & Structured Audit Trail *(new)*
31. Internationalisation, Localisation & Input Methods *(new)*
32. Camera, Microphone & AV Privacy *(new)*
33. PKI & Certificate Trust Store — `trustd` *(new)*
34. Inspirations, Resources, Reading List
35. Closing Words

---

## 1. Project Philosophy & North Star

Use the principles in `PHILOSOPHY.md` to guide architectural decisions.

**Ruzt's North Star:**

1. **Memory safety is non-negotiable.** Outside a tightly-audited `unsafe` core (paging, MMIO, atomics, context switches), every line compiles in safe Rust. The unsafe core is documented, justified, and re-reviewed quarterly.
2. **Least privilege, always.** No process gets a permission it did not explicitly request. The default capability set on a new process is *empty*. This is the privacy story.
3. **The user is the principal, not the application.** Apps don't "own" their data; the user grants apps capabilities to specific data. (This is the same insight Qubes OS and Android's permission model began with, but enforced from the kernel up.)
4. **Telemetry-zero by default.** Not "opt-out". *Off.* No analytics endpoint exists in the base system. If a future feature requires telemetry, it requires an explicit RFC and a user opt-in flow.
5. **Reproducible from source.** Anyone with the source tree, the toolchain version, and a clean machine must produce a byte-identical image. This is the supply-chain story.
6. **Aesthetic as a feature, not a finishing touch.** Visual coherence is engineered from day one — the boot splash, the TTY font, the panic screen, the installer, and the desktop must feel like one product, not a kit of parts.
7. **Discoverable internals.** A motivated newcomer should be able to read the source of any subsystem and understand it within an afternoon. This is partly a code-style choice and partly an architectural one (small modules, clear ownership).
8. **Robust under failure.** Every subsystem assumes its peers may crash. Recovery is a first-class operation, not an afterthought. Crash-only design (Section 17) is a project rule, not an aspiration.
9. **Boring where it matters, bold where it pays off.** Use battle-tested ideas (paging, ELF, MMIO, Wayland) for the substrate. Save novelty for the interfaces (capability model, package format, capability-aware protocol extensions) where it changes the user experience.

**Anti-goals — say "no" loudly:**

- Ruzt is **not** a Linux clone. POSIX is a compatibility *shim*, not a goal.
- Ruzt is **not** a server-first OS. The first-class persona is a privacy-conscious end-user laptop, with a path to mobile.
- Ruzt is **not** trying to be the fastest. Microkernels pay a per-syscall cost. We accept that.
- Ruzt **does not** ship a JavaScript runtime in the base image. (No Electron-shaped escape hatches.)

Print this on the wiki. Refuse PRs that contradict it.

---

## 2. Architectural Decisions (Locked-in)

Based on the foundational choices already settled:

| Decision | Choice | Why it shapes everything |
|---|---|---|
| Kernel model | **Microkernel** | Drivers, FS, network, even page-fault handler logic above the trap level live in user space. The kernel itself is ~10–15k lines. Compromises are isolated, not catastrophic. |
| Initial target | **x86_64 first, aarch64 from Phase 1 in HAL** | Active development on x86_64 (best QEMU + tooling), but the kernel/HAL split exists from day one. aarch64 reaches feature parity around Phase 6. RISC-V is left as a community port later. |
| Compatibility | **Hybrid: native Rust + POSIX shim** | The native Ruzt API is capability-first, async-first, idiomatic Rust. A separate `libruzt-posix` crate provides a partial POSIX surface for porting (initially: musl-style libc + a syscall translator). |
| Display stack | **Smithay-based compositor with capability-aware Wayland extensions** | We get full Wayland app compatibility (GTK, Qt, Firefox, etc.) for free. Privacy is enforced via custom Wayland protocol extensions gated by capabilities — no trust holes opened. |
| Privacy stack | **Capability-based security + FDE default + per-app network isolation + telemetry-zero + reproducible builds** | All five are foundational, not bolt-on. The capability system is the keystone — everything else hangs from it. |
| Robustness model | **Crash-only software with supervision tree** | Every user-space service is restartable. The init supervisor (Erlang-style) restarts crashed services, replays their initial capabilities, and the kernel's revocation primitive cleans up the previous instance's leaked references. |

These decisions are *settled*. When future contributors propose a monolithic-style driver, a Linux-syscall ABI inside the kernel, or a non-capability API surface, point at this table.

---

## 3. The Realistic Multi-Year Roadmap

A serious OS is a 3–7 year project even with a team. For solo development, plan for 4–6 years to reach a milestone where you can use it as a daily driver for browsing and writing. Don't be discouraged by this number. Linus had a hobby kernel for two years before it could host its own development. Redox is in year eleven and still pre-1.0.

**Phase 0 — "Hello, world from ring 0" (weeks)**
- Boot a `no_std` Rust binary in QEMU (`virt` machine on x86_64 first).
- Print to VGA text buffer / serial.
- Set up the IDT, handle a breakpoint exception, return.
- Output: a blinking cursor and a panic handler.
- Reference: the entire `phil-opp/blog_os` series; do not skip it.

**Phase 1 — Minimal kernel and HAL split (months)**
- Define the HAL trait surface (`ruzt-hal` crate). Even though only x86_64 implements it now, write the trait so that aarch64 cannot become a rewrite later.
- Physical frame allocator.
- Page tables, virtual memory, kernel heap.
- Interrupts: timer, keyboard.
- A round-robin scheduler with two kernel threads.
- Output: kernel printk runs concurrently with a keyboard echo task.

**Phase 2 — Capabilities and the first user-space process (months)**
- Define the capability table data structure.
- Implement five kernel objects: `Untyped`, `CNode`, `Endpoint`, `Notification`, `Frame` (lifted from seL4's vocabulary).
- Implement the `invoke` syscall (the *only* syscall, more or less).
- Load an ELF into a fresh address space, hand it an empty capability table plus one endpoint to a "root server", and jump.
- Output: a user-space `rootsrv` prints to the console via IPC.

**Phase 3 — User-space drivers and the SDK (months)**
- Move the keyboard, serial, and timer interrupts up into user-space drivers.
- Write the `ruzt-driver-sdk` crate (MMIO, DMA, IRQ helpers).
- Build a `framebuffer-driver` that drives the bootloader-provided linear framebuffer.
- Build a tiny `block-driver` for virtio-blk (QEMU's virtual disk).
- Output: the kernel itself no longer does any I/O. Everything is messages.

**Phase 4 — VFS and RuztFS v0 (months)**
- Define the `Filesystem` capability interface.
- Implement an in-memory tmpfs for testing.
- Implement RuztFS v0: COW, no encryption yet, no snapshots, just blocks.
- Implement a VFS broker that mounts FS instances at paths.
- Output: a user-space program reads `/etc/hostname`.

**Phase 5 — Networking + supervision tree (months)**
- Integrate `smoltcp` as a user-space crate inside a `netd` server.
- Implement a virtio-net user-space driver.
- Define per-process network namespaces from day one.
- Promote `rootsrv` to a real supervisor: declarative service files, restart policy, health checks.
- Output: ping a remote host from a user-space program through `netd`; kill `netd` and watch the supervisor restart it cleanly.

**Phase 6 — POSIX shim, first ports, and aarch64 catch-up (months)**
- Stand up `libruzt-posix` with: `read`, `write`, `open`, `close`, `mmap`, `fork`-emulation (process-spawn + COW), `execve`, basic signals.
- Port `coreutils` (the Rust rewrite) — `ls`, `cat`, `cp`.
- Port a real shell — `nushell` or a small custom one.
- Bring aarch64 to feature parity with x86_64 by completing `ruzt-hal-aarch64` against the QEMU `virt` machine.
- Output: a working text-mode userland on both architectures.

**Phase 7 — Storage encryption and reproducible installer (months)**
- Add per-file encryption to RuztFS v1 (Argon2id-derived KEK, file keys wrapped by master).
- Build a reproducible installer ISO (`xorriso` deterministic).
- Add measured boot via TPM 2.0 on x86_64 and the equivalent on aarch64 (UEFI Secure Boot + DRTM where available).
- Output: install Ruzt to a real machine, boot encrypted.

**Phase 8 — Display server, compositor, DE (months → year)**
- `displayd` compositor built on the **Smithay** crates — full Wayland protocol support out of the gate.
- Implement Ruzt-specific Wayland protocol extensions for capability-gated screen capture, surface introspection, and global hotkeys.
- A reference desktop environment ("**Zephyr**") with a panel, launcher, settings.
- A native widget toolkit on top of `iced` adapted for Ruzt.
- `virtio-gpu` + `venus` Vulkan protocol enabled — full 3D in QEMU.
- Output: a graphical desktop running stock Wayland apps.

**Phase 9 — Hardening (continuous, intensifies here)**
- Fuzzing every IPC entry point.
- Property tests on the capability rules.
- Formal verification of the IPC fast path (Kani / Creusot).
- Sigstore-style signing for the package manager.
- FIDO2 hardware key authentication in `authd`.
- Output: a base system you'd let your mother use.

**Phase 10 — First real ARM hardware**
- Bring up Ruzt on a Raspberry Pi 5 (well-documented bootloader, virtio-style mailbox protocol).
- Bring up Ruzt on Apple Silicon via the Asahi/m1n1 boot path (this is the bigger, more rewarding project).
- Touch and HiDPI work in `displayd`.
- Real GPU driver: Intel `anv`, AMD `radv`, Apple `agx` (Asahi Mesa, production-quality as of 2024).

**Phase 11 — Mobile profile (year+, see Section 23)**
- Telephony and modem isolation.
- Power management profile.
- Mobile-form-factor Zephyr variant.

**Be ruthless about phase boundaries.** Don't start Phase 4 work in Phase 2 because it sounds fun. Discipline beats inspiration on a project this size.

---

## 4. Repository Layout & Workspace Structure

A Cargo workspace with one root `Cargo.toml` that lists every crate. This is non-negotiable — it gives you one `cargo check`, one `cargo test`, and one dependency graph for the entire OS.

```
ruzt/
├── Cargo.toml                  # workspace
├── rust-toolchain.toml         # pinned nightly
├── README.md
├── PHILOSOPHY.md               # the constitution (Section 1)
├── docs/
│   ├── adr/                    # architecture decision records
│   ├── rfc/                    # accepted RFCs
│   └── book/                   # mdBook-rendered manual
├── design/
│   ├── tokens.toml             # the design system source-of-truth
│   ├── colors.md
│   ├── typography.md
│   └── motion.md
├── boot/
│   ├── boot-x86_64/            # thin wrapper around `bootloader` crate
│   └── boot-aarch64/           # UEFI / U-Boot entry stubs
├── kernel/
│   └── ruzt-kernel/            # the microkernel itself, arch-generic
├── hal/
│   ├── ruzt-hal/               # the trait surface (no_std, no impl)
│   ├── ruzt-hal-x86_64/        # x86_64 backend
│   └── ruzt-hal-aarch64/       # aarch64 backend
├── crates/
│   ├── ruzt-abi/               # syscall numbers, IPC message types — shared kernel/user
│   ├── ruzt-cap/               # capability types
│   ├── ruzt-ipc/               # user-side IPC client library
│   ├── ruzt-runtime/           # async runtime, allocator, panic handler for user processes
│   ├── ruzt-driver-sdk/        # MMIO, DMA, IRQ helpers for user-space drivers
│   └── ruzt-posix/             # POSIX shim (libc surface)
├── servers/
│   ├── rootsrv/                # first user-space process; supervision tree
│   ├── vfs/                    # filesystem broker
│   ├── netd/                   # network stack server
│   ├── inputd/                 # keyboard/mouse aggregator
│   ├── permd/                  # capability prompt + permission ledger
│   ├── displayd/               # Smithay-based Wayland compositor
│   ├── powerd/                 # power management, ACPI/LAI, thermal
│   ├── audiod/                 # audio graph server
│   ├── audio-sessiond/         # audio routing policy (WirePlumber-style)
│   ├── usbhostd/               # xHCI host controller daemon
│   ├── wifid/                  # 802.11 management daemon
│   ├── authd/                  # authentication daemon
│   ├── logd/                   # structured binary log daemon
│   ├── imd/                    # input method daemon (IME)
│   ├── camd/                   # camera/UVC daemon
│   ├── trustd/                 # PKI certificate trust store
│   └── localed/                # locale and time-zone service
├── drivers/
│   ├── virtio-blk/
│   ├── virtio-net/
│   ├── virtio-gpu/
│   ├── ahci/
│   ├── nvme/
│   ├── ps2/
│   ├── hda/                    # Intel HD Audio
│   ├── pl011-uart/             # aarch64 serial (QEMU virt + Pi)
│   ├── wifi-phy/               # 802.11 PHY/MAC driver (chipset-specific)
│   ├── usb-hid/
│   ├── usb-msc/
│   ├── usb-audio/
│   └── usb-uvc/
├── userland/
│   ├── shell/
│   ├── coreutils/
│   ├── editor/
│   └── installer/
├── desktop/
│   ├── zephyr-shell/           # reference DE (panel, launcher, settings)
│   ├── zephyr-toolkit/         # iced-based widget toolkit theming
│   └── zephyr-apps/            # files, terminal, settings, etc.
├── tools/
│   ├── ruzt-pkg/               # package manager
│   ├── ruzt-build/             # reproducible build orchestrator
│   └── ruzt-test/              # in-QEMU test harness
├── tests/
│   ├── integration/
│   └── fuzz/
└── third_party/                # vendored deps, each with provenance.toml
```

**Conventions enforced by `clippy.toml` and `rustfmt.toml`:**
- `#![forbid(unsafe_code)]` on every crate that doesn't legitimately need it. There are roughly seven crates that need `unsafe` (kernel, both HAL backends, ipc, driver-sdk, runtime, abi). Every other crate forbids it.
- Every public `unsafe fn` has a `# Safety` doc comment that explains the invariants.
- No `panic!` in the kernel after Phase 1, except in `unreachable!()`-style branches that have been audited.
- No `unwrap()` outside tests and `lazy_static!` initializers.

---

## 5. Toolchain & Bootstrap

Pin everything. Reproducibility starts at the toolchain.

```toml
# rust-toolchain.toml
[toolchain]
channel = "nightly-2026-04-15"   # pin a specific date; bump deliberately via RFC
components = ["rust-src", "llvm-tools-preview", "rustfmt", "clippy"]
targets = [
  "x86_64-unknown-none",
  "aarch64-unknown-none-softfloat",
]
```

Required external tools:
- `qemu-system-x86_64` and `qemu-system-aarch64`.
- `mtools` and `xorriso` (deterministic) to build ISOs.
- `OVMF.fd` (UEFI firmware for QEMU x86_64) and `QEMU_EFI.fd` (aarch64) — vendor known versions under `boot/firmware/`.
- `cargo-make` for the top-level build orchestrator.
- `cargo-fuzz` for fuzzing (Phase 9 onward).
- `kani` for formal verification of selected functions.

**Targets:** `x86_64-unknown-none` and `aarch64-unknown-none-softfloat` are the right bases. You'll need `-Z build-std=core,alloc,compiler_builtins` for both.

A custom kernel target spec for x86_64 (`x86_64-ruzt-kernel.json`) disables SSE in kernel mode and uses LLVM's `kernel` code model:

```json
{
  "llvm-target": "x86_64-unknown-none",
  "data-layout": "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128",
  "arch": "x86_64",
  "target-endian": "little",
  "target-pointer-width": "64",
  "target-c-int-width": "32",
  "os": "none",
  "executables": true,
  "linker-flavor": "ld.lld",
  "linker": "rust-lld",
  "panic-strategy": "abort",
  "disable-redzone": true,
  "features": "-mmx,-sse,+soft-float",
  "code-model": "kernel"
}
```

The aarch64 kernel target (`aarch64-ruzt-kernel.json`) disables NEON in kernel context and selects `+strict-align`:

```json
{
  "llvm-target": "aarch64-unknown-none",
  "data-layout": "e-m:e-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128",
  "arch": "aarch64",
  "target-endian": "little",
  "target-pointer-width": "64",
  "target-c-int-width": "32",
  "os": "none",
  "executables": true,
  "linker-flavor": "ld.lld",
  "linker": "rust-lld",
  "panic-strategy": "abort",
  "features": "+strict-align,-neon,-fp-armv8",
  "disable-redzone": true
}
```

User-space targets (`x86_64-ruzt-user.json`, `aarch64-ruzt-user.json`) keep SIMD enabled and use the small code model.

---

## 6. Bootloader & Early Boot

Don't write your own UEFI bootloader from scratch in year one.

**On x86_64,** use the `bootloader` crate (Phil Opp's project). It understands BIOS + UEFI and hands you:
- A linear framebuffer and its pixel format.
- A memory map (regions free, reserved, ACPI, etc.).
- A pointer to the RSDP (ACPI root table).
- The kernel image already loaded into a fresh virtual address space.

**On aarch64,** the picture is more fragmented and that is the point — design the early-boot interface so the kernel doesn't care which boot path got it there.

- **QEMU `virt` machine:** boot via `-kernel` directly (PE/COFF) or via UEFI (`QEMU_EFI.fd`). Use UEFI; it more closely mirrors real ARM server hardware.
- **Apple Silicon:** the `m1n1` bootloader (from the Asahi project) chain-loads a Mach-O kernel and provides the Apple Device Tree (ADT) plus a known framebuffer. Treat `m1n1` as the equivalent of UEFI on this platform.
- **Raspberry Pi 4/5:** the GPU-side bootloader hands off to U-Boot, which loads the kernel and a Device Tree Blob (DTB).
- **Generic UEFI ARM servers:** standard UEFI handoff with ACPI tables.

The `ruzt-hal-aarch64` crate's bootstrap accepts a normalized `BootInfo`:

```rust
pub struct BootInfo {
    pub framebuffer: Option<Framebuffer>,
    pub memory_map: &'static [MemoryRegion],
    pub firmware_tables: FirmwareTables, // ACPI, DTB, or ADT
    pub initrd: &'static [u8],
}
```

The kernel itself takes a `BootInfo` regardless of arch. The HAL is responsible for building it.

Skeleton entry on x86_64:

```rust
// boot/boot-x86_64/src/main.rs
use bootloader_api::{entry_point, BootInfo, BootloaderConfig, config::Mapping};

pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut c = BootloaderConfig::new_default();
    c.mappings.physical_memory = Some(Mapping::Dynamic);
    c.kernel_stack_size = 256 * 1024;
    c
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    let normalized = ruzt_hal_x86_64::normalize(boot_info);
    ruzt_kernel::main(normalized)
}
```

Skeleton entry on aarch64 (UEFI):

```rust
// boot/boot-aarch64/src/main.rs
#![no_main]
#![no_std]

use uefi::prelude::*;

#[entry]
fn efi_main(handle: Handle, mut st: SystemTable<Boot>) -> Status {
    let normalized = ruzt_hal_aarch64::boot_from_uefi(handle, &mut st);
    ruzt_kernel::main(normalized)
}
```

**Boot splash from frame zero.** Even before the kernel is fully up, paint a single brand-mark to the framebuffer so the user knows *something* is alive. This is part of the "aesthetic from day one" rule. The same splash binary runs on both arches; it consumes the normalized `Framebuffer`.

---

## 7. The Kernel Core — `ruzt-kernel`

The microkernel is small, but every line is high-leverage. Treat this directory as the most-reviewed code in the project.

### 7.1 The `no_std` environment

```rust
#![no_std]
#![no_main]
#![feature(naked_functions, asm_const, allocator_api)]
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;
```

`unsafe_op_in_unsafe_fn` means even *inside* an `unsafe fn`, you must write `unsafe { … }` blocks. This forces the author to think about each unsafe operation individually rather than wrapping a 200-line function in a single `unsafe`.

### 7.2 Memory management

Three layers from the bottom up; the kernel uses HAL traits (Section 8) so the same code compiles on both arches.

**(a) Physical frame allocator.** Walks the bootloader memory map, owns a bitmap (or buddy structure) of granule-sized frames. On x86_64 the granule is 4 KiB; on aarch64 it can be 4 KiB, 16 KiB, or 64 KiB depending on the implementation. Standardize on 4 KiB to keep things simple.

```rust
pub struct FrameAllocator {
    bitmap: BitVec,
    next_search_hint: usize,
    total_frames: usize,
    free_frames: AtomicUsize,
}

impl FrameAllocator {
    pub fn allocate(&mut self) -> Option<PhysFrame> { /* … */ }
    pub fn allocate_contiguous(&mut self, count: usize) -> Option<PhysFrame> { /* … */ }
    pub fn deallocate(&mut self, frame: PhysFrame) { /* … */ }
}
```

Use a buddy allocator for contiguous-frame requests (DMA needs them).

**(b) Virtual memory.** On x86_64, 4-level paging via the `x86_64` crate. On aarch64, `TTBR0_EL1` for user, `TTBR1_EL1` for kernel, with stage-1 translation tables. The HAL exposes a uniform `Mapper` trait so the kernel doesn't branch on arch at the call site.

```rust
pub trait Mapper {
    fn map(&mut self, virt: VirtAddr, phys: PhysFrame, flags: PageFlags) -> Result<(), MapError>;
    fn unmap(&mut self, virt: VirtAddr) -> Result<PhysFrame, MapError>;
    fn translate(&self, virt: VirtAddr) -> Option<PhysAddr>;
    fn flush(&mut self, virt: VirtAddr); // local TLB invalidate
    fn flush_all_smp(&mut self);          // IPI / DSB+TLBI broadcast
}
```

The `AddressSpace` type wraps a HAL-provided mapper plus accounting:

```rust
pub struct AddressSpace {
    root: PhysFrame,
    regions: BTreeMap<VirtAddr, Region>,
}

impl AddressSpace {
    pub fn map(&mut self, v: VirtAddr, p: PhysFrame, f: PageFlags) -> Result<(), MapError> {
        // W^X check: never both Writable and Executable.
        if f.contains(PageFlags::WRITABLE | PageFlags::EXECUTABLE) {
            return Err(MapError::WriteExecute);
        }
        // delegate to HAL mapper
    }
}
```

**(c) Kernel heap.** Start with `linked_list_allocator` (a small, well-tested crate). Move to a custom slab allocator once you hit fragmentation issues — measure first. The kernel heap should be small (a few MiB); most allocation in a microkernel is per-process, not kernel-global.

### 7.3 Interrupts and exceptions

This is the most arch-specific surface in the kernel and the cleanest argument for the HAL split. The kernel exposes a logical `IrqNumber`; the HAL maps it to APIC vectors on x86_64 or GIC interrupt IDs on aarch64.

**On x86_64:** statically-initialized IDT via the `x86_64` crate. Use IST stacks for double-fault recovery. Move from the legacy 8259 PIC to LAPIC + IO-APIC as soon as you have multiple cores or want MSI/MSI-X.

**On aarch64:** vector table in the `VBAR_EL1` register, sixteen entries grouped by source (current EL with SPx, lower EL using AArch64, etc.). Interrupt distribution via GICv3 (Generic Interrupt Controller). A driver-class crate (`ruzt-hal-aarch64::gic`) handles the LPI / SPI / PPI distinction.

In a microkernel, hardware interrupts (other than the timer) generally do not run logic in the kernel. They wake a user-space driver via a notification capability, then return. The driver does the actual work.

### 7.4 Scheduler

Start brutally simple: one global run queue, round-robin, preemption every 10 ms (or whatever your timer fires at). This is correct enough for Phase 1.

```rust
pub struct Scheduler {
    runnable: VecDeque<ThreadId>,
    threads: BTreeMap<ThreadId, Thread>,
    current: Option<ThreadId>,
}

impl Scheduler {
    pub fn schedule(&mut self) {
        if let Some(prev) = self.current.take() {
            if self.threads[&prev].state == ThreadState::Runnable {
                self.runnable.push_back(prev);
            }
        }
        if let Some(next) = self.runnable.pop_front() {
            self.current = Some(next);
            unsafe { hal::context_switch(&mut self.threads, prev, next) };
        } else {
            hal::cpu_idle();
        }
    }
}
```

Evolve toward a per-CPU run queue with work-stealing once you support SMP. Hold off on a CFS-clone until you have real workloads.

### 7.5 IPC — the heart of the microkernel

This is the single most important subsystem. Get it right and the rest of the OS falls into place. Get it wrong and you'll be reluctantly rewriting it for a year.

**Two primitives, in seL4 style:**

- **Endpoints:** synchronous, blocking, rendezvous-style message passing. Sender blocks until a receiver picks up; receiver blocks until a sender shows up. Capabilities can be transferred *in* the message.
- **Notifications:** asynchronous, non-blocking, single-bit semaphores. Used for interrupt forwarding and for waking a thread that is waiting on multiple sources.

**Design the message format with care.** A fixed-size header plus a small inline payload (e.g., 56 bytes inline + four capability transfer slots) gives you a fast path that fits in registers and cache lines.

```rust
#[repr(C)]
pub struct IpcMessage {
    pub label: u64,          // userspace-defined message kind
    pub length: u16,         // valid bytes in `data`
    pub cap_count: u8,       // 0..=4
    pub flags: u8,
    pub data: [u8; 56],      // inline payload
    pub caps: [CapSlot; 4],  // capability transfer slots
}
```

Anything bigger than `data` goes via a shared memory region established once and reused.

The IPC fast path — sender and receiver both runnable, message fits inline, no scheduler decision needed — is the hottest path in the entire OS. **Measure it.** seL4's fast path on x86_64 is around 200 cycles. Yours will start at 5,000 and you'll spend years getting it under 1,000. That is fine.

### 7.6 The capability system

This is the privacy story expressed in data structures. Adopt a simplified seL4 model:

- Every kernel object (a thread, an address space, an endpoint, a notification, a memory region) is referenced *only* through a capability.
- Capabilities live in per-process **CSpaces** (capability spaces), trees of `CNode`s.
- A process can do *exactly nothing* without a capability. The default cap set on process creation is a single endpoint to its parent.
- Capability operations: `Mint` (derive a less-privileged copy), `Move`, `Delete`, `Revoke`. `Revoke` is the privacy power-tool — it transitively kills every derived copy. It is also the **robustness power-tool** (Section 17): when a service crashes, the supervisor revokes all caps it had handed out, guaranteeing the next instance starts from a clean slate.

```rust
pub enum CapType {
    Null,
    Untyped { phys: PhysFrame, size_bits: u8 },
    CNode { radix_bits: u8, ptr: *mut CNode },
    Thread(ThreadHandle),
    AddressSpace(AddressSpaceHandle),
    Endpoint(EndpointHandle),
    Notification(NotificationHandle),
    Frame { phys: PhysFrame, size: FrameSize },
    Irq(IrqLine),
}

#[repr(C)]
pub struct CapSlot {
    pub cap_type: CapType,
    pub rights: CapRights,    // Read, Write, Grant, Reply
    pub badge: u64,           // sender identification on receive
}
```

The "Untyped" capability is the source of all memory. A process holding an Untyped can `Retype` it into specific kernel objects (a Thread, an Endpoint, a Frame). This is how memory accounting works without garbage collection: the kernel gives every process a fixed Untyped budget, and the process spends it.

### 7.7 SMP

Don't bother in Phase 1–2. Single core is enough to expose every interesting bug. Move to multi-core in Phase 4 by:
- Bringing up APs through INIT-SIPI-SIPI on x86_64, PSCI on aarch64.
- Per-CPU run queues with work-stealing.
- Per-CPU heaps with a global fallback.
- TLB shootdowns via IPIs (x86_64) or DSB+TLBI broadcasts (aarch64).

### 7.8 Arch-specific hardening — turn it on early

x86_64 features to enable as soon as the kernel supports them:
- **SMEP, SMAP** — kernel cannot execute or accidentally read user pages.
- **CET (IBT + Shadow Stack)** — hardware-enforced control-flow integrity.
- **KASLR** — randomized kernel base.
- **Kernel Page-Table Isolation** — isolate user and kernel page tables to neutralize Meltdown-class issues on older CPUs.

aarch64 features (free wins, enable from Phase 6 forward):
- **PAN** (Privileged Access Never) — analogous to SMAP.
- **PXN** (Privileged Execute Never) — analogous to SMEP.
- **PAC** (Pointer Authentication) — signs return addresses; defeats most ROP.
- **BTI** (Branch Target Identification) — control-flow integrity.
- **MTE** (Memory Tagging Extension) on supporting CPUs — hardware-assisted use-after-free detection. A massive privacy and robustness win when we get here.

---

## 8. The Hardware Abstraction Layer

The HAL is the contract between the architecture-generic kernel and the metal. Designed early, it pays for itself the day someone files a "boots on Apple Silicon" PR.

The `ruzt-hal` crate is **just traits** — no implementations, no `unsafe`, no arch-specific code. It can be compiled by any crate as documentation of the contract.

```rust
// hal/ruzt-hal/src/lib.rs (skeleton)
#![no_std]

pub trait CpuOps {
    fn cpu_id() -> u32;
    fn cpu_idle();
    fn enable_interrupts();
    fn disable_interrupts() -> InterruptGuard;
}

pub trait Mapper { /* see 7.2 */ }

pub trait Timer {
    fn now_monotonic_ns() -> u64;
    fn set_oneshot_ns(deadline_ns: u64);
}

pub trait IrqController {
    fn enable(irq: IrqNumber);
    fn disable(irq: IrqNumber);
    fn route(irq: IrqNumber, cpu: u32);
    fn end_of_interrupt(irq: IrqNumber);
}

pub trait Console {
    fn write_bytes(bytes: &[u8]);
}

pub trait BootInfoSource {
    fn build() -> &'static crate::BootInfo;
}
```

`ruzt-hal-x86_64` and `ruzt-hal-aarch64` each implement the full set. The kernel selects one at compile time via Cargo features:

```toml
# kernel/ruzt-kernel/Cargo.toml
[features]
arch-x86_64  = ["ruzt-hal-x86_64"]
arch-aarch64 = ["ruzt-hal-aarch64"]
```

**The cardinal rule: no `cfg(target_arch)` outside the HAL.** If you need it, you've found a bug in the trait surface. Fix the trait.

---

## 9. User-Space Drivers

The microkernel commitment means most of the "OS" lives outside the kernel. A driver is just a user-space process that:

- Holds an `Irq` capability (granted by the bus enumerator) so it can wait on a device interrupt.
- Holds one or more `Frame` capabilities mapped at the device's MMIO addresses (granted by ACPI / device-tree / ADT enumeration).
- Holds an `Endpoint` to receive client requests.
- May hold DMA-capable contiguous physical frames if it needs bus mastering.

The `drivers/` crates each look roughly like:

```rust
// drivers/virtio-blk/src/main.rs
fn main() {
    let env = ruzt_runtime::startup();
    let mmio: MmioRegion = env.cap("device.mmio").unwrap();
    let irq:  Irq        = env.cap("device.irq").unwrap();
    let listen: Endpoint = env.cap("listen").unwrap();

    let device = VirtioBlk::probe(mmio).expect("probe failed");
    let dma    = ruzt_runtime::dma_pool(64 * 1024).unwrap();

    loop {
        ruzt_ipc::select![
            req = listen.recv() => handle_request(&device, &dma, req),
            _   = irq.wait()    => device.handle_completion(),
        ];
    }
}
```

**Design the driver SDK first.** `ruzt-driver-sdk` provides MMIO accessors, DMA buffers, IRQ helpers, hot-plug events, and a debug-tracing format. Every driver consumes this SDK. It is the contract between the kernel team and the driver team.

**Bus enumeration is itself a user-space service.** A `pcid` (PCI enumerator) on x86_64 / a `dtsrv` (device tree server) on aarch64 walks the bus, identifies devices, and hands out the right MMIO/IRQ caps to drivers as the supervisor spawns them. This is also the natural place to gate "which devices exist for which apps" — though for now, the answer is "all devices belong to drivers, and drivers are trusted system services".

---

## 10. Storage, Filesystem & Full-Disk Encryption

### 10.1 The block layer

```rust
pub trait BlockDevice: Send + Sync {
    fn block_size(&self) -> usize;
    fn block_count(&self) -> u64;
    async fn read(&self, lba: u64, buf: &mut [u8]) -> Result<(), IoError>;
    async fn write(&self, lba: u64, buf: &[u8]) -> Result<(), IoError>;
    async fn flush(&self) -> Result<(), IoError>;
    async fn discard(&self, lba: u64, count: u64) -> Result<(), IoError>;
}
```

### 10.2 RuztFS — the native filesystem

Don't try to be a research filesystem. Aim for "a clean re-implementation of ZFS's main ideas, simplified":

- **Copy-on-write everything.** Crash safety is free.
- **Merkle tree of block hashes.** Integrity is free.
- **Snapshots are nearly free** — keep an old root pointer alive.
- **Per-file encryption keys** wrapped by a master key, master key wrapped by a user key derived via Argon2id from a passphrase. Better than block-level FDE because backups can be stored encrypted without re-encryption.
- **Endian-portable on-disk format.** Always little-endian on disk regardless of host. (Important when x86_64 and aarch64 share a disk.)

A first-cut on-disk layout:

```
[ superblock × 2 (mirrored) ]
[ space-tree root ]
[ object-tree root ]
[ snapshots list ]
[ data extents ]
```

Be honest about timing: a *correct* COW FS is 6–12 months of focused work. For Phase 4, ship a tmpfs and a FAT32 read-only driver, then do the encrypted RuztFS in Phase 7.

### 10.3 Encryption defaults

- **At rest:** all writable filesystems require a key. The installer creates one master key, splits it into a TPM-sealed half and a passphrase-derived half. Boot needs both.
- **In transit:** TLS 1.3 only, no fallback. Default DNS is DNS-over-HTTPS.
- **In memory:** sensitive memory regions (key material, keyboard buffers in password fields) are mapped with the `Sensitive` flag — the kernel zeros them on free.

### 10.4 VFS broker

The `vfs` server is a user-space process that holds:
- A mount table mapping path prefixes to filesystem-server endpoints.
- A capability cache for open files (the `File` capability is a badged endpoint to the FS server).

When a process opens `/home/ruzgar/notes.txt`:
1. POSIX shim translates `open()` to an IPC to `vfs`.
2. `vfs` looks up the longest matching mount → routes to RuztFS server endpoint.
3. RuztFS resolves the path, returns a new badged endpoint as the `File` cap.
4. `vfs` returns the cap to the process.
5. The process now talks to RuztFS *directly* — `vfs` is not in the read/write hot path.

This direct-handoff pattern is critical for performance.

---

## 11. Networking Stack & Isolation

### 11.1 smoltcp inside `netd`

`smoltcp` is a `no_std` Rust TCP/IP stack. It is mature, embedded-friendly, and a perfect fit. Don't write your own stack — port `smoltcp` and contribute fixes upstream.

`netd` is a user-space server that owns:
- Each network interface's queue capabilities.
- A `smoltcp::Interface` per NIC.
- A namespace map: `ProcessId → NetworkNamespace`.

### 11.2 Per-process network namespaces

A process gets network access only when explicitly granted, and only on the interfaces it was granted on. Three default namespaces:

- `none` — no sockets at all. The default for newly-spawned processes.
- `default` — direct internet via the user's chosen interface.
- `private` — through the system VPN (WireGuard) or Tor, depending on user config.

A namespace is a capability. The user grants it via the desktop UI ("Allow Firefox to use the internet" prompt); the desktop's permission service mints a namespace cap and passes it to the launching process.

### 11.3 Tor and WireGuard built-in

- **WireGuard** in the base image, configured via a single `wg.toml` plus a Settings panel. Implemented in user space inside `netd` — a clean fit for the microkernel model.
- **arti** (the Rust Tor implementation) included as an optional package, enabled via a single switch. When enabled, the `private` namespace's egress goes through arti.

### 11.4 Hardening defaults

- DNS-over-HTTPS to a user-chosen resolver.
- MAC address randomization on Wi-Fi every scan (see §27.3 for the full Wi-Fi model).
- Bluetooth off by default.
- mDNS off by default.
- No automatic captive-portal detection over plaintext HTTP.

---

## 12. POSIX Shim — `libruzt-posix`

The compatibility story without committing to compatibility forever.

**Approach:** port `relibc` (Redox's libc) as a starting point, replacing its syscall layer with calls into Ruzt's IPC. This gives you 80% of musl's surface for ~20% of the work of writing a libc from scratch.

```rust
// libruzt-posix/src/unistd.rs
#[no_mangle]
pub extern "C" fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize {
    let file_cap = match fd_table::lookup(fd) {
        Some(c) => c,
        None => return set_errno(EBADF),
    };
    let slice = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, count) };
    match ruzt_ipc::file::read(file_cap, slice) {
        Ok(n) => n as isize,
        Err(e) => set_errno(e.into()),
    }
}
```

**`fork()` is the hard one.** A microkernel doesn't have fork built in. Implement it as:
1. Create a new address space (capability operation).
2. CoW-copy every mapped region.
3. Duplicate the file descriptor (capability) table.
4. Spawn a thread starting at the saved instruction pointer.

It's not free, but it is correct and lets every POSIX program work.

**ELF loader for foreign binaries.** Optional and Phase 8+. Far simpler is "static-link Rust port and run it natively", which is what most modern open-source userland already supports. Don't promise binary compatibility with Linux; promise *source* compatibility.

---

## 13. Init System, Service Management & the Supervision Tree

systemd has good ideas mixed with regrettable scope. Take the good ones.

`rootsrv` is the first user-space process. It reads `/etc/services/*.toml` declarative service files and supervises them. Erlang/OTP's lessons apply directly: model the system as a *tree* of supervisors and workers, each layer responsible for restarting its children.

```toml
# /etc/services/netd.toml
[service]
name        = "netd"
binary      = "/system/bin/netd"
restart     = "on-failure"
restart-max = 5
restart-window = "60s"

[health]
endpoint = "netd.health"
interval = "10s"
timeout  = "2s"

[capabilities.required]
hardware    = ["pci.bus.0"]
filesystem  = ["read:/etc/network"]

[capabilities.granted]
endpoints   = ["public:netd.sock"]

[supervises]
children = ["wg-link", "tor-link"]
```

A service receives, on startup, exactly the capabilities the manifest declares. **This is the user-space mirror of the kernel's capability rule, and it is why Ruzt has no setuid.**

A service that fails its health check or crashes is *revoked* (its caps recursively destroyed), then *restarted* with a fresh cap set. Because all state worth keeping lives in capabilities backed by other services (the FS, etc.), the restart leaves no orphan resources. This is the crash-only pattern; see Section 17.

---

## 14. Display Server, Compositor & GUI Stack

This is where the project becomes a *product* people can see. Treat it as such.

### 14.1 Smithay as the foundation

Smithay (https://github.com/Smithay/smithay) is the right choice. It is a collection of modular Rust crates for building Wayland compositors:

- `wayland-server` — the protocol implementation.
- `smithay::backend::*` — DRM/KMS, libinput, winit, virtio-gpu backends.
- `smithay::desktop` — window/space management primitives.
- `smithay::wayland` — handlers for core Wayland protocols (compositor, seat, output, xdg-shell).

Building on Smithay buys us the entire Wayland ecosystem — GTK, Qt, Firefox, every native Wayland app — for the cost of writing a compositor process, not a windowing protocol from scratch. We do not lose the privacy story; we *implement* it as Wayland protocol extensions, which is the textbook way to do it.

**Architecture of `displayd`:**

```rust
// servers/displayd/src/main.rs (sketch)
use smithay::{
    backend::renderer::gles::GlesRenderer,
    desktop::{Space, Window},
    reexports::{calloop::EventLoop, wayland_server::Display},
    wayland::compositor::CompositorState,
    wayland::shell::xdg::XdgShellState,
    wayland::seat::SeatState,
    wayland::output::OutputManagerState,
};

struct DisplayD {
    display: Display<State>,
    space: Space<Window>,
    compositor: CompositorState,
    xdg_shell: XdgShellState,
    seat: SeatState<State>,
    outputs: OutputManagerState,
    permissions: PermissionState, // Ruzt-specific
}

fn main() {
    let env = ruzt_runtime::startup();
    let gpu_cap = env.cap("gpu").unwrap();
    let input_cap = env.cap("input").unwrap();
    let fb_cap = env.cap("framebuffer").unwrap();
    // …
}
```

### 14.2 Capability-aware Wayland protocol extensions

The Wayland trust model already gives us a lot: clients cannot see each other's surfaces by default, input is delivered only to the focused window, etc. What it does *not* gate per-app are:

- Screen capture / screencast (`zwlr_screencopy_v1`, `zext_screencopy_manager_v1`).
- Global hotkeys.
- Surface introspection / input redirection.
- Clipboard reads.

These are exactly the privacy holes in current Wayland desktops. Ruzt's compositor implements them as **`zruzt_*` Wayland protocol extensions** that require a capability:

- `zruzt_screencast_v1` — only granted if the user explicitly approves a screen-capture session in `permd`.
- `zruzt_global_hotkey_v1` — only granted with explicit user approval, scoped to specific keysyms.
- `zruzt_clipboard_persistent_v1` — clipboard *reads* require either user activation (a paste action) or explicit cap; clipboard *writes* are unrestricted.
- `zruzt_session_lock_v1` — session lock surface protocol (see §29.3).

Document each extension in `docs/protocol/`. Publish them.

### 14.3 Toolkit

Pick one default and unify on it. Two reasonable paths:

- **Adopt `iced`** — mature, retained-mode, MIT-licensed, Rust-native, theming built in. Build a `ruzt-iced` backend that targets the Smithay-served protocol.
- **Adopt `egui`** — immediate-mode, very productive for tools, less suited for highly polished consumer UI.

Recommendation: **`iced` for end-user apps, `egui` for developer tools and the installer.** Different tools for different jobs. GTK and Qt apps continue to work via standard Wayland protocols.

### 14.4 Reference desktop: "Zephyr"

A reference DE that ships in the base image. Components:

- **Panel** (top bar): clock, network, battery, sound, notifications, AV-capture indicators.
- **Launcher** (Cmd-Space): fuzzy search over apps, files, and settings.
- **Window manager**: tiling-by-default with floating override; keyboard-first but mouse-fluent.
- **Settings**: one app, one search box, capability-centric (e.g., "What can Firefox read?").
- **Notifications**: do-not-disturb default off, but quiet hours easy.

---

## 15. Package Management & Reproducible Builds

### 15.1 Reproducibility is a property, not a hope

Three rules:
1. **Pinned toolchain.** Already in `rust-toolchain.toml`.
2. **Pinned dependencies with content addressing.** `Cargo.lock` is mandatory; in addition, a `provenance.toml` per third-party crate records the upstream commit hash and the SHA256 of the vendored source.
3. **Hermetic build environment.** The build runs inside a sandbox (a Ruzt sandbox in production, a `podman` container during bootstrap) with no network, only the declared inputs.

A build run produces a build attestation (in-toto / Sigstore format) signed by the builder's key. Multiple independent builders signing the same hash is the trust signal — not "one company says so".

### 15.2 The package format: `.rzpk`

A `.rzpk` is a Zstandard-compressed tarball with:
- `manifest.toml` — name, version, description, dependencies, declared capabilities.
- `payload/` — files to install.
- `signatures/` — one or more detached Sigstore-style signatures.
- `bom.json` — software bill of materials.

The package manager `ruzt-pkg`:
- Verifies signatures against a user-configurable keyring.
- Verifies the BoM against the lock-file equivalent.
- **Sandboxes the install.** A package install is itself a process running with narrow caps — only writing to the package's destination path. Post-install scripts run with no network, no FS access outside their destination, ever.
- Records every install in an append-only log. `ruzt-pkg history` is a feature.

### 15.3 Two channels

- **Stable.** Rolls forward only after passing a CI matrix (boot + install + smoke tests on N hardware profiles, both arches).
- **Edge.** Daily, for contributors.

No "AUR-equivalent" of arbitrary user packages without explicit re-signing. People can run unsigned packages by name, but the UI screams.

---

## 16. Security Architecture Deep Dive

A consolidated view of what's already scattered through prior sections.

| Layer | Mechanism |
|---|---|
| Hardware (x86_64) | Secure Boot + TPM-measured boot; SMEP, SMAP, CET; W^X. |
| Hardware (aarch64) | UEFI Secure Boot; PAN, PXN, PAC, BTI, MTE where available; W^X. |
| Kernel | Capability-only API; `unsafe` budgeted and audited; KASLR; KPTI on x86_64. |
| User-space | Per-process capability set; default empty; namespacing for net, fs, ipc. |
| Filesystem | At-rest encryption per-file with Argon2id-derived KEK. |
| Network | Per-app namespaces; WireGuard/Tor first-class; DoH default. |
| Compositor | Capability-gated Wayland extensions for screen capture, global hotkeys, clipboard reads. |
| Package | Reproducible builds; Sigstore attestations; sandboxed install; append-only history. |
| Update | Atomic A/B updates with rollback (Chrome OS pattern); update bundle is itself a signed `.rzpk`. |
| Boot | Measured boot, TPM-sealed disk key, requires user passphrase + TPM consensus. |
| PKI | `trustd` daemon; Mozilla CA bundle; OCSP caching; CT enforcement; user distrust overrides. |
| AV privacy | `Camera` and `Audio::Capture` capabilities; hardware LED enforcement; compositor indicators. |

**Threat model — write it down explicitly.** A common failure mode is "we are secure against everything", which means "we have not thought about this". Ruzt's stated threat model:

- **In scope:** local malware escalation, network attacker, supply-chain compromise of a single dependency, lost laptop, opportunistic data harvesting.
- **Out of scope (for now):** physical tampering with mounted hardware, nation-state targeted attacks, side-channel attacks on the CPU itself (Spectre etc.) — we apply standard mitigations but make no novel claim.

Putting the out-of-scope items in writing prevents users from misplacing trust and prevents you from being held to a standard you didn't promise.

---

## 17. Robustness & Crash-Only Design

Robustness is not "don't crash". Robustness is "crash safely, recover quickly, lose nothing important". Ruzt's robustness story is built from four reinforcing pieces.

### 17.1 Crash-only software

Every user-space service is designed so that **the only shutdown path is "crash"**. There is no graceful-shutdown protocol, no `SIGTERM` handler, no "save state before exit" code path. A service either runs or is dead, with nothing in between.

This sounds aggressive, and it is. The payoff: there is exactly one recovery mechanism — the supervisor restarts the dead service. You don't have a graceful path that's tested every Tuesday and a crash path that's exercised once a year on a production weekend at 3 a.m. You have one path, exercised every time.

What this implies for service authors:
- Persistent state goes through the FS, atomically (RuztFS COW makes this easy).
- Volatile state is *truly* volatile — fine to lose.
- No "cleanup on exit". If you can't be killed at any instant without consequence, you have a bug.

### 17.2 Capability revocation as the recovery primitive

When `rootsrv` decides a service is unhealthy, it issues `Revoke` on the service's root CNode. The kernel transitively destroys every capability derived from that CNode — every endpoint clients held to it, every file descriptor, every memory region it had handed out. Clients that try to use those caps get `EBADCAP` and either retry through service discovery (the supervisor exposes a stable name → endpoint mapping that the new instance reclaims) or fail loudly.

This is *the* benefit of the capability model from a robustness perspective: no orphaned references can outlive a service's death.

### 17.3 Supervision trees

`rootsrv` is the root supervisor. It supervises a small fixed set of system-level supervisors (`net-sup`, `fs-sup`, `dev-sup`, `ui-sup`, etc.), each of which supervises the actual leaf services. Restarts are localized: a crashed `wg-link` is restarted by `net-sup`, not by `rootsrv`. The blast radius shrinks as you go up the tree.

Every supervisor has a restart policy:
- `permanent` — always restart.
- `transient` — restart only on abnormal exit.
- `temporary` — never restart (one-shot service).

And a restart strategy:
- `one-for-one` — restart only the dead child.
- `one-for-all` — if any child dies, restart all siblings.
- `rest-for-one` — restart the dead child and all siblings started after it.

These are Erlang/OTP terms because Erlang/OTP got this right twenty-five years ago.

### 17.4 Atomic A/B system updates

The system root is a RuztFS subvolume. Updates write a new subvolume, run integrity checks, and atomically swap the boot pointer. A failed boot rolls back automatically (the bootloader checks a "boot succeeded" flag set by the running system; if it's not set after N seconds, the previous root is selected on next boot).

Combined with reproducible builds, this means: an update can never brick the system, and any "this update broke X" complaint is bisectable to the byte.

### 17.5 Other defenses

- **Watchdog timers** on every long-running service.
- **Memory pressure handlers** at the per-process level.
- **Panic-on-corruption in the kernel.** Better to halt than to continue with corrupt state.

---

## 18. Privacy Architecture

Privacy is the cluster of properties that, taken together, make the system a tool *for* the user rather than *against* them.

- **Telemetry-zero.** No analytics endpoint exists in the codebase. CI fails on a regex pattern that matches network egress in the base userland.
- **Per-app permission grants.** Every capability mint that crosses a privacy boundary (camera, microphone, location, contacts-equivalent) is gated by a UI prompt served by `permd`. The grant is **scoped** (one-shot, this-session, always) and **revocable from one place** in Settings.
- **Reproducible builds + signed releases.** The user can verify their installed bytes match the source tree.
- **MAC randomization + DNS-over-HTTPS + no broadcasting.** Defaults that protect users on hostile networks without configuration.
- **Disk encryption mandatory.** The installer does not offer a "no encryption" path.
- **Capability-gated Wayland extensions.** A keylogger cannot install itself by reading the global keyboard state.
- **No cloud account required.** Ever. There is no Ruzt account. There is no "log in to your OS".
- **Hardware AV indicators.** Camera LED and microphone dot enforced at the compositor level — cannot be spoofed by apps.

---

## 19. Aesthetic & UX Design System

You named *aesthetic* as a first-class requirement. Engineer it from day one.

### 19.1 The brand surface

Define a single design tokens file in `design/tokens.toml`. Every visible component consumes from this file. The tokens are versioned the same way the rest of the OS is versioned.

```toml
# design/tokens.toml
[colors]
bg.0       = "#0E1014"   # base canvas
bg.1       = "#161A21"
bg.2       = "#1E232C"
fg.0       = "#E8EAEE"
fg.1       = "#B8BDC7"
accent     = "#8AB4FF"   # "wind"
accent-2   = "#7FE3C4"   # "breeze"
warn       = "#FFB86C"
error      = "#FF6E6E"

[typography]
display    = "Inter Variable"
ui         = "Inter Variable"
mono       = "JetBrains Mono"

[motion]
fast       = "120ms"
medium     = "220ms"
slow       = "420ms"
ease.std   = "cubic-bezier(0.2, 0.0, 0.0, 1.0)"
ease.in    = "cubic-bezier(0.4, 0.0, 1.0, 1.0)"
```

Light and dark themes are both first-class.

### 19.2 Visual language principles

- **Quiet by default, expressive on demand.** No "look at me" gradients on every panel.
- **One radius value used everywhere.** Pick `8px` for windows and panels, `4px` for inline elements.
- **Animation is *informational*, not decorative.** Movement explains a state change — never just to look slick.
- **Typography hierarchy is structural.** Three sizes max in the base UI.
- **Asymmetry over decoration.**

### 19.3 The places people will judge you

- **Boot splash.** Painted from the bootloader phase. A single brand-mark.
- **TTY font.** JetBrains Mono, available before the framebuffer is.
- **Panic screen.** Design it. A friendly, clean wall — error code, suggestion, QR code to docs. Not a wall of register dumps.
- **Installer.** Three screens: language → disk → user. Nothing else. No telemetry consent dialog.
- **First-run desktop.** A single welcome card. Dismisses cleanly. Doesn't pop up again.

### 19.4 Accessibility

- Type scales to 200% without breaking layout.
- Minimum contrast 4.5:1 for body, 7:1 for body-on-accent.
- Every interaction reachable from keyboard.
- A high-contrast theme that is *actually* usable.
- Screen reader hooks at the protocol level — a `Surface` advertises its accessibility tree the same way it advertises its damage region.
- Touch and HiDPI as full peers in the layout system.

---

## 20. Development Workflow

- Document each crate's responsibilities, public API, invariants, and test commands.
- Define expected behavior in tests and run the relevant checks before submitting a change.
- Document the safety invariants of new `unsafe` code and cite primary specifications for hardware constants.
- During review, check memory safety, capability boundaries, telemetry, and separation between the kernel and architecture-specific code.

---

## 21. Testing, Fuzzing & Formal Verification

### 21.1 Three layers of automated testing

1. **Unit tests in `no_std`.** Run on every `cargo make test`.
2. **Integration tests in QEMU.** Both arches in CI.
3. **End-to-end tests on real hardware.** Three laptops (Intel, AMD, ThinkPad-class), a Raspberry Pi 5, eventually Apple Silicon.

### 21.2 Fuzzing

Fuzz every cross-trust boundary:
- IPC syscall entry point.
- ELF loader with malformed binaries.
- Filesystem with corrupted images.
- TCP stack with malformed packets.
- Wayland protocol parsing in `displayd` — especially the `zruzt_*` extensions.

### 21.3 Property tests

Use `proptest` for invariants the type system can't express:
- "Mint then Revoke restores the cap table to its prior state."
- "Two concurrent IPCs deliver in some order, never both lost, never both received."
- "Allocating then freeing a frame returns the bitmap to its prior state."

### 21.4 Formal verification — pick your battles

- IPC fast path memory safety: **Kani**.
- Page-table update invariants: **Creusot** or **Prusti**.
- Capability-revocation transitive closure: **TLA+**.

### 21.5 CI matrix

Per-PR: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`, QEMU integration on both arches, license check, `cargo deny`, telemetry-zero regex sweep, doc build.

Nightly: full fuzz corpus replay, formal verification re-runs, hardware lab smoke.

---

## 22. Contribution Model & Governance

### 22.1 License

- **MPL-2.0** for the kernel and core servers.
- **Apache-2.0 OR MIT** for crates intended for ecosystem reuse (toolkit, IPC client lib).

Document this matrix in `LICENSE.md`.

### 22.2 RFC process

For changes touching public ABI, the capability model, the package format, the design system, or any of the locked-in decisions in Section 2: an RFC PR in `docs/rfc/`. Two-week minimum comment window. Decision by maintainer council.

### 22.3 Governance over time

Solo at first. As contributors come in: a "core team" of three with merge access, a "trusted maintainer" tier for component owners, an "RFC council" that breaks ties. Don't structure governance until you have to.

### 22.4 Code of conduct

Adopt the Rust CoC verbatim.

---

## 23. Mobile & Future Form Factors

You signaled mobile as a future direction. Most decisions in this document already accommodate that. A short list of what *additionally* needs to happen:

### 23.1 What "mobile" means for Ruzt

A mobile Ruzt is the same OS, the same kernel, the same userland, with three deltas:
1. **A different display profile.** `displayd` runs in single-window-per-output mode, launcher fills the screen, touch targets are sized correctly.
2. **A power profile.** Aggressive idle, frequency scaling, background-app freeze. The supervisor enforces a "frozen" service state where caps are revoked but state is preserved (a checkpointing capability).
3. **Modem isolation.** The cellular modem runs as an isolated user-space driver with no DMA outside its dedicated bounce buffer.

### 23.2 Hardware paths for mobile

- **PinePhone Pro / PineTab** as the first target.
- Long-term: a custom reference device the Ruzt project endorses.

### 23.3 Touch as a first-class input

Smithay supports touch via libinput. The `iced` adaptation needs pointer/touch unification, gesture recognition, and haptic-feedback capability gating (apps can't buzz arbitrarily).

### 23.4 Telephony

Phase 12 work. `telephonyd` server modeled after Phosh/ModemManager but capability-gated. Phone calls and SMS are the most sensitive operations on a mobile device.

---

## 24. Power Management — `powerd` & Energy Subsystem

For a "privacy-conscious end-user laptop", power management is as critical as the display server. A system that cannot sleep, wake cleanly, or scale CPU frequency is not a daily driver. In a microkernel the problem is more tractable than it sounds: the decision to suspend is made by a user-space daemon, and the actual hardware transition is the smallest possible kernel primitive.

### 24.1 The privilege split

Power management has two halves.

**Kernel half (minimal):**
- A `Suspend` kernel capability: when invoked, the kernel flushes the TLB, saves per-CPU state, writes the ACPI S3 sleep register (x86_64) or issues `PSCI CPU_SUSPEND` (aarch64), and halts. On wake it restores state and delivers a `Wake` notification to the holder.
- A `PState` capability: authorises the holder to write CPU P-state (via `PERF_CTL` MSR on x86_64 or the SCMI `CPUFREQ` interface on aarch64). Handed exclusively to `powerd` at startup.
- A `WatchdogTimer` capability: the kernel fires a forced lower P-state if `powerd` stops checking in — a crashed `powerd` cannot leave the system running flat-out indefinitely.

**User-space half (`powerd`):** all ACPI AML execution, device freeze coordination, battery polling, thermal management, CPU frequency scaling, and power-event policy. `powerd` is a supervised service; if it crashes the supervisor restarts it — aggressive power management is briefly offline, not catastrophic.

### 24.2 ACPI AML in user space: LAI

Do not put an AML interpreter in the kernel. The correct solution is **LAI** (Lightweight AML Interpreter, `github.com/managarm/lai`): ~5,000 lines of C, designed explicitly for user-space microkernel use. It runs entirely outside the kernel and communicates with hardware through the same MMIO and port-IO capabilities that every other user-space driver uses.

Rust bindings exist: `lai-rs` (`github.com/aero-os/lai-rs`) wraps LAI with a safe Rust interface. ACPICA also supports user-space execution, but LAI is smaller and gives you more control.

`powerd` links LAI, receives the ACPI tables as a read-only Frame capability from boot, and uses it to:
- Walk the namespace at startup (enumerate devices, thermal zones, battery objects).
- Execute `_PTS` before a suspend and `_WAK` after resume.
- Respond to ACPI Notify events (lid, power button, battery threshold changes).
- Execute `_PS0` / `_PS3` per-device power-state methods during suspend/resume.

```toml
# /etc/services/powerd.toml
[service]
name   = "powerd"
binary = "/system/bin/powerd"

[capabilities.required]
hardware   = ["acpi.tables", "acpi.ports", "cpu.pstate", "acpi.suspend"]
filesystem = ["read:/etc/power", "write:/run/power"]

[capabilities.granted]
endpoints  = ["public:powerd.events", "public:powerd.battery"]
```

### 24.3 CPU frequency scaling and thermal

`powerd` runs a `schedutil`-inspired governor entirely in user space:

1. Every 50 ms it samples CPU utilisation via per-CPU counters (a read-only `CpuStats` capability minted by the kernel).
2. It writes the desired P-state via the `PState` capability.
3. On modern Intel/AMD: CPPC (`_CPC` ACPI method via LAI). On aarch64: PSCI + SCMI.

**Thermal management:** ACPI thermal zones expose `_TMP` temperature sensors. `powerd` polls them every second and enforces a three-trip-point model:

| Trip | Action |
|---|---|
| Passive (e.g. 75 °C) | Reduce P-state |
| Active (e.g. 85 °C) | Raise fan speed via `_ACx` |
| Critical (e.g. 100 °C) | Orderly shutdown via `rootsrv` IPC |

### 24.4 Suspend/resume sequence

1. `powerd` signals intent → sends `Suspend` notification to `rootsrv`.
2. `rootsrv` freezes services → each supervisor sends `Freeze` to leaf services; they drain queues and flush pending FS writes.
3. Drivers quiesce → each driver drains its request queue; USB host puts devices in U3.
4. `powerd` executes `_PTS` via LAI.
5. `powerd` invokes `Suspend` capability → kernel saves state, machine sleeps.
6. On wake → kernel delivers `Wake` notification to `powerd`.
7. `powerd` executes `_WAK` via LAI.
8. `rootsrv` thaws services in reverse order.
9. `displayd` maps lock surface → user authenticates via `authd` before the desktop is restored.

Step 9 is critical: the lock screen is presented **before** the desktop is restored. There is no brief window of an unlocked desktop.

### 24.5 Battery and power events

`powerd` exposes a stable `powerd.battery` endpoint. Any process with a `BatteryRead` capability (granted freely to the panel widget) can query charge percentage, time-to-full, time-to-empty, AC adapter state, and battery health.

Power button, lid, and sleep-key events arrive as ACPI Notify interrupts forwarded to `powerd` as notification capabilities. Policy lives in `/etc/power/events.toml`.

### 24.6 Hibernate (S4) — Phase 9

Allocate an encrypted swap subvolume on RuztFS. `powerd` asks the kernel to serialise physical memory into it via a capability-gated bulk write. The bootloader checks for a hibernate image before normal boot and restores it if present. The swap subvolume is encrypted with the same KEK as the root filesystem.

---

## 25. Audio — `audiod` & the Capability-Gated Media Graph

Without audio, Ruzt cannot play video, run a voice call, or host a music player. Audio is also a high-consequence privacy surface — microphone access must be capability-gated with the same rigour as the camera.

### 25.1 Architecture: graph-based, PipeWire-inspired

Do not implement a monolithic audio server. The proven model (PipeWire, shipping on every major Linux desktop since 2022) is a **graph of nodes** where each node has input and output ports:

- **Source nodes:** hardware capture (microphone), system sounds, app playback streams.
- **Sink nodes:** hardware playback (speakers, headphones), recording endpoints.
- **Filter nodes:** resampling, mixing, effects.

Nodes run in separate processes or inside `audiod`. Data moves between nodes via shared memory — a pair of Frame capabilities mapped into both producer and consumer — synchronised by a Notification capability.

**Two processes:**

- **`audiod`** — owns the hardware device capabilities (HD Audio or USB Audio endpoint). Owns the graph, schedules the processing quantum (typically 512 or 1024 frames at 48 kHz ≈ 10–21 ms).
- **`audio-sessiond`** — implements routing policy (which app goes to which device, volume, default sink/source). Separated from `audiod` so a policy bug cannot crash the audio graph. Analogous to WirePlumber 0.5.

```
App (music player)    App (browser call)
      |                      |
 [Audio::Playback]    [Audio::Capture]
      |                      |
      +-------[audiod graph]-------+
              /      |       \
        [mixer] [resampler] [spatial]
                     |
           [HD Audio driver endpoint]
```

### 25.2 The `Audio` capability

- **`Audio::Playback`** — right to submit PCM frames to a named stream. Granted by `permd` without a UI prompt; audio playback is not privacy-sensitive.
- **`Audio::Capture`** — right to receive PCM frames from a capture device. **Requires a UI prompt via `permd`**, identical in flow to camera or screen-capture grants. The grant is scoped (one-shot, session, always) and revocable from Settings → Privacy → Microphone.

This is the privacy guarantee that current Linux desktops lack: on a stock PipeWire system, any process can open the microphone without any permission check.

### 25.3 Compatibility

| App type | Served by | Mechanism |
|---|---|---|
| Native Ruzt | `ruzt-audio` crate | Direct IPC to `audiod` |
| PulseAudio apps | `pulse-shim` process | Speaks PA Unix socket, proxies to `audiod` |
| JACK apps | `jack-shim` process | Speaks JACK API, proxies to `audiod` |
| ALSA apps | `alsa-shim` (`LD_PRELOAD`) | Intercepts ALSA PCM calls, proxies to `audiod` |

PipeWire ships all three of these shims. Ruzt adopts the same strategy.

### 25.4 Low-latency guarantee

`audiod` runs its processing thread with a `RealtimePriority` capability (explicitly granted by the supervisor). Quantum is negotiated: music playback accepts 1024 frames; voice call wants 128 frames. The graph runs at the minimum requested quantum, identical to JACK's fixed-period model.

### 25.5 Privacy indicators

When any `Audio::Capture` stream is open, `audiod` notifies `displayd` via a dedicated endpoint. `displayd` renders a persistent orange-dot microphone indicator in the compositor layer — not in any app's surface. An app cannot fake or suppress it. This is the iOS model, enforced at the compositor level.

---

## 26. USB Subsystem — `usbhostd` & Device Class Isolation

USB is the largest driver surface on a real laptop. The microkernel architecture makes this tractable: one process owns the host controller, and each device class runs as an isolated child process.

### 26.1 `usbhostd` — the host controller daemon

The kernel grants `usbhostd` two capabilities: the xHCI controller MMIO Frame and the corresponding IRQ Notification. Everything above that lives in `usbhostd`.

Use the **`rust-osdev/xhci`** crate for typed, safe register-level access to xHCI capability registers, operational registers, doorbell array, and event ring. `usbhostd` handles USB device enumeration (reset, address assignment, descriptor fetch) and transfer ring management per endpoint. It does **not** implement any device class logic.

### 26.2 Device class isolation

When `usbhostd` identifies a device by class/subclass/protocol or VID/PID, it signals `rootsrv`, which spawns the appropriate driver:

| USB Class | Driver process | Forwarded to |
|---|---|---|
| HID (keyboard, mouse) | `usb-hid-driver` | `inputd` |
| Mass Storage (MSC) | `usb-msc-driver` | `vfs` block layer |
| Audio (UAC 1/2) | `usb-audio-driver` | `audiod` |
| Video (UVC — webcam) | `usb-uvc-driver` | `camd` |
| Network (CDC-NCM, CDC-ECM) | `usb-net-driver` | `netd` |
| Bluetooth HCI | `usb-bt-driver` | `btd` (future) |

A buggy `usb-msc-driver` cannot corrupt the keyboard stack. A compromised webcam driver cannot read the filesystem.

### 26.3 USB power management

USB selective suspend (U1/U2/U3 link states) is managed by `usbhostd` in coordination with `powerd`. Idle devices are put in U2 after a configurable timeout. On system suspend, `usbhostd` puts all devices in U3 before `powerd` invokes the system `Suspend` capability.

### 26.4 Security notes

No process can touch a USB device unless `usbhostd` has granted it an endpoint capability. There is no equivalent of Linux's `/dev/hidraw0` that any user-mode process with file permissions can open. BadUSB/Rubber Ducky mitigation: the HID driver throttles keystroke injection rate (default 30 keys/second maximum burst). USB networking enters `netd`'s `none` namespace by default.

---

## 27. Wi-Fi & Wireless Networking

Section 11 covers the TCP/IP stack inside `netd`. This section covers the layer beneath it: 802.11 management, authentication, and driver architecture.

### 27.1 Two-layer split

**`wifi-phy-driver`** — hardware-specific, owns the NIC MMIO cap and IRQ, handles frame TX/RX and radio control. Different per chipset.

**`wifid`** — hardware-agnostic 802.11 management daemon. Implements the 802.11 state machine: scanning, authentication, association, roaming, power-save modes. The cfg80211/mac80211 equivalent, entirely in user space.

`wifid` talks to `wifi-phy-driver` via a `WifiPhy` capability. `wifid` talks to `netd` via a `NewInterface` IPC when association completes.

### 27.2 Authentication: WPA3 as the baseline

WPA3 (IEEE 802.11-2020) is Ruzt's required baseline. WPA2 is supported for legacy compatibility but downgrade attempts are logged and surfaced to the user.

| Protocol | Mode | Notes |
|---|---|---|
| WPA3-Personal | SAE (Dragonfly) | No offline dictionary attack possible. Default for new connections. |
| WPA3-Enterprise | 802.1X / EAP | For corporate networks; EAP backend is pluggable. |
| OWE | Opportunistic | Encrypted open networks — no password, traffic still encrypted. |
| WPA2-PSK | Legacy | Accepted; downgrade logged and warned. |

Port `wpa_supplicant`'s SAE implementation into a Rust wrapper or link the C library in an isolated process. The v2.11 release (July 2024) added RADIUS-backed SAE and preliminary Wi-Fi 7 (EHT/802.11be) support — track this upstream.

### 27.3 MAC address randomisation

Randomise MAC on **every scan**, not just every association. This prevents cross-location tracking via probe requests.

`wifid` generates a fresh random MAC before each active scan and instructs `wifi-phy-driver` to program it. After association, it switches to a per-network stable MAC derived as `HMAC-SHA256(secret_seed, SSID)` — same network always gets the same MAC (DHCP leases are stable), different networks get different MACs. This is the Android 10+ model.

### 27.4 Network interface lifecycle in `netd`

When `wifid` completes association, it sends `netd` a `NewInterface` message with the interface MAC, SSID, and a `WifiControl` capability. `netd` starts DHCP. Namespace assignment follows the profile in `/etc/network/profiles/<ssid>.toml`; if absent, `permd` prompts.

---

## 28. GPU & Graphics API Stack

`displayd` already owns the DRM/KMS plane (§14). What is missing is the path for applications to use the GPU for rendering — Vulkan, OpenGL, and compute.

### 28.1 The `GpuRender` capability

The GPU's MMIO region has two facets:

- **KMS (display output):** owned exclusively by `displayd`. Never shared with apps.
- **Render (3D/compute):** a separate sub-region exposed as a `GpuRender` capability. `displayd` mints one per application that requests GPU access and passes it at launch. This is the DRM render-node model (`/dev/dri/renderD128`) translated into capabilities.

An app with a `GpuRender` cap submits GPU command buffers but cannot write to the scanout framebuffer — that requires submitting a `wl_buffer` to `displayd` via the Wayland protocol.

### 28.2 Mesa Vulkan ICD model

1. Write a Mesa Vulkan backend for Ruzt's GPU abstraction. **First target: `virtio-gpu` + the `venus` Vulkan-over-virtio protocol** — full Vulkan in QEMU before any real GPU driver exists. `venus` is production-quality in Mesa since 2022.
2. The ICD communicates with the GPU via the `GpuRender` capability.
3. **VK_KHR_wayland_surface (WSI)** is implemented by talking to `displayd` via the standard Wayland protocol — no compositor change required.
4. **Buffer sharing:** apps render into a `dmabuf` (a Frame cap holding a GPU-visible buffer), submit it to `displayd` via `wl_dmabuf`. Compositing happens entirely on GPU — no CPU copies.

For Ruzt-native `iced` apps: `iced`'s `wgpu` backend already targets Vulkan via the `wgpu` crate. Pointing it at the Ruzt Vulkan ICD requires only the Vulkan backend plus WSI.

### 28.3 Phase ordering

| Phase | GPU milestone |
|---|---|
| 3 | `virtio-gpu` framebuffer only — software blitting, no 3D |
| 8 | `virtio-gpu` + `venus` — full Vulkan in QEMU |
| 10 | Real hardware: Intel `anv`, AMD `radv`, Apple Silicon `agx` (Asahi Mesa, production-quality 2024) |
| 10+ | GPGPU via `VK_KHR_compute` — same `GpuRender` cap, no new capability needed |

### 28.4 OpenGL

OpenGL is layered on top of Vulkan via **`zink`** (Mesa's OpenGL-over-Vulkan driver, production-quality as of Mesa 24). No separate OpenGL driver is needed; any app linking `libGL` gets zink → Vulkan ICD → GPU.

### 28.5 Software fallback

**`lavapipe`** (Mesa's CPU-based software Vulkan) requires no `GpuRender` cap. `displayd` falls back to the framebuffer backend when no `GpuRender` is present; apps get `lavapipe`. Correct, slow, and sufficient for CI and early hardware bring-up.

---

## 29. User Authentication, Multi-User & Session Lock

The document has implied a single-user system throughout. A laptop OS needs login, user switching, and screen lock. These are security-critical and deserve explicit design.

### 29.1 `authd` — the authentication daemon

`authd` is the single gatekeeper for all authentication decisions. It renders credential prompts by sending a `ShowPrompt` IPC to `displayd`'s lock-surface protocol. The compositor owns the prompt surface at the highest Z-order — no app can spoof a password dialog.

Authentication backends (ordered, pluggable):

| Backend | Phase | Notes |
|---|---|---|
| Passphrase (Argon2id) | 1 | Always present. Parameters re-tuned each OS version. |
| FIDO2 / WebAuthn (hardware keys) | 9 | `authd` holds `UsbHid` cap for token; implements CTAP2. |
| Fingerprint (libfprint-equivalent) | 10 | USB HID reader cap held exclusively by `authd`. |
| TOTP | 10+ | Time-based OTP via authenticator app. |

```toml
# /etc/auth/policy.toml
[unlock]
primary        = "passphrase"
second_factor  = "fido2"      # required if a key is enrolled
biometric_ok   = true
timeout_seconds = 120
```

### 29.2 Multi-user model

Each user has a unique `UserId`, a RuztFS subvolume at `/home/<username>/` encrypted with a user-derived KEK, a separate capability space (the kernel enforces this — no `setuid` involved), and a separate Wayland session in `displayd`. `rootsrv` maintains one user-session supervisor per logged-in user.

### 29.3 Session lock (`zruzt_session_lock_v1`)

When `authd` (or the idle timer in `powerd`) requests a lock:

1. `displayd` sets a `locked` flag. All new app surfaces are held invisible.
2. `displayd` maps the lock surface at the highest Z-order, held by a dedicated lock process.
3. Input is delivered **only** to the lock surface.
4. The lock surface cannot be covered, minimised, or focused-out by any app capability.
5. On authentication success, `authd` sends `displayd` an `Unlock` IPC; the lock surface is destroyed and normal input resumes.

This adopts the `ext-session-lock-v1` Wayland protocol model as `zruzt_session_lock_v1`. The lock is enforced by the compositor, not by a killable process.

### 29.4 Privilege escalation (no root)

There is no root user and no `setuid`. There is a `SystemAdmin` capability, minted by `rootsrv` and held by the first user's session supervisor. Privileged operations require presenting this capability with an `authd` re-authentication prompt.

---

## 30. Logging — `logd` & Structured Audit Trail

Every service generates events. Without a logging daemon they vanish. With naive plaintext syslog they are unsearchable. The correct design is structured, binary, capability-gated, and bounded.

### 30.1 Design goals

- **Structured:** every entry is a typed key-value record, queryable without `grep`.
- **Capability-gated writes:** a service writes only to its own log — it cannot impersonate another or read any log.
- **Capability-gated reads:** a reader holds a read cap scoped to specific service IDs.
- **Append-only, bounded:** per-service ring buffers with configurable retention; old entries rotate via RuztFS snapshot.
- **Available before `logd`:** the kernel maintains a small ring buffer in a shared-memory Frame. `logd` drains it on startup.

### 30.2 Wire format: CBOR

Use **CBOR** (RFC 8949). It is compact, self-describing, schema-free, and `no_std`-compatible via `ciborium` / `cbor4ii`.

```
// Conceptual log entry (shown as JSON for readability; stored as CBOR)
{
  "ts":      1746394012345678,  // u64 monotonic nanoseconds since boot
  "wall":    1746394012,        // u64 Unix seconds
  "service": "netd",
  "level":   2,                 // 0=trace 1=debug 2=info 3=warn 4=error 5=fatal
  "msg":     "interface eth0 up",
  "fields":  { "iface": "eth0", "mac": "02:ab:cd:ef:01:23" }
}
```

### 30.3 `logd` architecture

Each service receives a `logd.write` endpoint badged with its service ID. `logd` verifies the badge on every write — a service cannot impersonate another. Readers hold a `logd.read` endpoint scoped to a set of service IDs. Log rotation uses RuztFS snapshots.

### 30.4 Crash reporter

When the supervisor detects a crash: it signals `logd` to flush and seal the crashed service's log, writes a crash record (service name, restart count, timestamp, last 1,000 log entries), and makes the record available in Settings → Diagnostics. It is **never sent anywhere automatically** — telemetry-zero applies here.

---

## 31. Internationalisation, Localisation & Input Methods

An OS that only functions in English is not a product. i18n decisions made in Phases 3–6 either accommodate international users or make retrofitting painful.

### 31.1 `icu4x` as the i18n engine

**`icu4x`** (Unicode Consortium, with Mozilla Gecko integration shipping in 2024) is the correct choice:
- Pure Rust, `no_std`-compatible.
- Modular: include only the formatters the app needs (numbers, dates, plural rules, collation, segmentation, BiDi).
- Data-driven: locale data ships as separate blobs, not compiled into binaries.
- Replaces ICU4C entirely — no C FFI required.

Covers: number and date/time formatting, plural categories, collation, bidirectional text reordering, Unicode grapheme-cluster segmentation, and Unicode normalisation.

### 31.2 Text rendering pipeline

```
String (Unicode scalars)
    → icu4x BiDi reorder   (RTL/LTR mixing)
    → HarfBuzz shaping     (ligatures, kerning — Arabic, Devanagari, CJK, Hangul)
    → fontdue rasterise    (pure-Rust, fast, no_std-capable)
    → GPU atlas texture    → Vulkan quad → display
```

**HarfBuzz** is the industry-standard shaper (Chrome, Firefox, Android). Link as a C library initially; `rustybuzz` (pure-Rust port) is the long-term replacement.

### 31.3 Input methods (IME)

For CJK, Indic, and other composed scripts, Ruzt uses `zwp_text_input_v3` as the standard interface:

- **`displayd`** implements `zwp_text_input_v3` — the compositor mediates between app and IME.
- **`imd`** (input method daemon) extends `inputd` and implements `zwp_input_method_v2`. IME engines (Pinyin, Mozc for Japanese, Hangul) are plugins loaded by `imd`.
- Apps declare text focus via `zwp_text_input_v3`; `imd` injects pre-edit text and commit strings through the compositor.

This is the Fcitx5-on-Wayland architecture — tested and working with GTK and Qt. Ruzt adopts it from day one.

### 31.4 `localed` — the locale service

`localed` owns the system locale and IANA time zone. Apps request locale data via `localed`'s endpoint; `localed` provides the appropriate `icu4x` data blob as a read-only Frame capability.

**No `LC_*` environment variables.** Locale is a capability delivered by `localed`, not ambient environment state. This eliminates locale-injection attacks and is consistent with the rest of the capability model.

---

## 32. Camera, Microphone & AV Privacy

Camera and microphone are the two highest-consequence privacy surfaces on a laptop.

### 32.1 `camd` — the camera daemon

`camd` is spawned by `usbhostd` when a UVC webcam is detected (or by `pcid` for an integrated ISP). It holds a `UvcEndpoint` capability from `usbhostd` and a `CameraLed` capability tied to the hardware indicator LED.

The `CameraLed` capability is **not optional and not software-controllable by apps.** The kernel enforces: while any frame is being transmitted from `camd` to a client, the LED is on. `camd` cannot extinguish it while streaming. On GPIO-controlled hardware, the kernel owns the GPIO register.

### 32.2 The `Camera` capability

A process wanting camera access must hold a `Camera` capability — minted by `permd` after a UI prompt rendered by `displayd`. It then connects to `camd`'s endpoint, presenting the `Camera` cap, and receives a stream of Frame capabilities each holding one video frame.

Grant scoping:

| Scope | Lifetime | Use case |
|---|---|---|
| `OneShot` | One frame consumed | "Take a photo" action |
| `Session` | Until app exits | Video call |
| `Always` | Stored in `permd` ledger | Persistent permission; revocable from Settings |

### 32.3 Microphone (formalisation)

Microphone follows the identical pattern via `audiod` (§25.2). `Audio::Capture` cap required, hardware mic LED or compositor orange-dot active during any open capture stream, same OneShot / Session / Always scoping.

### 32.4 Privacy toggles

- **Physical camera shutter** (where present): mechanical — no software involvement.
- **Fn + camera/mic key** (ThinkPad, Framework, etc.): ACPI event delivered to `powerd`, which revokes the relevant cap from `permd`'s ledger and signals `displayd` to show a "Camera off" OSD.
- **Settings → Privacy panel:** lists every active `Camera`, `Audio::Capture`, and `Screencast` cap with the holding app, grant scope, and a one-tap revoke button.

The three AV capabilities — `Camera`, `Audio::Capture`, `Screencast` — are the **complete** set of sensor caps in Ruzt. No other API provides ambient sensing without a capability.

---

## 33. PKI & Certificate Trust Store — `trustd`

TLS is only as strong as the trust anchors behind it. Ruzt needs an explicit design for how CA certificates are managed and how applications verify server identity.

### 33.1 `trustd` — the trust anchor daemon

`trustd` owns the system certificate trust store and provides two capabilities:

- **`TrustRead`** — granted freely to any process needing TLS verification (browsers, `netd`, package manager, update client).
- **`TrustAdmin`** — held only by the package manager and the Settings app; required to add or distrust a CA.

`trustd` ships with the **Mozilla CA bundle** (NSS `certdata.txt`) as the baseline. This is the same bundle used by Firefox, curl, and the open-source ecosystem.

### 33.2 TLS verification

`rustls` is the TLS stack (implied by the TLS 1.3-only policy in §10.3). `rustls` accepts a custom `ServerCertVerifier` — `trustd` implements this interface so all TLS verification flows through one trust store.

```rust
// ruzt-tls/src/verify.rs
pub fn verify_chain(
    chain: &[Certificate],
    hostname: &str,
    trust_cap: &TrustRead,
) -> Result<(), VerifyError> {
    // 1. Build chain to a trust anchor in trustd's bundle.
    // 2. Check validity period.
    // 3. Verify signatures (ring / rustls).
    // 4. Check OCSP staple if present; else query trustd's OCSP cache.
    // 5. Check CT logs if enforced (Phase 9+).
}
```

### 33.3 OCSP and CRL caching

`trustd` maintains an OCSP response cache. Cache miss: `trustd` fetches the OCSP response via `netd` using the system's `default` namespace — decoupled from the app's network namespace. The response is returned to the client as a signed blob for stapling or in-flight verification.

### 33.4 Certificate Transparency enforcement

Phase 9+ hardening: enforce CT log presence for publicly-trusted certificates. `trustd` verifies that the certificate's SCT is from a known CT log. The CT log list ships in the OS and updates via the system update mechanism.

### 33.5 User trust overrides

- **Distrust a CA:** the user marks any CA as distrusted in Settings → Security → Certificates. `trustd` records the distrust in `/etc/trust/overrides/`; it takes effect system-wide immediately — unlike Linux today, where Firefox ignores the system store.
- **Add a local CA:** the package manager or `trustd` CLI adds a CA to `/etc/trust/anchors/`. Required for corporate MITM proxies; surfaced with a clear warning.
- **App-level pinning:** an app can request a `PinnedTrust` cap scoped to a specific SPKI hash set. `trustd` enforces the pin during verification. This is HPKP done correctly — app-declared, not HTTP-header-declared.

---

## 34. Inspirations, Resources, Reading List

Read these. In roughly this order.

**OS textbooks and tutorials**
- *Operating Systems: Three Easy Pieces* (Remzi & Andrea Arpaci-Dusseau). Free PDF. The OS book.
- *Writing an OS in Rust* by Philipp Oppermann (`os.phil-opp.com`). Phase 0 and Phase 1 in tutorial form. **Do this.**
- The OSDev wiki (`wiki.osdev.org`). Reference, not pedagogy. Dense. Use it as a man page.

**Microkernel canon**
- The seL4 Reference Manual. Even if you don't follow it exactly, internalize the capability model.
- Liedtke's L4 papers (1993, 1995). The IPC performance argument.
- The MINIX 3 papers (Tanenbaum). Rationale for the user-space-driver model.

**Rust OS projects to read**
- **Redox OS** — the closest spiritual sibling. Read `kernel/`, `relibc/`, `ion/`.
- **Theseus OS** — research microkernel in Rust. Their *intralingual design* paper is mandatory reading for the IPC fast path.
- **Hubris** (Oxide Computer) — embedded Rust OS, capability-influenced. The supervisor pattern is excellent.
- **Drone OS** — embedded async Rust kernel. Great for understanding async in `no_std`.
- **rust-vmm** crates — high-quality device crates.
- **managarm** — a microkernel OS that uses LAI for ACPI; excellent reference for the `powerd` design.

**Wayland and compositors**
- The Wayland book (`wayland-book.com`).
- The Smithay repository — read the `anvil` example end to end.
- The `wlroots` source.

**ARM**
- The Arm Architecture Reference Manual. Extract chapters D5, D8, G2.
- The Asahi Linux project's m1n1 documentation — gold standard for Apple Silicon bring-up.

**Filesystem and storage**
- *ZFS: The Last Word in File Systems* (Bonwick & Moore).
- The btrfs on-disk format spec.
- LUKS2 spec. Read once for the threat model.

**Networking**
- The smoltcp source. Small enough to read end-to-end.
- WireGuard whitepaper. Eight pages.
- The arti README and architecture doc.
- wpa_supplicant v2.11 changelog — WPA3/SAE and Wi-Fi 7 additions.

**Audio**
- PipeWire architecture documentation (`docs.pipewire.org/page_design.html`).
- WirePlumber 0.5 documentation — the session manager model.
- The JACK design rationale — fixed-quantum, real-time audio graph.

**Security and privacy**
- *Security Engineering* (Ross Anderson). The book.
- The Qubes OS architecture spec.
- Sigstore: cosign documentation. The reproducible-builds.org site.

**Power management**
- LAI (Lightweight AML Interpreter) README — `github.com/managarm/lai`.
- ACPI Specification (latest) — Chapter 7 (Power and Performance Management).
- Linux kernel documentation: `Documentation/power/` — the suspend/resume sequence.

**i18n and text rendering**
- `icu4x` documentation — `docs.rs/icu`.
- HarfBuzz documentation — `harfbuzz.github.io`.
- The Unicode BiDi algorithm (UAX #9).

**Robustness**
- "Crash-Only Software" — Candea & Fox, 2003.
- The Erlang/OTP Design Principles — Supervisor and gen_server chapters.
- Oxide Computer's Hubris papers.

**Aesthetics and UX**
- Refactoring UI (Adam Wathan, Steve Schoger).
- The macOS HIG and GNOME HIG. Steal selectively.
- *About Face* (Cooper).

---

## 35. Closing Words

A few things, plainly stated, before you close this file.

**You will not finish this in a year.** Not because you're not capable, but because the *known unknowns* compound. Plan in months and quarters, ship in weeks, celebrate in days.

**You will hit walls where you can't tell if it's a hardware bug, a QEMU bug, a Rust nightly bug, or your bug.** It will be your bug 95% of the time. The other 5% will eat a week each and teach you the most.

**Write the boring documentation as you go.** Future-you will not remember why you chose 4 KiB pages over 16 KiB on aarch64, or why the IPC slot count is four. Write it down. ADRs (`docs/adr/0001-page-size.md`) are the format.

**The aesthetic matters because you have to want to come back to this.** A project that looks like a hobby drains motivation. A project that, every morning, shows you a clean boot and a confident desktop will pull you back in. Spend an afternoon on the boot splash early. It pays for itself in months of motivation.

**Robustness compounds with privacy.** Every design choice that makes Ruzt robust under crash — capabilities, supervision, atomic updates, crash-only services — is the same choice that makes Ruzt private. A system that cannot leak references after a crash also cannot leak data after a compromise. That is not coincidence; it is the same property under two names.

**The subsystems added in v0.3 are not afterthoughts.** Power management, audio, USB, Wi-Fi, GPU, authentication, logging, i18n, camera privacy, and PKI are the difference between a kernel demo and a laptop OS someone can live in. The design principle is the same for all ten: capability-gated, supervised, user-space, crash-recoverable. When you reach each of these sections in practice, re-read the relevant design, then scope the work to the current phase and no further.

**Linus had a Sinclair QL in 1990 and a goal: "make this thing run my own programs". His goal scaled. Yours will too if you keep it concrete.** When you don't know what to do next, build the most boring next thing that gets one user-visible thing working end-to-end.

You said maybe you'll fail and maybe you won't, and you want to have *tried*. That framing is correct, and it produces good systems work. The "clueless person" framing is a feature: you start without preconceptions about what's "impossible". That's an advantage. Build the thing.

Fair winds, captain.

— *Ruzt design report, v0.3*
