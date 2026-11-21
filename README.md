# Ruzt

Ruzt is an experimental, privacy-first operating system built around a Rust microkernel. Its design uses capabilities to grant explicit access to resources and moves services such as drivers and filesystems into user space. The project targets x86_64 in QEMU first.

## Development status

The x86_64 kernel contains early boot code, serial diagnostics, interrupt handling, memory management, and a scheduler. The graphical x86_64 boot loads `rootsrv` into its own address space and starts it in ring 3. It checks a request and reply on its bootstrap endpoint and reports the outcome through the debug syscall. The AArch64 boot path is a stub.

The bootstrap endpoint has a single pending reply and is served by a kernel echo handler. The kernel forwards PS/2 interrupts to `rootsrv` and hands it the boot framebuffer. The server holds separate capabilities for the interrupt, data port, and framebuffer. It decodes the Space key and draws a status tile in ring 3. Keyboard interrupts are currently polled while the scheduler supports only kernel threads.

## Repository layout

| Path | Contents |
| --- | --- |
| [`kernel/ruzt-kernel`](kernel/ruzt-kernel) | Kernel entry point, memory management, scheduler, capabilities, IPC, and syscalls |
| [`hal/`](hal) | Hardware abstraction traits and architecture-specific implementations |
| [`boot/`](boot) | Architecture-specific boot programs and the x86_64 QEMU integration test |
| [`crates/`](crates) | Shared ABI, capability types, IPC client, and user-space runtime |
| [`crates/ruzt-driver-sdk`](crates/ruzt-driver-sdk) | User-space device access through capabilities |
| [`servers/rootsrv`](servers/rootsrv) | First user-space server |

## Local checks

From the repository root, run the host tests for the ABI, capability types, x86_64 HAL, and kernel.

```sh
cargo test --locked -p ruzt-abi -p ruzt-cap -p ruzt-hal -p ruzt-hal-x86_64 -p ruzt-kernel --lib
```

Run the kernel-only and ring-3 QEMU tests with the pinned Rust nightly and components in [`rust-toolchain.toml`](rust-toolchain.toml). It requires `qemu-system-x86_64` and `timeout` on your path.

```sh
cargo test --locked -p boot-x86_64 --test boot_test -- --nocapture
```

Each test builds a BIOS image in a fresh temporary directory. The kernel-only test checks breakpoint recovery, thread scheduling, and blocking IPC. The ring-3 test packages `rootsrv` as the bootloader ramdisk, checks its IPC round trip and rejection of an ungranted capability, then injects Space with the QEMU monitor and checks screenshots for the tile's color change.

GitHub Actions runs both commands on pushes to `main` and on pull requests.

## Graphical boot

Run these commands from the repository root with QEMU's GTK display backend installed.

```sh
(cd servers/rootsrv && cargo build --locked --target x86_64-unknown-none)
(cd kernel/ruzt-kernel && cargo build --locked)
cargo run --locked -p boot-x86_64
```

QEMU opens a window for the boot screen and streams serial diagnostics to the terminal. With that window focused, press Space to toggle the top-right tile between blue and mint.

## Design

Read [Project Philosophy](PHILOSOPHY.md) for the project's principles and the [Technical Design Report](Ruzt_Technical_Design_Report.md) for the architecture, roadmap, and proposed licensing model.
