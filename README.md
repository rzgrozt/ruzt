# Ruzt

Ruzt is an experimental, privacy-first operating system built around a Rust microkernel. Its design uses capabilities to grant explicit access to resources and moves services such as drivers and filesystems into user space. The project targets x86_64 in QEMU first.

## Development status

The x86_64 kernel contains early boot code, serial diagnostics, interrupt handling, memory management, and a scheduler. Capability, IPC, and ELF-loading code is in development. Launching the first user-space process, `rootsrv`, from kernel startup is pending. The AArch64 boot path is a stub.

The next milestone is a reproducible x86_64 boot in QEMU with serial output that confirms the kernel handled a breakpoint and continued running.

## Repository layout

| Path | Contents |
| --- | --- |
| [`kernel/ruzt-kernel`](kernel/ruzt-kernel) | Kernel entry point, memory management, scheduler, capabilities, IPC, and syscalls |
| [`hal/`](hal) | Hardware abstraction traits and architecture-specific implementations |
| [`boot/`](boot) | Architecture-specific boot programs and the x86_64 QEMU integration test |
| [`crates/`](crates) | Shared ABI, capability types, IPC client, and user-space runtime |
| [`servers/rootsrv`](servers/rootsrv) | First user-space server |

## Local checks

From the repository root, run the host tests for the ABI, capability types, and HAL traits with Cargo.

```sh
cargo test --locked -p ruzt-abi -p ruzt-cap -p ruzt-hal
```

The full boot test requires the Rust nightly components listed in [`rust-toolchain.toml`](rust-toolchain.toml) and `qemu-system-x86_64` on your path.

```sh
cargo test --locked -p boot-x86_64 --test boot_test -- --nocapture
```

The boot test is currently blocked by toolchain compatibility issues in the x86_64 and bootloader dependencies and the custom user-space target. It also checks for the pending ring-3 `rootsrv` launch.

## Design

Read [Project Philosophy](PHILOSOPHY.md) for the project's principles and the [Technical Design Report](Ruzt_Technical_Design_Report.md) for the architecture, roadmap, and proposed licensing model.
