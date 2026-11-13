# Ruzt

Ruzt is an experimental, privacy-first operating system built around a Rust microkernel. Its design uses capabilities to grant explicit access to resources and moves services such as drivers and filesystems into user space. The project targets x86_64 in QEMU first.

## Development status

The x86_64 kernel contains early boot code, serial diagnostics, interrupt handling, memory management, and a scheduler. Capability, IPC, and ELF-loading code is in development. Launching the first user-space process, `rootsrv`, from kernel startup is pending. The AArch64 boot path is a stub.

The x86_64 QEMU smoke test checks that the kernel handles a breakpoint and resumes execution. The next milestone is launching `rootsrv` in ring 3.

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

Run the kernel-only boot smoke test with the pinned Rust nightly and components in [`rust-toolchain.toml`](rust-toolchain.toml). It requires `qemu-system-x86_64` and `timeout` on your path.

```sh
cargo test --locked -p boot-x86_64 --test boot_test -- --nocapture
```

The test builds the kernel in a fresh temporary directory, creates a BIOS disk image, and checks that QEMU prints the breakpoint and return messages in order before exiting successfully.

## Design

Read [Project Philosophy](PHILOSOPHY.md) for the project's principles and the [Technical Design Report](Ruzt_Technical_Design_Report.md) for the architecture, roadmap, and proposed licensing model.
