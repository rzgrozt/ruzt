# Ruzt

Ruzt is an experimental, privacy-first operating system built around a Rust microkernel. Its design uses capabilities to grant explicit access to resources and moves services such as drivers and filesystems into user space. The project targets x86_64 in QEMU first.

## Development status

The x86_64 kernel contains early boot code, serial diagnostics, interrupt handling, memory management, and a scheduler. The kernel boots `rootsrv`, which launches `consoled` in a separate ring-3 address space through an executable capability from the boot archive. The child receives four explicit startup grants for IPC and UART access. `rootsrv` transfers its greeting through a read-only shared frame, and `consoled` acknowledges it on a separate reply endpoint. The AArch64 boot path is a stub.

Each service has its own capability space. The console endpoints grant send and receive rights separately. The kernel forwards PS/2 interrupts to `rootsrv` and hands it the boot framebuffer. The server sleeps while waiting for an interrupt, then decodes the Space key and draws a status tile in ring 3.

Capabilities keep kernel objects alive while copies exist. A caller with grant rights can derive a capability with reduced rights. Moving a capability preserves its ancestry, and revoking it removes all its descendants, unmaps their shared pages, and wakes waiters that lost their authority. IPC transfers install capabilities only in empty slots designated by the receiver. Each frame capability can establish one non-executable mapping in the caller, and mapped memory stays allocated until the final page-table alias is removed.

The root server receives a 32 KiB Untyped RAM budget at boot. It creates console endpoints from the budget and reserves two separate 8 KiB regions, delegating one to the console service for its scratch buffer. A frame, endpoint, or notification currently costs one 4 KiB page. Copies of an Untyped capability draw from the same budget. A reserved region returns to its parent after the region cap and its last live object are gone.

When a service exits or takes a user-mode fault, the kernel closes endpoints designated at launch, wakes blocked peers, and reclaims its stack and private address-space memory after switching away. `rootsrv` uses the process status capability to distinguish exit from fault and retries a failed console instance once with fresh endpoints.

## Repository layout

| Path | Contents |
| --- | --- |
| [`kernel/ruzt-kernel`](kernel/ruzt-kernel) | Kernel entry point, memory management, scheduler, capabilities, IPC, and syscalls |
| [`hal/`](hal) | Hardware abstraction traits and architecture-specific implementations |
| [`boot/`](boot) | Architecture-specific boot programs and the x86_64 QEMU integration test |
| [`crates/`](crates) | Shared ABI, capability types, IPC client, and user-space runtime |
| [`crates/ruzt-driver-sdk`](crates/ruzt-driver-sdk) | User-space device access through capabilities |
| [`servers/rootsrv`](servers/rootsrv) | First user-space server |
| [`servers/consoled`](servers/consoled) | User-space COM1 console service |

## Local checks

From the repository root, run the host tests for the ABI, capability types, x86_64 HAL, and kernel.

```sh
cargo test --locked -p ruzt-abi -p ruzt-cap -p ruzt-hal -p ruzt-hal-x86_64 -p ruzt-kernel --lib
```

Run the kernel-only and ring-3 QEMU tests with the pinned Rust nightly and components in [`rust-toolchain.toml`](rust-toolchain.toml). It requires `qemu-system-x86_64`, GNU `tar`, and `timeout` on your path.

```sh
cargo test --locked -p boot-x86_64 --test boot_test -- --nocapture
```

Each test builds a BIOS image in a fresh temporary directory. The kernel-only test checks breakpoint recovery, scheduling, and blocking IPC. The ring-3 test packages both services in a ustar archive and checks a console write from shared memory, notification transfer, rights attenuation, and removal of the console mapping on revocation. It then injects Space with the QEMU monitor and verifies the tile's color change in screenshots.

A separate guest keeps the console service CPU-bound after its first reply. It verifies that timer preemption still lets `rootsrv` handle keyboard input.

The exit and fault guests terminate the console while its scratch frame is mapped. After reaping each instance, `rootsrv` reads its exit code or exception vector, reclaims both delegated budgets, and restarts the service with fresh endpoints. It continues handling input when the replacement also fails.

GitHub Actions runs both commands on pushes to `main` and on pull requests.

## Graphical boot

Run these commands from the repository root with QEMU's GTK display backend installed.

```sh
(cd servers && cargo build --locked --target x86_64-unknown-none -p rootsrv -p consoled)
(cd kernel/ruzt-kernel && cargo build --locked)
cargo run --locked -p boot-x86_64
```

QEMU opens a window for the boot screen and streams serial diagnostics to the terminal. With that window focused, press Space to toggle the top-right tile between blue and mint.

## Design

Read [Project Philosophy](PHILOSOPHY.md) for the project's principles and the [Technical Design Report](Ruzt_Technical_Design_Report.md) for the architecture, roadmap, and proposed licensing model.
