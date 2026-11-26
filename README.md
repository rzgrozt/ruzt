# Ruzt

Ruzt is an experimental, privacy-first operating system built around a Rust microkernel. Its design uses capabilities to grant explicit access to resources and moves services such as drivers and filesystems into user space. The project targets x86_64 in QEMU first.

## Development status

The x86_64 kernel contains early boot code, serial diagnostics, interrupt handling, memory management, and a scheduler. The kernel boots `rootsrv`, which launches `consoled` in a separate ring-3 address space through an executable capability from the boot archive. The child receives four explicit startup grants for IPC and UART access. `rootsrv` transfers its greeting through a read-only shared frame, and `consoled` acknowledges it on a separate reply endpoint. The AArch64 boot path is a stub.

The root server can resolve named executables through its boot-program catalog capability. Issued program capabilities derive from that authority and can be delegated and revoked. Lookup accepts bounded single-component names from the immutable boot archive. The console launch exercises this interface, and QEMU fixtures check missing names, occupied destinations, invalid authority and revocation.

Each service has its own capability space. The console endpoints grant send and receive rights separately. `rootsrv` claims and binds the PS/2 interrupt and receives the boot framebuffer. It draws a status tile in ring 3 and changes the tile when Space is pressed.

Capabilities keep kernel objects alive while copies exist. A caller with grant rights can derive a capability with reduced rights. Moving a capability preserves its ancestry, and revoking it removes all its descendants, unmaps their shared pages, and wakes waiters that lost their authority. IPC transfers install capabilities only in empty slots designated by the receiver. Each frame capability can establish one non-executable mapping in the caller, and mapped memory stays allocated until the final page-table alias is removed.

Processes can retype Untyped memory into capability tables, or CNodes, with up to 256 slots per table. Root slot numbers remain valid, and `ruzt_abi::cptr_path` addresses deeper slots for invocation, slot operations, and IPC transfers. Traversal requires read authority on each CNode, while slot changes also require write authority along the path. A shared CNode exposes only grantable capabilities owned by another process. The kernel rejects cycles, and deleting the last reference to a CNode releases its slots and returns its page to the budget.

Capability metadata is limited to 1,024 live records per process and 8,192 system-wide. Moving a capability preserves its original accounting owner. Metadata allocation and quota failures return `NoMemory` before publishing a slot. A failed IPC grant batch rolls back its partial installations.

The IPC library can block on up to eight endpoints, notifications, driver IRQs, and process status capabilities in one call. The kernel selects the first ready source in list order and consumes its message or signal as part of the wait. Endpoint messages can include capability grants, and a closed endpoint or reaped process wakes the waiter. Revoking a wait source or a CNode capability on its path cancels the wait.

User tasks can read the monotonic clock, supply an absolute deadline to a capability wait, or sleep until a deadline without waiting on any capability. x86-64 wakes these tasks at scheduler safe points using the PIT's roughly 10 ms tick. The PIT uses the I/O APIC when firmware provides usable ACPI interrupt routing.

The x86-64 kernel enables SMEP and SMAP when the CPU advertises them. Syscalls copy through supervisor-only aliases after checking access on every user page. Interrupt and syscall entry clear the live AC and DF flags and preserve the interrupted task's flags for return. A user trap starts on the CPU's guarded entry stack. The common entry stub moves the saved frame onto the thread's kernel stack before dispatch so the thread can block or migrate. The QEMU preemption test exercises this path with both protections enabled.

Kernel page-table isolation gives user roots only their own mappings and dedicated supervisor pages for privilege transitions. Kernel dispatch runs under a permanent root with global translations disabled. Returning to user mode installs the process root from the entry stack. The QEMU fixtures check that the kernel heap, physical-memory map, and kernel-only stacks are absent from the user root, then exercise user IPC and interrupt delivery with isolated roots.

On CET-capable x86-64 CPUs, an instrumented kernel enables supervisor indirect branch tracking. When all scheduler CPUs support user shadow stacks, each user process receives a guarded shadow stack. The kernel saves its pointer with the thread's trap frame and restores it on return to user mode, including after a scheduling migration.

Double faults switch to a dedicated supervisor stack with an unmapped guard page. The handler writes directly to COM1 before halting. The QEMU fixture reaches it with an unmapped interrupted stack and the normal serial lock held.

The x86-64 bootstrap starts firmware-enabled secondary CPUs with INIT and SIPI messages. Each secondary switches to the permanent supervisor mappings, installs its own descriptor tables and guarded stacks, and acknowledges a fixed IPI before the kernel reclaims the temporary startup pages.

Each online x86-64 scheduler CPU has its own round-robin run queue and idle context. User threads start on a least-loaded CPU, and an idle CPU can steal a ready user thread or kernel worker after its previous CPU saves its context. The PIT routes through the BSP, which sends reschedule IPIs that can preempt user code on secondary CPUs. The four-CPU BIOS and UEFI QEMU fixtures migrate a saved worker across secondaries and verify stack reclamation. The UEFI fixture also verifies an IPC transfer between user services on different CPU queues.

Small kernel allocations use a bounded per-CPU heap. Large allocations and local exhaustion use the shared heap. A block's address identifies its original heap when a task frees it after migrating. The four-CPU fixtures verify both allocation paths and free a CPU-local block on a different CPU.

Syscalls, device interrupt delivery, timeout processing, and user process cleanup serialize capability operations and IPC through a shared kernel transaction. Blocking calls register the wait before releasing the transaction, then reacquire it after resuming. Waking a thread on another CPU sends a reschedule IPI. The four-CPU fixtures verify a blocking endpoint rendezvous between secondary CPUs.

Device interrupts target the BSP. Interrupt vector reuse and re-arming check that CPU's local APIC, using a synchronous IPI when the request comes from a secondary. The four-CPU fixtures distinguish a pending vector from an idle vector while the BSP waits for the transaction with interrupts masked.

Page-table removal waits for TLB acknowledgements from online CPUs before returning the old frame or freeing detached tables. A CPU waiting for the mapper lock can service the invalidation with interrupts disabled. The four-CPU fixtures verify replacement mappings in both the shared supervisor half and a user root active on the secondaries.

UEFI images built with `uefi-kaslr` randomize the kernel image and stack within the supervisor half. The physical-memory map and kernel heap occupy fixed, disjoint ranges. The UEFI test boots the same image twice and verifies different kernel addresses while exercising console IPC, the framebuffer, and keyboard input. BIOS images use the default kernel build because the pinned BIOS loader exhausts its early stack while initializing ASLR.

The boot server can claim and delegate exclusive ISA device IRQ capabilities. The x86-64 kernel uses ACPI's MADT to route them through the local APIC and I/O APIC, including firmware overrides for the pin, polarity, and trigger mode. The 8259 PIC remains the fallback. A driver binds a claim, waits through the device SDK or IPC wait list, and acknowledges it after servicing the device. The line stays masked between delivery and acknowledgement. Revoking the binding capability or reaping its driver removes the binding. QEMU exercises delegation with a real COM1 interrupt in `consoled`, and the standalone boot test disables ACPI to exercise the PIC.

An IRQ-control holder can also claim a non-ISA global system interrupt through `ruzt_driver_sdk::claim_gsi`. The caller supplies the GSI, polarity, and trigger mode from platform routing information. The kernel validates the pin against the discovered I/O APICs and reserves its vector until the last capability is gone and outstanding delivery has drained. The Q35 BIOS and UEFI tests use the fixed EDU fixture route to verify level-triggered PCI INTx delivery, acknowledgement, revocation, and reclamation.

The boot server can enumerate conventional PCI configuration space and claim firmware-programmed memory BARs on endpoint functions with bus mastering disabled. A claim can clear firmware-enabled bus mastering for a directly attached endpoint when VT-d covers the requester and supports draining. QEMU checks that OVMF's firmware-enabled EDU is delegated with VT-d and refused when the guest has no remapper. The boot server can delegate individual page-aligned BAR ranges with read or write rights. Device mappings are uncached and non-executable, and revocation removes their page-table entries. The QEMU EDU guest checks a real PCI register read and write, read-only delegation, rollback on an occupied page, and reclamation after revocation.

On supported x86-64 systems the kernel validates ACPI's DMA remapping table and starts a segment-zero Intel VT-d unit with an empty root table. Covered PCI requesters start without DMA access. The q35 test temporarily enables bus mastering for an isolated EDU fixture and requires a hardware fault that identifies both the unassigned requester and its DMA address.

VT-d units with queued invalidation use a kernel-owned ring for DMA context and IOTLB invalidation. The kernel waits for the hardware completion write before recycling DMA resources. Units with the register interface can still invalidate through it. The BIOS fixture wraps the ring before testing DMA isolation and revocation.

When the ACPI DMAR table identifies a requester for each I/O APIC, supported VT-d units can remap those interrupts with exact requester-ID validation. The kernel masks the inputs while it switches delivery formats and synchronizes the interrupt cache before reusing a retired device vector. Q35 BIOS and UEFI exercise remapped timer, keyboard, serial, and PCI INTx delivery.

A writable PCI device capability can derive one MSI interrupt for a directly attached, VT-d-covered endpoint. The kernel programs the message and validates its requester ID in the remapping table. The IRQ interface coalesces messages and preserves a notification for arrivals between consuming an event and acknowledging it. Release disables MSI and drains the remapper before the kernel reuses the vector. The EDU fixture exercises MSI while holding the separate DMA lease required for QEMU bus mastering.

The same PCI lease can delegate individual MSI-X entries. The kernel reserves all pages covering the interrupt table and pending-bit array before it grants BAR mappings. Each IRQ has a separate mask and remapping entry. Releasing the last vector disables MSI-X and restores the original INTx setting. The ivshmem fixture delivers two vectors independently and verifies that drivers can still open the device's shared-memory BAR.

Drivers can reserve a contiguous DMA buffer from Untyped and map it into their address space. Binding requires a writable PCI device capability and buffer access rights that match the requested DMA direction. A directly attached bus-zero endpoint gets one buffer in a private VT-d domain. The kernel publishes the translation before enabling bus mastering. Unbinding, revocation, and driver exit disable bus mastering and drain pending transactions before releasing the domain. If teardown fails, the kernel retains the device lease and memory. The q35 test verifies an EDU round trip across two pages, revokes the delegated buffer, and reallocates the scrubbed memory from the same budget.

The root server receives an 8 MiB Untyped RAM budget at boot. Each process's image, user stack, heap, and private page tables draw from its address-space budget. `rootsrv` reserves 2 MiB for the console address space and delegates a separate 8 KiB region to the service for its scratch buffer. Copies of an Untyped capability draw from the same budget. A reserved region returns to its parent after the region cap and its last live allocation are gone.

Each process has a self address-space capability for mapping zeroed anonymous pages at a chosen virtual address. These pages draw from its address-space budget and may be read-only or writable. Unmapping returns the pages to the budget. A failed range operation preserves existing mappings.

The runtime starts with a 1 MiB heap. On allocation pressure it can extend the heap inside a reserved 16 MiB virtual range using pages from the same budget. A failed extension leaves the heap intact. The kernel returns the grown heap to its budget when it reaps the process.

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

Run the kernel-only and ring-3 QEMU tests with the pinned Rust nightly and components in [`rust-toolchain.toml`](rust-toolchain.toml). Install `qemu-system-x86_64`, SeaBIOS, the 4 MiB OVMF firmware, GNU `tar`, and `timeout`.

```sh
cargo test --locked -p boot-x86_64 --test boot_test -- --nocapture
```

On a Linux host with KVM and both CET features exposed to guests, run the hardware-assisted CET fixture.

```sh
cargo test --locked -p boot-x86_64 --test boot_test -- test_cet_under_kvm --ignored
```

Each test builds a BIOS image in a fresh temporary directory. The kernel-only test checks breakpoint recovery, scheduling, and blocking IPC. The ring-3 test packages both services in a ustar archive and checks a console write from shared memory, notification transfer, rights attenuation, and removal of the console mapping on revocation. It then injects Space with the QEMU monitor and verifies the tile's color change in screenshots.

A separate guest keeps the console service CPU-bound after its first reply. It verifies that timer preemption still lets `rootsrv` handle keyboard input.

The exit and fault guests terminate the console while its scratch frame and an anonymous page are mapped. After reaping each instance, `rootsrv` checks that it can reserve the full address-space budget again and that both scratch budgets are reclaimed. It restarts the service with fresh endpoints and continues handling input when the replacement also fails.

GitHub Actions runs both commands on pushes to `main` and on pull requests.

## Graphical boot

Run these commands from the repository root with QEMU's GTK display backend installed.

```sh
(cd servers && cargo build --locked --target x86_64-unknown-none -p rootsrv -p consoled)
(cd kernel/ruzt-kernel && cargo build --locked)
cargo run --locked -p boot-x86_64
```

QEMU opens a window for the boot screen and streams serial diagnostics to the terminal. With that window focused, press Space to toggle the top-right tile between blue and mint.

For UEFI with address randomization, build the UEFI kernel and pass the OVMF code and variables template. Set the paths for your distribution.

```sh
(cd kernel/ruzt-kernel && cargo build --locked --features uefi-kaslr)
cargo run --locked -p boot-x86_64 -- --uefi /usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/OVMF/OVMF_VARS_4M.fd
```

## Design

The current [storage and Rust driver milestone](docs/pre-desktop.md) records the accepted pre-desktop direction and its completion criteria.

Read [Project Philosophy](PHILOSOPHY.md) for the project's principles and the [Technical Design Report](Ruzt_Technical_Design_Report.md) for the architecture, roadmap, and proposed licensing model.
