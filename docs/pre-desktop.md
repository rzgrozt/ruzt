# Storage and Rust drivers before Zephyr

This milestone prepares x86-64 QEMU for persistent native applications. It follows Technical Design Report sections 9, 10, 17, 26 and 28. Each implementation step is committed and pushed after its checks pass. Progress estimates refer to this milestone.

## Accepted direction

- Hardware drivers execute as Rust user-space services using the capability-based driver SDK. Hardware documentation and existing implementations inform Rust buffer ownership, command sequencing and recovery.
- Mesa remains available for later Vulkan and OpenGL integration. The initial display target is VirtIO GPU with software-rendered buffers.
- RuztFS provides named folders, stable object identities, transactions, snapshots and encryption. Native applications operate relative to granted file and folder capabilities. Object identifiers identify data, while capabilities authorize access.
- Application data remains user-controlled. The POSIX compatibility layer translates path-based operations into native services.
- Physical-machine bring-up and Zephyr development follow this milestone.

## Implementation sequence and evidence

The capability metadata foundation is implemented in commit `406cbaa`. All 91 host tests and nine default QEMU fixtures passed. Independent source review found no concrete defects. The two optional CET fixtures were excluded by the default test selection.

The boot-program catalog now issues executable capabilities for named archive entries, with grants derived from the catalog authority. The console resolves its executable through this interface. All 93 host tests and nine default QEMU fixtures passed, including missing names, invalid names and authority, occupied destinations and revocation of issued capabilities. Device discovery and general driver supervision remain to be implemented.

The driver SDK supports configuration reads through a claimed PCI device's read capability. DMA binding still requires write authority. All 93 host tests and nine default QEMU fixtures passed, including an isolated console reading its delegated EDU function and rejecting unaligned reads and wrong capability types.

1. Bound kernel capability metadata and make allocation fallible. Exercise minting, IPC batch rollback, deletion, revocation and independent-process access at the limit. Run host and QEMU regressions.
2. Extend boot program registration, device discovery and driver supervision for independent service executables. Drivers receive only the PCI, IRQ, DMA and endpoint authorities they require. Validate replacement of a failed driver and rejection of obsolete service handles.
3. Implement Rust VirtIO block I/O and the block service interface, including device geometry, request bounds, completion errors and durable flush. Exercise a disposable data disk across guest reboots. Keep DMA buffers alive through completion and reset.
4. Implement the native filesystem service and RuztFS. Begin with an in-memory service exercising the same native operations, then a versioned disk format and transactional allocation. Add snapshots, bounded reclamation, integrity checks, encryption and key recovery. Provide host-side image creation and read-only inspection tools.
5. Implement keyboard and pointer services plus Rust VirtIO GPU display output. Verify input events, buffer ownership, presentation and service recovery through real QEMU devices.
6. Run the final repository security scan, record remaining findings and verify the acceptance conditions below.

## Durability and isolation requirements

A successful persistent commit must survive a restart when the device honors its advertised persistence guarantees. Root publication follows durable data and metadata writes. Mount validates checkpoint generations and checksums. Allocation, snapshot retention and reclamation belong to the same consistency model.

Crash testing interrupts each persistence stage and checks recovery against acknowledged transactions. Corruption tests require bounded parsing and explicit errors. Encryption tests cover incorrect keys, authenticated data and metadata, nonce uniqueness through recovery, and recovery-key access. Encrypted storage is required for the persistent user-data acceptance milestone.

The supervisor reissues authority to restarted services and clients acquire replacement endpoints. Outstanding I/O and DMA ownership must be resolved before resources can be recycled. Resource exhaustion returns a bounded error to the caller.

## Acceptance

- A native client creates, reads, edits and renames documents through granted folder and file capabilities.
- Committed documents survive guest reboot and interrupted saves without exposing partial committed state.
- Snapshots retain earlier versions and release unreferenced blocks within a bounded reclamation process.
- Encrypted data can be unlocked through the documented key and recovery paths.
- Device and filesystem services can fail and restart while independent clients continue making progress.
- QEMU display output and keyboard/pointer input work through the new services.
- Host tests, applicable QEMU fixtures and the final security review have recorded results.

## References

- [Technical Design Report](../Ruzt_Technical_Design_Report.md)
- [OSTEP crash consistency](https://pages.cs.wisc.edu/~remzi/OSTEP/file-journaling.pdf)
- [Btrfs design](https://btrfs.readthedocs.io/en/latest/dev/dev-btrfs-design.html)
- [RedoxFS](https://github.com/redox-os/redoxfs)
- [Rust VirtIO drivers](https://github.com/rcore-os/virtio-drivers)
- [VirtIO specification](https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html)
- [Rust xHCI register types](https://github.com/rust-osdev/xhci)
