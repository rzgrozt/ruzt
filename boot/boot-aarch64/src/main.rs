//! aarch64 boot stub.
//! In Phase 6 this will be a UEFI entry point that normalizes boot info
//! and calls `ruzt_kernel::main()`. For now, it's a placeholder.
fn main() {
    println!("boot-aarch64: stub — real UEFI boot impl in Phase 6.");
}
