//! aarch64 context switch — not yet implemented.
//! Requires saving/restoring x19-x30 + SP_EL0 + TTBR0_EL1 + TPIDR_EL0.
//! Will be implemented in Phase 6.

/// Stub — context switch will live here.
pub unsafe fn switch(_old_rsp: *mut u64, _new_rsp: u64) {
    todo!("aarch64 context switch: save/restore callee-saved regs. Phase 6.");
}

/// Stub — stack initialization will live here.
pub unsafe fn init_stack(_stack: &mut [u8], _entry: fn() -> !) -> u64 {
    todo!("aarch64 stack init: set up initial frame. Phase 6.");
}
