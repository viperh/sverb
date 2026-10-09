//! Compile-fail fixture (T-03): must be rejected by `unsafe_code = "deny"`,
//! which every crate inherits from `[workspace.lints]`. Compiled by
//! `crates/sverb-e2e/tests/forbid_unsafe.rs`, never by this crate.

pub fn read(p: *const u8) -> u8 {
    unsafe { *p }
}
