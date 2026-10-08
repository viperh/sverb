//! M1-01 / T-16: feeds arbitrary bytes to `sverb_crypto::envelope::open_item`
//! (via `fuzz_open_item`, which also exercises the unpad + capped zstd path).
//! It must never panic. The cargo-fuzz workspace (`fuzz/Cargo.toml`, with
//! `libfuzzer-sys` and a `sverb-crypto` path dependency) is created in M7-05;
//! the body below is compiled and property-tested today by
//! `crates/sverb-crypto/tests/primitives.rs::fuzz_open_item_never_panics`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    sverb_crypto::envelope::fuzz_open_item(data);
});
