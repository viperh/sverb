//! M1-01 / T-16: feeds arbitrary bytes to `sverb_crypto::envelope::open_item` (via
//! `fuzz_open_item`, which also exercises the unpad + capped zstd path). It must never
//! panic. Run it with `cargo +nightly fuzz run envelope_open` from `fuzz/` (the cargo-fuzz
//! workspace); the same body is property-tested on stable by
//! `crates/sverb-crypto/tests/primitives.rs::fuzz_open_item_never_panics`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    sverb_crypto::envelope::fuzz_open_item(data);
});
