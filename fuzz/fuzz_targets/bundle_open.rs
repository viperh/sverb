//! M4-03 / T-09: feeds arbitrary bytes to the account private/recovery bundle decoders via
//! `sverb_crypto::account::fuzz_open_bundle`. It must never panic. Run it with `cargo
//! +nightly fuzz run bundle_open` from `fuzz/` (the cargo-fuzz workspace); the same body is
//! property-tested on stable by
//! `crates/sverb-crypto/tests/account.rs::t09_decoders_never_panic`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    sverb_crypto::account::fuzz_open_bundle(data);
});
