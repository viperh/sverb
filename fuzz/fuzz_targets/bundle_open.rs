//! M4-03 / T-09: feeds arbitrary bytes to the account private/recovery bundle
//! decoders via `sverb_crypto::account::fuzz_open_bundle`. It must never
//! panic. The cargo-fuzz workspace (`fuzz/Cargo.toml`) is created in M7-05;
//! the body below is compiled and property-tested today by
//! `crates/sverb-crypto/tests/account.rs::t09_decoders_never_panic`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    sverb_crypto::account::fuzz_open_bundle(data);
});
