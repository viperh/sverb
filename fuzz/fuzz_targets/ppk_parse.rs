//! M7-03 / T-07 (SPEC §19): feeds arbitrary bytes to the PuTTY `.ppk` parser
//! (`sverb_core::keychain::formats::ppk`) with and without a passphrase. It must never
//! panic, and hostile Argon2 parameters must be refused before any derivation. The
//! cargo-fuzz workspace (`fuzz/Cargo.toml`, with `libfuzzer-sys` and a `sverb-core` path
//! dependency) is created in M7-05; the same body runs today as the property tests
//! `keychain::formats::ppk::tests::t07_*` in `sverb-core`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sverb_core::keychain::formats::ppk;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = ppk::is_ppk(&text);
    let _ = ppk::parse(&text);
    let _ = ppk::public_key(&text);
    let _ = ppk::decode(&text, None);
    let _ = ppk::decode(&text, Some("fixture"));
});
