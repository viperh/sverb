//! (`sverb_core::keychain::formats::ppk`) with and without a passphrase. It must never
//! panic, and hostile Argon2 parameters must be refused before any derivation. Run it with
//! `cargo +nightly fuzz run ppk_parse` from `fuzz/` (the cargo-fuzz workspace); the same
//! body runs on stable as the property tests `keychain::formats::ppk::tests::t07_*` in
//! `sverb-core`.
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
