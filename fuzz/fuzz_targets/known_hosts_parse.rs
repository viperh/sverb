//! matches every parsed entry against a fixed host (hashed fields, globs). It must never
//! panic. Run it with `cargo +nightly fuzz run known_hosts_parse` from `fuzz/` (the cargo-fuzz
//! workspace); the same body runs on stable as the property test
//! `known_hosts::tests::parser_never_panics` in `sverb-core`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let (entries, _warnings) = sverb_core::known_hosts::parse_known_hosts(&text);
    let _ = sverb_core::known_hosts::lookup(&entries, "host.example", 2222);
    let _ = sverb_core::known_hosts::export(&entries);
    for entry in &entries {
        let _ = sverb_core::known_hosts::check::KeyInfo::of_entry(entry);
    }
});
