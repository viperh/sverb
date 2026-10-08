//! M1-15 / T-18: feeds arbitrary text to `sverb_core::known_hosts::parse_known_hosts`
//! and matches every parsed entry against a fixed host (hashed fields, globs). It must
//! never panic. The cargo-fuzz workspace (`fuzz/Cargo.toml`, with `libfuzzer-sys` and a
//! `sverb-core` path dependency) is created in M7-05; the same body runs today as the
//! property test `known_hosts::tests::parser_never_panics` in `sverb-core`.
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
