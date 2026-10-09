//! OSC 133 shell-integration marks around arbitrary payloads, fed whole and byte
//! by byte (`sverb_term::fuzz::fuzz_osc133_scan`; property-tested in `sverb-term`).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    sverb_term::fuzz::fuzz_osc133_scan(data);
});
