//! encoder, and the paste encoder, which must strip every bracketed-paste marker
//! (`sverb_term::fuzz::fuzz_key_event_encode`; property-tested in `sverb-term`).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    sverb_term::fuzz::fuzz_key_event_encode(data);
});
