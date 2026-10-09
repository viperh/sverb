//! Remote output into the terminal emulator, split at arbitrary read boundaries,
//! with resizes, rendering, query replies and the snapshot replay
//! (`sverb_term::fuzz::fuzz_emulator_feed`; property-tested in `sverb-term`). Seeds:
//! `crates/sverb-term/tests/streams/`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    sverb_term::fuzz::fuzz_emulator_feed(data);
});
