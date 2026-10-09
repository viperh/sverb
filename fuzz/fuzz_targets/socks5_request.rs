//! `parse_request5`, SOCKS4/4a) via `sverb_conn::forward::socks::fuzz_socks_request`. It
//! must never panic. Run it with `cargo +nightly fuzz run socks5_request` from `fuzz/` (the
//! cargo-fuzz workspace); the same body is property-tested on stable by
//! `crates/sverb-conn/src/forward/socks.rs::tests::fuzz_body_never_panics`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    sverb_conn::forward::socks::fuzz_socks_request(data);
});
