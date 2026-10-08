//! M2-08 / T-20: feeds arbitrary bytes to the pure SOCKS parsers
//! (`parse_hello`, `parse_request5`, SOCKS4/4a) via
//! `sverb_conn::forward::socks::fuzz_socks_request`. It must never panic. The
//! cargo-fuzz workspace (`fuzz/Cargo.toml`, with a `sverb-conn` path dependency) is
//! created in M7-05; the body below is exercised today by
//! `crates/sverb-conn/src/forward/socks.rs::tests::fuzz_body_never_panics`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    sverb_conn::forward::socks::fuzz_socks_request(data);
});
