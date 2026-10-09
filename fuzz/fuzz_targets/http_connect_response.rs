//! M7-05: an HTTP proxy's answer to CONNECT, delivered in reads of 1..=32 bytes
//! (`sverb_conn::proxy::http_connect::fuzz_http_connect_response`; property-tested in
//! `sverb-conn`). Bytes after the headers must reach the SSH layer unchanged.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    sverb_conn::proxy::http_connect::fuzz_http_connect_response(data);
});
