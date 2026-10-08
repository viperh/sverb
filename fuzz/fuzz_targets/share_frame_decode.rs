//! M6-02 / T-08: feeds arbitrary bytes to the share payload and frame
//! decoders (`ShareFrame::decode`, `SharePayload::decode`) and to a channel
//! `open_frame` via `sverb_proto::share_frame::fuzz_share_frame_decode`. It
//! must never panic. The cargo-fuzz workspace (`fuzz/Cargo.toml`, with a
//! `sverb-proto` path dependency) is created in M7-05; the body below is
//! exercised today by
//! `crates/sverb-proto/src/share_frame.rs::tests::fuzz_body_never_panics`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    sverb_proto::share_frame::fuzz_share_frame_decode(data);
});
