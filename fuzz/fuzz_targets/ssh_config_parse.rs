//! (`sverb_core::importers::ssh_config::parse_str_no_include`: lexer, blocks, the
//! wildcard-group and first-match mapping; `Include` is not followed, so no file is read)
//! and renders the preview. It must never panic. Run it with `cargo +nightly fuzz run ssh_config_parse
//!` from `fuzz/` (the cargo-fuzz workspace); the seed corpus is
//! `tests/fixtures/ssh_config/`. The same body runs on stable as
//! `importers::tests::parser_never_panics_on_garbage` in `sverb-core`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let plan = sverb_core::importers::ssh_config::parse_str_no_include(&text);
    let _ = plan.render_table();
    let _ = plan.identity_files();
});
