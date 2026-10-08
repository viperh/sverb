//! M2-11 / T-16: feeds arbitrary text to the `ssh_config` importer
//! (`sverb_core::importers::ssh_config::parse_str_no_include`: lexer, blocks, the
//! wildcard-group and first-match mapping; `Include` is not followed, so no file is
//! read) and renders the preview. It must never panic. The cargo-fuzz workspace
//! (`fuzz/Cargo.toml`, with `libfuzzer-sys` and a `sverb-core` path dependency) is
//! created in M7-05; the seed corpus is `tests/fixtures/ssh_config/`. The same body
//! runs today as `importers::tests::parser_never_panics_on_garbage` in `sverb-core`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let plan = sverb_core::importers::ssh_config::parse_str_no_include(&text);
    let _ = plan.render_table();
    let _ = plan.identity_files();
});
