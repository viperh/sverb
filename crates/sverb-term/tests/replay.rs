//! Replay recorded byte streams at 80×24 and snapshot the final grid.
//!
//! Fixtures live in `tests/streams/*.bin`; re-record them with `tests/streams/record.sh`.
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use sverb_term::{AlacrittyEmulator, Emulator, EmulatorConfig};

fn replay(bytes: &[u8], chunk: usize) -> AlacrittyEmulator {
    let mut e = AlacrittyEmulator::new(EmulatorConfig {
        cols: 80,
        rows: 24,
        scrollback: 1000,
    });
    for part in bytes.chunks(chunk.max(1)) {
        e.feed(part);
    }
    e.flush_sync();
    e
}

fn check(name: &str) {
    let path = format!("{}/tests/streams/{name}.bin", env!("CARGO_MANIFEST_DIR"));
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let whole = replay(&bytes, bytes.len());
    // Splitting the stream at arbitrary points (inside escapes and UTF-8) changes nothing.
    for chunk in [1, 7, 64] {
        assert_eq!(
            whole.screen_dump(true),
            replay(&bytes, chunk).screen_dump(true),
            "{name} chunk={chunk}"
        );
    }
    // snapshot_vt recreates the same screen in a fresh emulator.
    let mut b = AlacrittyEmulator::new(EmulatorConfig {
        cols: 80,
        rows: 24,
        scrollback: 0,
    });
    b.feed(&whole.snapshot_vt());
    assert_eq!(
        whole.screen_dump(true),
        b.screen_dump(true),
        "{name} snapshot_vt"
    );

    insta::assert_snapshot!(name, whole.screen_dump(false));
}

#[test]
fn vim() {
    check("vim");
}

#[test]
fn htop() {
    check("htop");
}

#[test]
fn tmux_split() {
    check("tmux_split");
}

#[test]
fn less_man() {
    check("less_man");
}

#[test]
fn color_test() {
    check("color_test");
}

#[test]
fn utf8_test() {
    check("utf8_test");
}

#[test]
fn decstbm() {
    check("decstbm");
}
