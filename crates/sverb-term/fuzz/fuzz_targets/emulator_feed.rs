//! T-18 (M1-09): arbitrary remote output never panics the emulator.
//!
//! The first two bytes pick the grid size, the rest is split into chunks at positions taken
//! from the input itself, so split escapes and split UTF-8 are exercised too. Also checks the
//! OSC 52 read invariant and that `snapshot_vt` output is itself safe to feed.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sverb_term::{AlacrittyEmulator, Emulator, EmulatorConfig};

fuzz_target!(|data: &[u8]| {
    let (cols, rows, rest) = match data {
        [c, r, rest @ ..] => (u16::from(*c % 200) + 1, u16::from(*r % 60) + 1, rest),
        _ => return,
    };
    let mut emu = AlacrittyEmulator::new(EmulatorConfig {
        cols,
        rows,
        scrollback: 100,
    });
    let mut rest = rest;
    while !rest.is_empty() {
        let n = (usize::from(rest[0]) % 64 + 1).min(rest.len());
        emu.feed(&rest[..n]);
        rest = &rest[n..];
    }
    for r in emu.take_responses() {
        assert!(!r.starts_with(b"\x1b]52"), "clipboard read answered");
    }
    let _ = emu.take_events();
    let snap = emu.snapshot_vt();
    let mut fresh = AlacrittyEmulator::new(EmulatorConfig {
        cols,
        rows,
        scrollback: 0,
    });
    fresh.feed(&snap);
    emu.resize(cols / 2 + 1, rows + 3);
});
