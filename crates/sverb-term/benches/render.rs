//! T-15 (M1-10): render a full 300×100 grid with dense SGR (SPEC §19: < 2 ms per frame).
//!
//! `cargo bench -p sverb-term --bench render`. The gate is enforced in M7-06.
#![allow(missing_docs, clippy::unwrap_used)]

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use ratatui_core::buffer::Buffer;
use ratatui_core::layout::Rect;
use sverb_term::{AlacrittyEmulator, ColorDepth, Emulator, EmulatorConfig, ViewState, scheme};

const COLS: u16 = 300;
const ROWS: u16 = 100;

/// Every cell gets its own SGR: rotating 16-color, 256-color and 24-bit colors plus
/// attributes, with some wide and combining chars.
fn dense_screen() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"\x1b[H\x1b[2J");
    let mut i: u32 = 0;
    for row in 0..ROWS {
        out.extend_from_slice(format!("\x1b[{};1H", row + 1).as_bytes());
        let mut col = 0;
        while col < COLS {
            let sgr = match i % 6 {
                0 => format!("\x1b[0;{}m", 31 + i % 7),
                1 => format!("\x1b[1;{}m", 91 + i % 7),
                2 => format!("\x1b[3;38;5;{}m", i % 256),
                3 => format!("\x1b[4;48;5;{}m", (i * 7) % 256),
                4 => format!(
                    "\x1b[7;38;2;{};{};{}m",
                    i % 256,
                    (i * 3) % 256,
                    (i * 5) % 256
                ),
                _ => format!("\x1b[0;48;2;{};{};{}m", (i * 11) % 256, i % 256, 40),
            };
            out.extend_from_slice(sgr.as_bytes());
            if i.is_multiple_of(50) && col + 2 <= COLS {
                out.extend_from_slice("中".as_bytes());
                col += 2;
            } else if i.is_multiple_of(37) {
                out.extend_from_slice("e\u{301}".as_bytes());
                col += 1;
            } else {
                out.push(b'a' + u8::try_from(i % 26).unwrap());
                col += 1;
            }
            i += 1;
        }
    }
    out.extend_from_slice(b"\x1b[0m");
    out
}

fn bench(c: &mut Criterion) {
    let mut emu = AlacrittyEmulator::new(EmulatorConfig {
        cols: COLS,
        rows: ROWS,
        scrollback: 1000,
    });
    emu.feed(&dense_screen());
    let area = Rect::new(0, 0, COLS, ROWS);
    let mut buf = Buffer::empty(area);
    let mut group = c.benchmark_group("render");
    for (name, view) in [
        ("terminal_truecolor", ViewState::default()),
        (
            "dracula_truecolor",
            ViewState {
                scheme: scheme::builtin("dracula"),
                ..ViewState::default()
            },
        ),
        (
            "dracula_256",
            ViewState {
                scheme: scheme::builtin("dracula"),
                depth: ColorDepth::Indexed256,
                ..ViewState::default()
            },
        ),
    ] {
        group.bench_function(format!("300x100_{name}"), |b| {
            b.iter(|| emu.render(black_box(area), black_box(&mut buf), black_box(&view)));
        });
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
