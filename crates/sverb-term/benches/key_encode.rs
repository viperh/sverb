//! and kitty keyboard protocol.
#![allow(missing_docs, clippy::unwrap_used)]

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use sverb_term::input::{EncodeOpts, Key, KeyInput, KeyMods, encode_key};
use sverb_term::{KittyKeyboardFlags, TermModes};

fn keys() -> Vec<KeyInput> {
    let mut out: Vec<KeyInput> = "the quick brown fox jumps over the lazy dog"
        .chars()
        .map(|c| KeyInput::new(Key::Char(c), KeyMods::default()))
        .collect();
    for key in [
        Key::Enter,
        Key::Tab,
        Key::Backspace,
        Key::Esc,
        Key::Up,
        Key::Down,
        Key::PageUp,
        Key::Delete,
        Key::F(5),
        Key::F(12),
    ] {
        out.push(KeyInput::new(key, KeyMods::default()));
        out.push(KeyInput::new(key, KeyMods::CTRL));
    }
    out.push(KeyInput::new(Key::Char('c'), KeyMods::CTRL));
    out.push(KeyInput::new(Key::Char('A'), KeyMods::SHIFT));
    out
}

fn bench(c: &mut Criterion) {
    let keys = keys();
    let opts = EncodeOpts::default();
    let legacy = TermModes::default();
    let kitty = TermModes {
        kitty_keyboard: KittyKeyboardFlags(
            KittyKeyboardFlags::DISAMBIGUATE_ESC_CODES | KittyKeyboardFlags::REPORT_ALL_KEYS_AS_ESC,
        ),
        ..TermModes::default()
    };
    let mut g = c.benchmark_group("key_encode");
    for (name, modes) in [("legacy", &legacy), ("kitty", &kitty)] {
        g.bench_function(name, |b| {
            b.iter(|| {
                for k in &keys {
                    black_box(encode_key(black_box(*k), modes, &opts));
                }
            });
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
