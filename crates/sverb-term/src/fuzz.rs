//! M7-05: fuzz entry points (SPEC §19 "Fuzzing"). Each function takes arbitrary bytes and
//! must never panic, hang or allocate without bound. The cargo-fuzz targets in
//! `fuzz/fuzz_targets/` call them, and the property tests below run the same bodies on
//! every `cargo test`, so they can't rot between fuzz runs.
//!
//! - [`fuzz_emulator_feed`] (`emulator_feed`): remote output into the emulator, split at
//!   arbitrary read boundaries, with resizes, rendering, replies and the snapshot.
//! - [`fuzz_osc133_scan`] (`osc133_scan`): OSC 133 marks around arbitrary payloads, fed
//!   whole and byte by byte.
//! - [`fuzz_key_event_encode`] (`key_event_encode`): keys, modifiers and modes into the
//!   key encoder, plus the paste encoder (which must strip every bracketed-paste marker).

use ratatui_core::{buffer::Buffer, layout::Rect};

use crate::{
    AlacrittyEmulator, Emulator, EmulatorConfig, GridPoint, KittyKeyboardFlags, TermModes,
    ViewState,
    input::{
        BackspaceMode, EncodeOpts, Key, KeyInput, KeyMods, KeypadKey, PASTE_END, PASTE_START,
        encode_key, encode_paste,
    },
};

/// Small byte reader: missing bytes read as 0.
struct Bytes<'a>(&'a [u8]);

impl Bytes<'_> {
    fn byte(&mut self) -> u8 {
        let (first, rest) = self.0.split_first().map_or((0, &[][..]), |(f, r)| (*f, r));
        self.0 = rest;
        first
    }
}

fn emulator(cols: u16, rows: u16) -> AlacrittyEmulator {
    AlacrittyEmulator::new(EmulatorConfig {
        cols,
        rows,
        scrollback: 200,
    })
}

/// Everything a pane does with an emulator after a read.
fn exercise(e: &mut AlacrittyEmulator) {
    let _ = e.take_responses();
    let _ = e.take_events();
    let _ = e.prompt_state();
    let _ = e.cursor();
    let _ = e.modes();
    let (cols, rows) = e.size();
    let area = Rect::new(0, 0, cols, rows);
    let mut buf = Buffer::empty(area);
    e.render(area, &mut buf, &ViewState::default());
    // Diff the frame like the real terminal flush does: ratatui asserts there that no cell
    // holds a control character (a `\t` from the grid once crashed sverb here).
    let _ = Buffer::empty(area).diff(&buf);
    let _ = e.hyperlink_at(GridPoint::new(0, 0));
    let _ = e.row(-1);
}

/// `emulator_feed`: the first two bytes pick the size (1..=120 × 1..=50), the third the
/// read chunk length; the rest is remote output. Every chunk is followed by what the
/// UI does after a read, and a byte `0xFF` at a chunk start also resizes. The final
/// screen is snapshotted and replayed into a fresh emulator.
pub fn fuzz_emulator_feed(data: &[u8]) {
    let mut input = Bytes(data);
    let cols = u16::from(input.byte() % 120) + 1;
    let rows = u16::from(input.byte() % 50) + 1;
    let chunk = usize::from(input.byte() % 64) + 1;
    let mut e = emulator(cols, rows);
    for piece in input.0.chunks(chunk) {
        if piece.first() == Some(&0xFF) && piece.len() >= 3 {
            e.resize(u16::from(piece[1] % 200), u16::from(piece[2] % 80));
        }
        e.feed(piece);
        exercise(&mut e);
    }
    let snapshot = e.snapshot_vt();
    let (cols, rows) = e.size();
    let mut replay = emulator(cols, rows);
    replay.feed(&snapshot);
    exercise(&mut replay);
    let _ = e.grid_text(GridPoint::new(-5, 0), GridPoint::new(i32::from(rows), 0));
}

/// `osc133_scan`: arbitrary bytes are wrapped in OSC 133 marks (the first byte picks
/// which ones and the terminators), then fed whole to one emulator and one byte at a
/// time to another. Neither may panic.
pub fn fuzz_osc133_scan(data: &[u8]) {
    let mut input = Bytes(data);
    let shape = input.byte();
    let st: &[u8] = if shape & 1 == 0 { b"\x07" } else { b"\x1b\\" };
    let mut stream = Vec::with_capacity(input.0.len() + 64);
    for (bit, mark) in [(2, &b"A"[..]), (4, b"B"), (8, b"C")] {
        if shape & bit != 0 {
            stream.extend_from_slice(b"\x1b]133;");
            stream.extend_from_slice(mark);
            stream.extend_from_slice(st);
        }
        stream.extend_from_slice(input.0);
    }
    if shape & 16 != 0 {
        stream.extend_from_slice(b"\x1b]133;D;");
        stream.extend_from_slice(&input.0[..input.0.len().min(12)]);
        stream.extend_from_slice(st);
    }
    let mut whole = emulator(40, 6);
    whole.feed(&stream);
    exercise(&mut whole);
    let mut split = emulator(40, 6);
    for byte in &stream {
        split.feed(std::slice::from_ref(byte));
    }
    exercise(&mut split);
}

fn key_from(input: &mut Bytes<'_>) -> Key {
    match input.byte() % 18 {
        0 => {
            let raw = u32::from_le_bytes([input.byte(), input.byte(), input.byte() % 0x11, 0]);
            Key::Char(char::from_u32(raw).unwrap_or('a'))
        }
        1 => Key::Enter,
        2 => Key::Tab,
        3 => Key::Backspace,
        4 => Key::Esc,
        5 => Key::Up,
        6 => Key::Down,
        7 => Key::Left,
        8 => Key::Right,
        9 => Key::Home,
        10 => Key::End,
        11 => Key::Insert,
        12 => Key::Delete,
        13 => Key::PageUp,
        14 => Key::PageDown,
        15 => Key::F(input.byte()),
        16 => Key::Keypad(match input.byte() % 8 {
            0 => KeypadKey::Digit(input.byte()),
            1 => KeypadKey::Decimal,
            2 => KeypadKey::Divide,
            3 => KeypadKey::Multiply,
            4 => KeypadKey::Subtract,
            5 => KeypadKey::Add,
            6 => KeypadKey::Enter,
            _ => KeypadKey::Equal,
        }),
        _ => Key::Char(char::from(input.byte())),
    }
}

/// `key_event_encode`: a mode byte pair, then (key, modifiers) records until the input
/// runs out; the remaining bytes (lossy UTF-8) are also pasted, with and without
/// bracketed paste. A bracketed paste must contain exactly one start and one end marker.
pub fn fuzz_key_event_encode(data: &[u8]) {
    let mut input = Bytes(data);
    let flags = input.byte();
    let modes = TermModes {
        app_cursor: flags & 1 != 0,
        app_keypad: flags & 2 != 0,
        line_feed_new_line: flags & 4 != 0,
        bracketed_paste: flags & 8 != 0,
        modify_other_keys: (flags >> 4) % 3,
        kitty_keyboard: KittyKeyboardFlags(input.byte()),
        ..TermModes::default()
    };
    let opts = EncodeOpts {
        backspace: if flags & 0x80 != 0 {
            BackspaceMode::CtrlH
        } else {
            BackspaceMode::Del
        },
    };
    let paste = String::from_utf8_lossy(input.0).into_owned();
    for _ in 0..64 {
        if input.0.is_empty() {
            break;
        }
        let key = key_from(&mut input);
        let mods = KeyMods::from_bits(input.byte());
        let out = encode_key(KeyInput::new(key, mods), &modes, &opts);
        if matches!(key, Key::Char(_)) {
            assert!(out.is_some_and(|b| !b.is_empty()), "{key:?} {mods:?}");
        }
    }
    let bracketed = TermModes {
        bracketed_paste: true,
        ..modes
    };
    let out = encode_paste(&paste, &bracketed);
    let text = String::from_utf8_lossy(&out);
    assert_eq!(text.matches(PASTE_START).count(), 1, "{text:?}");
    assert_eq!(text.matches(PASTE_END).count(), 1, "{text:?}");
    let _ = encode_paste(&paste, &TermModes::default());
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const STREAMS: [&[u8]; 4] = [
        include_bytes!("../tests/streams/vim.bin"),
        include_bytes!("../tests/streams/bash_osc133.bin"),
        include_bytes!("../tests/streams/utf8_test.bin"),
        include_bytes!("../tests/streams/decstbm.bin"),
    ];

    #[test]
    fn seed_streams_run() {
        for stream in STREAMS {
            let mut data = vec![80, 24, 63];
            data.extend_from_slice(stream);
            fuzz_emulator_feed(&data);
            fuzz_osc133_scan(&stream[..stream.len().min(512)]);
            fuzz_key_event_encode(&stream[..stream.len().min(256)]);
        }
        fuzz_emulator_feed(&[]);
        fuzz_osc133_scan(&[]);
        fuzz_key_event_encode(&[]);
    }

    #[test]
    fn paste_markers_split_around_each_other_are_stripped() {
        // `ESC[20` + `ESC[201~` + `1~`: removing the inner marker must not leave a new one.
        let mut data = vec![8, 0];
        data.extend_from_slice(b"\x1b[20\x1b[201~1~ rm -rf ~\x1b[200~");
        fuzz_key_event_encode(&data);
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

        #[test]
        fn emulator_feed_never_panics(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
            fuzz_emulator_feed(&data);
        }

        #[test]
        fn osc133_scan_never_panics(data in proptest::collection::vec(any::<u8>(), 0..256)) {
            fuzz_osc133_scan(&data);
        }

        #[test]
        fn key_event_encode_never_panics(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            fuzz_key_event_encode(&data);
        }

        #[test]
        fn escape_heavy_streams_never_panic(
            parts in proptest::collection::vec(
                prop_oneof![
                    Just(&b"\x1b["[..]), Just(&b"\x1b]"[..]), Just(&b"\x1bP"[..]),
                    Just(&b"\x07"[..]), Just(&b"\x1b\\"[..]), Just(&b";"[..]),
                    Just(&b"133;A"[..]), Just(&b"52;c;"[..]), Just(&b"8;;"[..]),
                    Just(&b"?1049h"[..]), Just(&b"999999999"[..]), Just(&b"\xc3"[..]),
                ],
                0..200,
            )
        ) {
            let mut data = vec![20, 5, 7];
            for p in parts {
                data.extend_from_slice(p);
            }
            fuzz_emulator_feed(&data);
        }
    }
}
