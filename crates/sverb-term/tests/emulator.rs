#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use bytes::Bytes;
use proptest::prelude::*;
use regex::Regex;
use sverb_term::{
    AlacrittyEmulator, CharsetCodec, ClipboardTarget, ColorScheme, Direction, Emulator,
    EmulatorConfig, GridPoint, MouseEncoding, MouseMode, PromptMarkKind, Rgb, TermEvent,
};

fn emu(cols: u16, rows: u16) -> AlacrittyEmulator {
    AlacrittyEmulator::new(EmulatorConfig {
        cols,
        rows,
        scrollback: 1000,
    })
}

fn joined(responses: &[Bytes]) -> Vec<u8> {
    responses.iter().flat_map(|b| b.iter().copied()).collect()
}

#[test]
fn da1_reply() {
    let mut e = emu(80, 24);
    e.feed(b"\x1b[c");
    let r = e.take_responses();
    assert_eq!(joined(&r), b"\x1b[?6c");
    // DA2 too, and a second take is empty.
    e.feed(b"\x1b[>c");
    assert!(joined(&e.take_responses()).starts_with(b"\x1b[>0;"));
    assert!(e.take_responses().is_empty());
}

/// Row 10, column 5 (1-based) → `ESC [ 10 ; 5 R`.
#[test]
fn dsr_cpr() {
    let mut e = emu(80, 24);
    e.feed(b"\x1b[10;5H\x1b[6n");
    assert_eq!(joined(&e.take_responses()), b"\x1b[10;5R");
}

#[test]
fn osc11_background_query() {
    let mut e = emu(80, 24);
    let scheme = ColorScheme {
        background: Rgb::new(0x12, 0x34, 0xab),
        ..ColorScheme::default()
    };
    e.set_color_scheme(&scheme);
    e.feed(b"\x1b]11;?\x07");
    let r = String::from_utf8(joined(&e.take_responses())).unwrap();
    assert_eq!(r, "\x1b]11;rgb:1212/3434/abab\x07");
    // OSC 10 with ST terminator, and OSC 4 for an index.
    e.feed(b"\x1b]10;?\x1b\\\x1b]4;1;?\x07");
    let r = String::from_utf8(joined(&e.take_responses())).unwrap();
    assert!(r.contains("\x1b]10;rgb:e5e5/e5e5/e5e5\x1b\\"), "{r:?}");
    assert!(r.contains("\x1b]4;1;rgb:cdcd/0000/0000\x07"), "{r:?}");
}

/// T-04 (cont.): a remote override (OSC 11 set) is what later queries report.
#[test]
fn osc11_reports_remote_override() {
    let mut e = emu(80, 24);
    e.feed(b"\x1b]11;rgb:01/02/03\x07\x1b]11;?\x07");
    let r = String::from_utf8(joined(&e.take_responses())).unwrap();
    assert_eq!(r, "\x1b]11;rgb:0101/0202/0303\x07");
}

/// Query-looking text inside an OSC string (title) is not a query, and the title carrying it
/// is never echoed back.
#[test]
fn responses_are_not_echoes() {
    let mut e = emu(80, 24);
    e.feed(b"\x1b]2;hello [6n \\x1b[6n world\x07");
    e.feed(b"\x1b]2;x\x9b6n y\x07");
    e.feed("\x1b]2;\u{9b}6n\x07".as_bytes());
    e.feed(b"\x1b]0;\x1b\\"); // empty title, ST-terminated
    e.feed(b"\x1b[21t"); // XTWINOPS title report: alacritty doesn't implement it
    assert!(e.take_responses().is_empty());
    // An ESC inside an OSC aborts the string (as in xterm); the CSI that follows is a real query
    // and its reply is generated from emulator state (cursor), not from the remote's bytes.
    e.feed(b"\x1b]2;abc\x1b[6n\x07");
    assert_eq!(joined(&e.take_responses()), b"\x1b[1;1R");
}

/// OSC 52 read is denied: no response, no event.
#[test]
fn osc52_read_denied() {
    let mut e = emu(80, 24);
    e.feed(b"\x1b]52;c;aGVsbG8=\x07"); // a write first, so there *is* clipboard content
    let _ = e.take_events();
    e.feed(b"\x1b]52;c;?\x07\x1b]52;p;?\x1b\\\x1b]52;s;?\x07");
    assert!(e.take_responses().is_empty());
    assert!(e.take_events().is_empty());
}

#[test]
fn osc52_write_reported() {
    let mut e = emu(80, 24);
    e.feed(b"\x1b]52;c;aGVsbG8=\x07");
    assert_eq!(
        e.take_events(),
        vec![TermEvent::ClipboardWriteRequest {
            target: ClipboardTarget::Clipboard,
            text: "hello".into()
        }]
    );
    assert!(e.take_responses().is_empty());
}

#[test]
fn title_is_capped() {
    let mut e = emu(80, 24);
    let mut seq = b"\x1b]2;".to_vec();
    for i in 0..10_000 {
        seq.push(if i % 100 == 0 {
            0x01
        } else {
            b'a' + (i % 26) as u8
        });
    }
    seq.push(0x07);
    e.feed(&seq);
    let events = e.take_events();
    let [TermEvent::Title(Some(title))] = events.as_slice() else {
        panic!("{events:?}")
    };
    assert!(title.chars().count() <= 256);
    assert!(!title.chars().any(char::is_control));
    e.feed(b"\x1b]2;\x07");
    assert_eq!(e.take_events(), vec![TermEvent::Title(Some(String::new()))]);
}

#[test]
fn modes_are_tracked() {
    let mut e = emu(80, 24);
    assert!(!e.modes().app_cursor);
    e.feed(b"\x1b[?1h");
    assert!(e.modes().app_cursor);
    e.feed(b"\x1b[?2004h");
    assert!(e.modes().bracketed_paste);
    e.feed(b"\x1b[?1000h\x1b[?1006h");
    let m = e.modes();
    assert_eq!(m.mouse_mode, MouseMode::Click);
    assert_eq!(m.mouse_encoding, MouseEncoding::Sgr);
    e.feed(b"\x1b[?1049h");
    assert!(e.modes().alt_screen);
    e.feed(b"\x1b[?1003h\x1b[?1006l\x1b[?1015h\x1b[?1004h\x1b=");
    let m = e.modes();
    assert_eq!(m.mouse_mode, MouseMode::Motion);
    assert_eq!(m.mouse_encoding, MouseEncoding::Urxvt);
    assert!(m.focus_reporting);
    assert!(m.app_keypad);
    e.feed(b"\x1b[>4;2m\x1b[>5u\x1b[5 q\x1b[?25l");
    let m = e.modes();
    assert_eq!(m.modify_other_keys, 2);
    assert_eq!(m.kitty_keyboard.0, 5);
    assert_eq!(m.cursor_shape, sverb_term::CursorShape::Bar);
    assert!(m.cursor_blinking);
    assert!(!m.cursor_visible);
    e.feed(b"\x1b[?1049l\x1b[?2004l\x1b[?1l");
    let m = e.modes();
    assert!(!m.alt_screen && !m.bracketed_paste && !m.app_cursor);
}

#[test]
fn split_utf8() {
    let mut e = emu(10, 2);
    e.feed(&[0xC3]);
    e.feed(&[0xA9]);
    assert_eq!(e.grid_text(GridPoint::new(0, 0), GridPoint::new(0, 9)), "é");
    assert_eq!(e.cursor().point, GridPoint::new(0, 1));
}

/// T-10 (cont.): a chunk ending inside a character followed by more text keeps every byte
/// (regression for a vte 0.15 partial-UTF-8 bug that dropped the following space).
#[test]
fn split_utf8_followed_by_text() {
    let mut e = emu(20, 2);
    e.feed(b"ab\xd7");
    e.feed(b"\x9d \xd7\xa2x");
    assert_eq!(
        e.grid_text(GridPoint::new(0, 0), GridPoint::new(0, 19)),
        "ab\u{5dd} \u{5e2}x"
    );
    // 4-byte emoji split at every position.
    let s = "x\u{1f600} y".as_bytes();
    for i in 1..s.len() {
        let mut e = emu(20, 2);
        e.feed(&s[..i]);
        e.feed(&s[i..]);
        assert_eq!(
            e.grid_text(GridPoint::new(0, 0), GridPoint::new(0, 19)),
            "x\u{1f600} y",
            "split {i}"
        );
    }
}

#[test]
fn charset_windows_1252() {
    let mut codec = CharsetCodec::for_label("windows-1252").unwrap();
    let mut e = emu(10, 2);
    e.feed(&codec.decode(&[0x80, b'x']));
    assert_eq!(
        e.grid_text(GridPoint::new(0, 0), GridPoint::new(0, 9)),
        "€x"
    );
    assert_eq!(&*codec.encode("€"), &[0x80]);
}

#[test]
fn charset_shift_jis_split() {
    let mut codec = CharsetCodec::for_label("shift_jis").unwrap();
    let mut e = emu(20, 2);
    // "日本語" = 93 FA 96 7B 8C EA, split at every byte.
    for b in [0x93u8, 0xFA, 0x96, 0x7B, 0x8C, 0xEA] {
        e.feed(&codec.decode(&[b]));
    }
    assert_eq!(
        e.grid_text(GridPoint::new(0, 0), GridPoint::new(0, 19)),
        "日本語"
    );
    assert_eq!(e.cursor().point.column, 6);
}

#[test]
fn wide_chars() {
    let mut e = emu(10, 2);
    e.feed("a中b".as_bytes());
    assert_eq!(e.cursor().point, GridPoint::new(0, 4));
    // `b` is at column 3: the wide char occupies columns 1 and 2 (spacer).
    assert_eq!(e.grid_text(GridPoint::new(0, 3), GridPoint::new(0, 3)), "b");
    assert_eq!(
        e.grid_text(GridPoint::new(0, 1), GridPoint::new(0, 2)),
        "中"
    );
    let dump = e.screen_dump(true);
    assert!(
        dump.contains("0,1: '中'") && dump.contains("WIDE_CHAR"),
        "{dump}"
    );
    assert!(
        dump.contains("0,2: ' '") && dump.contains("WIDE_CHAR_SPACER"),
        "{dump}"
    );
}

#[test]
fn resize_shrink_grow() {
    let mut e = emu(80, 24);
    for i in 0..200 {
        e.feed(format!("line {i} {}\r\n", "x".repeat(i % 70)).as_bytes());
    }
    let history = e.scrollback_len();
    assert!(history > 0);
    let total_before = history + 24;
    e.resize(40, 10);
    assert_eq!(e.size(), (40, 10));
    e.resize(1, 0); // clamped, never panics
    assert_eq!(e.size(), (2, 1));
    e.resize(120, 50);
    e.resize(80, 24);
    assert_eq!(e.size(), (80, 24));
    // Rows-only resizes move lines between screen and history without losing them.
    let mut f = emu(80, 24);
    for i in 0..200 {
        f.feed(format!("line {i}\r\n").as_bytes());
    }
    let before = f.scrollback_len() + 24;
    f.resize(80, 10);
    assert_eq!(f.scrollback_len() + 10, before);
    f.resize(80, 30);
    assert_eq!(f.scrollback_len() + 30, before);
    assert!(total_before > 0);
    // Text written after resizes lands where the cursor says.
    e.feed(b"\x1b[2J\x1b[Hok");
    assert_eq!(
        e.grid_text(GridPoint::new(0, 0), GridPoint::new(0, 79)),
        "ok"
    );
}

const COLORFUL: &[u8] = b"\x1b[1;31mbold red\x1b[0m \x1b[2;3;4mdim it ul\x1b[0m \x1b[4:3;58;5;196mcurly\x1b[0m\r\n\
\x1b[7;38;5;208minverse 208\x1b[0m \x1b[9;48;2;10;20;30mstrike rgb-bg\x1b[0m \x1b[8mhidden\x1b[0m\r\n\
\x1b[44m\x1b[Kblue line erased with bce\x1b[0m\r\n\
\xe4\xb8\xad\xe6\x96\x87 e\xcc\x81 \xf0\x9f\x98\x80 \x1b]8;id=x;https://example.com\x1b\\link\x1b]8;;\x1b\\ \x1b]8;;https://anon.example\x07anon\x1b]8;;\x07\r\n\
\x1b[10;78Hwrap\x1b[20;80H\xe4\xb8\xad\
\x1b[23;80HZ\
\x1b]4;3;rgb:11/22/33\x07\x1b]11;rgb:00/00/10\x07\
\x1b[?1h\x1b[?2004h\x1b[?1002h\x1b[?1006h\x1b[?1004h\x1b[>4;1m\x1b[>1u\x1b[3 q\x1b[1;32;45m";

fn assert_round_trip(a: &AlacrittyEmulator) {
    let snap = a.snapshot_vt();
    let (cols, rows) = a.size();
    let mut b = emu(cols, rows);
    b.feed(&snap);
    assert_eq!(
        a.screen_dump(true),
        b.screen_dump(true),
        "snapshot: {:?}",
        String::from_utf8_lossy(&snap)
    );
    // Feeding the same continuation into both keeps them identical (pen, wrap state, modes).
    let mut a2 = emu(cols, rows);
    a2.feed(&a.snapshot_vt());
    let tail = b"tail\x1b[5;5Hmore\r\n\x1b[?1049l";
    a2.feed(tail);
    b.feed(tail);
    assert_eq!(a2.screen_dump(true), b.screen_dump(true));
}

#[test]
fn snapshot_round_trip_primary() {
    let mut a = emu(80, 24);
    a.feed(COLORFUL);
    assert!(a.screen_dump(false).contains("bold red"));
    assert_round_trip(&a);
}

/// T-15 (alt screen)
#[test]
fn snapshot_round_trip_alt_screen() {
    let mut a = emu(80, 24);
    a.feed(b"primary content\r\n\x1b[?1049h");
    a.feed(COLORFUL);
    assert!(a.modes().alt_screen);
    assert_round_trip(&a);
    let mut b = emu(80, 24);
    b.feed(&a.snapshot_vt());
    assert!(b.modes().alt_screen);
}

/// T-15 (pending wrap, autowrap off, hidden cursor, origin)
#[test]
fn snapshot_round_trip_edge_states() {
    let mut a = emu(20, 5);
    a.feed(b"\x1b[1;1H01234567890123456789"); // cursor pending wrap at the last column
    assert_round_trip(&a);
    let mut a = emu(20, 5);
    a.feed(b"\x1b[3;1Hxx\x1b[?7l\x1b[?25l\x1b[4h\x1b[20h\x1b[?1007l");
    assert_round_trip(&a);
    let mut a = emu(20, 5);
    a.feed("\x1b[1;20H中x".as_bytes()); // leading wide-char spacer + soft wrap
    assert_round_trip(&a);
}

#[test]
fn scrollback_size_is_honored() {
    let mut e = AlacrittyEmulator::new(EmulatorConfig {
        cols: 80,
        rows: 24,
        scrollback: 100,
    });
    for i in 0..1000 {
        e.feed(format!("{i}\r\n").as_bytes());
    }
    assert!(e.scrollback_len() <= 100);
    assert_eq!(e.scrollback_len(), 100);
}

#[test]
fn search_backwards_across_scrollback() {
    let mut e = emu(80, 24);
    e.feed(b"error42 at the top\r\n");
    for i in 0..100 {
        e.feed(format!("noise {i}\r\n").as_bytes());
    }
    e.feed(b"ERROR7 uppercase does not match\r\n");
    let re = Regex::new(r"error\d+").unwrap();
    let cursor = e.cursor().point;
    let m = e.search(&re, Direction::Backward, cursor).expect("match");
    assert!(m.start.line < 0, "{m:?}");
    assert_eq!(e.grid_text(m.start, m.end), "error42");
    // Forward from the match start finds nothing newer.
    let after = GridPoint::new(m.end.line, m.end.column + 1);
    let fwd = e.search(&re, Direction::Forward, after);
    assert!(fwd.is_none_or(|f| f == m), "{fwd:?}");
    // Inline flags still work.
    let ci = Regex::new(r"(?i)error7").unwrap();
    let m = e
        .search(&ci, Direction::Backward, cursor)
        .expect("ci match");
    assert_eq!(e.grid_text(m.start, m.end), "ERROR7");
}

/// Other listener events: bell, title reset, text area size, OSC 7, OSC 133.
#[test]
fn other_events() {
    let mut e = emu(80, 24);
    e.set_pixel_size(9, 18);
    e.feed(b"\x07\x1b]2;t\x07\x1b[22;0t\x1b[23;0t\x1b[14t\x1b[18t");
    let r = String::from_utf8(joined(&e.take_responses())).unwrap();
    assert!(r.contains("\x1b[4;432;720t"), "{r:?}");
    assert!(r.contains("\x1b[8;24;80t"), "{r:?}");
    let ev = e.take_events();
    assert_eq!(ev[0], TermEvent::Bell);
    assert_eq!(ev[1], TermEvent::Title(Some("t".into())));
    e.feed(b"\x1b]7;file://host/tmp/a%20b\x07\x1b[3;5H\x1b]133;A\x07$ \x1b]133;D;1\x1b\\");
    let ev = e.take_events();
    assert_eq!(
        ev[0],
        TermEvent::Cwd {
            host: Some("host".into()),
            path: "/tmp/a b".into()
        }
    );
    assert!(matches!(
        ev[1],
        TermEvent::PromptMark {
            kind: PromptMarkKind::PromptStart,
            cursor: GridPoint { line: 2, column: 4 },
            ..
        }
    ));
    assert!(matches!(
        ev[2],
        TermEvent::PromptMark {
            kind: PromptMarkKind::CommandFinished { exit_code: Some(1) },
            cursor: GridPoint { line: 2, column: 6 },
            ..
        }
    ));
}

#[test]
fn hyperlink_lookup() {
    let mut e = emu(80, 24);
    e.feed(b"\x1b]8;id=a;https://example.com\x1b\\link\x1b]8;;\x1b\\ plain");
    let link = e.hyperlink_at(GridPoint::new(0, 1)).unwrap();
    assert_eq!(link.uri, "https://example.com");
    assert!(e.hyperlink_at(GridPoint::new(0, 6)).is_none());
}

#[test]
fn boxed_trait_object() {
    let mut e: Box<dyn Emulator> = Box::new(emu(80, 24));
    e.feed(b"hi\x1b[c");
    assert_eq!(e.take_responses().len(), 1);
    assert!(!e.snapshot_vt().is_empty());
}

#[test]
fn hostile_osc_indices_do_not_panic() {
    let mut e = emu(80, 24);
    e.feed(
        b"\x1b]4;255;?\x07\x1b]4;999;?\x07\x1b]4;300;rgb:00/00/00\x07\x1b]12;?\x07\x1b]104;999\x07",
    );
    let r = String::from_utf8(joined(&e.take_responses())).unwrap();
    assert!(r.contains("\x1b]4;255;rgb:eeee/eeee/eeee\x07"), "{r:?}");
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    /// T-18 (in-CI companion of the fuzz target): arbitrary bytes never panic, and nothing
    /// fed in ever produces a clipboard read reply.
    #[test]
    fn arbitrary_bytes_never_panic(chunks in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..256), 0..8),
                                   cols in 1u16..200, rows in 1u16..60) {
        let mut e = AlacrittyEmulator::new(EmulatorConfig { cols, rows, scrollback: 50 });
        for c in &chunks {
            e.feed(c);
            e.resize(cols.saturating_add(1), rows);
        }
        let _ = e.snapshot_vt();
        let _ = e.modes();
        let _ = e.take_events();
        for r in e.take_responses() {
            prop_assert!(!r.starts_with(b"\x1b]52"));
        }
    }

    /// Escape-heavy input: random sequences built from sequence fragments.
    #[test]
    fn escape_soup_never_panics(parts in proptest::collection::vec(prop_oneof![
        Just(&b"\x1b["[..]), Just(&b"\x1b]"[..]), Just(&b"\x1bP"[..]), Just(&b"\x07"[..]),
        Just(&b"\x1b\\"[..]), Just(&b";"[..]), Just(&b"?"[..]), Just(&b">"[..]), Just(&b"999999"[..]),
        Just(&b"1049h"[..]), Just(&b"4"[..]), Just(&b"52;c;?"[..]), Just(&b"m"[..]), Just(&b"r"[..]),
        Just(&b"H"[..]), Just("中".as_bytes()), Just(&b"\r\n"[..]), Just(&b"\x1bc"[..]), Just(&b"\x1b[?2026h"[..]),
    ], 0..200)) {
        let mut e = emu(20, 5);
        let bytes: Vec<u8> = parts.concat();
        e.feed(&bytes);
        let mut b = emu(20, 5);
        b.feed(&e.snapshot_vt());
        let _ = e.take_responses();
    }
}
