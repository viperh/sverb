//! The styled renderer.
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::fmt::Write as _;

use ratatui_core::buffer::Buffer;
use ratatui_core::layout::{Position, Rect};
use ratatui_core::style::{Color, Modifier};
use sverb_term::render::cursor_position;
use sverb_term::{
    AlacrittyEmulator, ColorDepth, Emulator, EmulatorConfig, GridPoint, Match, Selection,
    ViewState, scheme,
};

fn emu(cols: u16, rows: u16, bytes: &[u8]) -> AlacrittyEmulator {
    let mut e = AlacrittyEmulator::new(EmulatorConfig {
        cols,
        rows,
        scrollback: 1000,
    });
    e.feed(bytes);
    e.flush_sync();
    e
}

fn draw(e: &AlacrittyEmulator, view: &ViewState) -> Buffer {
    let (cols, rows) = e.size();
    let area = Rect::new(0, 0, cols, rows);
    let mut buf = Buffer::empty(area);
    e.render(area, &mut buf, view);
    buf
}

fn cell(buf: &Buffer, x: u16, y: u16) -> &ratatui_core::buffer::Cell {
    buf.cell(Position::new(x, y)).unwrap()
}

/// Buffer → text plus one line per run of identically styled cells (non-default only).
fn styled_text(buf: &Buffer) -> String {
    let mut out = String::new();
    let area = buf.area;
    for y in 0..area.height {
        out.push('|');
        for x in 0..area.width {
            out.push_str(cell(buf, x, y).symbol());
        }
        out.push_str("|\n");
    }
    for y in 0..area.height {
        let mut x = 0;
        while x < area.width {
            let c = cell(buf, x, y);
            let key = (c.fg, c.bg, c.modifier);
            let start = x;
            while x < area.width {
                let d = cell(buf, x, y);
                if (d.fg, d.bg, d.modifier) != key {
                    break;
                }
                x += 1;
            }
            if key != (Color::Reset, Color::Reset, Modifier::empty()) {
                let _ = writeln!(
                    out,
                    "{y}:{start}..{} fg={:?} bg={:?} mod={:?}",
                    x - 1,
                    key.0,
                    key.1,
                    key.2
                );
            }
        }
    }
    out
}

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/streams/{name}.bin", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

#[test]
fn snapshots() {
    for name in ["vim", "htop", "less_man"] {
        let e = emu(80, 24, &fixture(name));
        let view = ViewState {
            focused: true,
            ..ViewState::default()
        };
        insta::assert_snapshot!(name, styled_text(&draw(&e, &view)));
    }
}

// Every SGR attribute.
#[test]
fn modifiers() {
    let cases: [(&str, Modifier); 9] = [
        ("1", Modifier::BOLD),
        ("2", Modifier::DIM),
        ("3", Modifier::ITALIC),
        ("4", Modifier::UNDERLINED),
        ("4:3", Modifier::UNDERLINED),
        ("4:4", Modifier::UNDERLINED),
        ("7", Modifier::REVERSED),
        ("8", Modifier::HIDDEN),
        ("9", Modifier::CROSSED_OUT),
    ];
    for (sgr, m) in cases {
        let e = emu(10, 2, format!("\x1b[{sgr}mX").as_bytes());
        let buf = draw(&e, &ViewState::default());
        assert_eq!(cell(&buf, 0, 0).symbol(), "X");
        assert_eq!(cell(&buf, 0, 0).modifier, m, "SGR {sgr}");
    }
    let e = emu(10, 2, b"\x1b[1;3;4;9mX");
    assert_eq!(
        cell(&draw(&e, &ViewState::default()), 0, 0).modifier,
        Modifier::BOLD | Modifier::ITALIC | Modifier::UNDERLINED | Modifier::CROSSED_OUT
    );
}

// Wide chars.
#[test]
fn wide_chars() {
    let e = emu(10, 2, "a中b".as_bytes());
    let buf = draw(&e, &ViewState::default());
    assert_eq!(cell(&buf, 0, 0).symbol(), "a");
    assert_eq!(cell(&buf, 1, 0).symbol(), "中");
    assert_eq!(cell(&buf, 2, 0).symbol(), " ", "spacer is reset");
    assert_eq!(cell(&buf, 3, 0).symbol(), "b");
}

// Combining characters stay in one cell.
#[test]
fn combining() {
    let e = emu(10, 2, "e\u{301}x".as_bytes());
    let buf = draw(&e, &ViewState::default());
    assert_eq!(cell(&buf, 0, 0).symbol(), "e\u{301}");
    assert_eq!(cell(&buf, 1, 0).symbol(), "x");
}

// The `terminal` scheme passes named colors through.
#[test]
fn terminal_scheme() {
    let e = emu(
        10,
        2,
        b"\x1b[31mR\x1b[0mD\x1b[38;2;255;0;0mT\x1b[48;5;100mI",
    );
    let view = ViewState::default();
    let buf = draw(&e, &view);
    assert_eq!(cell(&buf, 0, 0).fg, Color::Indexed(1));
    assert_eq!(cell(&buf, 1, 0).fg, Color::Reset);
    assert_eq!(cell(&buf, 1, 0).bg, Color::Reset);
    assert_eq!(cell(&buf, 2, 0).fg, Color::Rgb(255, 0, 0));
    assert_eq!(cell(&buf, 3, 0).bg, Color::Indexed(100));
    let buf = draw(
        &e,
        &ViewState {
            depth: ColorDepth::Indexed256,
            ..ViewState::default()
        },
    );
    assert_eq!(cell(&buf, 0, 0).fg, Color::Indexed(1));
    assert_eq!(cell(&buf, 2, 0).fg, Color::Indexed(196));
    let buf = draw(
        &e,
        &ViewState {
            depth: ColorDepth::Ansi16,
            ..ViewState::default()
        },
    );
    assert_eq!(cell(&buf, 2, 0).fg, Color::Indexed(9));
    assert!(matches!(cell(&buf, 3, 0).bg, Color::Indexed(0..=15)));
}

// A named scheme remaps.
#[test]
fn named_scheme() {
    let dracula = scheme::builtin("dracula").unwrap();
    let e = emu(10, 2, b"\x1b[31mR\x1b[0mD");
    let view = ViewState {
        scheme: Some(dracula.clone()),
        ..ViewState::default()
    };
    let buf = draw(&e, &view);
    assert_eq!(cell(&buf, 0, 0).fg, Color::Rgb(0xff, 0x55, 0x55));
    assert_eq!(cell(&buf, 1, 0).fg, Color::Rgb(0xf8, 0xf8, 0xf2));
    assert_eq!(cell(&buf, 1, 0).bg, Color::Rgb(0x28, 0x2a, 0x36));
    let view = ViewState {
        scheme: Some(dracula),
        depth: ColorDepth::Indexed256,
        ..ViewState::default()
    };
    let buf = draw(&e, &view);
    let expected = sverb_term::color::rgb_to_ansi256(0xff, 0x55, 0x55);
    assert_eq!(cell(&buf, 0, 0).fg, Color::Indexed(expected));
}

// OSC 4 overrides from the remote win over the scheme.
#[test]
fn remote_palette_override() {
    let e = emu(10, 2, b"\x1b]4;1;rgb:12/34/56\x07\x1b[31mR");
    let buf = draw(
        &e,
        &ViewState {
            scheme: scheme::builtin("nord"),
            ..ViewState::default()
        },
    );
    assert_eq!(cell(&buf, 0, 0).fg, Color::Rgb(0x12, 0x34, 0x56));
}

// Mono (NO_COLOR) keeps attributes only.
#[test]
fn mono() {
    let e = emu(10, 2, b"\x1b[1;31;44mB\x1b[0;7;38;2;1;2;3mI");
    let view = ViewState {
        scheme: scheme::builtin("dracula"),
        depth: ColorDepth::Mono,
        ..ViewState::default()
    };
    let buf = draw(&e, &view);
    for x in 0..10 {
        for y in 0..2 {
            assert_eq!(cell(&buf, x, y).fg, Color::Reset);
            assert_eq!(cell(&buf, x, y).bg, Color::Reset);
        }
    }
    assert_eq!(cell(&buf, 0, 0).modifier, Modifier::BOLD);
    assert_eq!(cell(&buf, 1, 0).modifier, Modifier::REVERSED);
}

// Focused → real cursor; unfocused → hollow cell; scrolled back → none.
#[test]
fn cursor() {
    let e = emu(10, 3, b"ab");
    let area = Rect::new(5, 1, 10, 3);
    let focused = ViewState {
        focused: true,
        ..ViewState::default()
    };
    let cur = e.cursor();
    assert_eq!(
        cursor_position(&cur, area, &focused),
        Some(Position::new(7, 1))
    );
    let buf = draw(&e, &focused);
    assert_eq!(
        cell(&buf, 2, 0).modifier,
        Modifier::empty(),
        "no hollow cell"
    );

    let unfocused = ViewState::default();
    let buf = draw(&e, &unfocused);
    assert_eq!(
        cell(&buf, 2, 0).modifier,
        Modifier::UNDERLINED | Modifier::DIM
    );
    // The caller never places the real cursor for an unfocused pane (the widget only asks
    // when focused), but the position itself stays well-defined.

    // Hidden cursor (DECTCEM off): nothing.
    let hidden = emu(10, 3, b"ab\x1b[?25l");
    assert_eq!(cursor_position(&hidden.cursor(), area, &focused), None);
    let buf = draw(&hidden, &unfocused);
    assert_eq!(cell(&buf, 2, 0).modifier, Modifier::empty());

    // Scrolled back: no cursor of either kind.
    let mut lines = Vec::new();
    for i in 0..10 {
        lines.extend_from_slice(format!("line {i}\r\n").as_bytes());
    }
    let e = emu(10, 3, &lines);
    let scrolled = ViewState {
        scroll_offset: 2,
        ..ViewState::default()
    };
    assert_eq!(cursor_position(&e.cursor(), area, &scrolled), None);
    let buf = draw(&e, &scrolled);
    for y in 0..3 {
        for x in 0..10 {
            assert!(!cell(&buf, x, y).modifier.contains(Modifier::DIM));
        }
    }
}

// The scroll indicator.
#[test]
fn scroll_indicator() {
    let mut lines = Vec::new();
    for i in 0..30 {
        lines.extend_from_slice(format!("line {i}\r\n").as_bytes());
    }
    let e = emu(30, 5, &lines);
    let live = draw(&e, &ViewState::default());
    let top: String = (0..30)
        .map(|x| cell(&live, x, 0).symbol().to_owned())
        .collect();
    assert!(!top.contains("[scroll"), "{top}");

    let view = ViewState {
        scroll_offset: 3,
        ..ViewState::default()
    };
    let buf = draw(&e, &view);
    let top: String = (0..30)
        .map(|x| cell(&buf, x, 0).symbol().to_owned())
        .collect();
    let history = e.scrollback_len();
    let label = format!("[scroll: 3/{history}]");
    assert!(top.ends_with(&label), "{top:?}");
    assert!(top.starts_with("line"), "{top:?}");
    assert_eq!(cell(&buf, 29, 0).modifier, Modifier::REVERSED);
    // Scrolled content: the second row shows the line two above the live top row.
    let row1: String = (0..7)
        .map(|x| cell(&buf, x, 1).symbol().to_owned())
        .collect();
    let live_row0: String = (0..7)
        .map(|x| cell(&live, x, 0).symbol().to_owned())
        .collect();
    assert_ne!(row1, live_row0);
}

#[test]
fn overlays() {
    let e = emu(10, 3, b"hello\r\nworld");
    let view = ViewState {
        focused: true,
        selection: Some(Selection {
            start: GridPoint::new(0, 3),
            end: GridPoint::new(1, 1),
            block: false,
        }),
        search_matches: vec![Match {
            start: GridPoint::new(0, 0),
            end: GridPoint::new(0, 1),
        }],
        current_match: Some(Match {
            start: GridPoint::new(1, 3),
            end: GridPoint::new(1, 4),
        }),
        hovered_link: Some(Match {
            start: GridPoint::new(2, 0),
            end: GridPoint::new(2, 2),
        }),
        ..ViewState::default()
    };
    let buf = draw(&e, &view);
    // Selection: (0,3)..=(1,1) streams to the end of row 0.
    for (x, y) in [(3, 0), (4, 0), (9, 0), (0, 1), (1, 1)] {
        assert!(
            cell(&buf, x, y).modifier.contains(Modifier::REVERSED),
            "{x},{y}"
        );
    }
    assert!(!cell(&buf, 2, 0).modifier.contains(Modifier::REVERSED));
    assert!(!cell(&buf, 2, 1).modifier.contains(Modifier::REVERSED));
    assert_eq!(cell(&buf, 0, 0).bg, view.overlay.match_bg);
    assert_eq!(cell(&buf, 3, 1).bg, view.overlay.current_match_bg);
    assert!(cell(&buf, 1, 2).modifier.contains(Modifier::UNDERLINED));
    assert_eq!(cell(&buf, 1, 2).fg, view.overlay.link_fg);
}

#[test]
fn larger_area_and_offset() {
    let e = emu(4, 2, b"\x1b[44mab");
    let area = Rect::new(2, 1, 6, 3);
    let mut buf = Buffer::empty(Rect::new(0, 0, 10, 5));
    buf.cell_mut((7, 3)).unwrap().set_char('#');
    e.render(area, &mut buf, &ViewState::default());
    assert_eq!(cell(&buf, 2, 1).symbol(), "a");
    assert_eq!(cell(&buf, 2, 1).bg, Color::Indexed(4));
    // Outside the grid but inside the area: blanked.
    assert_eq!(cell(&buf, 7, 3).symbol(), " ");
    // Outside the area: untouched.
    assert_eq!(cell(&buf, 0, 0).symbol(), " ");
}
