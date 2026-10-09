//! Regression: control characters in the grid must never reach a rendered cell.
//!
//! alacritty keeps a literal `\t` in the cell where a tab starts (so copied text keeps
//! its tabs). The renderer used to copy it into the ratatui buffer, which crashed sverb
//! in ratatui's `cell_width` debug assertion ("control character passed to cell_width
//! without filtering") on the first frame flush after any tab in remote output, and
//! would write a raw control byte to the outer terminal in release builds.
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use ratatui_core::buffer::Buffer;
use ratatui_core::layout::Rect;
use sverb_term::render::display_char;
use sverb_term::{AlacrittyEmulator, Emulator, EmulatorConfig, ViewState};

fn emu(cols: u16, rows: u16, bytes: &[u8]) -> AlacrittyEmulator {
    let mut e = AlacrittyEmulator::new(EmulatorConfig {
        cols,
        rows,
        scrollback: 100,
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

/// Every cell whose symbol contains a control character, as `(x, y, symbol)`.
fn control_cells(buf: &Buffer) -> Vec<(u16, u16, String)> {
    let area = buf.area;
    let mut out = Vec::new();
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            let s = buf[(x, y)].symbol();
            if s.chars().any(char::is_control) {
                out.push((x, y, s.to_owned()));
            }
        }
    }
    out
}

/// Draw, check no cell holds a control character, then run ratatui's diff (the code path
/// that panicked in the crash) against an empty and a different previous frame.
fn assert_renders_clean(e: &AlacrittyEmulator, view: &ViewState) -> Buffer {
    let buf = draw(e, view);
    assert_eq!(
        control_cells(&buf),
        Vec::new(),
        "control characters in rendered cells"
    );
    let blank = Buffer::empty(buf.area);
    let _ = blank.diff(&buf).len();
    let _ = buf.diff(&blank).len();
    buf
}

fn row_text(buf: &Buffer, y: u16) -> String {
    (buf.area.left()..buf.area.right())
        .map(|x| buf[(x, y)].symbol().to_owned())
        .collect()
}

/// The crash: a single tab in remote output.
#[test]
fn tab_renders_as_blank() {
    let e = emu(20, 3, b"ab\tcd");
    let buf = assert_renders_clean(&e, &ViewState::default());
    // The tab advances to column 8; the cells it skips are blank.
    assert_eq!(row_text(&buf, 0).trim_end(), "ab      cd");
}

/// Typical tab-separated output (`ls`, `make`, man pages) over several lines.
#[test]
fn tab_separated_columns() {
    let e = emu(40, 4, b"a\tb\tc\r\nlong-name\tx\r\n\t\tindented\r\n");
    let buf = assert_renders_clean(&e, &ViewState::default());
    assert_eq!(row_text(&buf, 0).trim_end(), "a       b       c");
    assert_eq!(row_text(&buf, 1).trim_end(), "long-name       x");
    assert_eq!(row_text(&buf, 2).trim_end(), "                indented");
}

/// A tab at the right margin, and tabs scrolled into scrollback and viewed there.
#[test]
fn tab_at_margin_and_in_scrollback() {
    let mut bytes = b"0123456789\t".to_vec();
    for i in 0..20 {
        bytes.extend_from_slice(format!("line{i}\tcol\r\n").as_bytes());
    }
    let e = emu(12, 4, &bytes);
    assert_renders_clean(&e, &ViewState::default());
    let scrolled = ViewState {
        scroll_offset: 10,
        ..ViewState::default()
    };
    assert_renders_clean(&e, &scrolled);
}

/// The tab is drawn as a blank but stays in the grid, so selection and copy keep it.
#[test]
fn grid_still_holds_the_tab_for_copy() {
    let e = emu(20, 3, b"ab\tcd");
    let row = e.row(0).expect("row 0");
    assert_eq!(row.cells[2].c, '\t', "the grid keeps the tab character");
    assert_renders_clean(&e, &ViewState::default());
}

/// Every C0 control, DEL and a C1 control (in UTF-8) mixed into text, also after
/// switching to the DEC line-drawing charset and inside the alternate screen.
#[test]
fn every_control_byte_renders_clean() {
    let prefixes: [&[u8]; 4] = [b"", b"\x1b(0", b"\x1b[?1049h", b"\x1b[4h"];
    for prefix in prefixes {
        for b in (0u8..0x20).chain([0x7f]) {
            let mut bytes = prefix.to_vec();
            bytes.extend_from_slice(b"ab");
            bytes.push(b);
            bytes.extend_from_slice(b"cd\xc2\x9bef");
            let e = emu(20, 4, &bytes);
            let buf = draw(&e, &ViewState::default());
            assert_eq!(
                control_cells(&buf),
                Vec::new(),
                "prefix {prefix:?} byte {b:#04x}"
            );
            let _ = Buffer::empty(buf.area).diff(&buf).len();
        }
    }
}

/// Pseudo-random output heavy in control bytes and escapes never leaves a control
/// character in a rendered cell (a deterministic mini-fuzz; the cargo-fuzz target
/// `emulator_feed` now diffs every frame too).
#[test]
fn random_streams_render_clean() {
    let mut seed: u64 = 0x5eed_7ab5;
    for _ in 0..500 {
        let mut bytes = Vec::with_capacity(256);
        for _ in 0..256 {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let v = (seed >> 33) as u8;
            bytes.push(match v % 5 {
                0 => b'\t',
                1 => 0x1b,
                2 => v % 0x20,
                _ => v,
            });
        }
        let e = emu(30, 8, &bytes);
        let buf = draw(&e, &ViewState::default());
        assert_eq!(control_cells(&buf), Vec::new(), "input {bytes:?}");
        let _ = Buffer::empty(buf.area).diff(&buf).len();
    }
}

#[test]
fn display_char_maps_only_controls() {
    for c in ['\0', '\t', '\n', '\r', '\x1b', '\x7f', '\u{80}', '\u{9b}'] {
        assert_eq!(display_char(c), ' ', "{c:?}");
    }
    for c in ['a', ' ', '~', 'é', '─', '漢', '\u{2800}'] {
        assert_eq!(display_char(c), c, "{c:?}");
    }
}
