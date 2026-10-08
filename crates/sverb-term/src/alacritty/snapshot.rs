//! `snapshot_vt` (SPEC §14.2): a VT byte stream that recreates the visible screen, the cursor and
//! the active modes when fed to a fresh emulator of the same size.
//!
//! Not reproduced (documented in `docs/emulator.md`): scrollback, the primary screen while the
//! alternate screen is active, the scroll region (DECSTBM), tab stops, the saved cursor (DECSC),
//! G0–G3 charset designations and the title stack.

use std::fmt::Write as _;

use alacritty_terminal::Term;
use alacritty_terminal::grid::Dimensions;
use alacritty_terminal::index::{Column, Line};
use alacritty_terminal::term::TermMode;
use alacritty_terminal::term::cell::{Cell, Flags, Hyperlink};
use alacritty_terminal::term::color::COUNT as COLOR_COUNT;
use alacritty_terminal::vte::ansi::{Color, CursorShape as AlacShape, NamedColor};

/// State alacritty doesn't track but the emulator does (from the side scanner).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SnapshotExtras {
    pub(crate) modify_other_keys: u8,
    pub(crate) urxvt_mouse: bool,
}

/// Flags that are rendering attributes (as opposed to layout flags like WRAPLINE).
const STYLE_FLAGS: Flags = Flags::BOLD
    .union(Flags::DIM)
    .union(Flags::ITALIC)
    .union(Flags::ALL_UNDERLINES)
    .union(Flags::INVERSE)
    .union(Flags::HIDDEN)
    .union(Flags::STRIKEOUT);

/// The "pen": everything SGR / OSC 8 sets.
#[derive(Debug, Clone, PartialEq)]
struct Pen {
    fg: Color,
    bg: Color,
    flags: Flags,
    underline: Option<Color>,
    link: Option<Hyperlink>,
}

impl Pen {
    fn of(cell: &Cell) -> Self {
        Self {
            fg: cell.fg,
            bg: cell.bg,
            flags: cell.flags & STYLE_FLAGS,
            underline: cell.underline_color(),
            link: cell.hyperlink(),
        }
    }

    fn default_pen() -> Self {
        Self::of(&Cell::default())
    }
}

fn is_blank(cell: &Cell) -> bool {
    cell.c == ' '
        && cell.fg == Color::Named(NamedColor::Foreground)
        && cell.bg == Color::Named(NamedColor::Background)
        && cell.flags.is_empty()
        && cell.extra.is_none()
}

struct Writer {
    out: String,
    pen: Pen,
}

impl Writer {
    fn set_pen(&mut self, pen: &Pen) {
        if pen.link != self.pen.link {
            match &pen.link {
                Some(link) => {
                    let _ = write!(self.out, "\x1b]8;id={};{}\x1b\\", link.id(), link.uri());
                }
                None => self.out.push_str("\x1b]8;;\x1b\\"),
            }
        }
        if pen.fg != self.pen.fg
            || pen.bg != self.pen.bg
            || pen.flags != self.pen.flags
            || pen.underline != self.pen.underline
        {
            self.out.push_str("\x1b[0");
            let f = pen.flags;
            for (flag, code) in [
                (Flags::BOLD, "1"),
                (Flags::DIM, "2"),
                (Flags::ITALIC, "3"),
                (Flags::UNDERLINE, "4"),
                (Flags::DOUBLE_UNDERLINE, "4:2"),
                (Flags::UNDERCURL, "4:3"),
                (Flags::DOTTED_UNDERLINE, "4:4"),
                (Flags::DASHED_UNDERLINE, "4:5"),
                (Flags::INVERSE, "7"),
                (Flags::HIDDEN, "8"),
                (Flags::STRIKEOUT, "9"),
            ] {
                if f.contains(flag) {
                    self.out.push(';');
                    self.out.push_str(code);
                }
            }
            push_color(&mut self.out, pen.fg, 30, 90, "38");
            push_color(&mut self.out, pen.bg, 40, 100, "48");
            if let Some(ul) = pen.underline {
                push_color(&mut self.out, ul, 0, 0, "58");
            }
            self.out.push('m');
        }
        self.pen = pen.clone();
    }

    fn write_cell(&mut self, cell: &Cell) {
        self.set_pen(&Pen::of(cell));
        self.out.push(cell.c);
        for c in cell.zerowidth().into_iter().flatten() {
            self.out.push(*c);
        }
    }
}

/// Append `;<sgr>` for a color. `base`/`bright_base` are the 8-color SGR bases (0 = always use
/// the extended form, as for underline colors).
fn push_color(out: &mut String, color: Color, base: u8, bright_base: u8, ext: &str) {
    match color {
        Color::Named(named) => {
            let n = named as usize;
            if n < 16 {
                if base == 0 {
                    let _ = write!(out, ";{ext};5;{n}");
                } else if n < 8 {
                    let _ = write!(out, ";{}", usize::from(base) + n);
                } else {
                    let _ = write!(out, ";{}", usize::from(bright_base) + n - 8);
                }
            }
            // Foreground/Background/other named defaults: already reset by `0`.
        }
        Color::Indexed(i) => {
            let _ = write!(out, ";{ext};5;{i}");
        }
        Color::Spec(rgb) => {
            let _ = write!(out, ";{ext};2;{};{};{}", rgb.r, rgb.g, rgb.b);
        }
    }
}

pub(crate) fn snapshot_vt<T>(term: &Term<T>, extras: SnapshotExtras) -> Vec<u8> {
    let grid = term.grid();
    let mode = *term.mode();
    let cols = grid.columns();
    let rows = grid.screen_lines();
    let mut w = Writer {
        out: String::with_capacity(cols * rows * 2 + 256),
        pen: Pen::default_pen(),
    };

    // Full reset, palette reset, then the right screen.
    w.out
        .push_str("\x1bc\x1b]104\x1b\\\x1b]110\x1b\\\x1b]111\x1b\\\x1b]112\x1b\\");
    if mode.contains(TermMode::ALT_SCREEN) {
        w.out.push_str("\x1b[?1049h");
    }
    w.out.push_str("\x1b[0m\x1b[H\x1b[2J");

    // Palette overrides set by the remote (OSC 4/10/11/12).
    let colors = term.colors();
    for i in 0..COLOR_COUNT.min(259) {
        if let Some(c) = colors[i] {
            let rgb = format!("rgb:{:02x}/{:02x}/{:02x}", c.r, c.g, c.b);
            let _ = match i {
                0..=255 => write!(w.out, "\x1b]4;{i};{rgb}\x1b\\"),
                _ => write!(w.out, "\x1b]{};{rgb}\x1b\\", i - 256 + 10),
            };
        }
    }

    // Grid rows.
    let mut prev_wrapped = false;
    for line in 0..rows {
        let row = &grid[Line(line as i32)];
        let wraps = row[Column(cols - 1)].flags.contains(Flags::WRAPLINE);
        let mut end = if wraps {
            cols
        } else {
            (0..cols)
                .rev()
                .find(|&c| !is_blank(&row[Column(c)]))
                .map_or(0, |c| c + 1)
        };
        if prev_wrapped && end == 0 {
            end = 1;
        }
        if end > 0 && !prev_wrapped {
            let _ = write!(w.out, "\x1b[{};1H", line + 1);
        }
        for c in 0..end {
            let cell = &row[Column(c)];
            if cell
                .flags
                .intersects(Flags::WIDE_CHAR_SPACER | Flags::LEADING_WIDE_CHAR_SPACER)
            {
                continue;
            }
            w.write_cell(cell);
        }
        prev_wrapped = wraps && end > 0;
    }

    // Modes.
    let set = |out: &mut String, on: bool, seq: &str| {
        if on {
            out.push_str(seq);
        }
    };
    let o = &mut w.out;
    set(o, mode.contains(TermMode::APP_CURSOR), "\x1b[?1h");
    set(o, mode.contains(TermMode::APP_KEYPAD), "\x1b=");
    set(
        o,
        mode.contains(TermMode::MOUSE_REPORT_CLICK),
        "\x1b[?1000h",
    );
    set(o, mode.contains(TermMode::MOUSE_DRAG), "\x1b[?1002h");
    set(o, mode.contains(TermMode::MOUSE_MOTION), "\x1b[?1003h");
    set(o, mode.contains(TermMode::UTF8_MOUSE), "\x1b[?1005h");
    set(o, mode.contains(TermMode::SGR_MOUSE), "\x1b[?1006h");
    set(o, extras.urxvt_mouse, "\x1b[?1015h");
    set(o, mode.contains(TermMode::FOCUS_IN_OUT), "\x1b[?1004h");
    set(o, mode.contains(TermMode::BRACKETED_PASTE), "\x1b[?2004h");
    set(o, !mode.contains(TermMode::ALTERNATE_SCROLL), "\x1b[?1007l");
    set(o, !mode.contains(TermMode::URGENCY_HINTS), "\x1b[?1042l");
    set(o, mode.contains(TermMode::INSERT), "\x1b[4h");
    set(o, mode.contains(TermMode::LINE_FEED_NEW_LINE), "\x1b[20h");
    set(o, !mode.contains(TermMode::SHOW_CURSOR), "\x1b[?25l");
    set(o, mode.contains(TermMode::ORIGIN), "\x1b[?6h");
    let kitty = kitty_bits(mode);
    if kitty != 0 {
        let _ = write!(o, "\x1b[>{kitty}u");
    }
    if extras.modify_other_keys != 0 {
        let _ = write!(o, "\x1b[>4;{}m", extras.modify_other_keys);
    }
    let style = term.cursor_style();
    let shape = match style.shape {
        AlacShape::Underline => Some(3),
        AlacShape::Beam => Some(5),
        AlacShape::Block => Some(1),
        AlacShape::HollowBlock | AlacShape::Hidden => None,
    };
    if let Some(base) = shape {
        let n = if style.blinking { base } else { base + 1 };
        let _ = write!(o, "\x1b[{n} q");
    }

    // Cursor position, including the pending-wrap state, then the pen.
    let cursor = &grid.cursor;
    let point = cursor.point;
    if cursor.input_needs_wrap {
        let mut col = point.column;
        let row = &grid[point.line];
        if row[col].flags.contains(Flags::WIDE_CHAR_SPACER) && col.0 > 0 {
            col -= 1;
        }
        let _ = write!(w.out, "\x1b[{};{}H", point.line.0 + 1, col.0 + 1);
        // Rewriting the same cell (autowrap is still on here) re-arms the pending wrap.
        w.write_cell(&row[col]);
    } else {
        let _ = write!(w.out, "\x1b[{};{}H", point.line.0 + 1, point.column.0 + 1);
    }
    // Autowrap last: disabling it earlier would change how the rows above were written.
    if !mode.contains(TermMode::LINE_WRAP) {
        w.out.push_str("\x1b[?7l");
    }
    let template = Pen::of(&cursor.template);
    w.set_pen(&template);

    w.out.into_bytes()
}

pub(crate) fn kitty_bits(mode: TermMode) -> u8 {
    let mut bits = 0;
    for (flag, bit) in [
        (TermMode::DISAMBIGUATE_ESC_CODES, 1),
        (TermMode::REPORT_EVENT_TYPES, 2),
        (TermMode::REPORT_ALTERNATE_KEYS, 4),
        (TermMode::REPORT_ALL_KEYS_AS_ESC, 8),
        (TermMode::REPORT_ASSOCIATED_TEXT, 16),
    ] {
        if mode.contains(flag) {
            bits |= bit;
        }
    }
    bits
}
