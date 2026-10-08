//! The styled renderer behind [`Emulator::render`](crate::Emulator::render) (M1-10, SPEC §7.2).
//!
//! Walks the visible rows of the alacritty grid at the view's scroll offset and writes every
//! cell straight into the ratatui [`Buffer`] (no per-cell allocation: symbols are set with
//! `set_char`, combining sequences reuse one `String`, colors come from a per-frame palette
//! cache).
//!
//! - **Attributes**: BOLD, DIM, ITALIC, every underline style → UNDERLINED, INVERSE →
//!   REVERSED, HIDDEN, STRIKEOUT → CROSSED_OUT.
//! - **Wide chars**: the char goes into the first cell; the spacer cell is `reset()` (ratatui's
//!   own convention for cells hidden by a wide grapheme).
//! - **Combining chars** are appended to the cell's symbol.
//! - **Colors** ([`Palette`]): with the `terminal` scheme (`view.scheme == None`) named and
//!   indexed colors stay `Indexed(n)` and the defaults stay `Reset`, so the outer terminal's own
//!   palette is used; only RGB is downsampled. With a named scheme every color is resolved to RGB
//!   through the scheme and then downsampled to the color depth. Colors the remote set with
//!   OSC 4/10/11/12 win over the scheme. `Mono` → `Reset`, modifiers kept.
//! - **Hollow cursor** (unfocused panes, live view only): the cursor cell gets `UNDERLINED |
//!   DIM`, or `REVERSED | DIM` when the cell is already underlined. The focused pane's cursor
//!   is the real terminal cursor, placed by the caller ([`cursor_position`]).
//! - **Overlays** (after the cells): selection toggles REVERSED, search matches get the
//!   `match_bg` background, the current match `current_match_bg`, a hovered link is
//!   underlined in `link_fg`. In `Mono` the colors become modifiers (matches UNDERLINED, the
//!   current match REVERSED).
//! - **Scrolled back**: `[scroll: N/M]` in the top-right corner (REVERSED).

use alacritty_terminal::Term;
use alacritty_terminal::event::EventListener;
use alacritty_terminal::grid::Dimensions;
use alacritty_terminal::index::{Column, Line};
use alacritty_terminal::term::cell::Flags;
use alacritty_terminal::term::color::Colors;
use alacritty_terminal::vte::ansi::{Color as AnsiColor, NamedColor, Rgb as AlacRgb};
use ratatui_core::buffer::{Buffer, Cell, CellDiffOption};
use ratatui_core::layout::{Position, Rect};
use ratatui_core::style::{Color, Modifier};

use crate::color::{ColorDepth, downsample};
use crate::emulator::{CursorInfo, GridPoint, Match, ViewState};
use crate::scheme::ColorScheme;

/// Palette slots: 0–255, then the default foreground, background and cursor.
const FG: usize = 256;
const BG: usize = 257;
const CURSOR: usize = 258;
const SLOTS: usize = 259;
/// Size of the direct-mapped RGB → color cache (a power of two).
const RGB_CACHE: usize = 64;

/// Resolves alacritty colors for one frame.
struct Palette<'a> {
    scheme: Option<&'a ColorScheme>,
    depth: ColorDepth,
    overrides: &'a Colors,
    slots: [Option<Color>; SLOTS],
    rgb: [Option<(AlacRgb, Color)>; RGB_CACHE],
}

impl<'a> Palette<'a> {
    fn new(view: &'a ViewState, overrides: &'a Colors) -> Self {
        Self {
            scheme: view.scheme.as_deref(),
            depth: view.depth,
            overrides,
            slots: [None; SLOTS],
            rgb: [None; RGB_CACHE],
        }
    }

    fn resolve(&mut self, color: AnsiColor) -> Color {
        if self.depth == ColorDepth::Mono {
            return Color::Reset;
        }
        match color {
            AnsiColor::Spec(rgb) => self.spec(rgb),
            AnsiColor::Indexed(i) => self.slot(usize::from(i)),
            AnsiColor::Named(n) => self.slot(named_slot(n)),
        }
    }

    fn spec(&mut self, rgb: AlacRgb) -> Color {
        if self.depth == ColorDepth::TrueColor {
            return Color::Rgb(rgb.r, rgb.g, rgb.b);
        }
        let key = (usize::from(rgb.r) * 7 + usize::from(rgb.g) * 13 + usize::from(rgb.b) * 31)
            & (RGB_CACHE - 1);
        match self.rgb[key] {
            Some((k, c)) if k == rgb => c,
            _ => {
                let c = downsample(Color::Rgb(rgb.r, rgb.g, rgb.b), self.depth);
                self.rgb[key] = Some((rgb, c));
                c
            }
        }
    }

    fn slot(&mut self, slot: usize) -> Color {
        if let Some(c) = self.slots[slot] {
            return c;
        }
        let c = self.compute(slot);
        self.slots[slot] = Some(c);
        c
    }

    fn compute(&self, slot: usize) -> Color {
        // A color the remote set (OSC 4/10/11/12) wins over the scheme.
        if let Some(rgb) = self.overrides[slot] {
            return downsample(Color::Rgb(rgb.r, rgb.g, rgb.b), self.depth);
        }
        let passthrough = self.scheme.is_none() || self.depth == ColorDepth::Ansi16;
        match (self.scheme, slot) {
            (_, FG | BG | CURSOR) if passthrough => Color::Reset,
            (_, i) if passthrough => {
                downsample(Color::Indexed(u8::try_from(i).unwrap_or(0)), self.depth)
            }
            (Some(s), i) => {
                let rgb = match i {
                    FG => s.foreground,
                    BG => s.background,
                    CURSOR => s.cursor,
                    i => s.indexed(u8::try_from(i).unwrap_or(0)),
                };
                downsample(Color::Rgb(rgb.r, rgb.g, rgb.b), self.depth)
            }
            (None, _) => Color::Reset,
        }
    }
}

/// The palette slot of a named color. Dim variants use their base color (the DIM
/// modifier carries the dimming); bright/dim foregrounds use the foreground.
fn named_slot(n: NamedColor) -> usize {
    match n {
        NamedColor::Foreground | NamedColor::BrightForeground | NamedColor::DimForeground => FG,
        NamedColor::Background => BG,
        NamedColor::Cursor => CURSOR,
        NamedColor::DimBlack => 0,
        NamedColor::DimRed => 1,
        NamedColor::DimGreen => 2,
        NamedColor::DimYellow => 3,
        NamedColor::DimBlue => 4,
        NamedColor::DimMagenta => 5,
        NamedColor::DimCyan => 6,
        NamedColor::DimWhite => 7,
        other => (other as usize).min(255),
    }
}

/// Cell flags → ratatui modifiers.
#[must_use]
pub fn modifiers(flags: Flags) -> Modifier {
    let mut m = Modifier::empty();
    if flags.contains(Flags::BOLD) {
        m |= Modifier::BOLD;
    }
    if flags.contains(Flags::DIM) {
        m |= Modifier::DIM;
    }
    if flags.contains(Flags::ITALIC) {
        m |= Modifier::ITALIC;
    }
    // Curly, dotted, dashed and double underlines need outer-terminal support: plain underline.
    if flags.intersects(Flags::ALL_UNDERLINES) {
        m |= Modifier::UNDERLINED;
    }
    if flags.contains(Flags::INVERSE) {
        m |= Modifier::REVERSED;
    }
    if flags.contains(Flags::HIDDEN) {
        m |= Modifier::HIDDEN;
    }
    if flags.contains(Flags::STRIKEOUT) {
        m |= Modifier::CROSSED_OUT;
    }
    m
}

/// Where the real terminal cursor goes for a focused pane drawn at `area`: `None` when
/// the cursor is hidden, the view is scrolled back, or the cursor is outside `area`.
#[must_use]
pub fn cursor_position(cursor: &CursorInfo, area: Rect, view: &ViewState) -> Option<Position> {
    if !cursor.visible || view.scroll_offset > 0 {
        return None;
    }
    let x = u16::try_from(cursor.point.column).ok()?;
    let y = u16::try_from(cursor.point.line).ok()?;
    (x < area.width && y < area.height).then(|| Position::new(area.x + x, area.y + y))
}

fn write_cell(out: &mut Cell, symbol: char, fg: Color, bg: Color, modifier: Modifier) {
    out.set_char(symbol);
    out.fg = fg;
    out.bg = bg;
    out.modifier = modifier;
    out.diff_option = CellDiffOption::None;
}

/// Draw `term` into `buf` (see the module docs).
pub(crate) fn render_term<T: EventListener>(
    term: &Term<T>,
    cursor: CursorInfo,
    area: Rect,
    buf: &mut Buffer,
    view: &ViewState,
) {
    let area = area.intersection(buf.area);
    if area.is_empty() {
        return;
    }
    let grid = term.grid();
    let history = grid.history_size();
    let offset = view.scroll_offset.min(history);
    let offset_i = i32::try_from(offset).unwrap_or(i32::MAX);
    let rows = usize::from(area.height).min(grid.screen_lines());
    let cols = usize::from(area.width).min(grid.columns());
    let mut palette = Palette::new(view, term.colors());
    let default_bg = palette.slot(BG);
    let default_fg = palette.slot(FG);
    let mut symbol = String::new();

    for y in 0..usize::from(area.height) {
        let ay = area.y + u16::try_from(y).unwrap_or(u16::MAX);
        if y >= rows {
            // Area taller than the grid (resize pending): blank rows.
            for x in 0..area.width {
                if let Some(out) = buf.cell_mut((area.x + x, ay)) {
                    write_cell(out, ' ', default_fg, default_bg, Modifier::empty());
                }
            }
            continue;
        }
        let row = &grid[Line(i32::try_from(y).unwrap_or(i32::MAX) - offset_i)];
        for x in 0..usize::from(area.width) {
            let ax = area.x + u16::try_from(x).unwrap_or(u16::MAX);
            let Some(out) = buf.cell_mut((ax, ay)) else {
                continue;
            };
            if x >= cols {
                write_cell(out, ' ', default_fg, default_bg, Modifier::empty());
                continue;
            }
            let cell = &row[Column(x)];
            let flags = cell.flags;
            let fg = palette.resolve(cell.fg);
            let bg = palette.resolve(cell.bg);
            if flags.contains(Flags::WIDE_CHAR_SPACER) {
                out.reset();
                out.fg = fg;
                out.bg = bg;
                continue;
            }
            let c = if flags.contains(Flags::LEADING_WIDE_CHAR_SPACER) {
                ' '
            } else {
                cell.c
            };
            write_cell(out, c, fg, bg, modifiers(flags));
            if let Some(zw) = cell.zerowidth() {
                symbol.clear();
                symbol.push(c);
                symbol.extend(zw.iter());
                out.set_symbol(&symbol);
            }
        }
    }

    let visible_rows = rows;
    let ctx = Overlay {
        area,
        offset: offset_i,
        rows: visible_rows,
        cols,
    };

    // Hollow cursor for unfocused panes on the live view.
    if !view.focused && offset == 0 && cursor.visible {
        let p = cursor.point;
        if let Some(out) = ctx.cell(buf, p.line, p.column) {
            if out.modifier.contains(Modifier::UNDERLINED) {
                out.modifier |= Modifier::REVERSED | Modifier::DIM;
            } else {
                out.modifier |= Modifier::UNDERLINED | Modifier::DIM;
            }
        }
    }

    let mono = view.depth == ColorDepth::Mono;
    for m in &view.search_matches {
        ctx.paint(buf, m.start, m.end, false, |c| {
            if mono {
                c.modifier |= Modifier::UNDERLINED;
            } else {
                c.bg = view.overlay.match_bg;
            }
        });
    }
    if let Some(m) = &view.current_match {
        ctx.paint(buf, m.start, m.end, false, |c| {
            if mono {
                c.modifier |= Modifier::REVERSED;
            } else {
                c.bg = view.overlay.current_match_bg;
            }
        });
    }
    if let Some(sel) = &view.selection {
        ctx.paint(buf, sel.start, sel.end, sel.block, |c| {
            c.modifier.toggle(Modifier::REVERSED);
        });
    }
    if let Some(Match { start, end }) = &view.hovered_link {
        ctx.paint(buf, *start, *end, false, |c| {
            c.modifier |= Modifier::UNDERLINED;
            if !mono {
                c.fg = view.overlay.link_fg;
            }
        });
    }

    if offset > 0 {
        scroll_indicator(buf, area, offset, history, &mut symbol);
    }
}

/// Maps grid points to buffer cells for overlays.
struct Overlay {
    area: Rect,
    offset: i32,
    rows: usize,
    cols: usize,
}

impl Overlay {
    /// The visible row of a grid line.
    fn row(&self, line: i32) -> Option<u16> {
        let y = line.checked_add(self.offset)?;
        let y = usize::try_from(y).ok()?;
        (y < self.rows).then(|| u16::try_from(y).ok()).flatten()
    }

    fn cell<'b>(&self, buf: &'b mut Buffer, line: i32, col: usize) -> Option<&'b mut Cell> {
        let y = self.row(line)?;
        if col >= self.cols {
            return None;
        }
        let x = u16::try_from(col).ok()?;
        buf.cell_mut((self.area.x + x, self.area.y + y))
    }

    /// Apply `f` to every visible cell of a range (stream or block).
    fn paint(
        &self,
        buf: &mut Buffer,
        a: GridPoint,
        b: GridPoint,
        block: bool,
        mut f: impl FnMut(&mut Cell),
    ) {
        if self.cols == 0 {
            return;
        }
        let (s, e) = if b < a { (b, a) } else { (a, b) };
        let first = s.line.max(-self.offset);
        let last = e
            .line
            .min(i32::try_from(self.rows).unwrap_or(i32::MAX) - 1 - self.offset);
        for line in first..=last {
            let (c0, c1) = if block {
                (s.column.min(e.column), s.column.max(e.column))
            } else {
                (
                    if line == s.line { s.column } else { 0 },
                    if line == e.line {
                        e.column
                    } else {
                        self.cols - 1
                    },
                )
            };
            for col in c0..=c1.min(self.cols - 1) {
                if let Some(cell) = self.cell(buf, line, col) {
                    f(cell);
                }
            }
        }
    }
}

fn scroll_indicator(buf: &mut Buffer, area: Rect, offset: usize, history: usize, s: &mut String) {
    use std::fmt::Write as _;
    s.clear();
    let _ = write!(s, "[scroll: {offset}/{history}]");
    let width = u16::try_from(s.chars().count()).unwrap_or(u16::MAX);
    if width > area.width {
        return;
    }
    let x0 = area.x + area.width - width;
    for (i, ch) in s.chars().enumerate() {
        let x = x0 + u16::try_from(i).unwrap_or(0);
        if let Some(out) = buf.cell_mut((x, area.y)) {
            write_cell(out, ch, Color::Reset, Color::Reset, Modifier::REVERSED);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_slots() {
        assert_eq!(named_slot(NamedColor::Red), 1);
        assert_eq!(named_slot(NamedColor::BrightWhite), 15);
        assert_eq!(named_slot(NamedColor::DimBlue), 4);
        assert_eq!(named_slot(NamedColor::Foreground), FG);
        assert_eq!(named_slot(NamedColor::DimForeground), FG);
        assert_eq!(named_slot(NamedColor::Background), BG);
    }

    #[test]
    fn every_underline_style_is_underlined() {
        for f in [
            Flags::UNDERLINE,
            Flags::DOUBLE_UNDERLINE,
            Flags::UNDERCURL,
            Flags::DOTTED_UNDERLINE,
            Flags::DASHED_UNDERLINE,
        ] {
            assert_eq!(modifiers(f), Modifier::UNDERLINED, "{f:?}");
        }
    }
}
