//! The selection model and copy-mode motions over grid text (SPEC §7.1, §8.2).
//!
//! Everything here is pure: it reads rows through [`TextGrid`] (an emulator via
//! [`EmulatorGrid`], or a [`VecGrid`] in tests) and never touches the emulator's state.
//!
//! Coordinates are [`GridPoint`]s: line 0 is the top of the live screen, negative lines are
//! scrollback. Rows that soft-wrap into the next row ([`GridRow::wrapped`]) form one logical
//! line: text extraction joins them without a newline and word motions run across them.
//!
//! - **Text extraction** ([`extract_text`]): character-wise and line-wise selections trim
//!   trailing whitespace at hard line ends; a block selection takes the same columns of each
//!   row. Wide characters are emitted once (their spacer cell is skipped).
//! - **Motions**: `w b e` with `terminal.word_separators` (separators form their own words, as
//!   punctuation does in vim), `W B E` whitespace words, `0 ^ $`, `{ }` blank-line paragraphs.

use crate::emulator::{Emulator, GridPoint, Selection};

/// One cell of a [`GridRow`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowCell {
    /// The character (`' '` for an empty cell).
    pub c: char,
    /// Combining characters drawn in the same cell.
    pub zerowidth: Vec<char>,
    /// Columns the character covers: 1, 2 for a wide character, 0 for the spacer cell after a
    /// wide character (or the padding before one that didn't fit at the end of a row).
    pub width: u8,
}

impl RowCell {
    /// A plain one-column cell.
    #[must_use]
    pub fn new(c: char) -> Self {
        Self {
            c,
            zerowidth: Vec::new(),
            width: 1,
        }
    }

    fn is_spacer(&self) -> bool {
        self.width == 0
    }

    fn is_blank(&self) -> bool {
        self.c == ' ' || self.c == '\0' || self.c == '\t'
    }
}

/// One grid row as text.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GridRow {
    /// Exactly `columns` cells.
    pub cells: Vec<RowCell>,
    /// The row soft-wraps into the next one (no newline between them).
    pub wrapped: bool,
}

impl GridRow {
    /// Column of the last non-blank cell (`None` for a blank row).
    #[must_use]
    pub fn last_non_blank(&self) -> Option<usize> {
        self.cells
            .iter()
            .rposition(|c| !c.is_spacer() && !c.is_blank())
            .map(|i| self.lead_of(i))
    }

    /// Column of the first non-blank cell (`None` for a blank row).
    #[must_use]
    pub fn first_non_blank(&self) -> Option<usize> {
        self.cells
            .iter()
            .position(|c| !c.is_spacer() && !c.is_blank())
    }

    /// Whether the row has no visible character.
    #[must_use]
    pub fn is_blank(&self) -> bool {
        self.first_non_blank().is_none()
    }

    /// The column holding the character drawn at `col` (the wide character for its spacer).
    #[must_use]
    pub fn lead_of(&self, col: usize) -> usize {
        if col > 0
            && self.cells.get(col).is_some_and(RowCell::is_spacer)
            && self.cells.get(col - 1).is_some_and(|c| c.width == 2)
        {
            col - 1
        } else {
            col
        }
    }

    /// The text of `cols` (inclusive), wide characters once.
    fn text(&self, c0: usize, c1: usize, out: &mut String) {
        if self.cells.is_empty() {
            return;
        }
        let c0 = self.lead_of(c0.min(self.cells.len() - 1));
        let c1 = c1.min(self.cells.len() - 1);
        for cell in self.cells.iter().take(c1 + 1).skip(c0) {
            if cell.is_spacer() {
                continue;
            }
            out.push(if cell.c == '\0' { ' ' } else { cell.c });
            out.extend(cell.zerowidth.iter());
        }
    }
}

/// Read access to grid rows (screen and scrollback).
pub trait TextGrid {
    /// Columns per row.
    fn columns(&self) -> usize;
    /// The oldest scrollback line (`-scrollback_len`).
    fn top_line(&self) -> i32;
    /// The last screen line (`rows - 1`).
    fn bottom_line(&self) -> i32;
    /// The row at `line`, `None` outside `top_line()..=bottom_line()`.
    fn row(&self, line: i32) -> Option<GridRow>;

    /// `p` clamped into the grid.
    fn clamp(&self, p: GridPoint) -> GridPoint {
        GridPoint::new(
            p.line.clamp(self.top_line(), self.bottom_line()),
            p.column.min(self.columns().saturating_sub(1)),
        )
    }
}

/// An emulator as a [`TextGrid`] (through [`Emulator::row`]).
pub struct EmulatorGrid<'a>(pub &'a dyn Emulator);

impl std::fmt::Debug for EmulatorGrid<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmulatorGrid").finish_non_exhaustive()
    }
}

impl TextGrid for EmulatorGrid<'_> {
    fn columns(&self) -> usize {
        usize::from(self.0.size().0)
    }
    fn top_line(&self) -> i32 {
        -i32::try_from(self.0.scrollback_len()).unwrap_or(i32::MAX)
    }
    fn bottom_line(&self) -> i32 {
        i32::from(self.0.size().1) - 1
    }
    fn row(&self, line: i32) -> Option<GridRow> {
        self.0.row(line)
    }
}

/// An in-memory grid (tests, fixtures). Line `top` is `rows[0]`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VecGrid {
    /// Columns per row.
    pub cols: usize,
    /// The line of `rows[0]` (negative when there is scrollback).
    pub top: i32,
    /// The rows, oldest first.
    pub rows: Vec<GridRow>,
}

impl VecGrid {
    /// Rows from text lines, each soft-wrapped at `cols`. `screen_rows` is how many of the
    /// last rows are the live screen (the rest is scrollback). Characters in the common CJK
    /// and emoji ranges take two columns.
    #[must_use]
    pub fn from_lines(lines: &[&str], cols: usize, screen_rows: usize) -> Self {
        let mut rows = Vec::new();
        for line in lines {
            let mut row = GridRow::default();
            for c in line.chars() {
                let w = if is_wide(c) { 2 } else { 1 };
                if row.cells.len() + w > cols {
                    pad(&mut row, cols);
                    row.wrapped = true;
                    rows.push(std::mem::take(&mut row));
                }
                row.cells.push(RowCell {
                    c,
                    zerowidth: Vec::new(),
                    width: u8::try_from(w).unwrap_or(1),
                });
                if w == 2 {
                    row.cells.push(RowCell {
                        c: ' ',
                        zerowidth: Vec::new(),
                        width: 0,
                    });
                }
            }
            pad(&mut row, cols);
            rows.push(row);
        }
        while rows.len() < screen_rows {
            let mut row = GridRow::default();
            pad(&mut row, cols);
            rows.push(row);
        }
        let history = rows.len() - screen_rows.min(rows.len());
        Self {
            cols,
            top: -i32::try_from(history).unwrap_or(0),
            rows,
        }
    }
}

fn pad(row: &mut GridRow, cols: usize) {
    while row.cells.len() < cols {
        row.cells.push(RowCell::new(' '));
    }
}

fn is_wide(c: char) -> bool {
    matches!(u32::from(c),
        0x1100..=0x115F
        | 0x2E80..=0xA4CF
        | 0xAC00..=0xD7A3
        | 0xF900..=0xFAFF
        | 0xFE30..=0xFE4F
        | 0xFF00..=0xFF60
        | 0xFFE0..=0xFFE6
        | 0x1F300..=0x1FAFF
        | 0x20000..=0x3FFFD)
}

impl TextGrid for VecGrid {
    fn columns(&self) -> usize {
        self.cols
    }
    fn top_line(&self) -> i32 {
        self.top
    }
    fn bottom_line(&self) -> i32 {
        self.top + i32::try_from(self.rows.len()).unwrap_or(i32::MAX) - 1
    }
    fn row(&self, line: i32) -> Option<GridRow> {
        let i = usize::try_from(line - self.top).ok()?;
        self.rows.get(i).cloned()
    }
}

// ------------------------------------------------------------------ selection

/// How a selection extends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SelectionMode {
    /// `v`: a stream of characters.
    Char,
    /// `V`: whole lines.
    Line,
    /// `ctrl-v`: a rectangle.
    Block,
}

/// A selection: the fixed `anchor` and the moving `cursor` (both inclusive).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SelectionRange {
    /// Where the selection started.
    pub anchor: GridPoint,
    /// The end that follows the cursor.
    pub cursor: GridPoint,
    /// Char-wise, line-wise or block.
    pub mode: SelectionMode,
}

impl SelectionRange {
    /// An empty selection (one cell) at `at`.
    #[must_use]
    pub fn new(mode: SelectionMode, at: GridPoint) -> Self {
        Self {
            anchor: at,
            cursor: at,
            mode,
        }
    }

    /// `o`: swap the anchor and the cursor.
    pub fn swap(&mut self) {
        std::mem::swap(&mut self.anchor, &mut self.cursor);
    }

    /// The ordered ends (`start <= end`) of a stream selection.
    #[must_use]
    pub fn ordered(&self) -> (GridPoint, GridPoint) {
        if self.cursor < self.anchor {
            (self.cursor, self.anchor)
        } else {
            (self.anchor, self.cursor)
        }
    }

    /// The selection with every line moved by `delta`.
    #[must_use]
    pub fn shifted(&self, delta: i32) -> Self {
        let shift = |p: GridPoint| GridPoint::new(p.line + delta, p.column);
        Self {
            anchor: shift(self.anchor),
            cursor: shift(self.cursor),
            mode: self.mode,
        }
    }

    /// The overlay the renderer draws (`ViewState::selection`).
    #[must_use]
    pub fn to_view(&self, columns: usize) -> Selection {
        let (s, e) = self.ordered();
        match self.mode {
            SelectionMode::Char => Selection {
                start: s,
                end: e,
                block: false,
            },
            SelectionMode::Line => Selection {
                start: GridPoint::new(s.line, 0),
                end: GridPoint::new(e.line, columns.saturating_sub(1)),
                block: false,
            },
            SelectionMode::Block => Selection {
                start: GridPoint::new(
                    s.line.min(e.line),
                    self.anchor.column.min(self.cursor.column),
                ),
                end: GridPoint::new(
                    s.line.max(e.line),
                    self.anchor.column.max(self.cursor.column),
                ),
                block: true,
            },
        }
    }

    /// The selected text (see [`extract_text`]).
    #[must_use]
    pub fn text(&self, grid: &dyn TextGrid) -> String {
        let v = self.to_view(grid.columns());
        let mode = if v.block {
            SelectionMode::Block
        } else {
            SelectionMode::Char
        };
        extract_text(grid, v.start, v.end, mode)
    }
}

/// The text between `start` and `end` (inclusive).
///
/// - `Char`/`Line`: rows in reading order; a soft-wrapped row joins the next without a
///   newline (its trailing blanks are content); at a hard line end trailing whitespace is
///   trimmed and a `\n` separates the rows. `Line` is `Char` from column 0 to the last.
/// - `Block`: columns `start.column..=end.column` of each row, trimmed, joined with `\n`.
#[must_use]
pub fn extract_text(
    grid: &dyn TextGrid,
    start: GridPoint,
    end: GridPoint,
    mode: SelectionMode,
) -> String {
    let cols = grid.columns();
    if cols == 0 {
        return String::new();
    }
    let (s, e) = if end < start {
        (end, start)
    } else {
        (start, end)
    };
    let (s, e) = (grid.clamp(s), grid.clamp(e));
    let mut out = String::new();
    match mode {
        SelectionMode::Block => {
            let (c0, c1) = (s.column.min(e.column), s.column.max(e.column));
            for line in s.line..=e.line {
                let mut text = String::new();
                if let Some(row) = grid.row(line) {
                    row.text(c0, c1, &mut text);
                }
                out.push_str(text.trim_end());
                if line != e.line {
                    out.push('\n');
                }
            }
        }
        SelectionMode::Char | SelectionMode::Line => {
            let (s, e) = if mode == SelectionMode::Line {
                (GridPoint::new(s.line, 0), GridPoint::new(e.line, cols - 1))
            } else {
                (s, e)
            };
            let mut pending = String::new();
            for line in s.line..=e.line {
                let Some(row) = grid.row(line) else { continue };
                let c0 = if line == s.line { s.column } else { 0 };
                let c1 = if line == e.line { e.column } else { cols - 1 };
                row.text(c0, c1, &mut pending);
                if row.wrapped && line != e.line {
                    continue;
                }
                out.push_str(pending.trim_end());
                pending.clear();
                if line != e.line {
                    out.push('\n');
                }
            }
            out.push_str(pending.trim_end());
        }
    }
    out
}

// ------------------------------------------------------------------ motions

/// Character classes for word motions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Blank,
    Separator,
    Word,
}

/// Which words a motion uses.
#[derive(Debug, Clone, Copy)]
pub enum WordKind<'a> {
    /// `w b e`: runs of word characters, or runs of `separators` characters.
    Small(&'a str),
    /// `W B E`: runs of non-blank characters.
    Big,
}

impl WordKind<'_> {
    fn class(self, cell: &RowCell) -> Class {
        if cell.is_blank() {
            return Class::Blank;
        }
        match self {
            Self::Small(seps) if seps.contains(cell.c) => Class::Separator,
            _ => Class::Word,
        }
    }
}

/// Walks cells in reading order, skipping spacers, with a one-row cache.
struct Walker<'g> {
    grid: &'g dyn TextGrid,
    line: i32,
    col: usize,
    row: GridRow,
}

impl<'g> Walker<'g> {
    fn new(grid: &'g dyn TextGrid, p: GridPoint) -> Self {
        let p = grid.clamp(p);
        let row = grid.row(p.line).unwrap_or_default();
        let col = row.lead_of(p.column);
        Self {
            grid,
            line: p.line,
            col,
            row,
        }
    }

    fn point(&self) -> GridPoint {
        GridPoint::new(self.line, self.col)
    }

    fn cell(&self) -> RowCell {
        self.row
            .cells
            .get(self.col)
            .cloned()
            .unwrap_or_else(|| RowCell::new(' '))
    }

    /// One cell forward. `Some(crossed_hard_break)`, or `None` at the end of the grid.
    fn forward(&mut self) -> Option<bool> {
        let mut col = self.col + 1;
        while self.row.cells.get(col).is_some_and(RowCell::is_spacer) {
            col += 1;
        }
        if col < self.row.cells.len() {
            self.col = col;
            return Some(false);
        }
        if self.line >= self.grid.bottom_line() {
            return None;
        }
        let hard = !self.row.wrapped;
        self.line += 1;
        self.row = self.grid.row(self.line).unwrap_or_default();
        self.col = 0;
        while self.row.cells.get(self.col).is_some_and(RowCell::is_spacer) {
            self.col += 1;
        }
        Some(hard)
    }

    /// One cell back. `Some(crossed_hard_break)`, or `None` at the start of the grid.
    fn backward(&mut self) -> Option<bool> {
        let mut col = self.col;
        while col > 0 {
            col -= 1;
            if !self.row.cells.get(col).is_some_and(RowCell::is_spacer) {
                self.col = col;
                return Some(false);
            }
        }
        if self.line <= self.grid.top_line() {
            return None;
        }
        self.line -= 1;
        self.row = self.grid.row(self.line).unwrap_or_default();
        let hard = !self.row.wrapped;
        self.col = self.row.lead_of(self.row.cells.len().saturating_sub(1));
        Some(hard)
    }
}

/// `w` / `W`: the start of the next word (the last cell if there is none).
#[must_use]
pub fn word_forward(grid: &dyn TextGrid, from: GridPoint, kind: WordKind<'_>) -> GridPoint {
    let mut w = Walker::new(grid, from);
    let start = kind.class(&w.cell());
    if start != Class::Blank {
        loop {
            match w.forward() {
                None => return w.point(),
                Some(true) => break,
                Some(false) if kind.class(&w.cell()) != start => break,
                Some(false) => {}
            }
        }
    }
    while kind.class(&w.cell()) == Class::Blank {
        if w.forward().is_none() {
            return w.point();
        }
    }
    w.point()
}

/// `e` / `E`: the end of the current or next word.
#[must_use]
pub fn word_end(grid: &dyn TextGrid, from: GridPoint, kind: WordKind<'_>) -> GridPoint {
    let mut w = Walker::new(grid, from);
    if w.forward().is_none() {
        return w.point();
    }
    while kind.class(&w.cell()) == Class::Blank {
        if w.forward().is_none() {
            return w.point();
        }
    }
    let class = kind.class(&w.cell());
    loop {
        let here = (w.line, w.col, w.row.clone());
        match w.forward() {
            Some(false) if kind.class(&w.cell()) == class => {}
            _ => {
                (w.line, w.col, w.row) = here;
                return w.point();
            }
        }
    }
}

/// `b` / `B`: the start of the current or previous word.
#[must_use]
pub fn word_backward(grid: &dyn TextGrid, from: GridPoint, kind: WordKind<'_>) -> GridPoint {
    let mut w = Walker::new(grid, from);
    if w.backward().is_none() {
        return w.point();
    }
    while kind.class(&w.cell()) == Class::Blank {
        if w.backward().is_none() {
            return w.point();
        }
    }
    let class = kind.class(&w.cell());
    loop {
        let here = (w.line, w.col, w.row.clone());
        match w.backward() {
            Some(false) if kind.class(&w.cell()) == class => {}
            _ => {
                (w.line, w.col, w.row) = here;
                return w.point();
            }
        }
    }
}

/// The word (or separator run) under `p` for a double click, within its logical line.
/// A blank cell selects just itself.
#[must_use]
pub fn word_at(grid: &dyn TextGrid, p: GridPoint, separators: &str) -> (GridPoint, GridPoint) {
    let kind = WordKind::Small(separators);
    let mut w = Walker::new(grid, p);
    let class = kind.class(&w.cell());
    let center = (w.line, w.col, w.row.clone());
    if class == Class::Blank {
        return (w.point(), w.point());
    }
    loop {
        let here = (w.line, w.col, w.row.clone());
        match w.backward() {
            Some(false) if kind.class(&w.cell()) == class => {}
            _ => {
                (w.line, w.col, w.row) = here;
                break;
            }
        }
    }
    let start = w.point();
    (w.line, w.col, w.row) = center;
    loop {
        let here = (w.line, w.col, w.row.clone());
        match w.forward() {
            Some(false) if kind.class(&w.cell()) == class => {}
            _ => {
                (w.line, w.col, w.row) = here;
                break;
            }
        }
    }
    (start, w.point())
}

/// The first and last line of the logical line (soft-wrapped rows) containing `line`.
#[must_use]
pub fn logical_bounds(grid: &dyn TextGrid, line: i32) -> (i32, i32) {
    let line = line.clamp(grid.top_line(), grid.bottom_line());
    let mut first = line;
    while first > grid.top_line() && grid.row(first - 1).is_some_and(|r| r.wrapped) {
        first -= 1;
    }
    let mut last = line;
    while last < grid.bottom_line() && grid.row(last).is_some_and(|r| r.wrapped) {
        last += 1;
    }
    (first, last)
}

/// `^`: the first non-blank column of `line` (0 for a blank line).
#[must_use]
pub fn first_non_blank(grid: &dyn TextGrid, line: i32) -> usize {
    grid.row(line)
        .and_then(|r| r.first_non_blank())
        .unwrap_or(0)
}

/// `$`: the last non-blank column of `line` (0 for a blank line).
#[must_use]
pub fn last_non_blank(grid: &dyn TextGrid, line: i32) -> usize {
    grid.row(line).and_then(|r| r.last_non_blank()).unwrap_or(0)
}

/// `}` (`forward`) / `{`: the next / previous blank line after a non-blank one, or the
/// last / first line of the grid.
#[must_use]
pub fn paragraph(grid: &dyn TextGrid, line: i32, forward: bool) -> i32 {
    let blank = |l: i32| grid.row(l).is_none_or(|r| r.is_blank());
    let (step, limit) = if forward {
        (1, grid.bottom_line())
    } else {
        (-1, grid.top_line())
    };
    let mut l = line;
    // Skip the blank lines we are on, then the paragraph, stopping on the next blank line.
    while l != limit && blank(l) {
        l += step;
    }
    while l != limit && !blank(l) {
        l += step;
    }
    l
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const SEPS: &str = " ,│`|:\"'()[]{}<>";

    fn p(line: i32, column: usize) -> GridPoint {
        GridPoint::new(line, column)
    }

    /// `w` stops at `:` in `host:22`.
    #[test]
    fn t01_word_motions_honor_separators() {
        let g = VecGrid::from_lines(&["ssh host:22 now"], 20, 1);
        let small = WordKind::Small(SEPS);
        assert_eq!(word_forward(&g, p(0, 0), small), p(0, 4));
        assert_eq!(word_forward(&g, p(0, 4), small), p(0, 8), "`host` → `:`");
        assert_eq!(word_forward(&g, p(0, 8), small), p(0, 9), "`:` → `22`");
        assert_eq!(word_forward(&g, p(0, 9), small), p(0, 12));
        // Big words skip the separator.
        assert_eq!(word_forward(&g, p(0, 4), WordKind::Big), p(0, 12));
        assert_eq!(word_end(&g, p(0, 4), small), p(0, 7));
        assert_eq!(word_end(&g, p(0, 4), WordKind::Big), p(0, 10));
        assert_eq!(word_backward(&g, p(0, 12), small), p(0, 9));
        assert_eq!(word_backward(&g, p(0, 9), small), p(0, 8));
        assert_eq!(word_backward(&g, p(0, 12), WordKind::Big), p(0, 4));
        // Without `:` in the separators, `host:22` is one word.
        assert_eq!(word_forward(&g, p(0, 4), WordKind::Small(" ")), p(0, 12));
        assert_eq!(word_at(&g, p(0, 5), SEPS), (p(0, 4), p(0, 7)));
    }

    #[test]
    fn word_motions_cross_lines() {
        let g = VecGrid::from_lines(&["abc", "  def"], 10, 2);
        let small = WordKind::Small(SEPS);
        assert_eq!(word_forward(&g, p(0, 0), small), p(1, 2));
        assert_eq!(word_backward(&g, p(1, 2), small), p(0, 0));
        assert_eq!(word_end(&g, p(0, 2), small), p(1, 4));
        // A soft-wrapped word is one word.
        let g = VecGrid::from_lines(&["abcdefgh xy"], 4, 3);
        assert_eq!(word_forward(&g, p(0, 0), small), p(2, 1));
        assert_eq!(word_end(&g, p(0, 0), small), p(1, 3));
        assert_eq!(word_at(&g, p(1, 0), SEPS), (p(0, 0), p(1, 3)));
        // At the end of the grid `w` stays on the last cell.
        let g = VecGrid::from_lines(&["ab"], 2, 1);
        assert_eq!(word_forward(&g, p(0, 0), small), p(0, 1));
    }

    /// Wrapped lines join without a newline; line-wise trims; block takes columns.
    #[test]
    fn t02_extraction() {
        // "hello world" wrapped at 6 columns: "hello " + "world".
        let g = VecGrid::from_lines(&["hello world", "next line   "], 6, 4);
        assert!(g.rows[0].wrapped);
        let t = extract_text(&g, p(0, 0), p(1, 4), SelectionMode::Char);
        assert_eq!(t, "hello world");
        let t = extract_text(&g, p(0, 2), p(2, 3), SelectionMode::Char);
        assert_eq!(t, "llo world\nnext");

        let g = VecGrid::from_lines(&["one   ", "two  ", "three"], 10, 3);
        let t = extract_text(&g, p(0, 3), p(1, 1), SelectionMode::Line);
        assert_eq!(t, "one\ntwo");
        let sel = SelectionRange {
            anchor: p(1, 4),
            cursor: p(0, 0),
            mode: SelectionMode::Line,
        };
        assert_eq!(sel.text(&g), "one\ntwo");

        let g = VecGrid::from_lines(&["0123456789", "abcdefghij", "ABCDEFGHIJ"], 10, 3);
        let sel = SelectionRange {
            anchor: p(0, 5),
            cursor: p(2, 2),
            mode: SelectionMode::Block,
        };
        assert_eq!(sel.text(&g), "2345\ncdef\nCDEF");
        assert_eq!(
            sel.to_view(10),
            Selection {
                start: p(0, 2),
                end: p(2, 5),
                block: true
            }
        );
    }

    /// A wide character inside a selection comes out once.
    #[test]
    fn t03_wide_chars_once() {
        let g = VecGrid::from_lines(&["a漢字b"], 10, 1);
        assert_eq!(g.rows[0].cells[1].width, 2);
        assert_eq!(g.rows[0].cells[2].width, 0);
        assert_eq!(
            extract_text(&g, p(0, 0), p(0, 5), SelectionMode::Char),
            "a漢字b"
        );
        // Starting on a spacer takes its wide character; ending on the first half too.
        assert_eq!(
            extract_text(&g, p(0, 2), p(0, 3), SelectionMode::Char),
            "漢字"
        );
        assert_eq!(
            extract_text(&g, p(0, 1), p(0, 4), SelectionMode::Block),
            "漢字"
        );
        // Word motions step over spacers.
        let small = WordKind::Small(SEPS);
        assert_eq!(word_end(&g, p(0, 0), small), p(0, 5));
    }

    #[test]
    fn line_motions_and_paragraphs() {
        let g = VecGrid::from_lines(&["  ab cd  ", "", "x", "y", "", "z"], 10, 6);
        assert_eq!(first_non_blank(&g, 0), 2);
        assert_eq!(last_non_blank(&g, 0), 6);
        assert_eq!(last_non_blank(&g, 1), 0);
        assert_eq!(paragraph(&g, 0, true), 1);
        assert_eq!(paragraph(&g, 1, true), 4);
        assert_eq!(paragraph(&g, 4, true), 5);
        assert_eq!(paragraph(&g, 3, false), 1);
        assert_eq!(paragraph(&g, 0, false), 0);
        assert_eq!(logical_bounds(&g, 2), (2, 2));
    }

    #[test]
    fn emulator_rows() {
        use crate::{AlacrittyEmulator, Emulator, EmulatorConfig};
        let mut e = AlacrittyEmulator::new(EmulatorConfig {
            cols: 6,
            rows: 3,
            scrollback: 10,
        });
        e.feed("old\r\nhello world\r\na漢b".as_bytes());
        let g = EmulatorGrid(&e);
        assert_eq!((g.top_line(), g.bottom_line(), g.columns()), (-1, 2, 6));
        assert!(g.row(0).unwrap().wrapped);
        assert_eq!(
            extract_text(&g, p(-1, 0), p(2, 5), SelectionMode::Char),
            "old\nhello world\na漢b"
        );
        assert_eq!(g.row(2).unwrap().cells[1].width, 2);
        assert!(g.row(3).is_none());
    }

    #[test]
    fn swap_and_shift() {
        let mut s = SelectionRange::new(SelectionMode::Char, p(0, 1));
        s.cursor = p(2, 3);
        s.swap();
        assert_eq!((s.anchor, s.cursor), (p(2, 3), p(0, 1)));
        assert_eq!(s.ordered(), (p(0, 1), p(2, 3)));
        assert_eq!(s.shifted(-2).anchor, p(0, 3));
    }
}
