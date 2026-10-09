//! Copy mode (`leader [`, SPEC §8.2).
//!
//! Vim-style motions over the screen and scrollback, `v`/`V`/`ctrl-v` selections, `y`/`Y`
//! yanks, `/`/`?` regex search with `n`/`N`, `o` on a link (open after confirmation), and
//! `q`/`Esc`/`ctrl-c` to leave. This module is the pure part: the key table
//! ([`CopyKeymap`], `[keys.copy]` overrides) and the state machine ([`CopyState`]), which
//! reads the grid through [`TextGrid`]. The reducer glue (emulator access, effects, the
//! confirm dialog, rendering) is `app/input/copy.rs`.
//!
//! **Coordinates.** Output keeps flowing while copy mode is on, and every new scrollback line
//! moves existing content one line up (`GridPoint` lines are relative to the live screen).
//! The state remembers the scrollback length its points were computed at
//! ([`CopyState::history`]); [`CopyState::rebase`] shifts everything when it grew, so the
//! view stays **frozen** on the same content and the "+N lines" badge counts the new lines.
//! (Once the scrollback is full, old lines are dropped and the view drifts; the badge stops
//! growing then.)

use std::{collections::HashMap, str::FromStr};

use crossterm::event::KeyCode;
use strum::{EnumIter, EnumString, IntoStaticStr};
use sverb_core::config::Config;
use sverb_term::{
    Direction, GridPoint, Match,
    search::{self, MATCH_COUNT_CAP, SearchPattern},
    selection::{self, SelectionMode, SelectionRange, TextGrid, WordKind},
};

use crate::{
    app::SessionId,
    keymap::chord::{KeyChord, Mods},
};

/// A copy-mode command (`[keys.copy]` action names; `sverb_core::config::COPY_ACTIONS`).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, EnumString, EnumIter, IntoStaticStr,
)]
#[strum(serialize_all = "snake_case")]
pub enum CopyAction {
    /// `h` / `←`.
    MoveLeft,
    /// `j` / `↓`.
    MoveDown,
    /// `k` / `↑`.
    MoveUp,
    /// `l` / `→`.
    MoveRight,
    /// `w`: next word start (`terminal.word_separators`).
    WordForward,
    /// `b`: previous word start.
    WordBackward,
    /// `e`: word end.
    WordEnd,
    /// `W`: next whitespace-delimited word.
    BigWordForward,
    /// `B`.
    BigWordBackward,
    /// `E`.
    BigWordEnd,
    /// `0` / `home`.
    LineStart,
    /// `^`.
    LineFirstNonBlank,
    /// `$` / `end`.
    LineEnd,
    /// `g g`: top of the scrollback.
    Top,
    /// `G`: bottom.
    Bottom,
    /// `H`: top line of the view.
    ScreenTop,
    /// `M`.
    ScreenMiddle,
    /// `L`.
    ScreenBottom,
    /// `ctrl-u`.
    HalfPageUp,
    /// `ctrl-d`.
    HalfPageDown,
    /// `ctrl-b` / `pageup`.
    PageUp,
    /// `ctrl-f` / `pagedown`.
    PageDown,
    /// `{`.
    ParagraphBackward,
    /// `}`.
    ParagraphForward,
    /// `v`.
    SelectChar,
    /// `V`.
    SelectLine,
    /// `ctrl-v`.
    SelectBlock,
    /// `O` (and `o` while selecting): swap the selection's ends.
    SwapAnchor,
    /// `y`: copy the selection and leave.
    Yank,
    /// `Y`: copy the current line (`count` lines) and leave.
    YankLine,
    /// `/`.
    SearchForward,
    /// `?`.
    SearchBackward,
    /// `n`.
    SearchNext,
    /// `N`.
    SearchPrev,
    /// `o`: open the link under the cursor (after confirmation); with a selection it swaps
    /// the ends instead (vim's `o`).
    OpenLink,
    /// `q` / `Esc` / `ctrl-c`.
    Exit,
}

/// Built-in bindings.
pub const COPY_DEFAULTS: &[(&str, CopyAction)] = &[
    ("h", CopyAction::MoveLeft),
    ("left", CopyAction::MoveLeft),
    ("j", CopyAction::MoveDown),
    ("down", CopyAction::MoveDown),
    ("k", CopyAction::MoveUp),
    ("up", CopyAction::MoveUp),
    ("l", CopyAction::MoveRight),
    ("right", CopyAction::MoveRight),
    ("w", CopyAction::WordForward),
    ("b", CopyAction::WordBackward),
    ("e", CopyAction::WordEnd),
    ("W", CopyAction::BigWordForward),
    ("B", CopyAction::BigWordBackward),
    ("E", CopyAction::BigWordEnd),
    ("0", CopyAction::LineStart),
    ("home", CopyAction::LineStart),
    ("^", CopyAction::LineFirstNonBlank),
    ("$", CopyAction::LineEnd),
    ("end", CopyAction::LineEnd),
    ("g g", CopyAction::Top),
    ("G", CopyAction::Bottom),
    ("H", CopyAction::ScreenTop),
    ("M", CopyAction::ScreenMiddle),
    ("L", CopyAction::ScreenBottom),
    ("ctrl-u", CopyAction::HalfPageUp),
    ("ctrl-d", CopyAction::HalfPageDown),
    ("ctrl-b", CopyAction::PageUp),
    ("pageup", CopyAction::PageUp),
    ("ctrl-f", CopyAction::PageDown),
    ("pagedown", CopyAction::PageDown),
    ("{", CopyAction::ParagraphBackward),
    ("}", CopyAction::ParagraphForward),
    ("v", CopyAction::SelectChar),
    ("V", CopyAction::SelectLine),
    ("ctrl-v", CopyAction::SelectBlock),
    ("O", CopyAction::SwapAnchor),
    ("y", CopyAction::Yank),
    ("Y", CopyAction::YankLine),
    ("/", CopyAction::SearchForward),
    ("?", CopyAction::SearchBackward),
    ("n", CopyAction::SearchNext),
    ("N", CopyAction::SearchPrev),
    ("o", CopyAction::OpenLink),
    ("q", CopyAction::Exit),
    ("esc", CopyAction::Exit),
    ("ctrl-c", CopyAction::Exit),
];

/// Result of looking up a key sequence in the copy table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyLookup {
    /// Bound.
    Action(CopyAction),
    /// A longer binding starts with it (`g` of `g g`).
    Prefix,
    /// Nothing.
    Unbound,
}

/// The effective copy-mode table: [`COPY_DEFAULTS`] merged with `[keys.copy]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyKeymap {
    bindings: HashMap<Vec<KeyChord>, CopyAction>,
}

impl Default for CopyKeymap {
    fn default() -> Self {
        Self {
            bindings: COPY_DEFAULTS
                .iter()
                .filter_map(|(k, a)| Some((KeyChord::parse_sequence(k).ok()?, *a)))
                .collect(),
        }
    }
}

impl CopyKeymap {
    /// The defaults with `config`'s `[keys.copy]` applied (`"none"` unbinds). Entries that
    /// don't parse were reported by config validation and are skipped here.
    #[must_use]
    pub fn from_config(config: &Config) -> Self {
        let mut map = Self::default();
        if let Some(user) = config.keys.mode("copy") {
            for (keys, action) in user {
                let Ok(seq) = KeyChord::parse_sequence(keys.as_str()) else {
                    continue;
                };
                if action == crate::keymap::keymap::UNBIND {
                    map.bindings.remove(&seq);
                } else if let Ok(action) = CopyAction::from_str(action) {
                    map.bindings.insert(seq, action);
                }
            }
        }
        map
    }

    /// Look up a (partial) sequence.
    #[must_use]
    pub fn lookup(&self, seq: &[KeyChord]) -> CopyLookup {
        let longer = self
            .bindings
            .keys()
            .any(|k| k.len() > seq.len() && k.starts_with(seq));
        match (self.bindings.get(seq), longer) {
            (_, true) => CopyLookup::Prefix,
            (Some(a), false) => CopyLookup::Action(*a),
            (None, false) => CopyLookup::Unbound,
        }
    }
}

/// The `/` or `?` prompt being typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchPrompt {
    /// `/` (towards newer output) or `?`.
    pub forward: bool,
    /// What was typed so far.
    pub text: String,
}

/// The last search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopySearch {
    /// The pattern (an invalid regex is searched literally).
    pub pattern: SearchPattern,
    /// Direction of the `/` or `?` that started it (`n` repeats it, `N` reverses).
    pub forward: bool,
    /// The current match (accented), in this state's coordinates.
    pub current: Option<Match>,
    /// Matches in the whole scrollback, capped at [`MATCH_COUNT_CAP`] (`true`: capped).
    pub count: (usize, bool),
}

/// What a key asks the reducer to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CopyOutcome {
    /// Nothing outside the state (redraw).
    None,
    /// Leave copy mode.
    Exit,
    /// Copy this text, then leave copy mode.
    Yank(String),
    /// Ask to open the link under the cursor.
    OpenLink,
}

/// Copy-mode state of the focused pane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyState {
    /// The pane's session.
    pub session: SessionId,
    /// The copy cursor.
    pub cursor: GridPoint,
    /// The first visible line (the view is frozen on it).
    pub view_top: i32,
    /// Visible rows.
    pub rows: usize,
    /// Scrollback length the points above refer to (see [`CopyState::rebase`]).
    pub history: usize,
    /// Scrollback length when copy mode started ("+N lines" counts from here).
    pub entry_history: usize,
    /// The selection, if one was started.
    pub selection: Option<SelectionRange>,
    /// A count being typed (`5` of `5j`).
    pub count: Option<usize>,
    /// Keys of an unfinished sequence (`g` of `g g`).
    pub pending: Vec<KeyChord>,
    /// The `/` or `?` prompt.
    pub prompt: Option<SearchPrompt>,
    /// The last search.
    pub search: Option<CopySearch>,
    /// A one-line message (search wrapped, not found, invalid regex).
    pub message: Option<String>,
}

/// Counts are capped (a stray `99999j` must not loop for long).
const MAX_COUNT: usize = 100_000;

impl CopyState {
    /// Enter copy mode: the cursor starts at the terminal cursor, the view at the pane's
    /// current scroll offset. If the cursor isn't in view it starts on the view's last row.
    #[must_use]
    pub fn enter(
        session: SessionId,
        grid: &dyn TextGrid,
        history: usize,
        scroll_offset: usize,
        rows: usize,
        cursor: GridPoint,
    ) -> Self {
        let offset = i32::try_from(scroll_offset.min(history)).unwrap_or(0);
        let rows = rows.max(1);
        let view_top = -offset;
        let bottom = view_top + i32::try_from(rows).unwrap_or(1) - 1;
        let cursor = if cursor.line > bottom {
            GridPoint::new(bottom, 0)
        } else {
            cursor
        };
        Self {
            session,
            cursor: grid.clamp(cursor),
            view_top,
            rows,
            history,
            entry_history: history,
            selection: None,
            count: None,
            pending: Vec::new(),
            prompt: None,
            search: None,
            message: None,
        }
    }

    /// Shift every point for a scrollback that now holds `history` lines (new output
    /// pushed lines into it): the view stays on the same content.
    pub fn rebase(&mut self, history: usize) {
        if history == self.history {
            return;
        }
        let delta = i32::try_from(history).unwrap_or(i32::MAX)
            - i32::try_from(self.history).unwrap_or(i32::MAX);
        let shift = |p: &mut GridPoint| p.line -= delta;
        shift(&mut self.cursor);
        self.view_top -= delta;
        if let Some(sel) = &mut self.selection {
            *sel = sel.shifted(-delta);
        }
        if let Some(Match { start, end }) = self.search.as_mut().and_then(|s| s.current.as_mut()) {
            shift(start);
            shift(end);
        }
        self.history = history;
    }

    /// A copy rebased to `history` (for drawing, which can't mutate the state).
    #[must_use]
    pub fn rebased(&self, history: usize) -> Self {
        let mut s = self.clone();
        s.rebase(history);
        s
    }

    /// The scroll offset that shows the frozen view.
    #[must_use]
    pub fn scroll_offset(&self) -> usize {
        usize::try_from(-self.view_top)
            .unwrap_or(0)
            .min(self.history)
    }

    /// Lines of output that arrived since copy mode started.
    #[must_use]
    pub fn new_lines(&self) -> usize {
        self.history.saturating_sub(self.entry_history)
    }

    fn rows_i(&self) -> i32 {
        i32::try_from(self.rows).unwrap_or(i32::MAX).max(1)
    }

    /// Keep the cursor inside the view (scrolling the view) and the view inside the grid.
    fn follow(&mut self, grid: &dyn TextGrid) {
        self.cursor = grid.clamp(self.cursor);
        let rows = self.rows_i();
        if self.cursor.line < self.view_top {
            self.view_top = self.cursor.line;
        } else if self.cursor.line > self.view_top + rows - 1 {
            self.view_top = self.cursor.line - rows + 1;
        }
        self.clamp_view(grid);
    }

    fn clamp_view(&mut self, grid: &dyn TextGrid) {
        let max_top = grid.bottom_line() - self.rows_i() + 1;
        self.view_top = self.view_top.min(max_top).max(grid.top_line()).min(0);
    }

    /// Scroll the view by `lines` (negative: up) and keep the cursor inside it (wheel).
    pub fn scroll(&mut self, grid: &dyn TextGrid, lines: i32) {
        self.view_top += lines;
        self.clamp_view(grid);
        let rows = self.rows_i();
        self.cursor.line = self
            .cursor
            .line
            .clamp(self.view_top, self.view_top + rows - 1);
        self.cursor = grid.clamp(self.cursor);
    }

    /// The point under pane cell (`col`, `row`).
    #[must_use]
    pub fn point_at(&self, col: u16, row: u16) -> GridPoint {
        GridPoint::new(self.view_top + i32::from(row), usize::from(col))
    }

    /// Handle one key. `separators` is `terminal.word_separators`.
    pub fn on_key(
        &mut self,
        chord: KeyChord,
        keymap: &CopyKeymap,
        grid: &dyn TextGrid,
        separators: &str,
    ) -> CopyOutcome {
        self.message = None;
        if self.prompt.is_some() {
            return self.on_prompt_key(chord, grid);
        }
        // Counts: `1`-`9`, then digits (a leading `0` is `line_start`).
        if self.pending.is_empty()
            && chord.mods == Mods::NONE
            && let KeyCode::Char(c @ '0'..='9') = chord.code
            && (c != '0' || self.count.is_some())
        {
            let digit = usize::from(c as u8 - b'0');
            self.count = Some((self.count.unwrap_or(0) * 10 + digit).min(MAX_COUNT));
            return CopyOutcome::None;
        }
        let mut seq = std::mem::take(&mut self.pending);
        seq.push(chord);
        match keymap.lookup(&seq) {
            CopyLookup::Prefix => {
                self.pending = seq;
                CopyOutcome::None
            }
            CopyLookup::Unbound => {
                self.count = None;
                CopyOutcome::None
            }
            CopyLookup::Action(action) => {
                let count = self.count.take();
                self.apply(action, count, grid, separators)
            }
        }
    }

    /// Run one action `count` times (where a count makes sense).
    pub fn apply(
        &mut self,
        action: CopyAction,
        count: Option<usize>,
        grid: &dyn TextGrid,
        separators: &str,
    ) -> CopyOutcome {
        use CopyAction as A;
        let n = count.unwrap_or(1).max(1);
        let n_i = i32::try_from(n).unwrap_or(i32::MAX);
        let cols = grid.columns().max(1);
        let rows = self.rows_i();
        let c = self.cursor;
        let repeat = |p: GridPoint, f: &dyn Fn(GridPoint) -> GridPoint| {
            let mut p = p;
            for _ in 0..n {
                let next = f(p);
                if next == p {
                    break;
                }
                p = next;
            }
            p
        };
        let small = WordKind::Small(separators);
        match action {
            A::MoveLeft => self.cursor.column = c.column.saturating_sub(n),
            A::MoveRight => self.cursor.column = (c.column + n).min(cols - 1),
            A::MoveUp => self.cursor.line = c.line.saturating_sub(n_i),
            A::MoveDown => self.cursor.line = c.line.saturating_add(n_i),
            A::WordForward => self.cursor = repeat(c, &|p| selection::word_forward(grid, p, small)),
            A::WordBackward => {
                self.cursor = repeat(c, &|p| selection::word_backward(grid, p, small));
            }
            A::WordEnd => self.cursor = repeat(c, &|p| selection::word_end(grid, p, small)),
            A::BigWordForward => {
                self.cursor = repeat(c, &|p| selection::word_forward(grid, p, WordKind::Big));
            }
            A::BigWordBackward => {
                self.cursor = repeat(c, &|p| selection::word_backward(grid, p, WordKind::Big));
            }
            A::BigWordEnd => {
                self.cursor = repeat(c, &|p| selection::word_end(grid, p, WordKind::Big));
            }
            A::LineStart => self.cursor.column = 0,
            A::LineFirstNonBlank => self.cursor.column = selection::first_non_blank(grid, c.line),
            A::LineEnd => self.cursor.column = selection::last_non_blank(grid, c.line),
            A::Top => self.cursor = GridPoint::new(grid.top_line(), 0),
            A::Bottom => self.cursor = GridPoint::new(grid.bottom_line(), 0),
            A::ScreenTop => self.cursor.line = self.view_top + (n_i - 1).min(rows - 1),
            A::ScreenMiddle => self.cursor.line = self.view_top + (rows - 1) / 2,
            A::ScreenBottom => {
                self.cursor.line = self.view_top + rows - 1 - (n_i - 1).min(rows - 1)
            }
            A::HalfPageUp | A::HalfPageDown | A::PageUp | A::PageDown => {
                let page = if matches!(action, A::HalfPageUp | A::HalfPageDown) {
                    (rows / 2).max(1)
                } else {
                    rows
                };
                let delta = page.saturating_mul(n_i);
                let delta = if matches!(action, A::HalfPageUp | A::PageUp) {
                    -delta
                } else {
                    delta
                };
                self.view_top = self.view_top.saturating_add(delta);
                self.cursor.line = c.line.saturating_add(delta);
                self.clamp_view(grid);
            }
            A::ParagraphBackward | A::ParagraphForward => {
                let forward = action == A::ParagraphForward;
                let mut line = c.line;
                for _ in 0..n {
                    line = selection::paragraph(grid, line, forward);
                }
                self.cursor = GridPoint::new(line, 0);
            }
            A::SelectChar | A::SelectLine | A::SelectBlock => {
                let mode = match action {
                    A::SelectChar => SelectionMode::Char,
                    A::SelectLine => SelectionMode::Line,
                    _ => SelectionMode::Block,
                };
                self.selection = match self.selection {
                    Some(s) if s.mode == mode => None,
                    Some(s) => Some(SelectionRange { mode, ..s }),
                    None => Some(SelectionRange::new(mode, c)),
                };
            }
            A::SwapAnchor => self.swap_anchor(),
            A::OpenLink => {
                if self.selection.is_some() {
                    self.swap_anchor();
                } else {
                    return CopyOutcome::OpenLink;
                }
            }
            A::Yank => {
                return match self.selection {
                    Some(sel) => CopyOutcome::Yank(sel.text(grid)),
                    None => {
                        self.message =
                            Some("Nothing selected (v selects, Y yanks the line)".to_owned());
                        CopyOutcome::None
                    }
                };
            }
            A::YankLine => {
                let last = c.line.saturating_add(n_i - 1).min(grid.bottom_line());
                return CopyOutcome::Yank(selection::extract_text(
                    grid,
                    GridPoint::new(c.line, 0),
                    GridPoint::new(last, 0),
                    SelectionMode::Line,
                ));
            }
            A::SearchForward | A::SearchBackward => {
                self.prompt = Some(SearchPrompt {
                    forward: action == A::SearchForward,
                    text: String::new(),
                });
            }
            A::SearchNext | A::SearchPrev => {
                for _ in 0..n.min(MATCH_COUNT_CAP) {
                    if !self.search_again(grid, action == A::SearchNext) {
                        break;
                    }
                }
            }
            A::Exit => return CopyOutcome::Exit,
        }
        if let Some(sel) = &mut self.selection {
            sel.cursor = grid.clamp(self.cursor);
        }
        self.follow(grid);
        if let Some(sel) = &mut self.selection {
            sel.cursor = self.cursor;
        }
        CopyOutcome::None
    }

    fn swap_anchor(&mut self) {
        if let Some(sel) = &mut self.selection {
            sel.swap();
            self.cursor = sel.cursor;
        }
    }

    fn on_prompt_key(&mut self, chord: KeyChord, grid: &dyn TextGrid) -> CopyOutcome {
        let Some(prompt) = &mut self.prompt else {
            return CopyOutcome::None;
        };
        match (chord.code, chord.mods) {
            (KeyCode::Esc, _) | (KeyCode::Char('c'), Mods::CTRL) => self.prompt = None,
            (KeyCode::Backspace, _) => {
                if prompt.text.pop().is_none() {
                    self.prompt = None;
                }
            }
            (KeyCode::Enter, _) => {
                let Some(prompt) = self.prompt.take() else {
                    return CopyOutcome::None;
                };
                let pattern = if prompt.text.is_empty() {
                    match &self.search {
                        Some(s) => s.pattern.clone(),
                        None => return CopyOutcome::None,
                    }
                } else {
                    SearchPattern::new(&prompt.text)
                };
                let count = search::count_matches(grid, &pattern, MATCH_COUNT_CAP);
                self.search = Some(CopySearch {
                    pattern,
                    forward: prompt.forward,
                    current: None,
                    count,
                });
                self.search_again(grid, true);
                self.follow(grid);
            }
            (KeyCode::Char(c), m) if !m.intersects(Mods::CTRL | Mods::ALT) => prompt.text.push(c),
            _ => {}
        }
        CopyOutcome::None
    }

    /// `n` (`same_direction`) or `N`. Returns whether a match was found.
    fn search_again(&mut self, grid: &dyn TextGrid, same_direction: bool) -> bool {
        let Some(s) = &mut self.search else {
            self.message = Some("No previous search".to_owned());
            return false;
        };
        let forward = s.forward == same_direction;
        let dir = if forward {
            Direction::Forward
        } else {
            Direction::Backward
        };
        let error = s.pattern.error().map(str::to_owned);
        let found = search::find_next(grid, &s.pattern, self.cursor, dir);
        let mut msg = error
            .as_ref()
            .map(|e| format!("Invalid regex ({e}): searching literally"));
        let hit = match found {
            Some(hit) => {
                s.current = Some(hit.found);
                self.cursor = hit.found.start;
                if hit.wrapped {
                    msg.get_or_insert_with(|| {
                        if forward {
                            "Search wrapped to the top".to_owned()
                        } else {
                            "Search wrapped to the bottom".to_owned()
                        }
                    });
                }
                true
            }
            None => {
                s.current = None;
                msg.get_or_insert_with(|| format!("Pattern not found: {}", s.pattern.source()));
                false
            }
        };
        self.message = msg;
        if let Some(sel) = &mut self.selection {
            sel.cursor = self.cursor;
        }
        hit
    }

    /// The footer line: the prompt being typed, else the message, else the search count.
    #[must_use]
    pub fn footer(&self) -> Option<String> {
        if let Some(p) = &self.prompt {
            return Some(format!("{}{}", if p.forward { '/' } else { '?' }, p.text));
        }
        if let Some(m) = &self.message {
            return Some(m.clone());
        }
        let s = self.search.as_ref()?;
        let (n, capped) = s.count;
        let plus = if capped { "+" } else { "" };
        Some(format!(
            "{}{} · {n}{plus} match{}",
            if s.forward { '/' } else { '?' },
            s.pattern.source(),
            if n == 1 && !capped { "" } else { "es" }
        ))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use strum::IntoEnumIterator;
    use sverb_term::selection::VecGrid;

    use super::*;

    const SEPS: &str = " ,│`|:\"'()[]{}<>";

    fn p(line: i32, column: usize) -> GridPoint {
        GridPoint::new(line, column)
    }

    fn keys(state: &mut CopyState, grid: &dyn TextGrid, chords: &str) -> Vec<CopyOutcome> {
        let map = CopyKeymap::default();
        KeyChord::parse_sequence(chords)
            .unwrap()
            .into_iter()
            .map(|c| state.on_key(c, &map, grid, SEPS))
            .collect()
    }

    #[test]
    fn actions_match_the_config_list() {
        let ours: Vec<&str> = CopyAction::iter().map(Into::into).collect();
        assert_eq!(ours, sverb_core::config::COPY_ACTIONS);
        for (keys, _) in COPY_DEFAULTS {
            assert!(KeyChord::parse_sequence(keys).is_ok(), "{keys}");
        }
    }

    /// `5j` moves 5 lines, `3w` moves 3 words.
    #[test]
    fn t11_counts() {
        let lines: Vec<String> = (0..20).map(|i| format!("a{i} b c d e")).collect();
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let g = VecGrid::from_lines(&refs, 20, 10);
        let mut s = CopyState::enter(SessionId(1), &g, 10, 0, 10, p(0, 0));
        keys(&mut s, &g, "5 j");
        assert_eq!(s.cursor, p(5, 0));
        keys(&mut s, &g, "3 w");
        assert_eq!(s.cursor, p(5, 8), "a15 b c |d");
        keys(&mut s, &g, "1 2 k");
        assert_eq!(s.cursor, p(-7, 8));
        assert_eq!(s.view_top, -7, "the view follows the cursor");
        keys(&mut s, &g, "g g");
        assert_eq!(s.cursor, p(-10, 0));
        keys(&mut s, &g, "G");
        assert_eq!((s.cursor, s.view_top), (p(9, 0), 0));
        keys(&mut s, &g, "$");
        assert_eq!(s.cursor, p(9, 10));
        keys(&mut s, &g, "0 H");
        assert_eq!(s.cursor, p(0, 0));
        keys(&mut s, &g, "ctrl-u");
        assert_eq!((s.cursor.line, s.view_top), (-5, -5));
        // Unbound keys and an Esc-less `g` then `x` do nothing harmful.
        keys(&mut s, &g, "g x z");
        assert_eq!(s.cursor.line, -5);
    }

    #[test]
    fn selection_yank_and_exit() {
        let g = VecGrid::from_lines(&["hello world", "second line"], 20, 2);
        let mut s = CopyState::enter(SessionId(1), &g, 0, 0, 2, p(0, 0));
        assert_eq!(keys(&mut s, &g, "y"), [CopyOutcome::None]);
        assert!(s.message.is_some());
        let out = keys(&mut s, &g, "v e y");
        assert_eq!(out.last(), Some(&CopyOutcome::Yank("hello".to_owned())));
        let mut s = CopyState::enter(SessionId(1), &g, 0, 0, 2, p(0, 3));
        let out = keys(&mut s, &g, "V j y");
        assert_eq!(
            out.last(),
            Some(&CopyOutcome::Yank("hello world\nsecond line".to_owned()))
        );
        let out = keys(&mut s, &g, "Y");
        assert_eq!(out, [CopyOutcome::Yank("second line".to_owned())]);
        // `o` with a selection swaps its ends; without one it asks to open a link.
        let mut s = CopyState::enter(SessionId(1), &g, 0, 0, 2, p(0, 0));
        keys(&mut s, &g, "v w o");
        assert_eq!(s.cursor, p(0, 0));
        assert_eq!(s.selection.unwrap().anchor, p(0, 6));
        keys(&mut s, &g, "v");
        assert!(s.selection.is_none(), "v again clears");
        assert_eq!(keys(&mut s, &g, "o"), [CopyOutcome::OpenLink]);
        for exit in ["q", "esc", "ctrl-c"] {
            assert_eq!(keys(&mut s, &g, exit), [CopyOutcome::Exit]);
        }
    }

    #[test]
    fn search_prompt_and_messages() {
        let g = VecGrid::from_lines(&["foo 1", "bar", "foo 2", "$"], 10, 4);
        let mut s = CopyState::enter(SessionId(1), &g, 0, 0, 4, p(3, 0));
        keys(&mut s, &g, "? f o o enter");
        assert_eq!(s.cursor, p(2, 0));
        assert_eq!(s.footer().unwrap(), "?foo · 2 matches");
        keys(&mut s, &g, "n");
        assert_eq!(s.cursor, p(0, 0));
        keys(&mut s, &g, "n");
        assert_eq!(s.cursor, p(2, 0));
        assert_eq!(s.footer().unwrap(), "Search wrapped to the bottom");
        keys(&mut s, &g, "N");
        assert_eq!(s.cursor, p(0, 0));
        keys(&mut s, &g, "/ ( enter");
        assert!(
            s.footer().unwrap().starts_with("Invalid regex"),
            "{:?}",
            s.footer()
        );
        keys(&mut s, &g, "/ z z enter");
        assert_eq!(s.footer().unwrap(), "Pattern not found: zz");
        keys(&mut s, &g, "/ x backspace backspace");
        assert!(s.prompt.is_none());
    }

    #[test]
    fn rebase_keeps_the_view_on_the_same_content() {
        let g = VecGrid::from_lines(&["a", "b", "c"], 5, 3);
        let mut s = CopyState::enter(SessionId(1), &g, 0, 0, 3, p(2, 0));
        keys(&mut s, &g, "v k");
        s.rebase(4);
        assert_eq!((s.view_top, s.cursor), (-4, p(-3, 0)));
        assert_eq!(s.selection.unwrap().anchor, p(-2, 0));
        assert_eq!((s.scroll_offset(), s.new_lines()), (4, 4));
    }

    #[test]
    fn config_overrides() {
        let mut config = Config::default();
        let copy = config.keys.0.entry("copy".to_owned()).or_default();
        copy.insert("x".into(), "yank".to_owned());
        copy.insert("y".into(), "none".to_owned());
        let map = CopyKeymap::from_config(&config);
        let x = KeyChord::char('x');
        assert_eq!(map.lookup(&[x]), CopyLookup::Action(CopyAction::Yank));
        assert_eq!(map.lookup(&[KeyChord::char('y')]), CopyLookup::Unbound);
        assert_eq!(map.lookup(&[KeyChord::char('g')]), CopyLookup::Prefix);
    }
}
