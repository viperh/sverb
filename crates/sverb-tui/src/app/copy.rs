//! M3-04: copy mode, mouse selection and hyperlinks in the reducer (SPEC §7.1, §7.3, §8.2,
//! §17).
//!
//! - **Copy mode** (`leader [`): [`CopyState`](crate::views::sessions::copy_mode::CopyState)
//!   does the motions, selections and searches; this module gives it the focused pane's grid
//!   (the emulator is locked only for the duration of one key), turns its outcomes into
//!   effects (`CopyToClipboard`, the "Open link?" dialog) and leaves the mode.
//! - **Mouse** (`SessionEvent::Mouse`: the remote didn't capture it, or Shift was held; and
//!   every mouse event in copy mode): drag selects character-wise, a double click a word
//!   (`terminal.word_separators`), a triple click the line; releasing copies the selection
//!   with a "Copied N chars" toast. The wheel scrolls the scrollback (Terminal mode) or the
//!   frozen view (copy mode). Clicks count as one double/triple click while
//!   `TimerKind::MultiClick` is pending.
//! - **Links**: OSC 8 hyperlinks and auto-detected URLs under the mouse (hover) or the copy
//!   cursor are underlined and shown in the status bar. Opening needs an explicit key (`o` in
//!   copy mode, ctrl-click) **and** a confirmation dialog that shows the URL; only then is
//!   `Effect::OpenUrl` issued.
//!
//! Reading the grid: [`App::with_terms`] gives the reducer read access to the emulators (the
//! session registry at runtime, a fake in tests). Without it copy mode still toggles but only
//! the exit keys work.

use std::{fmt, sync::Arc, time::Duration};

use sverb_conn::SharedEmulator;
use sverb_term::{
    Emulator, GridPoint, Match, ViewState,
    modes::input::{KeyMods, MouseAction, MouseButton, MouseInput},
    search,
    selection::{self, EmulatorGrid, SelectionMode, SelectionRange, TextGrid},
};

use super::{App, Config, Effect, SessionId, TimerKind, ToastLevel};
use crate::{
    keymap::chord::KeyChord,
    views::{
        dialogs::ModalDialog,
        sessions::copy_mode::{CopyKeymap, CopyOutcome, CopyState},
    },
    widgets::{
        dialog::{Button, Modal},
        terminal_pane::{PaneDecor, PaneSource},
    },
};

/// The double/triple-click window.
pub const MULTI_CLICK: Duration = Duration::from_millis(400);
/// Lines per wheel step.
pub const WHEEL_LINES: usize = 3;

/// Read access to the emulators. Compares equal to any other (it is a handle, not state).
#[derive(Clone, Default)]
pub struct TermAccess(Option<Arc<dyn PaneSource + Send + Sync>>);

impl fmt::Debug for TermAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.0.is_some() {
            "TermAccess(Some)"
        } else {
            "TermAccess(None)"
        })
    }
}

impl PartialEq for TermAccess {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for TermAccess {}

/// A mouse selection in Terminal mode (not copy mode).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MouseSelection {
    /// The pane.
    pub session: SessionId,
    /// The selection (points valid at `history`).
    pub range: SelectionRange,
    /// Scrollback length the points refer to.
    pub history: usize,
    /// The mouse moved since the press (a plain click selects nothing).
    pub moved: bool,
    /// 1, 2 (word) or 3 (line).
    pub clicks: u8,
}

/// The link under the mouse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoverLink {
    /// The pane.
    pub session: SessionId,
    /// Its cells (valid at `history`).
    pub found: Match,
    /// The URL.
    pub url: String,
    /// Scrollback length the cells refer to.
    pub history: usize,
}

/// Copy-mode and mouse state of [`App`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CopyUi {
    /// Emulator access.
    pub(crate) terms: TermAccess,
    /// The copy-mode key table.
    pub(crate) keymap: CopyKeymap,
    /// Copy mode of the focused pane (valid while `input.copy_mode` is on).
    pub(crate) state: Option<CopyState>,
    /// The URL under the copy cursor (status bar).
    pub(crate) cursor_link: Option<String>,
    /// A Terminal-mode mouse selection.
    pub(crate) mouse: Option<MouseSelection>,
    /// The link under the mouse.
    pub(crate) hover: Option<HoverLink>,
    /// Last press (pane, point, click count) while the multi-click window is open.
    pub(crate) last_press: Option<(SessionId, GridPoint, u8)>,
}

impl CopyUi {
    /// The state for a configuration (`[keys.copy]`).
    pub fn new(config: &Config) -> Self {
        Self {
            keymap: CopyKeymap::from_config(config),
            ..Self::default()
        }
    }
}

/// Lines between two scrollback lengths (new output while a selection was shown).
fn delta(now: usize, then: usize) -> i32 {
    i32::try_from(now).unwrap_or(i32::MAX) - i32::try_from(then).unwrap_or(i32::MAX)
}

fn shift(m: Match, d: i32) -> Match {
    Match {
        start: GridPoint::new(m.start.line - d, m.start.column),
        end: GridPoint::new(m.end.line - d, m.end.column),
    }
}

/// The OSC 8 link (with its run of cells on the row) or the auto-detected URL at `p`.
fn link_at(emu: &dyn Emulator, p: GridPoint) -> Option<(Match, String)> {
    let grid = EmulatorGrid(emu);
    let p = grid.clamp(p);
    if let Some(link) = emu.hyperlink_at(p) {
        let same =
            |col: usize| emu.hyperlink_at(GridPoint::new(p.line, col)).as_ref() == Some(&link);
        let mut start = p.column;
        while start > 0 && same(start - 1) {
            start -= 1;
        }
        let mut end = p.column;
        while end + 1 < grid.columns() && same(end + 1) {
            end += 1;
        }
        let found = Match {
            start: GridPoint::new(p.line, start),
            end: GridPoint::new(p.line, end),
        };
        return Some((found, link.uri));
    }
    search::url_at(&grid, p)
}

impl App {
    /// Give the reducer read access to session emulators (the runtime passes the session
    /// registry; tests a fake).
    #[must_use]
    pub fn with_terms(mut self, terms: Arc<dyn PaneSource + Send + Sync>) -> Self {
        self.copy.terms = TermAccess(Some(terms));
        self
    }

    // M7-01: also read by `app/history.rs`.
    pub(crate) fn emulator(&self, id: SessionId) -> Option<SharedEmulator> {
        self.copy.terms.0.as_ref()?.emulator(id)
    }

    /// `[keys.copy]` changed.
    pub(crate) fn copy_on_config(&mut self, config: &Config) {
        self.copy.keymap = CopyKeymap::from_config(config);
    }

    /// `leader [` (called after `input.copy_mode` was set): start at the terminal cursor
    /// with the view frozen where the pane is scrolled to.
    pub(crate) fn enter_copy_mode(&mut self) {
        self.copy.state = None;
        self.copy.cursor_link = None;
        self.copy.mouse = None;
        self.copy.hover = None;
        let Some(id) = self.focused_session() else {
            return;
        };
        let Some(emu) = self.emulator(id) else {
            return;
        };
        let offset = self.pane(id).scroll_offset;
        let term = emu.lock();
        let grid = EmulatorGrid(&**term);
        let state = CopyState::enter(
            id,
            &grid,
            term.scrollback_len(),
            offset,
            usize::from(term.size().1),
            term.cursor().point,
        );
        self.copy.cursor_link = link_at(&**term, state.cursor).map(|(_, url)| url);
        drop(term);
        self.copy.state = Some(state);
    }

    /// Leave copy mode: back to Terminal mode and the live view.
    pub(crate) fn exit_copy_mode(&mut self) {
        if let Some(state) = self.copy.state.take() {
            let mut info = self.pane(state.session);
            if info.scroll_offset != 0 {
                info.scroll_offset = 0;
                self.panes.insert(state.session, info);
            }
        }
        self.copy.cursor_link = None;
        self.input.copy_mode = false;
        self.needs_redraw = true;
    }

    /// A key in copy mode. `false` when there is no copy state (no emulator access): the
    /// caller then handles the exit keys alone.
    pub(crate) fn copy_mode_key(&mut self, chord: KeyChord, effects: &mut Vec<Effect>) -> bool {
        let Some(mut state) = self.copy.state.take() else {
            return false;
        };
        let Some(emu) = self
            .emulator(state.session)
            .filter(|_| self.focused_session() == Some(state.session))
        else {
            return false;
        };
        let term = emu.lock();
        let grid = EmulatorGrid(&**term);
        state.rebase(term.scrollback_len());
        state.rows = usize::from(term.size().1).max(1);
        let seps = self.config.terminal.word_separators.clone();
        let outcome = state.on_key(chord, &self.copy.keymap, &grid, &seps);
        let link = link_at(&**term, state.cursor);
        drop(term);
        self.copy.cursor_link = link.as_ref().map(|(_, url)| url.clone());
        self.copy.state = Some(state);
        self.needs_redraw = true;
        match outcome {
            CopyOutcome::None => {}
            CopyOutcome::Exit => self.exit_copy_mode(),
            CopyOutcome::Yank(text) => {
                self.yank(text, effects);
                self.exit_copy_mode();
            }
            CopyOutcome::OpenLink => match link {
                Some((_, url)) => self.confirm_open_link(url, effects),
                None => {
                    self.push_toast(
                        ToastLevel::Info,
                        "No link under the cursor".to_owned(),
                        effects,
                    );
                }
            },
        }
        true
    }

    /// Copy `text` with a "Copied N chars" toast (nothing for an empty selection).
    fn yank(&mut self, text: String, effects: &mut Vec<Effect>) {
        let n = text.chars().count();
        if n == 0 {
            self.push_toast(ToastLevel::Info, "Nothing to copy".to_owned(), effects);
            return;
        }
        self.copy_to_clipboard(text, effects);
        let s = if n == 1 { "" } else { "s" };
        self.push_toast(ToastLevel::Info, format!("Copied {n} char{s}"), effects);
    }

    /// "Open link?" with the URL; `OpenUrl` only on "Open". Disallowed schemes are refused
    /// with a toast (the opener refuses them too).
    pub(crate) fn confirm_open_link(&mut self, url: String, effects: &mut Vec<Effect>) {
        let scheme_ok = url.split_once(':').is_some_and(|(scheme, _)| {
            ["http", "https", "ftp", "mailto"]
                .iter()
                .any(|s| s.eq_ignore_ascii_case(scheme))
        });
        let shown: String = url.chars().filter(|c| !c.is_control()).collect();
        if !scheme_ok {
            self.push_toast(
                ToastLevel::Warning,
                format!("Not opening this link (unsupported scheme): {shown}"),
                effects,
            );
            return;
        }
        let modal = Modal::confirm(
            "Open link?",
            &format!("{shown}\n\nThis opens the link in your browser."),
            vec![
                Button::new("open", "Open", 'o'),
                Button::new("cancel", "Cancel", 'c').safe(),
            ],
            1,
            true,
        );
        self.push_modal(
            ModalDialog::new(modal).on("button:open", vec![Effect::OpenUrl(url)]),
            effects,
        );
    }

    /// A key went to the session (Terminal mode): drop the mouse selection and go back to
    /// the live view.
    pub(crate) fn copy_on_terminal_key(&mut self, id: SessionId) {
        if self.copy.mouse.take().is_some() {
            self.needs_redraw = true;
        }
        let mut info = self.pane(id);
        if info.scroll_offset != 0 {
            info.scroll_offset = 0;
            self.panes.insert(id, info);
            self.needs_redraw = true;
        }
    }

    /// The double/triple-click window closed.
    pub(crate) fn on_multi_click_timer(&mut self) {
        self.copy.last_press = None;
    }

    /// The URL under the copy cursor (copy mode) or the mouse, for the status bar.
    pub(crate) fn link_hint(&self) -> Option<String> {
        let id = self.focused_session()?;
        if self.input.copy_mode {
            return self.copy.cursor_link.clone();
        }
        self.copy
            .hover
            .as_ref()
            .filter(|h| h.session == id)
            .map(|h| h.url.clone())
    }

    /// A mouse event for sverb inside pane `id` (pane-relative cells): from the session
    /// (`SessionEvent::Mouse`) in Terminal mode, or straight from the input in copy mode.
    pub(crate) fn copy_on_mouse(
        &mut self,
        id: SessionId,
        ev: MouseInput,
        effects: &mut Vec<Effect>,
    ) {
        let Some(emu) = self.emulator(id) else {
            return;
        };
        let copy_mode = self.input.copy_mode
            && self.focused_session() == Some(id)
            && self.copy.state.as_ref().is_some_and(|s| s.session == id);
        let term = emu.lock();
        let history = term.scrollback_len();
        let grid = EmulatorGrid(&**term);
        let offset = i32::try_from(self.pane(id).scroll_offset.min(history)).unwrap_or(0);
        let mut state = if copy_mode {
            self.copy.state.take().map(|mut s| {
                s.rebase(history);
                s
            })
        } else {
            None
        };
        let point = match &state {
            Some(s) => s.point_at(ev.col, ev.row),
            None => GridPoint::new(i32::from(ev.row) - offset, usize::from(ev.col)),
        };
        let point = grid.clamp(point);
        let seps = self.config.terminal.word_separators.clone();
        let mut copy_text = None;
        let mut open = None;
        match ev.action {
            MouseAction::Press(MouseButton::Left) if ev.mods.contains(KeyMods::CTRL) => {
                open = Some(link_at(&**term, point));
            }
            MouseAction::Press(MouseButton::Left) => {
                let clicks = match self.copy.last_press {
                    Some((s, p, n)) if s == id && p == point => (n % 3) + 1,
                    _ => 1,
                };
                self.copy.last_press = Some((id, point, clicks));
                effects.push(Effect::ScheduleTimer {
                    kind: TimerKind::MultiClick,
                    after: MULTI_CLICK,
                });
                let range = click_range(&grid, point, clicks, &seps);
                match &mut state {
                    Some(s) => {
                        s.cursor = range.cursor;
                        s.selection = (clicks > 1).then_some(range);
                    }
                    None => {
                        self.copy.mouse = Some(MouseSelection {
                            session: id,
                            range,
                            history,
                            moved: false,
                            clicks,
                        });
                    }
                }
            }
            MouseAction::Drag(MouseButton::Left) => match &mut state {
                Some(s) => {
                    let anchor = s.selection.map_or(s.cursor, |r| r.anchor);
                    s.selection = Some(SelectionRange {
                        anchor,
                        cursor: point,
                        mode: s.selection.map_or(SelectionMode::Char, |r| r.mode),
                    });
                    s.cursor = point;
                }
                None => {
                    if let Some(sel) = self.copy.mouse.as_mut().filter(|m| m.session == id) {
                        let d = delta(history, sel.history);
                        sel.range = sel.range.shifted(-d);
                        sel.history = history;
                        sel.range.cursor = point;
                        sel.moved = true;
                    }
                }
            },
            MouseAction::Release(MouseButton::Left) if state.is_none() => {
                if let Some(sel) = self.copy.mouse.as_ref().filter(|m| m.session == id)
                    && (sel.moved || sel.clicks > 1)
                {
                    let d = delta(history, sel.history);
                    copy_text = Some(sel.range.shifted(-d).text(&grid));
                } else {
                    self.copy.mouse = None;
                }
            }
            MouseAction::Move => {
                let hover = link_at(&**term, point).map(|(found, url)| HoverLink {
                    session: id,
                    found,
                    url,
                    history,
                });
                if hover != self.copy.hover {
                    self.copy.hover = hover;
                    self.needs_redraw = true;
                }
            }
            MouseAction::WheelUp | MouseAction::WheelDown => {
                let up = ev.action == MouseAction::WheelUp;
                match &mut state {
                    Some(s) => {
                        let lines = i32::try_from(WHEEL_LINES).unwrap_or(3);
                        s.scroll(&grid, if up { -lines } else { lines });
                    }
                    None => {
                        let mut info = self.pane(id);
                        let next = if up {
                            (info.scroll_offset + WHEEL_LINES).min(history)
                        } else {
                            info.scroll_offset.saturating_sub(WHEEL_LINES)
                        };
                        if next != info.scroll_offset {
                            info.scroll_offset = next;
                            self.panes.insert(id, info);
                        }
                    }
                }
            }
            _ => {}
        }
        if let Some(s) = &state {
            self.copy.cursor_link = link_at(&**term, s.cursor).map(|(_, url)| url);
        }
        drop(term);
        if state.is_some() {
            self.copy.state = state;
        }
        self.needs_redraw = true;
        if let Some(text) = copy_text {
            self.yank(text, effects);
        }
        match open {
            Some(Some((_, url))) => self.confirm_open_link(url, effects),
            Some(None) => {
                self.push_toast(ToastLevel::Info, "No link here".to_owned(), effects);
            }
            None => {}
        }
    }

    /// The copy-mode / mouse overlays for pane `id`, while its emulator is locked for the
    /// draw (`TerminalPane::render_with`).
    pub(crate) fn pane_decor(
        &self,
        id: SessionId,
        emu: &dyn Emulator,
        view: &mut ViewState,
    ) -> PaneDecor {
        let history = emu.scrollback_len();
        let grid = EmulatorGrid(emu);
        let cols = grid.columns();
        let state = self.copy.state.as_ref().filter(|s| {
            self.input.copy_mode && s.session == id && self.focused_session() == Some(id)
        });
        if let Some(state) = state {
            let s = state.rebased(history);
            view.scroll_offset = s.scroll_offset();
            view.selection = s.selection.map(|r| r.to_view(cols));
            if let Some(search) = &s.search {
                let rows = i32::try_from(s.rows).unwrap_or(1);
                view.search_matches = search::matches_between(
                    &grid,
                    &search.pattern,
                    s.view_top,
                    s.view_top + rows - 1,
                );
                view.current_match = search.current;
            }
            view.hovered_link = link_at(emu, s.cursor).map(|(m, _)| m);
            let new = s.new_lines();
            let badge = if new > 0 {
                format!("COPY · +{new} line{}", if new == 1 { "" } else { "s" })
            } else {
                "COPY".to_owned()
            };
            // The copy cursor is drawn relative to the view the renderer uses.
            return PaneDecor {
                copy_cursor: Some(s.cursor),
                badge: Some(badge),
                footer: s.footer(),
            };
        }
        if let Some(sel) = self.copy.mouse.as_ref().filter(|m| m.session == id)
            && (sel.moved || sel.clicks > 1)
        {
            let d = delta(history, sel.history);
            view.selection = Some(sel.range.shifted(-d).to_view(cols));
        }
        if let Some(h) = self.copy.hover.as_ref().filter(|h| h.session == id) {
            view.hovered_link = Some(shift(h.found, delta(history, h.history)));
        }
        PaneDecor::default()
    }
}

/// The selection a click starts: a point, a word (double) or a line (triple).
fn click_range(grid: &dyn TextGrid, p: GridPoint, clicks: u8, seps: &str) -> SelectionRange {
    match clicks {
        2 => {
            let (start, end) = selection::word_at(grid, p, seps);
            SelectionRange {
                anchor: start,
                cursor: end,
                mode: SelectionMode::Char,
            }
        }
        3 => {
            let (first, last) = selection::logical_bounds(grid, p.line);
            SelectionRange {
                anchor: GridPoint::new(first, 0),
                cursor: GridPoint::new(last, grid.columns().saturating_sub(1)),
                mode: SelectionMode::Line,
            }
        }
        _ => SelectionRange::new(SelectionMode::Char, p),
    }
}

#[cfg(test)]
#[path = "copy_tests.rs"]
mod tests;
