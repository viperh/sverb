//! M3-01: split resizing, resize mode, mouse drags of split borders, zoom, tab rename
//! and reorder, and `equalize_panes` (SPEC §8.3, §8.4; `03-KEYBINDINGS.md` §3.1 A6,
//! §4.1, §4.4).
//!
//! - **Resize** (`leader H J K L`): **one** step ([`Layout::resize`]: 5% of the nearest
//!   matching split, at least one cell, clamped to 5 × 2 cells of content). There is no
//!   timed repeat: a plain `H` right after `leader H` goes to the session (A6).
//! - **Resize mode** (`leader r`): `h j k l`/arrows one step, `H J K L` three steps, `=`
//!   equalizes, `Esc`/`Enter` leave; it also ends after [`RESIZE_MODE_IDLE`] without a
//!   key. While it is on, **every** key is swallowed (never sent to the session, not
//!   even the leader) and the status bar's mode segment shows `RESIZE`.
//! - **Mouse** (with `ui.mouse`): pressing on a split border (the two border cells of
//!   the panes on either side) and dragging moves it live. The remote sizes follow
//!   through the 50 ms resize debounce of `app/tabs.rs` (one `ResizeSession` per
//!   affected pane once the drag pauses).
//! - **Zoom** (`leader z`): the focused pane takes the whole session area (`Z` in the
//!   tab bar). Hidden panes keep their sessions and are **not** resized, so programs in
//!   them see no `SIGWINCH` while zoomed and keep their pre-zoom size. Moving focus
//!   (`leader h j k l`), resizing, splitting or closing the zoomed pane unzooms.
//! - **Rename** (`leader ,`): a prompt prefilled with the current title; an empty name
//!   clears the override (back to the host label or OSC title).
//! - **Reorder** (`leader <` / `leader >`): move the current tab (no wrap); tab numbers
//!   follow the order.
//! - **Equalize** (`equalize_panes`, unbound by default, in the palette): all splits of
//!   the current tab get equal shares.
//!
//! [`Layout::resize`]: sverb_core::layout::Layout::resize

use std::time::Duration;

use crossterm::event::{KeyCode, KeyEvent, MouseButton, MouseEvent, MouseEventKind};
use sverb_core::layout::Border;

use super::{App, Effect, Focus, TimerKind, ToastLevel};
use crate::keymap::{
    action::ActionName,
    chord::{KeyChord, Mods},
    leader::KeyState,
};
use crate::views::{
    DialogId, DialogKind, MainView,
    dialogs::ModalDialog,
    sessions::{Direction, SplitDir, Tab, TabId, panes::to_core},
};
use crate::widgets::dialog::{Modal, ModalAnswer};

/// Resize mode ends after this long without a key (`03-KEYBINDINGS.md` §4.4).
pub const RESIZE_MODE_IDLE: Duration = Duration::from_secs(10);

/// Steps of `H J K L` in resize mode.
pub const BIG_STEP: u16 = 3;

/// The status-bar hint while resize mode is on.
pub const RESIZE_HINT: &str = "hjkl resize · HJKL ×3 · = equalize · esc done";

/// Longest tab title kept.
const MAX_TITLE_CHARS: usize = 256;

/// Resize mode, a border drag and the rename prompt (`Tabs::pane_ops`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PaneOps {
    /// Resize mode is on.
    pub resize_mode: bool,
    /// A split border being dragged with the mouse.
    pub drag: Option<BorderDrag>,
    /// The open rename prompt and the tab it renames.
    pub rename: Option<(DialogId, TabId)>,
}

/// A mouse drag of a split border.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BorderDrag {
    /// The tab.
    pub tab: TabId,
    /// The border.
    pub border: Border,
    /// Where the press was, relative to the border's position (keeps the grab point
    /// under the pointer).
    pub grab: i32,
}

impl App {
    /// The M3-01 actions. Returns `false` for actions it doesn't own.
    pub(crate) fn apply_pane_ops_action(
        &mut self,
        action: ActionName,
        effects: &mut Vec<Effect>,
    ) -> bool {
        use ActionName as A;
        match action {
            A::ResizeLeft => self.resize_action(Direction::Left, effects),
            A::ResizeRight => self.resize_action(Direction::Right, effects),
            A::ResizeUp => self.resize_action(Direction::Up, effects),
            A::ResizeDown => self.resize_action(Direction::Down, effects),
            A::ResizeMode => self.enter_resize_mode(effects),
            A::ZoomPane => self.toggle_zoom(effects),
            A::RenameTab => self.open_rename_tab(effects),
            A::MoveTabLeft => self.move_tab(false),
            A::MoveTabRight => self.move_tab(true),
            A::EqualizePanes => {
                if let Some(tab) = self.shown_tab_mut() {
                    tab.layout = tab.layout.equalize();
                    self.needs_redraw = true;
                } else {
                    self.no_pane_toast(effects);
                }
            }
            _ => return false,
        }
        true
    }

    /// The active tab while the session area shows it.
    fn shown_tab_mut(&mut self) -> Option<&mut Tab> {
        if self.shell.main_view != MainView::Sessions {
            return None;
        }
        self.tabs.list.get_mut(self.tabs.active)
    }

    fn no_pane_toast(&mut self, effects: &mut Vec<Effect>) {
        self.push_toast(ToastLevel::Info, "No pane to resize".to_owned(), effects);
    }

    fn resize_action(&mut self, dir: Direction, effects: &mut Vec<Effect>) {
        if !self.resize_focused(dir, 1) {
            self.no_pane_toast(effects);
        }
    }

    /// Resize the focused pane of the shown tab (unzooming it). Returns whether a tab
    /// was there.
    fn resize_focused(&mut self, dir: Direction, steps: u16) -> bool {
        let main = to_core(self.shell_rects().main);
        let Some(tab) = self.shown_tab_mut() else {
            return false;
        };
        tab.zoomed = None;
        tab.layout = tab.layout.resize(tab.focused, dir, main, steps);
        self.needs_redraw = true;
        true
    }

    // ------------------------------------------------------------------ resize mode

    fn enter_resize_mode(&mut self, effects: &mut Vec<Effect>) {
        if self.shown_tab_mut().is_none() || !matches!(self.focus, Focus::Session(_)) {
            self.no_pane_toast(effects);
            return;
        }
        self.tabs.pane_ops.resize_mode = true;
        effects.push(Effect::ScheduleTimer {
            kind: TimerKind::ResizeModeIdle,
            after: RESIZE_MODE_IDLE,
        });
        self.needs_redraw = true;
    }

    /// Leave resize mode (`Esc`/`Enter`, the idle timer, or the pane went away).
    pub(crate) fn exit_resize_mode(&mut self, effects: &mut Vec<Effect>) {
        if std::mem::take(&mut self.tabs.pane_ops.resize_mode) {
            effects.push(Effect::CancelTimer(TimerKind::ResizeModeIdle));
            self.needs_redraw = true;
        }
    }

    /// Whether the status bar shows `RESIZE`.
    pub(crate) fn resize_mode_shown(&self) -> bool {
        self.tabs.pane_ops.resize_mode
            && self.dialogs.is_empty()
            && matches!(self.focus, Focus::Session(_))
            && self.shell.main_view == MainView::Sessions
            && self.active_tab().is_some()
    }

    /// Keys for the rename prompt and resize mode, before the normal routing. Returns
    /// whether the key was taken.
    pub(crate) fn pane_ops_on_key(&mut self, key: KeyEvent, effects: &mut Vec<Effect>) -> bool {
        if self.rename_on_key(key) {
            return true;
        }
        if !self.tabs.pane_ops.resize_mode || !self.dialogs.is_empty() {
            return false;
        }
        if !self.resize_mode_shown() {
            // The pane or the session area went away: the mode ends, the key routes
            // normally.
            self.exit_resize_mode(effects);
            return false;
        }
        let chord = KeyChord::from_key_event(&key);
        let plain = chord.mods == Mods::NONE || chord.mods == Mods::SHIFT;
        let step = |c: char| match c.to_ascii_lowercase() {
            'h' => Some(Direction::Left),
            'j' => Some(Direction::Down),
            'k' => Some(Direction::Up),
            'l' => Some(Direction::Right),
            _ => None,
        };
        match chord.code {
            KeyCode::Esc | KeyCode::Enter if chord.mods == Mods::NONE => {
                self.exit_resize_mode(effects);
                return true;
            }
            KeyCode::Char(c) if plain && step(c).is_some() => {
                let steps = if c.is_ascii_uppercase() { BIG_STEP } else { 1 };
                if let Some(dir) = step(c) {
                    self.resize_focused(dir, steps);
                }
            }
            KeyCode::Left if chord.mods == Mods::NONE => {
                self.resize_focused(Direction::Left, 1);
            }
            KeyCode::Right if chord.mods == Mods::NONE => {
                self.resize_focused(Direction::Right, 1);
            }
            KeyCode::Up if chord.mods == Mods::NONE => {
                self.resize_focused(Direction::Up, 1);
            }
            KeyCode::Down if chord.mods == Mods::NONE => {
                self.resize_focused(Direction::Down, 1);
            }
            KeyCode::Char('=') if plain => {
                if let Some(tab) = self.shown_tab_mut() {
                    tab.layout = tab.layout.equalize();
                    self.needs_redraw = true;
                }
            }
            // Everything else is swallowed (K-06).
            _ => {}
        }
        // Idle is counted from the last key.
        effects.push(Effect::ScheduleTimer {
            kind: TimerKind::ResizeModeIdle,
            after: RESIZE_MODE_IDLE,
        });
        true
    }

    // ------------------------------------------------------------------ zoom

    fn toggle_zoom(&mut self, effects: &mut Vec<Effect>) {
        let Some(tab) = self.shown_tab_mut() else {
            self.push_toast(ToastLevel::Info, "No pane to zoom".to_owned(), effects);
            return;
        };
        if tab.zoomed.is_some() {
            tab.zoomed = None;
        } else if tab.panes.len() > 1 {
            tab.zoomed = Some(tab.focused);
        } else {
            self.push_toast(
                ToastLevel::Info,
                "Only one pane in this tab".to_owned(),
                effects,
            );
            return;
        }
        self.needs_redraw = true;
    }

    // ------------------------------------------------------------------ tabs

    fn move_tab(&mut self, right: bool) {
        let i = self.tabs.active;
        let n = self.tabs.list.len();
        let j = if right { i + 1 } else { i.wrapping_sub(1) };
        if i >= n || j >= n {
            return; // no wrap
        }
        self.tabs.list.swap(i, j);
        self.tabs.active = j;
        self.needs_redraw = true;
    }

    fn open_rename_tab(&mut self, effects: &mut Vec<Effect>) {
        let i = self.tabs.active;
        let (Some(tab), Some(item)) = (self.tabs.list.get(i), self.tab_items().get(i).cloned())
        else {
            self.push_toast(ToastLevel::Info, "No tab to rename".to_owned(), effects);
            return;
        };
        let tab = tab.id;
        let mut modal = Modal::prompt(
            "Rename tab",
            "An empty name restores the default title.",
            "Name:",
            false,
        );
        modal.paste(&item.label);
        let id = self.push_modal(ModalDialog::new(modal), effects);
        self.tabs.pane_ops.rename = Some((id, tab));
    }

    /// The rename prompt's keys (the leader still works in it).
    fn rename_on_key(&mut self, key: KeyEvent) -> bool {
        let Some((id, tab)) = self.tabs.pane_ops.rename else {
            return false;
        };
        if !self.dialogs.iter().any(|d| d.id == id) {
            self.tabs.pane_ops.rename = None;
            return false;
        }
        let chord = KeyChord::from_key_event(&key);
        if self.dialogs.last().is_none_or(|d| d.id != id)
            || matches!(self.input.keys, KeyState::Pending(_))
            || chord == self.keymap.leader()
        {
            return false;
        }
        let Some(DialogKind::Modal(m)) = self.dialogs.last_mut().map(|d| &mut d.kind) else {
            return false;
        };
        self.needs_redraw = true;
        let Some(answer) = m.modal.handle_key(&key) else {
            return true;
        };
        self.dialogs.pop();
        self.tabs.pane_ops.rename = None;
        self.mode = self.derive_mode();
        if let ModalAnswer::Text(text) = answer {
            self.rename_tab(tab, &text);
        }
        true
    }

    /// Set (or, with an empty name, clear) a tab's title override.
    pub(crate) fn rename_tab(&mut self, tab: TabId, name: &str) {
        let name: String = name.trim().chars().take(MAX_TITLE_CHARS).collect();
        if let Some(t) = self.tabs.list.iter_mut().find(|t| t.id == tab) {
            t.title_override = (!name.is_empty()).then_some(name);
            self.needs_redraw = true;
        }
    }

    // ------------------------------------------------------------------ mouse

    /// Press on a split border and drag it. Returns whether the event was taken.
    pub(crate) fn pane_ops_on_mouse(&mut self, mouse: MouseEvent) -> bool {
        if !self.config.ui.mouse || !self.dialogs.is_empty() {
            self.tabs.pane_ops.drag = None;
            return false;
        }
        let (col, row) = (mouse.column, mouse.row);
        match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                self.tabs.pane_ops.drag = None;
                let rects = self.shell_rects();
                if rects.too_small || self.shell.main_view != MainView::Sessions {
                    return false;
                }
                let main = to_core(rects.main);
                let Some(tab) = self.active_tab().filter(|t| t.zoomed.is_none()) else {
                    return false;
                };
                let Some(border) = tab.layout.border_at(main, col, row) else {
                    return false;
                };
                let Some(pos) = tab.layout.border_position(&border, main) else {
                    return false;
                };
                let grab = i32::from(along(border.dir, col, row)) - i32::from(pos);
                self.tabs.pane_ops.drag = Some(BorderDrag {
                    tab: tab.id,
                    border,
                    grab,
                });
                true
            }
            MouseEventKind::Drag(MouseButton::Left) => {
                let Some(drag) = self.tabs.pane_ops.drag.clone() else {
                    return false;
                };
                let main = to_core(self.shell_rects().main);
                let active = self.tabs.active;
                let Some(tab) = self.tabs.list.get_mut(active).filter(|t| t.id == drag.tab) else {
                    self.tabs.pane_ops.drag = None;
                    return false;
                };
                let Some(pos) = tab.layout.border_position(&drag.border, main) else {
                    self.tabs.pane_ops.drag = None;
                    return true;
                };
                let target = i32::from(along(drag.border.dir, col, row)) - drag.grab;
                let delta = target - i32::from(pos);
                if delta != 0 {
                    let moved = tab.layout.move_border(&drag.border, main, delta);
                    if moved != tab.layout {
                        tab.layout = moved;
                        self.needs_redraw = true;
                    }
                }
                true
            }
            MouseEventKind::Up(MouseButton::Left) => self.tabs.pane_ops.drag.take().is_some(),
            _ => false,
        }
    }
}

/// The mouse coordinate along a split's axis.
fn along(dir: SplitDir, col: u16, row: u16) -> u16 {
    match dir {
        SplitDir::Vertical => col,
        SplitDir::Horizontal => row,
    }
}

#[cfg(test)]
#[path = "resize_tests.rs"]
mod tests;
