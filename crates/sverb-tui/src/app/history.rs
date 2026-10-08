//! M7-01: command history and autocomplete in the reducer (SPEC §9.10).
//!
//! - **Tier 1 (shell integration).** The emulator captures commands between the OSC 133
//!   `B` and `C` marks (`sverb_term::osc133`); the session reports them as
//!   `SessionEvent::Command` and they are recorded as verified entries.
//! - **Tier 2 (heuristic).** In a pane where OSC 133 was never seen, `Enter` (with the
//!   alternate screen off) captures the cursor line, strips the learned prompt and
//!   records the rest as **unverified** (`sverb_core::history::capture`). The prompt is
//!   learned from the text left of the cursor when the first key is typed on a fresh
//!   line (the cursor at the end of the line: the shell is waiting, its output settled).
//! - **Storage.** `HistoryEffect::Record` goes to the history service, which stamps the
//!   time, writes the item (queued for sync only with `history.sync`), trims the host to
//!   `history.max_entries_per_host` and answers `HistoryEvent`s. `history.enabled =
//!   false` stops capturing. Locking drops the decrypted entries; unlocking reloads them.
//! - **`leader Space`** opens [`Autocomplete`] anchored at the pane's cursor, pre-filtered
//!   by the command line typed so far when tier 1 knows it. `Enter` types the remainder
//!   and `\r`, `Tab` only the remainder; a snippet row starts the snippet's run flow.
//! - **Ghost text** (`history.ghost_text`, off by default, tier 1 only): the best history
//!   command extending the command line is drawn dim after the cursor and accepted with
//!   `leader Tab` only. No unprefixed key is intercepted (`tasks/03-KEYBINDINGS.md` A7).
//! - **Purge.** "Clear history" on a host (`H` in the Hosts view) asks, then tombstones
//!   every entry of that host.

use std::{collections::BTreeMap, sync::Arc};

use crossterm::event::KeyCode;
use ratatui::{Frame, layout::Rect};
use sverb_conn::SessionEvent;
use sverb_core::{
    config::Config,
    error_report::ErrorReport,
    history::{
        CaptureContext, PromptLearner, SnippetSource, StoredEntry, ghost_suggestion,
        heuristic_capture, remainder, static_commands,
    },
    model::{HistoryEntry, ItemId},
    snippet::builtin::shell_integration::{INSTALL_NAME, install_snippet, uninstall_snippet},
    vault::LockState,
};
use sverb_term::{Emulator, GridPoint};

use super::{App, Effect, SessionId, SessionInput, ToastLevel, snippets::SnippetsEffect};
use crate::{
    keymap::chord::{KeyChord, Mods},
    views::{
        DialogKind,
        dialogs::ModalDialog,
        sessions::{
            autocomplete::{Autocomplete, AutocompleteAnswer},
            pane_of,
            panes::{content_rect, pane_rects},
        },
        snippets::SnippetsRequest,
    },
    widgets::{
        dialog::{Button, Modal},
        terminal_pane::PaneCursor,
    },
};

/// `[history]` as the service needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryPolicy {
    /// `history.enabled`
    pub enabled: bool,
    /// `history.sync`: written entries are queued for sync.
    pub sync: bool,
    /// `history.max_entries_per_host`
    pub max_entries_per_host: u32,
}

impl HistoryPolicy {
    /// From the configuration.
    pub fn from_config(config: &Config) -> Self {
        Self {
            enabled: config.history.enabled,
            sync: config.history.sync,
            max_entries_per_host: config.history.max_entries_per_host,
        }
    }
}

/// A history request for the service (`services::history`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryEffect {
    /// Load every entry (`HistoryEvent::Loaded`).
    Load,
    /// Store a captured command (the service sets `executed_at`).
    Record(HistoryEntry),
    /// Tombstone every entry of `host` ("Clear history").
    Purge {
        /// The host (`None`: local shells and unsaved targets).
        host: Option<ItemId>,
    },
    /// `[history]` changed (also sent once at startup by the runtime).
    Policy(HistoryPolicy),
}

/// Results from the history service.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HistoryEvent {
    /// Every live entry.
    Loaded(Vec<StoredEntry>),
    /// An entry was stored (or kept in memory while the vault is locked).
    Added(StoredEntry),
    /// Entries were tombstoned (the per-host cap).
    Removed(Vec<ItemId>),
    /// A host's history was purged.
    Purged {
        /// The host.
        host: Option<ItemId>,
        /// Entries tombstoned.
        count: usize,
    },
    /// Something failed.
    Failed(ErrorReport),
}

/// What the reducer knows about one pane.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PaneHistory {
    /// The heuristic tier's prompt.
    pub learner: PromptLearner,
    /// The next typed key starts a new command line (observe the prompt then).
    pub fresh: bool,
}

/// History state of [`App`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HistoryUi {
    /// Decrypted entries (dropped on lock), aligned with `ids`.
    pub(crate) entries: Arc<Vec<HistoryEntry>>,
    /// Item ids of `entries`.
    pub(crate) ids: Vec<ItemId>,
    /// A load is in flight or done since the last unlock.
    pub(crate) requested: bool,
    /// Per-pane capture state.
    pub(crate) panes: BTreeMap<SessionId, PaneHistory>,
}

impl HistoryUi {
    fn add(&mut self, stored: StoredEntry) {
        if let Some(i) = self.ids.iter().position(|id| *id == stored.id) {
            Arc::make_mut(&mut self.entries)[i] = stored.entry;
        } else {
            self.ids.push(stored.id);
            Arc::make_mut(&mut self.entries).push(stored.entry);
        }
    }

    fn remove(&mut self, gone: impl Fn(ItemId, &HistoryEntry) -> bool) -> usize {
        let before = self.ids.len();
        let entries = Arc::make_mut(&mut self.entries);
        let mut keep_ids = Vec::with_capacity(before);
        let mut keep = Vec::with_capacity(before);
        for (id, e) in self.ids.drain(..).zip(entries.drain(..)) {
            if !gone(id, &e) {
                keep_ids.push(id);
                keep.push(e);
            }
        }
        self.ids = keep_ids;
        *entries = keep;
        before - self.ids.len()
    }

    /// The decrypted entries.
    pub fn entries(&self) -> &[HistoryEntry] {
        &self.entries
    }
}

fn fx(op: HistoryEffect) -> Effect {
    Effect::History(op)
}

/// The text of one row's cells `[0, end)` (exact: blanks kept).
fn row_text(term: &dyn Emulator, line: i32, end: Option<usize>) -> Option<String> {
    let row = term.row(line)?;
    let end = end.unwrap_or(row.cells.len()).min(row.cells.len());
    let mut out = String::new();
    for cell in &row.cells[..end] {
        if cell.width == 0 {
            continue;
        }
        out.push(cell.c);
        out.extend(cell.zerowidth.iter());
    }
    Some(out)
}

/// The logical line (soft-wrapped rows joined) ending at row `line`, and its first row.
fn logical_line(term: &dyn Emulator, line: i32) -> (String, i32) {
    let mut first = line;
    while term.row(first - 1).is_some_and(|r| r.wrapped) {
        first -= 1;
    }
    let mut text = String::new();
    for l in first..=line {
        text.push_str(&row_text(term, l, None).unwrap_or_default());
    }
    (text.trim_end().to_owned(), first)
}

impl App {
    fn pane_host(&self, id: SessionId) -> Option<ItemId> {
        self.pane(id).host.as_deref().and_then(|h| h.parse().ok())
    }

    // ------------------------------------------------------------ data

    /// The service's answers.
    pub(crate) fn on_history(&mut self, ev: HistoryEvent, effects: &mut Vec<Effect>) {
        match ev {
            HistoryEvent::Loaded(list) => {
                let (ids, entries): (Vec<_>, Vec<_>) =
                    list.into_iter().map(|s| (s.id, s.entry)).unzip();
                self.history.ids = ids;
                self.history.entries = Arc::new(entries);
            }
            HistoryEvent::Added(stored) => self.history.add(stored),
            HistoryEvent::Removed(ids) => {
                self.history.remove(|id, _| ids.contains(&id));
            }
            HistoryEvent::Purged { host, count } => {
                self.history.remove(|_, e| e.host_id == host);
                let msg = match count {
                    1 => "Cleared 1 history entry".to_owned(),
                    n => format!("Cleared {n} history entries"),
                };
                self.push_toast(ToastLevel::Info, msg, effects);
            }
            HistoryEvent::Failed(report) => self.push_error(&report, effects),
        }
        self.needs_redraw = true;
    }

    /// Locking drops the decrypted entries; unlocking loads them.
    pub(crate) fn history_lock_transition(&mut self, was: LockState, effects: &mut Vec<Effect>) {
        let now = self.lock_state();
        if now == was {
            return;
        }
        if now == LockState::Unlocked {
            self.history_load(effects);
        } else {
            self.history.entries = Arc::default();
            self.history.ids.clear();
            self.history.requested = false;
        }
    }

    fn history_load(&mut self, effects: &mut Vec<Effect>) {
        if !self.history.requested && self.lock_state() == LockState::Unlocked {
            self.history.requested = true;
            effects.push(fx(HistoryEffect::Load));
        }
    }

    /// `[history]` may have changed.
    pub(crate) fn history_on_config(&mut self, effects: &mut Vec<Effect>) {
        effects.push(fx(HistoryEffect::Policy(HistoryPolicy::from_config(
            &self.config,
        ))));
    }

    fn record(&mut self, entry: HistoryEntry, effects: &mut Vec<Effect>) {
        if self.config.history.enabled && self.config.history.max_entries_per_host > 0 {
            effects.push(fx(HistoryEffect::Record(entry)));
        }
    }

    // ------------------------------------------------------------ capture

    /// Tier 1: a command captured through OSC 133; a closed pane is forgotten.
    pub(crate) fn history_on_session(
        &mut self,
        id: SessionId,
        ev: &SessionEvent,
        effects: &mut Vec<Effect>,
    ) {
        match ev {
            SessionEvent::Command(cmd) => {
                let entry = HistoryEntry {
                    command: cmd.command.clone(),
                    host_id: self.pane_host(id),
                    exit_code: cmd.exit_code,
                    verified: true,
                    ..HistoryEntry::default()
                };
                self.record(entry, effects);
            }
            SessionEvent::State(sverb_conn::SessionState::Closed) => {
                self.history.panes.remove(&id);
            }
            _ => {}
        }
    }

    /// Tier 2, before a Terminal-mode key goes to `id`: `Enter` captures the line; the
    /// first key on a fresh line teaches the prompt. Does nothing once OSC 133 was seen.
    pub(crate) fn history_on_terminal_key(
        &mut self,
        id: SessionId,
        chord: KeyChord,
        effects: &mut Vec<Effect>,
    ) {
        if !self.config.history.enabled {
            return;
        }
        let Some(emu) = self.emulator(id) else {
            return;
        };
        let secret_prompt_open = self
            .dialogs
            .iter()
            .any(|d| matches!(d.kind, DialogKind::AuthPrompt(_)));
        let pane = self.history.panes.entry(id).or_insert_with(|| PaneHistory {
            fresh: true,
            ..PaneHistory::default()
        });
        let term = emu.lock();
        if term.prompt_state().integrated {
            return;
        }
        let cursor = term.cursor().point;
        let plain = chord.mods == Mods::NONE || chord.mods == Mods::SHIFT;
        match chord.code {
            KeyCode::Enter if chord.mods == Mods::NONE => {
                let (line, first) = logical_line(&**term, cursor.line);
                let previous = row_text(&**term, first - 1, None).map(|t| t.trim_end().to_owned());
                let ctx = CaptureContext {
                    cursor_line: &line,
                    previous_line: previous.as_deref(),
                    alt_screen: term.modes().alt_screen,
                    secret_prompt_open,
                };
                let command = heuristic_capture(&ctx, &pane.learner);
                pane.fresh = true;
                drop(term);
                if let Some(command) = command {
                    let entry = HistoryEntry {
                        command,
                        host_id: self.pane_host(id),
                        verified: false,
                        ..HistoryEntry::default()
                    };
                    self.record(entry, effects);
                }
            }
            KeyCode::Char(_) if plain && pane.fresh => {
                pane.fresh = false;
                if term.modes().alt_screen {
                    return;
                }
                // The shell waits at the end of its prompt: nothing right of the cursor.
                let right_blank = term
                    .row(cursor.line)
                    .is_none_or(|r| r.cells.iter().skip(cursor.column).all(|c| c.c == ' '));
                if right_blank
                    && let Some(left) = row_text(&**term, cursor.line, Some(cursor.column))
                {
                    pane.learner.observe(&left);
                }
            }
            // Editing keys keep the line fresh only until something is typed.
            _ => {}
        }
    }

    // ------------------------------------------------------------ the overlay

    /// The screen cell of `id`'s cursor (inside its pane's content area).
    fn cursor_anchor(&self, id: SessionId, cursor: GridPoint) -> (u16, u16) {
        let main = self.shell_rects().main;
        let rect = self
            .active_tab()
            .and_then(|tab| {
                pane_rects(&tab.layout, tab.zoomed, main)
                    .into_iter()
                    .find(|(p, _)| *p == pane_of(id))
            })
            .map_or(main, |(_, r)| r);
        let inner = content_rect(rect);
        let col = u16::try_from(cursor.column).unwrap_or(u16::MAX);
        let row = u16::try_from(cursor.line.max(0)).unwrap_or(u16::MAX);
        (
            inner
                .x
                .saturating_add(col)
                .min(inner.right().saturating_sub(1)),
            inner
                .y
                .saturating_add(row)
                .min(inner.bottom().saturating_sub(1)),
        )
    }

    /// `leader Space`.
    pub(crate) fn open_autocomplete(&mut self, effects: &mut Vec<Effect>) {
        let Some(id) = self.focused_session() else {
            self.push_toast(
                ToastLevel::Info,
                "Autocomplete works in a session pane".to_owned(),
                effects,
            );
            return;
        };
        self.history_load(effects);
        let (cursor, state) = match self.emulator(id) {
            Some(emu) => {
                let term = emu.lock();
                (term.cursor().point, term.prompt_state())
            }
            None => (
                GridPoint::new(0, 0),
                sverb_term::osc133::PromptState::default(),
            ),
        };
        let snippets: Vec<SnippetSource> = self
            .views
            .snippets
            .list
            .rows()
            .iter()
            .map(|r| SnippetSource {
                id: r.id,
                name: r.snippet.name.clone(),
                first_line: r
                    .snippet
                    .script
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_owned(),
            })
            .collect();
        let overlay = Autocomplete::new(
            id,
            self.pane_host(id),
            self.cursor_anchor(id, cursor),
            state.input.unwrap_or_default(),
            state.integrated,
            Arc::clone(&self.history.entries),
            Arc::new(snippets),
            static_commands(),
        );
        self.push_dialog(DialogKind::Autocomplete(Box::new(overlay)));
    }

    /// After a key reached the overlay: carry out its answer and close it.
    pub(crate) fn take_autocomplete_answer(&mut self, effects: &mut Vec<Effect>) {
        let Some(top) = self.dialogs.last_mut() else {
            return;
        };
        let DialogKind::Autocomplete(overlay) = &mut top.kind else {
            return;
        };
        let Some(answer) = overlay.answer.take() else {
            return;
        };
        let session = overlay.session;
        self.dialogs.pop();
        self.needs_redraw = true;
        match answer {
            AutocompleteAnswer::Cancel => {}
            AutocompleteAnswer::Type { text, execute } => {
                let mut bytes = text.into_bytes();
                if execute {
                    bytes.push(b'\r');
                }
                if !bytes.is_empty() {
                    // Like typing: every broadcast member gets it (M3-02).
                    self.broadcast_send(session, SessionInput::Raw(bytes), effects);
                }
            }
            AutocompleteAnswer::Snippet(snippet) => {
                self.views.snippets.request = Some(SnippetsRequest::RunHere(snippet));
                self.take_snippets_request(effects);
            }
            AutocompleteAnswer::InstallIntegration => self.install_shell_integration(effects),
        }
    }

    /// Run the install snippet on hosts; add it (and the uninstall one) first if missing.
    fn install_shell_integration(&mut self, effects: &mut Vec<Effect>) {
        let existing = self
            .views
            .snippets
            .list
            .rows()
            .iter()
            .find(|r| r.snippet.name == INSTALL_NAME)
            .map(|r| r.id);
        if let Some(id) = existing {
            self.views.snippets.request = Some(SnippetsRequest::RunOnHosts(id));
            self.take_snippets_request(effects);
            return;
        }
        for snippet in [install_snippet(), uninstall_snippet()] {
            effects.push(Effect::Snippets(SnippetsEffect::Save { id: None, snippet }));
        }
        self.push_toast(
            ToastLevel::Info,
            format!(
                "Added the \"{INSTALL_NAME}\" snippet: press F2 in {} space again (or run it \
                 from Snippets) to install it on hosts",
                self.keymap.leader()
            ),
            effects,
        );
    }

    // ------------------------------------------------------------ ghost text

    /// The ghost text for `id` now: (the command line, the suggested remainder).
    fn ghost_for(&self, id: SessionId, term: &dyn Emulator) -> Option<String> {
        if !self.config.history.ghost_text {
            return None;
        }
        let state = term.prompt_state();
        let input = state.input.filter(|_| state.integrated)?;
        let text = ghost_suggestion(self.pane_host(id), &input, &self.history.entries)?;
        Some(remainder(text, &input).to_owned())
    }

    /// `leader Tab`: type the ghost-text suggestion.
    pub(crate) fn accept_ghost_text(&mut self, effects: &mut Vec<Effect>) {
        if !self.config.history.ghost_text {
            self.push_toast(
                ToastLevel::Info,
                "Ghost text is off (history.ghost_text)".to_owned(),
                effects,
            );
            return;
        }
        let Some(id) = self.focused_session() else {
            return;
        };
        let rest = self
            .emulator(id)
            .and_then(|emu| self.ghost_for(id, &**emu.lock()));
        match rest {
            Some(rest) if !rest.is_empty() => {
                self.broadcast_send(id, SessionInput::Raw(rest.into_bytes()), effects);
            }
            _ => {
                self.push_toast(ToastLevel::Info, "No suggestion".to_owned(), effects);
            }
        }
    }

    /// Draw the ghost text after the focused pane's cursor (inside `area`, the pane).
    pub(crate) fn render_ghost_text(
        &self,
        frame: &mut Frame<'_>,
        area: Rect,
        id: SessionId,
        emulator: Option<&sverb_conn::SharedEmulator>,
        cursor: Option<&PaneCursor>,
    ) {
        let (Some(emu), Some(cursor)) = (emulator, cursor) else {
            return;
        };
        if self.focused_session() != Some(id) || !self.dialogs.is_empty() {
            return;
        }
        let Some(rest) = self.ghost_for(id, &**emu.lock()) else {
            return;
        };
        let p = cursor.position;
        if !area.contains(p) {
            return;
        }
        let width = usize::from(area.right().saturating_sub(p.x));
        frame
            .buffer_mut()
            .set_stringn(p.x, p.y, &rest, width, self.theme.dim);
    }

    // ------------------------------------------------------------ purge

    /// "Clear history" for `host` (asks first).
    pub(crate) fn confirm_clear_history(
        &mut self,
        host: Option<ItemId>,
        label: &str,
        effects: &mut Vec<Effect>,
    ) {
        let modal = Modal::confirm(
            "Clear history",
            &format!("Delete the command history of {label}? This cannot be undone."),
            vec![
                Button::new("clear", "Clear", 'c').danger(),
                Button::new("keep", "Keep", 'k').safe(),
            ],
            1,
            true,
        );
        self.push_modal(
            ModalDialog::new(modal).on("button:clear", vec![fx(HistoryEffect::Purge { host })]),
            effects,
        );
    }
}

#[cfg(test)]
#[path = "history_tests.rs"]
mod tests;
