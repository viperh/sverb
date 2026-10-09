//! Key routing, modes and the leader.
//!
//! First match wins:
//! 1. a modal dialog that is not a form gets every key,
//! 2. a pending sequence (after the leader, or a Normal multi-key prefix) resolves,
//! 3. the leader starts a pending sequence (which-key after `ui.which_key_delay_ms`),
//! 4. the mode decides:
//!    - **Terminal** (live session focused): the key goes to the session, always,
//!    - **Insert** (a form has focus): the key goes to the form,
//!    - **Normal**: the Normal table, then the focused view.
//!
//! The mode is derived from focus (`App::derive_mode`), never set ad hoc.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Paragraph, Wrap},
};

use super::{
    App, Effect, Focus, Mode, SessionId, TimerKind, ToastLevel,
    effect::SessionInput,
    state::{MetaFlag, MetaFlags},
};
use crate::{
    keymap::{
        Keymap, Lookup, Table,
        action::ActionName,
        chord::{KeyChord, Mods},
        leader::{self, KeyState, LEADER_TIMEOUT, Pending, SEQUENCE_TIMEOUT, Step},
    },
    views::{DialogKind, MainView, Outcome, Region, ViewEvent},
    views::{Section, View as _},
};

/// A generic modal that edits text (a prompt): Insert mode, the leader works.
fn dialog_wants_text(kind: &DialogKind) -> bool {
    match kind {
        DialogKind::Modal(m) => m.modal.wants_text(),
        // The host form and quick connect edit text.
        DialogKind::HostForm(_) | DialogKind::QuickConnect(_) => true,
        DialogKind::Organize(o) => o.wants_text(),
        DialogKind::Identity(d) => d.wants_text(),
        // The "type the host name" prompt; the known-hosts edit form and path
        // prompts.
        DialogKind::HostKey(h) => h.wants_text(),
        DialogKind::KnownHosts(_) => true,
        // The forward form.
        DialogKind::Forward(f) => f.wants_text(),
        // The picker filters, form fields, an export path.
        DialogKind::Snippet(d) => d.wants_text(),
        // The wizard's path and password fields.
        DialogKind::ImportWizard(w) => w.wants_text(),
        // The autocomplete overlay's filter.
        DialogKind::Autocomplete(_) => true,
        // The palette's input line (the leader still works).
        DialogKind::Palette(_) => true,
        // The list's filter line and the name prompts.
        DialogKind::Workspaces(w) => w.wants_text(),
        // The wizard's fields.
        DialogKind::AccountWizard(w) => w.screen.prompt.is_some(),
        _ => false,
    }
}

// Paste confirmation and remote OSC 52 writes.
mod remote_io;

/// Key-routing state of [`App`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InputState {
    /// Leader / multi-key sequence state.
    pub keys: KeyState,
    /// Copy mode is on in the focused session pane.
    pub copy_mode: bool,
    /// The last action run from a key (for tests and the status bar).
    pub last_action: Option<ActionName>,
    /// The first-run leader notice was shown in this run.
    pub leader_notice_shown: bool,
    /// Sessions whose OSC 52 clipboard writes are allowed for the rest of the session
    /// ("allow for this session" in the `allow_remote_write = "ask"` prompt).
    pub remote_clipboard_allowed: std::collections::BTreeSet<SessionId>,
}

impl App {
    /// The mode, derived from focus and the dialog stack.
    pub(crate) fn derive_mode(&self) -> Mode {
        if let Some(top) = self.dialogs.last() {
            // A text prompt (`widgets::dialog`) edits text like a form.
            return if dialog_wants_text(&top.kind) {
                Mode::Insert
            } else {
                Mode::Normal
            };
        }
        match self.focused_session() {
            // An exited pane takes no input; its overlay owns `Enter`.
            // Nor does a disconnected one (banner, countdown, reconnecting).
            Some(id) if self.is_dead_pane(id) => Mode::Normal,
            Some(_) if self.input.copy_mode => Mode::Copy,
            Some(_) => Mode::Terminal,
            // A list filter line or a form field in the focused section view.
            None if self.section_view_insert() => Mode::Insert,
            None => Mode::Normal,
        }
    }

    /// The focused section view is editing text (`View::insert_mode`).
    fn section_view_insert(&self) -> bool {
        self.focus == Focus::Hosts
            && self.shell.region == Region::Main
            && self.shell.main_view == MainView::Sections
            && match self.shell.section {
                Section::Hosts => self.views.hosts.insert_mode(),
                // The Logs view's host filter.
                Section::Logs => self.views.logs.insert_mode(),
                // The Known Hosts list filter.
                Section::Known => self.views.known_hosts.insert_mode(),
                Section::Forwards => self.views.forwards.insert_mode(),
                // The Snippets list filter.
                Section::Snippets => self.views.snippets.insert_mode(),
                // The Keychain sub-tab's filter.
                Section::Keychain => self.views.keychain.insert_mode(),
                // The Team page's input line.
                Section::Settings => self.views.settings.insert_mode(),
            }
    }

    /// The focused session, if it is live.
    pub(crate) fn focused_session(&self) -> Option<SessionId> {
        match self.focus {
            Focus::Session(id) if self.tabs.sessions.contains(&id) => Some(id),
            _ => None,
        }
    }

    pub fn focus_session(&mut self, id: SessionId) {
        if !self.tabs.sessions.contains(&id) {
            self.tabs.sessions.push(id);
        }
        self.focus = Focus::Session(id);
        self.input.copy_mode = false;
        // The session area shows it.
        self.shell.main_view = MainView::Sessions;
        self.shell.region = Region::Main;
        self.mode = self.derive_mode();
        self.needs_redraw = true;
    }

    /// The effective keymap.
    pub fn keymap(&self) -> &Keymap {
        &self.keymap
    }

    /// Leader / sequence state.
    pub fn key_state(&self) -> &KeyState {
        &self.input.keys
    }

    /// Whether the which-key popup is visible.
    pub fn which_key_visible(&self) -> bool {
        matches!(&self.input.keys, KeyState::Pending(p) if p.which_key)
    }

    /// The last action run from a key.
    pub fn last_action(&self) -> Option<ActionName> {
        self.input.last_action
    }

    fn modal_dialog_open(&self) -> bool {
        self.dialogs
            .last()
            .is_some_and(|d| !dialog_wants_text(&d.kind))
    }

    /// Route one key press (releases are filtered by the caller).
    pub(crate) fn on_key(&mut self, key: KeyEvent, effects: &mut Vec<Effect>) {
        // The rename-tab prompt and resize mode (swallows every key).
        if self.pane_ops_on_key(key, effects) {
            return;
        }
        let chord = KeyChord::from_key_event(&key);
        if self.modal_dialog_open() {
            self.cancel_pending(effects);
            // Paste confirmation and remote clipboard prompts (`input/remote_io.rs`).
            if self.on_remote_io_dialog_key(chord, effects) {
                return;
            }
            // "Broadcast input to N panes?".
            if self.on_broadcast_dialog_key(key, effects) {
                return;
            }
            // Logs dialogs (details, delete, clear, export, replay player).
            if self.on_logs_dialog_key(key, effects) {
                return;
            }
            // The "Save as host?" offer.
            if self.on_hosts_dialog_key(key, effects) {
                return;
            }
            self.dispatch(&ViewEvent::Key(key), effects);
            return;
        }
        if let KeyState::Pending(pending) = &self.input.keys {
            let pending = pending.clone();
            self.on_pending_key(&pending, chord, key, effects);
            return;
        }
        if chord == self.keymap.leader() {
            self.start_leader(effects);
            return;
        }
        self.on_mode_key(chord, key, effects);
    }

    fn on_mode_key(&mut self, chord: KeyChord, key: KeyEvent, effects: &mut Vec<Effect>) {
        match self.derive_mode() {
            // The pass-through guarantee: no table, no exceptions (K-01).
            Mode::Terminal => {
                if let Some(id) = self.focused_session() {
                    // Typing drops a mouse selection and returns to the live view.
                    self.copy_on_terminal_key(id);
                    // The heuristic history tier sees the key first (read only).
                    self.history_on_terminal_key(id, chord, effects);
                    // To every broadcast member (each encodes with its own modes).
                    self.broadcast_send(id, SessionInput::Key(chord), effects);
                }
            }
            Mode::Insert => {
                self.dispatch(&ViewEvent::Key(key), effects);
            }
            Mode::Copy => self.on_copy_key(chord, effects),
            Mode::Normal => {
                // A pane without a live session: its overlay owns the few
                // keys it needs; everything else is swallowed, never forwarded (K-06).
                if matches!(self.focus, Focus::Session(_)) {
                    // `Enter` restarts an exited pane.
                    self.on_dead_pane_key(chord, effects);
                    return;
                }
                match self.keymap.lookup_seq(Table::Normal, &[chord]) {
                    Lookup::Action(action) => self.run_action(action, effects),
                    Lookup::Prefix { .. } => {
                        self.input.keys = KeyState::Pending(Pending {
                            table: Table::Normal,
                            keys: vec![chord],
                            which_key: false,
                        });
                        effects.push(Effect::ScheduleTimer {
                            kind: TimerKind::LeaderTimeout,
                            after: SEQUENCE_TIMEOUT,
                        });
                    }
                    Lookup::Unbound => {
                        // Then the shell (`tab` focus cycle, `Esc` on toasts, log scroll).
                        if self.dispatch(&ViewEvent::Key(key), effects) == Outcome::Ignored {
                            self.on_shell_key(chord, effects);
                        }
                    }
                }
            }
        }
    }

    fn on_copy_key(&mut self, chord: KeyChord, effects: &mut Vec<Effect>) {
        // Motions, counts, selection, yank, search, links (`app/copy.rs`). Nothing
        // reaches the session in copy mode. Without an emulator only the exit keys work.
        if self.copy_mode_key(chord, effects) {
            return;
        }
        let exit = matches!(
            (chord.code, chord.mods),
            (KeyCode::Char('q') | KeyCode::Esc, Mods::NONE) | (KeyCode::Char('c'), Mods::CTRL)
        );
        if exit {
            self.input.copy_mode = false;
            self.needs_redraw = true;
        }
    }

    fn start_leader(&mut self, effects: &mut Vec<Effect>) {
        self.input.keys = KeyState::Pending(Pending::leader());
        effects.push(Effect::ScheduleTimer {
            kind: TimerKind::LeaderTimeout,
            after: LEADER_TIMEOUT,
        });
        if self.config.ui.show_which_key {
            effects.push(Effect::ScheduleTimer {
                kind: TimerKind::WhichKey,
                after: std::time::Duration::from_millis(u64::from(
                    self.config.ui.which_key_delay_ms,
                )),
            });
        }
        self.needs_redraw = true;
    }

    /// Drop a pending sequence (and its timers).
    fn cancel_pending(&mut self, effects: &mut Vec<Effect>) {
        if let KeyState::Pending(p) = std::mem::take(&mut self.input.keys) {
            effects.push(Effect::CancelTimer(TimerKind::LeaderTimeout));
            if p.table == Table::Leader {
                effects.push(Effect::CancelTimer(TimerKind::WhichKey));
            }
            self.needs_redraw = true;
        }
    }

    fn on_pending_key(
        &mut self,
        pending: &Pending,
        chord: KeyChord,
        key: KeyEvent,
        effects: &mut Vec<Effect>,
    ) {
        let step = leader::step(&self.keymap, pending, chord);
        if let Step::Wait(next) = step {
            // Still a prefix: restart the timeout unless the popup suspends it.
            if !next.which_key {
                effects.push(Effect::ScheduleTimer {
                    kind: TimerKind::LeaderTimeout,
                    after: match next.table {
                        Table::Leader => LEADER_TIMEOUT,
                        Table::Normal => SEQUENCE_TIMEOUT,
                    },
                });
            }
            self.input.keys = KeyState::Pending(next);
            self.needs_redraw = true;
            return;
        }
        self.cancel_pending(effects);
        match step {
            Step::Wait(_) | Step::Cancel => {}
            // `toggle_log_pane` is unbound without `--debug`.
            Step::Run(action) if !self.action_available(action) => {
                let mut seq = pending.keys.clone();
                seq.push(chord);
                let msg = format!(
                    "No binding for {} {}",
                    self.keymap.leader(),
                    KeyChord::display_sequence(&seq)
                );
                self.push_toast(ToastLevel::Info, msg, effects);
            }
            Step::Run(action) => self.run_action(action, effects),
            Step::SendLeader => self.send_leader(effects),
            Step::Unbound(seq) => {
                let msg = format!(
                    "No binding for {} {}",
                    self.keymap.leader(),
                    KeyChord::display_sequence(&seq)
                );
                self.push_toast(ToastLevel::Info, msg, effects);
            }
            Step::Reprocess { exact } => {
                if let Some(action) = exact {
                    self.run_action(action, effects);
                }
                // Idle now, so this can't recurse further.
                self.on_key(key, effects);
            }
        }
    }

    /// `TimerKind::WhichKey` / `TimerKind::LeaderTimeout`.
    pub(crate) fn on_key_timer(&mut self, kind: TimerKind, effects: &mut Vec<Effect>) {
        let KeyState::Pending(pending) = &mut self.input.keys else {
            return; // stale timer
        };
        match kind {
            TimerKind::WhichKey if pending.table == Table::Leader && !pending.which_key => {
                // The popup suspends the timeout until a key is pressed.
                pending.which_key = true;
                effects.push(Effect::CancelTimer(TimerKind::LeaderTimeout));
                self.needs_redraw = true;
            }
            TimerKind::LeaderTimeout if !pending.which_key => {
                let pending = pending.clone();
                self.input.keys = KeyState::Idle;
                effects.push(Effect::CancelTimer(TimerKind::WhichKey));
                self.needs_redraw = true;
                if let Some(action) = leader::on_timeout(&self.keymap, &pending) {
                    self.run_action(action, effects);
                }
            }
            _ => {}
        }
    }

    /// Run an action from a key binding.
    pub(crate) fn run_action(&mut self, action: ActionName, effects: &mut Vec<Effect>) {
        self.input.last_action = Some(action);
        // `leader i` on a disconnected pane shows why (and its ConnLog entry).
        if action == ActionName::SessionInfo && self.show_disconnect_details(effects) {
            return;
        }
        self.apply_action(action, effects);
    }

    /// implemented by later tasks; until then they say so in a toast.
    pub(crate) fn apply_keymap_action(&mut self, action: ActionName, effects: &mut Vec<Effect>) {
        match action {
            ActionName::SendLeader => self.send_leader(effects),
            ActionName::NewLocalTab => {
                self.open_local_session(effects);
            }
            ActionName::ClosePane if self.close_exited_pane(effects) => {}
            // `leader R`.
            ActionName::ToggleRecording => self.toggle_recording(effects),
            ActionName::CopyMode => {
                if self.focused_session().is_some() {
                    self.input.copy_mode = true;
                    self.needs_redraw = true;
                    // The copy cursor, the frozen view.
                    self.enter_copy_mode();
                } else {
                    self.push_toast(
                        ToastLevel::Info,
                        "Copy mode needs a focused session".to_owned(),
                        effects,
                    );
                }
            }
            other => {
                self.push_toast(
                    ToastLevel::Info,
                    format!("`{other}` is not available yet"),
                    effects,
                );
            }
        }
    }

    /// Leader twice: the literal leader to the focused session. Nothing in Normal mode.
    fn send_leader(&mut self, effects: &mut Vec<Effect>) {
        if let Some(id) = self.focused_session() {
            effects.push(Effect::SendToSession {
                id,
                input: SessionInput::Key(self.keymap.leader()),
            });
        }
    }

    /// Paste: forwarded to a focused live session; `None` means it was handled here.
    pub(crate) fn on_paste(&mut self, text: String, effects: &mut Vec<Effect>) -> Option<String> {
        self.cancel_pending(effects);
        // Resize mode swallows pastes too.
        if self.resize_mode_shown() {
            return None;
        }
        match self.derive_mode() {
            Mode::Terminal => {
                if let Some(id) = self.focused_session() {
                    // The session asks back (`PasteConfirm`) for a multi-line paste
                    // without bracketed paste, unless the confirmation is off.
                    let input = if self.config.terminal.paste_confirm_multiline {
                        SessionInput::Paste(text)
                    } else {
                        SessionInput::PasteUnchecked(text)
                    };
                    // Broadcast (each pane applies its own bracketed-paste rule).
                    self.broadcast_send(id, input, effects);
                }
                None
            }
            Mode::Copy => None,
            Mode::Normal | Mode::Insert => Some(text),
        }
    }

    /// After a config (re)load: rebuild the keymap and drop any pending sequence.
    pub(crate) fn on_keymap_config(&mut self, config: &super::Config) {
        self.keymap = Keymap::from_config(config);
        self.input.keys = KeyState::Idle;
        // `[keys.copy]`.
        self.copy_on_config(config);
    }

    pub(crate) fn on_meta(&mut self, flags: MetaFlags, effects: &mut Vec<Effect>) {
        if !flags.seen_leader_notice && !self.input.leader_notice_shown {
            self.input.leader_notice_shown = true;
            self.push_dialog(DialogKind::LeaderNotice);
            effects.push(Effect::SetMetaFlag(MetaFlag::SeenLeaderNotice));
        }
    }

    /// Status-bar text after the mode label, rendered from the real leader.
    pub(crate) fn status_hint(&self) -> String {
        let leader = self.keymap.leader().hint();
        match (&self.input.keys, self.derive_mode()) {
            (KeyState::Pending(p), _) if p.table == Table::Leader => {
                format!("{leader} … (esc cancel)")
            }
            (_, Mode::Normal) => format!("{leader} ? help · q quit"),
            // The link under the copy cursor (or the mouse) is shown before opening.
            (_, Mode::Copy) => match self.link_hint() {
                Some(url) => format!("{url} · o open · q exit copy mode"),
                None => format!("{leader} ? help · q exit copy mode"),
            },
            (_, Mode::Terminal) if self.link_hint().is_some() => format!(
                "{} · ctrl-click open · {leader} ? help",
                self.link_hint().unwrap_or_default()
            ),
            _ => format!("{leader} ? help"),
        }
    }

    pub(crate) fn render_session_placeholder(
        &self,
        frame: &mut Frame<'_>,
        area: Rect,
        id: SessionId,
    ) {
        let live = self.tabs.sessions.contains(&id);
        let text = if let Some(code) = self.exited_code(id) {
            self.exited_overlay(code)
        } else if live {
            "Session pane (the terminal view arrives with M1-10).".to_owned()
        } else {
            "Session ended.".to_owned()
        };
        // Themed; focused unless a dialog is open.
        let focused = self.dialogs.is_empty();
        frame.render_widget(
            Paragraph::new(Line::raw(text))
                .wrap(Wrap { trim: true })
                .block(
                    Block::bordered()
                        .title(Span::styled(
                            format!(" session {} ", id.0),
                            self.theme.title_for(focused),
                        ))
                        .border_style(self.theme.border_for(focused)),
                ),
            area,
        );
    }
}
