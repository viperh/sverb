//! The reducer: `UiEvent → App::handle → Vec<Effect>`.
//!
//! [`App`] owns all UI state as plain data and is the single place where it changes
//! (SPEC §2.1). [`App::handle`] is synchronous and deterministic: it never reads the
//! clock (time arrives inside events), uses no randomness and performs no I/O. Side
//! effects are returned as [`Effect`]s, executed by
//! [`Services`](crate::services::Services) or the runtime loop, and their results come
//! back as [`UiEvent::EffectDone`].
//!
//! This module must not import the async runtime, filesystem, network or wall-clock
//! APIs; a test in `testing.rs` (T-02) enforces it.

pub mod config;
pub mod effect;
pub mod event;
// M0-10
pub mod input;
// M1-12: local terminal panes (`leader t`, exited-pane overlay).
mod local;
// M0-11
pub mod notify;
// M1-06: generic modal dialogs on the stack (timeouts, spinners).
mod modal;
// M1-10: pane state (scheme, title, overlay) and the session pane.
mod panes;
// M1-08: session events.
mod sessions;
pub mod shell;
pub mod state;
// M1-17: tabs, the layout tree of panes, splits, focus, close, resize debounce.
mod tabs;
// M3-01: split resizing, resize mode, border drags, zoom, tab rename and reorder.
pub mod resize;
// M3-04: copy mode, mouse selection, hyperlinks (glue around `views::sessions::copy_mode`).
pub mod copy;
// M3-02: broadcast input (`leader b` / `leader B`, fan-out of keys, pastes, snippets).
pub mod broadcast;
// M1-04: lock state, unlock / first-run / change-password prompts, auto-lock.
pub mod vault;
// M1-07: hosts (catalog, actions, quick connect, `sverb connect`).
pub mod hosts;
#[cfg(test)]
mod hosts_tests;
// M3-06: connection logs (list, dialogs, replay ticks, maintenance on unlock).
pub mod logs;
// M1-15: host-key prompts and the Known Hosts view.
pub mod known_hosts;
// M2-08: port forwards (rules, live status, start / stop, standalone tunnels).
pub mod forwards;
// M1-14: auth prompts (queue, dialog answers, saving credentials after success).
mod auth;
// M2-02: the Keychain section's identities (CRUD, usage, delete / convert).
pub mod keychain;
#[cfg(test)]
mod keychain_tests;
// M2-09: snippets (the section, `leader e`, variable form, exec runs, startup snippets).
pub mod snippets;
// M2-11: the import / export wizard's results.
mod import;
// M2-12: the command palette (sources, ranking, recents, running a pick).
pub mod palette;
// M4-07: `UiEvent::Sync` (toasts; the bars and index refresh are M4-09).
#[cfg(feature = "sync")]
mod sync;
#[cfg(test)]
mod palette_tests;
// M4-09: the sync facade (the UI's only `cfg(feature = "sync")` boundary).
#[cfg(all(test, feature = "sync"))]
mod sync_tests;
pub mod sync_ui;
// M3-03: workspaces (save, open with bounded concurrency, `--workspace`, manage).
pub mod workspaces;
// M7-01: command history (capture tiers, storage), the autocomplete overlay, ghost text.
pub mod history;

use std::{collections::BTreeMap, sync::Arc};

use crossterm::event::KeyEventKind;
use ratatui::Frame;
// M0-06
use sverb_core::config::{ConfigEvent, ConfigUpdate, LiveConfig};

pub use config::Config;
pub use effect::{Effect, EffectId, LevelMsg, LogLevel};
// M0-10
pub use effect::SessionInput;
pub use event::{
    EffectOutput, EffectResult, InputEvent, LaunchIntent, TimerFired, TimerKind, UiEvent,
};
pub use input::InputState;
use state::IdGen;
pub use state::{Focus, Layout, Mode, PendingKind, SessionId, Tabs, Toast, ToastId, ToastLevel};
pub use state::{MetaFlag, MetaFlags};
// M0-11
pub use notify::{
    COALESCE_WINDOW, HISTORY_LEN, MAX_VISIBLE_TOASTS as MAX_TOASTS, Notification, Notifications,
    TOAST_TTL,
};
pub use shell::DebugRing;
// M1-04
pub use vault::{
    UnlockFailure, UnlockRequest, VaultEffect, VaultEvent, VaultPassword, VaultScreen,
    VaultStatusInfo,
};
// M1-10
use sverb_term::scheme::SchemeCatalog;
// M3-06
pub use logs::{ConnLogEvent, LogsEffect};
// M1-15
pub use known_hosts::{KnownHostsEffect, KnownHostsEvent};
// M2-08
pub use forwards::{ForwardsEffect, ForwardsEvent};
// M2-09
pub use snippets::{SnippetsEffect, SnippetsEvent};

use crate::widgets::terminal_pane::{NoPanes, PaneCursor, PaneInfo, PaneSource};

use crate::{
    keymap::{Keymap, action::ActionName},
    theme::{Theme, ThemeEnv},
    views::{Dialog, DialogId, DialogKind, Outcome, ShellState, View, ViewCx, ViewEvent, Views},
};

// M0-09
/// Whether `Effect::Suspend` can work here (Unix job control).
const SUSPEND_SUPPORTED: bool = cfg!(unix);

/// The whole UI state. `Clone + Debug + PartialEq`, so tests can snapshot and diff it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct App {
    // M0-08
    pub(crate) mode: Mode,
    pub(crate) focus: Focus,
    pub(crate) layout: Layout,
    pub(crate) views: Views,
    pub(crate) tabs: Tabs,
    pub(crate) toasts: Vec<Toast>,
    /// Modal dialogs; the last one is on top and sees input first.
    pub(crate) dialogs: Vec<Dialog>,
    pub(crate) keymap: Keymap,
    pub(crate) config: Arc<Config>,
    /// In-flight effects awaiting `EffectDone`. A `BTreeMap` keeps any iteration deterministic.
    pub(crate) pending: BTreeMap<EffectId, PendingKind>,
    pub(crate) needs_redraw: bool,
    pub(crate) ids: IdGen,
    // M0-10
    /// Leader / sequence state, copy mode, one-time notices (`app/input.rs`).
    pub(crate) input: InputState,
    // M0-11
    /// Sections, sidebar, regions, session-area toggle, log pane (`app/shell.rs`).
    pub(crate) shell: ShellState,
    /// The last 100 notifications (`app/notify.rs`).
    pub(crate) notifications: Notifications,
    /// The resolved UI theme.
    pub(crate) theme: Theme,
    /// `NO_COLOR` / `COLORTERM`, from the runtime.
    pub(crate) theme_env: ThemeEnv,
    /// The `--debug` log ring (`None` without `--debug`).
    pub(crate) debug_ring: Option<DebugRing>,
    /// `total_pushed` of the debug ring at the last draw.
    pub(crate) log_drawn: u64,
    /// The `--debug` warning toast was shown.
    pub(crate) debug_warning_shown: bool,
    /// The session the session area showed last (`leader v` returns to it).
    pub(crate) last_session: Option<SessionId>,
    // M1-04
    /// Lock state and vault prompts (no key material; `app/vault.rs`).
    pub(crate) vault: vault::VaultUi,
    // M1-10
    /// Terminal color schemes (built-ins + `themes/*.toml`).
    pub(crate) schemes: Arc<SchemeCatalog>,
    /// Per-pane state: label, OSC title, host scheme, overlay (`widgets::terminal_pane`).
    pub(crate) panes: BTreeMap<SessionId, PaneInfo>,
    // M1-07
    /// Hosts: catalog loads, sessions opened from hosts, a pending `sverb connect`.
    pub(crate) hosts: hosts::HostsUi,
    // M1-14:
    /// Auth prompts waiting for the screen and credentials waiting for a successful
    /// login (`app/auth.rs`).
    pub(crate) auth: crate::widgets::auth_prompt::AuthPrompts,
    // M3-04
    /// Copy mode, mouse selection, hovered links and read access to the emulators
    /// (`app/copy.rs`).
    pub(crate) copy: copy::CopyUi,
    // M2-12
    /// The command palette's recent picks (`app/palette.rs`).
    pub(crate) palette: palette::PaletteUi,
    // M7-01
    /// Command history: entries, per-pane prompt learning (`app/history.rs`).
    pub(crate) history: history::HistoryUi,
    // M4-09
    /// Sync status, Settings → Sync / Devices / Team, the account wizard.
    pub(crate) sync: sync_ui::SyncUi,
}

impl App {
    /// Initial state for a configuration.
    pub fn new(config: Arc<Config>) -> Self {
        // M0-11
        let theme_env = ThemeEnv::default();
        let theme = Theme::resolve(&config.ui.theme, config.ui.truecolor, theme_env);
        // M3-04: the copy-mode table (`[keys.copy]`).
        let config_for_copy = Arc::clone(&config);
        Self {
            mode: Mode::default(),
            focus: Focus::default(),
            layout: Layout::default(),
            views: Views::default(),
            tabs: Tabs::default(),
            toasts: Vec::new(),
            dialogs: Vec::new(),
            // M0-10: built-ins merged with `[keys.*]` and `general.leader`.
            keymap: Keymap::from_config(&config),
            config,
            pending: BTreeMap::new(),
            needs_redraw: true,
            ids: IdGen::default(),
            // M0-10
            input: InputState::default(),
            // M0-11
            shell: ShellState::default(),
            notifications: Notifications::default(),
            theme,
            theme_env,
            debug_ring: None,
            log_drawn: 0,
            debug_warning_shown: false,
            last_session: None,
            // M1-04: unlocked without a vault service; the runtime calls `with_vault`.
            vault: vault::VaultUi::default(),
            // M1-10
            schemes: Arc::new(SchemeCatalog::builtin_only()),
            panes: BTreeMap::new(),
            // M1-07
            hosts: hosts::HostsUi::default(),
            // M1-14:
            auth: crate::widgets::auth_prompt::AuthPrompts::default(),
            // M3-04
            copy: copy::CopyUi::new(&config_for_copy),
            // M2-12
            palette: palette::PaletteUi::default(),
            // M7-01
            history: history::HistoryUi::default(),
            // M4-09
            sync: sync_ui::SyncUi::default(),
        }
        .with_settings_panel()
    }

    /// Replace the keymap (construction only; [`App::new`] derives it from the config).
    #[must_use]
    pub fn with_keymap(mut self, keymap: Keymap) -> Self {
        self.keymap = keymap;
        self
    }

    /// Apply one event and return the side effects it requests.
    pub fn handle(&mut self, ev: UiEvent) -> Vec<Effect> {
        let mut effects = Vec::new();
        // M3-06: unlock and lock, from any path (events, actions, timers).
        let was_locked = self.lock_state();
        match ev {
            UiEvent::Input(input) => self.on_input(input, &mut effects),
            UiEvent::EffectDone { id, result } => self.on_effect_done(id, result, &mut effects),
            UiEvent::Timer(fired) => self.on_timer(fired, &mut effects),
            // M0-06
            UiEvent::Config(change) => self.on_config(change, &mut effects),
            // M0-07
            UiEvent::Launch(intent) => self.on_launch(intent, &mut effects),
            // M0-10
            UiEvent::Meta(flags) => self.on_meta(flags, &mut effects),
            // M0-09: signals quit at once (no confirmation, SPEC §18).
            UiEvent::ShutdownRequested => effects.push(Effect::Quit { code: 0 }),
            // M1-08:
            UiEvent::Session(id, ev) => {
                // M2-09: a connected pane's startup snippet may need values.
                self.snippets_on_session(id, &ev, &mut effects);
                // M1-17: tab markers, titles, pane states.
                self.tabs_on_session(id, &ev);
                // M7-01: OSC 133 commands become history entries.
                self.history_on_session(id, &ev, &mut effects);
                self.on_session(id, ev, &mut effects);
            }
            // M1-04
            UiEvent::Vault(ev) => self.on_vault(ev, &mut effects),
            // M1-05
            UiEvent::IndexUpdated(snapshot) => {
                self.on_index_updated(snapshot);
                // M1-07: the Hosts view and its catalog follow the index.
                self.hosts_on_index(&mut effects);
                // M1-15: the Known Hosts view reloads.
                self.known_hosts_on_index(&mut effects);
                // M2-08: the Forwards view reloads.
                self.forwards_on_index(&mut effects);
                // M2-09: the Snippets view reloads.
                self.snippets_on_index(&mut effects);
            }
            // M3-06
            UiEvent::ConnLog(ev) => self.on_conn_log(ev, &mut effects),
            // M1-15
            UiEvent::KnownHosts(ev) => self.on_known_hosts(ev, &mut effects),
            // M2-08
            UiEvent::Forwards(ev) => self.on_forwards(ev, &mut effects),
            // M2-09
            UiEvent::Snippets(ev) => self.on_snippets(ev, &mut effects),
            // M2-11
            UiEvent::Import(ev) => self.on_import(ev, &mut effects),
            // M2-12
            UiEvent::Palette(ev) => self.on_palette(ev, &mut effects),
            // M3-03
            UiEvent::Workspaces(ev) => self.on_workspaces(ev, &mut effects),
            // M7-01
            UiEvent::History(ev) => self.on_history(ev, &mut effects),
            // M4-07
            #[cfg(feature = "sync")]
            UiEvent::Sync(ev) => self.on_sync(ev, &mut effects),
            // M4-09
            #[cfg(feature = "sync")]
            UiEvent::SyncUi(ev) => self.on_sync_ui(ev, &mut effects),
            // M2-07: the `confirm_on_use` modal (60 s, then deny).
            UiEvent::AgentConfirm(prompt) => {
                self.push_modal(
                    crate::views::dialogs::agent_confirm::dialog(&prompt),
                    &mut effects,
                );
            }
        }
        // M3-06: maintenance on unlock; the decrypted list goes on lock.
        self.logs_lock_transition(was_locked, &mut effects);
        // M1-15: the decrypted known hosts go on lock.
        self.known_hosts_lock_transition(was_locked);
        // M2-08: the decrypted rules go on lock; the status refresh stops.
        self.forwards_lock_transition(was_locked, &mut effects);
        // M2-09: the decrypted snippets (and dialogs holding values) go on lock.
        self.snippets_lock_transition(was_locked);
        // M2-12: the palette (host and snippet names) closes on lock.
        self.palette_lock_transition(was_locked);
        // M7-01: the decrypted history goes on lock and is reloaded on unlock.
        self.history_lock_transition(was_locked, &mut effects);
        // M4-09: the sync engine runs while unlocked.
        self.sync_lock_transition(was_locked, &mut effects);
        // M1-14: locking cancels outstanding auth prompts.
        self.auth_lock_transition(was_locked, &mut effects);
        // M1-17: tabs follow the sessions and focus; closes, new panes, resize debounce.
        self.tabs_after_handle(&mut effects);
        // M0-10: the mode follows focus.
        self.mode = self.derive_mode();
        effects
    }

    /// Whether anything changed since the last draw.
    pub fn needs_redraw(&self) -> bool {
        // M0-11: new lines for an open log pane.
        self.needs_redraw || self.log_dirty()
    }

    /// Called by the runtime after a frame was drawn.
    pub fn mark_drawn(&mut self) {
        self.needs_redraw = false;
        // M0-11
        self.note_log_drawn();
    }

    /// Current input mode.
    pub fn mode(&self) -> Mode {
        // M0-10: derived from focus and the dialog stack.
        self.derive_mode()
    }

    /// The configuration snapshot.
    pub fn config(&self) -> &Arc<Config> {
        &self.config
    }

    /// Open dialogs, bottom first.
    pub fn dialogs(&self) -> &[Dialog] {
        &self.dialogs
    }

    /// Visible toasts, oldest first.
    pub fn toasts(&self) -> &[Toast] {
        &self.toasts
    }

    /// Open tabs.
    pub fn tabs(&self) -> &Tabs {
        &self.tabs
    }

    /// All views.
    pub fn views(&self) -> &Views {
        &self.views
    }

    // M0-09
    /// Sessions whose panes the next frame draws; the runtime acknowledges their dirty
    /// flags when it draws (M1-17 extends this to the whole visible layout).
    pub fn visible_sessions(&self) -> Vec<SessionId> {
        // M1-17: every pane of the active tab.
        self.tabs_visible_sessions()
    }

    /// Number of in-flight effects awaiting a result.
    pub fn pending_effects(&self) -> usize {
        self.pending.len()
    }

    /// Push a dialog on top of the stack. Used by the reducer (actions) and by tests.
    pub(crate) fn push_dialog(&mut self, kind: DialogKind) -> DialogId {
        let id = self.ids.dialog();
        self.dialogs.push(Dialog { id, kind });
        self.needs_redraw = true;
        id
    }

    fn on_input(&mut self, input: InputEvent, effects: &mut Vec<Effect>) {
        // M1-04: while locked the prompt gets every key (only `leader q` also works);
        // while unlocked every input re-arms the idle auto-lock timer.
        if self.vault_on_input(&input, effects) {
            return;
        }
        let ev = match input {
            InputEvent::Resize { cols, rows } => {
                self.layout.size = Some((cols, rows));
                self.needs_redraw = true;
                return;
            }
            InputEvent::FocusGained | InputEvent::FocusLost => {
                self.layout.terminal_focused = matches!(input, InputEvent::FocusGained);
                return;
            }
            InputEvent::Key(key) if key.kind == KeyEventKind::Release => return,
            // M0-10: keys go through the mode router (`app/input.rs`).
            InputEvent::Key(key) => return self.on_key(key, effects),
            InputEvent::Mouse(mouse) => {
                // M3-01: dragging a split border.
                if self.pane_ops_on_mouse(mouse) {
                    return;
                }
                // M4-09: the top bar's sync indicator opens Settings → Sync.
                if self.sync_indicator_click(mouse, effects) {
                    return;
                }
                // M1-17: tab bar clicks, pane focus, mouse input for the focused pane.
                if self.tabs_on_mouse(mouse, effects) {
                    return;
                }
                ViewEvent::Mouse(mouse)
            }
            // M0-10: pastes go to a focused live session.
            InputEvent::Paste(text) => match self.on_paste(text, effects) {
                Some(text) => ViewEvent::Paste(text),
                None => return,
            },
        };
        self.dispatch(&ev, effects);
    }

    /// Dialog (top of stack) → focused view. Returns whether one of them consumed `ev`.
    fn dispatch(&mut self, ev: &ViewEvent, effects: &mut Vec<Effect>) -> Outcome {
        if let Some(dialog) = self.dialogs.last_mut() {
            let mut cx = ViewCx::new(&self.config, effects, &mut self.pending, &mut self.ids);
            let outcome = dialog.handle(ev, &mut cx);
            let (redraw, close) = (cx.redraw_requested(), cx.close_requested());
            self.needs_redraw |= redraw;
            if close {
                self.dialogs.pop();
            }
            if outcome == Outcome::Consumed {
                // M1-07: a quick-connect answer.
                self.take_hosts_requests(effects);
                // M2-02: "+ new identity" in a host form, a "Used by" pick.
                self.take_keychain_requests(effects);
                // M1-14: an answered auth prompt.
                self.take_auth_answer(effects);
                // M2-09: a snippet dialog's answer; run prompts' answers go to the run.
                self.take_snippet_answer(effects);
                self.reroute_snippet_answers(effects);
                // M2-12: the palette's re-ranking and answer.
                self.take_palette_answer(effects);
                // M3-03: the workspaces dialog's answer (open, save steps, rename, …).
                self.take_workspaces_answer(effects);
                // M7-01: the autocomplete overlay's choice.
                self.take_autocomplete_answer(effects);
                // M4-09: the account wizard's input.
                self.take_sync_dialog_answer(effects);
                return outcome;
            }
        }
        // M0-10: session panes are not views (yet); the router handles their keys.
        // M0-11: in the section views the focused region picks the view.
        let config = Arc::clone(&self.config);
        let mut pending = std::mem::take(&mut self.pending);
        let mut ids = std::mem::take(&mut self.ids);
        let (outcome, redraw) = match self.focused_view_mut() {
            Some(view) => {
                let mut cx = ViewCx::new(&config, effects, &mut pending, &mut ids);
                let outcome = view.handle(ev, &mut cx);
                (outcome, cx.redraw_requested())
            }
            None => (Outcome::Ignored, false),
        };
        self.pending = pending;
        self.ids = ids;
        self.needs_redraw |= redraw;
        self.after_dispatch();
        // M3-06: the Logs view's request (reconnect, dialogs, replay, export).
        self.take_logs_request(effects);
        // M1-15: the Known Hosts view's request (delete, edit, import, export).
        self.take_known_hosts_request(effects);
        // M2-08: the Forwards view's request (start, stop, add, edit, delete).
        self.take_forwards_request(effects);
        // M2-09: the Snippets view's request (run, run on hosts, paste, add, edit, …).
        self.take_snippets_request(effects);
        // M2-02: the Keychain view's request, "+ new identity", "Used by" answers.
        self.take_keychain_requests(effects);
        // M1-07: the Hosts view's request and a quick-connect answer.
        self.take_hosts_requests(effects);
        // M4-09: Settings → Sync / Devices / Team.
        self.take_settings_request(effects);
        outcome
    }

    fn apply_action(&mut self, action: ActionName, effects: &mut Vec<Effect>) {
        match action {
            ActionName::Quit => {
                if self.config.general.confirm_quit && self.tabs.has_sessions() {
                    self.push_dialog(DialogKind::ConfirmQuit);
                } else {
                    effects.push(Effect::Quit { code: 0 });
                }
            }
            // M1-04: `leader ctrl-l`.
            ActionName::LockVault if self.vault.active => self.lock_vault(effects),
            // M1-07: `leader o`.
            ActionName::QuickConnect => self.open_quick_connect(),
            // M2-09: `leader e`.
            ActionName::SnippetPicker => self.open_snippet_picker(effects),
            // M2-12: `leader p`, `ctrl-k`.
            ActionName::Palette => self.open_palette(effects),
            // M7-01: `leader Space`, `leader Tab`.
            ActionName::Autocomplete => self.open_autocomplete(effects),
            ActionName::AcceptGhostText => self.accept_ghost_text(effects),
            // M0-09: Windows has no job control; say so instead of doing nothing.
            ActionName::Suspend => self.on_suspend(SUSPEND_SUPPORTED, effects),
            // M4-09: sync status, sync now, devices, team keys.
            other if self.apply_sync_action(other, effects) => {}
            // M3-01: resize, resize mode, zoom, rename / move tab, equalize.
            other if self.apply_pane_ops_action(other, effects) => {}
            // M3-02: `leader b` / `leader B`.
            other if self.apply_broadcast_action(other, effects) => {}
            // M1-17: tabs, splits, pane focus, close pane / tab.
            other if self.apply_tab_action(other, effects) => {}
            // M0-11: help, sidebar, views, notifications, log pane.
            other if self.apply_shell_action(other, effects) => {}
            // M0-10
            other => self.apply_keymap_action(other, effects),
        }
    }

    // M0-09
    fn on_suspend(&mut self, supported: bool, effects: &mut Vec<Effect>) {
        if supported {
            effects.push(Effect::Suspend);
        } else {
            self.push_toast(
                ToastLevel::Info,
                "Suspend is not supported on Windows".to_owned(),
                effects,
            );
        }
    }

    fn on_effect_done(&mut self, id: EffectId, result: EffectResult, effects: &mut Vec<Effect>) {
        // Unknown or already-answered ids are ignored.
        let Some(kind) = self.pending.remove(&id) else {
            return;
        };
        // M1-07: host saves, catalog loads, the edit form.
        self.hosts_on_effect_done(&kind, result, effects);
    }

    fn on_timer(&mut self, fired: TimerFired, effects: &mut Vec<Effect>) {
        match fired.kind {
            // M0-11
            TimerKind::ToastExpiry(_) | TimerKind::ToastCoalesce(_) => {
                self.on_toast_timer(fired.kind);
            }
            // M0-10
            TimerKind::WhichKey | TimerKind::LeaderTimeout => {
                self.on_key_timer(fired.kind, effects);
            }
            // M1-04
            TimerKind::AutoLockCheck | TimerKind::UnlockCountdown => {
                self.vault_on_timer(fired.kind, effects);
            }
            // M1-17
            TimerKind::ResizeDebounce => self.on_resize_debounce(effects),
            // M1-06
            TimerKind::DialogTick(id) => self.on_dialog_tick(id, effects),
            // M3-06
            TimerKind::ReplayTick | TimerKind::LogsMaintenance => {
                self.on_logs_timer(fired.kind, fired.at, effects);
            }
            // M3-01
            TimerKind::ResizeModeIdle => self.exit_resize_mode(effects),
            // M2-08
            TimerKind::ForwardsRefresh => self.on_forwards_timer(effects),
            // M3-04
            TimerKind::MultiClick => self.on_multi_click_timer(),
        }
    }

    // M0-06: hot reload. All-or-nothing: a rejected file keeps the current config.
    // Live keys apply now; new-session/connection keys get a one-time info toast.
    fn on_config(&mut self, change: ConfigEvent, effects: &mut Vec<Effect>) {
        match LiveConfig::new(Arc::clone(&self.config)).apply(change) {
            ConfigUpdate::Applied {
                config,
                diff,
                notice,
                warnings,
            } => {
                if diff.contains("ui.mouse") {
                    effects.push(Effect::SetMouseCapture(config.ui.mouse));
                }
                // M0-10: `general.leader` and `[keys.*]` apply live.
                self.on_keymap_config(&config);
                self.config = config;
                // M0-11: `ui.theme` / `ui.truecolor` apply live.
                self.resolve_theme();
                // M3-06: `logs.sync`, `logs.retention_days`, `recording.retention_days`.
                self.logs_on_config(&diff, effects);
                // M7-01: `[history]` for the history service.
                if diff.changed.iter().any(|p| p.starts_with("history.")) {
                    self.history_on_config(effects);
                }
                self.needs_redraw = true;
                for warning in warnings {
                    self.push_toast(ToastLevel::Info, format!("config: {warning}"), effects);
                }
                if let Some(notice) = notice {
                    self.push_toast(ToastLevel::Info, notice.to_owned(), effects);
                }
            }
            ConfigUpdate::Rejected(errors) => {
                let first = errors.first().map_or_else(String::new, ToString::to_string);
                let more = match errors.len() {
                    0 | 1 => String::new(),
                    n => format!(" (+{} more)", n - 1),
                };
                self.push_toast(
                    ToastLevel::Error,
                    format!("config.toml not applied: {first}{more}"),
                    effects,
                );
            }
        }
    }

    // M0-07: the command-line intent. Opening sessions (M1-07), workspaces (M3-03)
    // and shared terminals (M6-03) replace these toasts.
    fn on_launch(&mut self, intent: LaunchIntent, effects: &mut Vec<Effect>) {
        // M1-04: delivered after unlock.
        let Some(intent) = self.vault_defer_launch(intent) else {
            return;
        };
        // M0-11: the one-time `--debug` warning.
        self.on_launch_shell(effects);
        let pending = match intent {
            LaunchIntent::Plain => return,
            // M1-07
            LaunchIntent::Connect(target) => return self.launch_connect(target, effects),
            // M3-03
            LaunchIntent::Workspace(name) => return self.launch_workspace(name, effects),
            LaunchIntent::Join(_) => "`sverb join` is not implemented yet (M6-03)",
        };
        self.push_toast(ToastLevel::Info, pending.to_owned(), effects);
    }

    /// Draw the whole UI (M0-11: the shell, `app/shell.rs`). Infallible: tiny areas
    /// degrade, they never panic. Session panes have no emulator here; the runtime
    /// uses [`App::render_with_panes`].
    pub fn render(&self, frame: &mut Frame<'_>) {
        self.render_shell(frame, &NoPanes);
        // M1-04: lock overlay and vault prompts on top.
        self.render_vault(frame);
    }

    // M1-10
    /// Draw the whole UI with session content from `panes` (the session registry).
    /// Returns the real cursor of the focused live pane (position and DECSCUSR shape);
    /// the position is already set on `frame`.
    pub fn render_with_panes(
        &self,
        frame: &mut Frame<'_>,
        panes: &dyn PaneSource,
    ) -> Option<PaneCursor> {
        let cursor = self.render_shell(frame, panes);
        // M1-04: lock overlay and vault prompts on top; no pane cursor under them.
        self.render_vault(frame);
        if self.vault_hides_panes() {
            return None;
        }
        cursor
    }
}

// M0-07
#[cfg(test)]
mod launch_tests {
    use super::*;

    #[test]
    fn plain_launch_does_nothing_and_others_toast() {
        let mut app = App::new(Arc::new(Config::default()));
        assert!(app.handle(UiEvent::Launch(LaunchIntent::Plain)).is_empty());
        assert!(app.toasts().is_empty());
        for intent in [
            LaunchIntent::Connect("db".into()),
            LaunchIntent::Workspace("w".into()),
            LaunchIntent::Join("l".into()),
        ] {
            let effects = app.handle(UiEvent::Launch(intent));
            assert!(!effects.is_empty());
        }
        // M1-07: `connect db` opens an (unsaved) SSH session instead of a toast.
        // M3-03: `--workspace w` asks the service for the list instead of a toast.
        assert_eq!(app.toasts().len(), 1);
        assert_eq!(app.tabs().sessions.len(), 1);
    }
}

// M0-09
#[cfg(test)]
mod shutdown_tests {
    use super::*;

    #[test]
    fn shutdown_quits_without_confirmation() {
        let mut app = App::new(Arc::new(Config::default()));
        app.focus_session(SessionId(1));
        assert!(app.config().general.confirm_quit);
        let effects = app.handle(UiEvent::ShutdownRequested);
        assert_eq!(effects, [Effect::Quit { code: 0 }]);
        assert!(app.dialogs().is_empty());
    }

    #[test]
    fn suspend_unsupported_shows_a_toast() {
        let mut app = App::new(Arc::new(Config::default()));
        let mut effects = Vec::new();
        app.on_suspend(false, &mut effects);
        assert!(!effects.contains(&Effect::Suspend));
        assert_eq!(app.toasts().len(), 1);
        assert!(app.toasts()[0].message.contains("not supported on Windows"));
        let mut effects = Vec::new();
        app.on_suspend(true, &mut effects);
        assert_eq!(effects, [Effect::Suspend]);
    }

    #[test]
    fn visible_sessions_follow_focus() {
        let mut app = App::new(Arc::new(Config::default()));
        assert!(app.visible_sessions().is_empty());
        app.focus_session(SessionId(7));
        assert_eq!(app.visible_sessions(), [SessionId(7)]);
    }
}
