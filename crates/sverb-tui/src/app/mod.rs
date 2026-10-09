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
//! APIs; a test in `testing.rs` enforces it.

pub mod config;
pub mod effect;
pub mod event;
pub mod input;
// Local terminal panes (`leader t`, exited-pane overlay).
mod local;
pub mod notify;
// Generic modal dialogs on the stack (timeouts, spinners).
mod modal;
// Pane state (scheme, title, overlay) and the session pane.
mod panes;
// Session events.
mod sessions;
pub mod shell;
pub mod state;
// Tabs, the layout tree of panes, splits, focus, close, resize debounce.
mod tabs;
// Split resizing, resize mode, border drags, zoom, tab rename and reorder.
pub mod resize;
// Copy mode, mouse selection, hyperlinks (glue around `views::sessions::copy_mode`).
pub mod copy;
// Broadcast input (`leader b` / `leader B`, fan-out of keys, pastes, snippets).
pub mod broadcast;
// Lock state, unlock / first-run / change-password prompts, auto-lock.
pub mod vault;
// Hosts (catalog, actions, quick connect, `sverb connect`).
pub mod hosts;
#[cfg(test)]
mod hosts_tests;
// Connection logs (list, dialogs, replay ticks, maintenance on unlock).
pub mod logs;
// Host-key prompts and the Known Hosts view.
pub mod known_hosts;
// Port forwards (rules, live status, start / stop, standalone tunnels).
pub mod forwards;
// Auth prompts (queue, dialog answers, saving credentials after success).
mod auth;
// The Keychain section's identities (CRUD, usage, delete / convert).
pub mod keychain;
#[cfg(test)]
mod keychain_tests;
// Snippets (the section, `leader e`, variable form, exec runs, startup snippets).
pub mod snippets;
// The import / export wizard's results.
mod import;
// The command palette (sources, ranking, recents, running a pick).
pub mod palette;
#[cfg(test)]
mod palette_tests;
#[cfg(feature = "sync")]
mod sync;
// The sync facade (the UI's only `cfg(feature = "sync")` boundary).
#[cfg(all(test, feature = "sync"))]
mod sync_tests;
pub mod sync_ui;
// Workspaces (save, open with bounded concurrency, `--workspace`, manage).
pub mod workspaces;
// Command history (capture tiers, storage), the autocomplete overlay, ghost text.
pub mod history;
// Terminal sharing (start dialog, approvals, viewers panel, viewer panes).
pub mod share;
#[cfg(test)]
mod share_tests;
// Accessibility pass.
#[cfg(test)]
mod a11y_tests;

use std::{collections::BTreeMap, sync::Arc};

use crossterm::event::KeyEventKind;
use ratatui::Frame;
use sverb_core::config::{ConfigEvent, ConfigUpdate, LiveConfig};

pub use config::Config;
pub use effect::SessionInput;
pub use effect::{Effect, EffectId, LevelMsg, LogLevel};
pub use event::{
    EffectOutput, EffectResult, InputEvent, LaunchIntent, TimerFired, TimerKind, UiEvent,
};
pub use forwards::{ForwardsEffect, ForwardsEvent};
pub use input::InputState;
pub use known_hosts::{KnownHostsEffect, KnownHostsEvent};
pub use logs::{ConnLogEvent, LogsEffect};
pub use notify::{
    COALESCE_WINDOW, HISTORY_LEN, MAX_VISIBLE_TOASTS as MAX_TOASTS, Notification, Notifications,
    TOAST_TTL,
};
pub use shell::DebugRing;
pub use snippets::{SnippetsEffect, SnippetsEvent};
use state::IdGen;
pub use state::{Focus, Layout, Mode, PendingKind, SessionId, Tabs, Toast, ToastId, ToastLevel};
pub use state::{MetaFlag, MetaFlags};
use sverb_term::scheme::SchemeCatalog;
pub use vault::{
    UnlockFailure, UnlockRequest, VaultEffect, VaultEvent, VaultPassword, VaultScreen,
    VaultStatusInfo,
};

use crate::widgets::terminal_pane::{NoPanes, PaneCursor, PaneInfo, PaneSource};

use crate::{
    keymap::{Keymap, action::ActionName},
    theme::{Theme, ThemeEnv},
    views::{Dialog, DialogId, DialogKind, Outcome, ShellState, View, ViewCx, ViewEvent, Views},
};

/// Whether `Effect::Suspend` can work here (Unix job control).
const SUSPEND_SUPPORTED: bool = cfg!(unix);

/// The whole UI state. `Clone + Debug + PartialEq`, so tests can snapshot and diff it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct App {
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
    /// Leader / sequence state, copy mode, one-time notices (`app/input.rs`).
    pub(crate) input: InputState,
    /// Sections, sidebar, regions, session-area toggle, log pane (`app/shell.rs`).
    pub(crate) shell: ShellState,
    /// The last 100 notifications (`app/notify.rs`).
    pub(crate) notifications: Notifications,
    /// The resolved UI theme.
    pub(crate) theme: Theme,
    /// `NO_COLOR` / `COLORTERM`, from the runtime.
    pub(crate) theme_env: ThemeEnv,
    /// The environment asks for ASCII glyphs (`ui.ascii = "auto"`), from the runtime.
    pub(crate) ascii_env: bool,
    /// The `--debug` log ring (`None` without `--debug`).
    pub(crate) debug_ring: Option<DebugRing>,
    /// `total_pushed` of the debug ring at the last draw.
    pub(crate) log_drawn: u64,
    /// The `--debug` warning toast was shown.
    pub(crate) debug_warning_shown: bool,
    /// The session the session area showed last (`leader v` returns to it).
    pub(crate) last_session: Option<SessionId>,
    /// Lock state and vault prompts (no key material; `app/vault.rs`).
    pub(crate) vault: vault::VaultUi,
    /// Terminal color schemes (built-ins + `themes/*.toml`).
    pub(crate) schemes: Arc<SchemeCatalog>,
    /// Per-pane state: label, OSC title, host scheme, overlay (`widgets::terminal_pane`).
    pub(crate) panes: BTreeMap<SessionId, PaneInfo>,
    /// Hosts: catalog loads, sessions opened from hosts, a pending `sverb connect`.
    pub(crate) hosts: hosts::HostsUi,
    /// Auth prompts waiting for the screen and credentials waiting for a successful
    /// login (`app/auth.rs`).
    pub(crate) auth: crate::widgets::auth_prompt::AuthPrompts,
    /// Copy mode, mouse selection, hovered links and read access to the emulators
    /// (`app/copy.rs`).
    pub(crate) copy: copy::CopyUi,
    /// The command palette's recent picks (`app/palette.rs`).
    pub(crate) palette: palette::PaletteUi,
    /// Command history: entries, per-pane prompt learning (`app/history.rs`).
    pub(crate) history: history::HistoryUi,
    /// Sync status, Settings → Sync / Devices / Team, the account wizard.
    pub(crate) sync: sync_ui::SyncUi,
    /// Shared panes and viewer panes (`app/share.rs`).
    pub(crate) share: share::ShareUi,
}

impl App {
    /// Initial state for a configuration.
    pub fn new(config: Arc<Config>) -> Self {
        let theme_env = ThemeEnv::default();
        let theme = Theme::resolve(&config.ui.theme, config.ui.truecolor, theme_env)
            // `ui.ascii` (the environment is unknown until `with_ascii_env`).
            .with_glyphs(
                crate::theme::glyphs::ascii_wanted(config.ui.ascii, false),
                config.ui.reduce_motion,
            );
        // The copy-mode table (`[keys.copy]`).
        let config_for_copy = Arc::clone(&config);
        Self {
            mode: Mode::default(),
            focus: Focus::default(),
            layout: Layout::default(),
            views: Views::default(),
            tabs: Tabs::default(),
            toasts: Vec::new(),
            dialogs: Vec::new(),
            // Built-ins merged with `[keys.*]` and `general.leader`.
            keymap: Keymap::from_config(&config),
            config,
            pending: BTreeMap::new(),
            needs_redraw: true,
            ids: IdGen::default(),
            input: InputState::default(),
            shell: ShellState::default(),
            notifications: Notifications::default(),
            theme,
            theme_env,
            ascii_env: false,
            debug_ring: None,
            log_drawn: 0,
            debug_warning_shown: false,
            last_session: None,
            // Unlocked without a vault service; the runtime calls `with_vault`.
            vault: vault::VaultUi::default(),
            schemes: Arc::new(SchemeCatalog::builtin_only()),
            panes: BTreeMap::new(),
            hosts: hosts::HostsUi::default(),
            auth: crate::widgets::auth_prompt::AuthPrompts::default(),
            copy: copy::CopyUi::new(&config_for_copy),
            palette: palette::PaletteUi::default(),
            history: history::HistoryUi::default(),
            sync: sync_ui::SyncUi::default(),
            share: share::ShareUi::default(),
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
        // Unlock and lock, from any path (events, actions, timers).
        let was_locked = self.lock_state();
        match ev {
            UiEvent::Input(input) => self.on_input(input, &mut effects),
            UiEvent::EffectDone { id, result } => self.on_effect_done(id, result, &mut effects),
            UiEvent::Timer(fired) => self.on_timer(fired, &mut effects),
            UiEvent::Config(change) => self.on_config(change, &mut effects),
            UiEvent::Launch(intent) => self.on_launch(intent, &mut effects),
            UiEvent::Meta(flags) => self.on_meta(flags, &mut effects),
            // Signals quit at once (no confirmation, SPEC §18).
            UiEvent::ShutdownRequested => effects.push(Effect::Quit { code: 0 }),
            UiEvent::Session(id, ev) => {
                // A connected pane's startup snippet may need values.
                self.snippets_on_session(id, &ev, &mut effects);
                // Tab markers, titles, pane states.
                self.tabs_on_session(id, &ev);
                // OSC 133 commands become history entries.
                self.history_on_session(id, &ev, &mut effects);
                self.on_session(id, ev, &mut effects);
            }
            UiEvent::Vault(ev) => self.on_vault(ev, &mut effects),
            UiEvent::IndexUpdated(snapshot) => {
                self.on_index_updated(snapshot);
                // The Hosts view and its catalog follow the index.
                self.hosts_on_index(&mut effects);
                // The Known Hosts view reloads.
                self.known_hosts_on_index(&mut effects);
                // The Forwards view reloads.
                self.forwards_on_index(&mut effects);
                // The Snippets view reloads.
                self.snippets_on_index(&mut effects);
            }
            UiEvent::ConnLog(ev) => self.on_conn_log(ev, &mut effects),
            UiEvent::KnownHosts(ev) => self.on_known_hosts(ev, &mut effects),
            UiEvent::Forwards(ev) => self.on_forwards(ev, &mut effects),
            UiEvent::Snippets(ev) => self.on_snippets(ev, &mut effects),
            UiEvent::Import(ev) => self.on_import(ev, &mut effects),
            UiEvent::Palette(ev) => self.on_palette(ev, &mut effects),
            UiEvent::Workspaces(ev) => self.on_workspaces(ev, &mut effects),
            UiEvent::History(ev) => self.on_history(ev, &mut effects),
            #[cfg(feature = "sync")]
            UiEvent::Sync(ev) => self.on_sync(ev, &mut effects),
            #[cfg(feature = "sync")]
            UiEvent::SyncUi(ev) => self.on_sync_ui(ev, &mut effects),
            UiEvent::Share(ev) => self.on_share(ev, &mut effects),
            // The `confirm_on_use` modal (60 s, then deny).
            UiEvent::AgentConfirm(prompt) => {
                self.push_modal(
                    crate::views::dialogs::agent_confirm::dialog(&prompt),
                    &mut effects,
                );
            }
        }
        // Maintenance on unlock; the decrypted list goes on lock.
        self.logs_lock_transition(was_locked, &mut effects);
        // The decrypted known hosts go on lock.
        self.known_hosts_lock_transition(was_locked);
        // The decrypted rules go on lock; the status refresh stops.
        self.forwards_lock_transition(was_locked, &mut effects);
        // The decrypted snippets (and dialogs holding values) go on lock.
        self.snippets_lock_transition(was_locked);
        // The palette (host and snippet names) closes on lock.
        self.palette_lock_transition(was_locked);
        // The decrypted history goes on lock and is reloaded on unlock.
        self.history_lock_transition(was_locked, &mut effects);
        // The sync engine runs while unlocked.
        self.sync_lock_transition(was_locked, &mut effects);
        // Locking cancels outstanding auth prompts.
        self.auth_lock_transition(was_locked, &mut effects);
        // Tabs follow the sessions and focus; closes, new panes, resize debounce.
        self.tabs_after_handle(&mut effects);
        // Viewer panes keep the host's size.
        self.share_after_handle(&mut effects);
        // The mode follows focus.
        self.mode = self.derive_mode();
        effects
    }

    /// Whether anything changed since the last draw.
    pub fn needs_redraw(&self) -> bool {
        // New lines for an open log pane.
        self.needs_redraw || self.log_dirty()
    }

    /// Called by the runtime after a frame was drawn.
    pub fn mark_drawn(&mut self) {
        self.needs_redraw = false;
        self.note_log_drawn();
    }

    /// Current input mode.
    pub fn mode(&self) -> Mode {
        // Derived from focus and the dialog stack.
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

    /// Sessions whose panes the next frame draws; the runtime acknowledges their dirty
    pub fn visible_sessions(&self) -> Vec<SessionId> {
        // Every pane of the active tab.
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
        // While locked the prompt gets every key (only `leader q` also works);
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
            // Keys go through the mode router (`app/input.rs`).
            InputEvent::Key(key) => return self.on_key(key, effects),
            InputEvent::Mouse(mouse) => {
                // Dragging a split border.
                if self.pane_ops_on_mouse(mouse) {
                    return;
                }
                // The top bar's sync indicator opens Settings → Sync.
                if self.sync_indicator_click(mouse, effects) {
                    return;
                }
                // Tab bar clicks, pane focus, mouse input for the focused pane.
                if self.tabs_on_mouse(mouse, effects) {
                    return;
                }
                ViewEvent::Mouse(mouse)
            }
            // Pastes go to a focused live session.
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
                // A quick-connect answer.
                self.take_hosts_requests(effects);
                // "+ new identity" in a host form, a "Used by" pick.
                self.take_keychain_requests(effects);
                // An answered auth prompt.
                self.take_auth_answer(effects);
                // A snippet dialog's answer; run prompts' answers go to the run.
                self.take_snippet_answer(effects);
                self.reroute_snippet_answers(effects);
                // The palette's re-ranking and answer.
                self.take_palette_answer(effects);
                // The workspaces dialog's answer (open, save steps, rename, …).
                self.take_workspaces_answer(effects);
                // The autocomplete overlay's choice.
                self.take_autocomplete_answer(effects);
                // The account wizard's input.
                self.take_sync_dialog_answer(effects);
                // The share dialogs (start, approve, viewers panel).
                self.take_share_answer(effects);
                return outcome;
            }
        }
        // Session panes are not views (yet); the router handles their keys.
        // In the section views the focused region picks the view.
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
        // The Logs view's request (reconnect, dialogs, replay, export).
        self.take_logs_request(effects);
        // The Known Hosts view's request (delete, edit, import, export).
        self.take_known_hosts_request(effects);
        // The Forwards view's request (start, stop, add, edit, delete).
        self.take_forwards_request(effects);
        // The Snippets view's request (run, run on hosts, paste, add, edit, …).
        self.take_snippets_request(effects);
        // The Keychain view's request, "+ new identity", "Used by" answers.
        self.take_keychain_requests(effects);
        // The Hosts view's request and a quick-connect answer.
        self.take_hosts_requests(effects);
        // Settings → Sync / Devices / Team.
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
            // `leader ctrl-l`.
            ActionName::LockVault if self.vault.active => self.lock_vault(effects),
            // `leader o`.
            ActionName::QuickConnect => self.open_quick_connect(),
            // `leader e`.
            ActionName::SnippetPicker => self.open_snippet_picker(effects),
            // `leader p`, `ctrl-k`.
            ActionName::Palette => self.open_palette(effects),
            // `leader Space`, `leader Tab`.
            ActionName::Autocomplete => self.open_autocomplete(effects),
            ActionName::AcceptGhostText => self.accept_ghost_text(effects),
            // Windows has no job control; say so instead of doing nothing.
            ActionName::Suspend => self.on_suspend(SUSPEND_SUPPORTED, effects),
            // Sync status, sync now, devices, team keys.
            other if self.apply_sync_action(other, effects) => {}
            // `leader S`.
            other if self.apply_share_action(other, effects) => {}
            // Resize, resize mode, zoom, rename / move tab, equalize.
            other if self.apply_pane_ops_action(other, effects) => {}
            // `leader b` / `leader B`.
            other if self.apply_broadcast_action(other, effects) => {}
            // Tabs, splits, pane focus, close pane / tab.
            other if self.apply_tab_action(other, effects) => {}
            // Help, sidebar, views, notifications, log pane.
            other if self.apply_shell_action(other, effects) => {}
            other => self.apply_keymap_action(other, effects),
        }
    }

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
        // Host saves, catalog loads, the edit form.
        self.hosts_on_effect_done(&kind, result, effects);
    }

    fn on_timer(&mut self, fired: TimerFired, effects: &mut Vec<Effect>) {
        match fired.kind {
            TimerKind::ToastExpiry(_) | TimerKind::ToastCoalesce(_) => {
                self.on_toast_timer(fired.kind);
            }
            TimerKind::WhichKey | TimerKind::LeaderTimeout => {
                self.on_key_timer(fired.kind, effects);
            }
            TimerKind::AutoLockCheck | TimerKind::UnlockCountdown => {
                self.vault_on_timer(fired.kind, effects);
            }
            TimerKind::ResizeDebounce => self.on_resize_debounce(effects),
            TimerKind::DialogTick(id) => self.on_dialog_tick(id, effects),
            TimerKind::ReplayTick | TimerKind::LogsMaintenance => {
                self.on_logs_timer(fired.kind, fired.at, effects);
            }
            TimerKind::ResizeModeIdle => self.exit_resize_mode(effects),
            TimerKind::ForwardsRefresh => self.on_forwards_timer(effects),
            TimerKind::MultiClick => self.on_multi_click_timer(),
        }
    }

    // Hot reload. All-or-nothing: a rejected file keeps the current config.
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
                // `general.leader` and `[keys.*]` apply live.
                self.on_keymap_config(&config);
                self.config = config;
                // `ui.theme` / `ui.truecolor` apply live.
                self.resolve_theme();
                // `logs.sync`, `logs.retention_days`, `recording.retention_days`.
                self.logs_on_config(&diff, effects);
                // `[history]` for the history service.
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

    // The command-line intent: sessions, workspaces and
    // shared terminals.
    fn on_launch(&mut self, intent: LaunchIntent, effects: &mut Vec<Effect>) {
        // Delivered after unlock.
        let Some(intent) = self.vault_defer_launch(intent) else {
            return;
        };
        // The one-time `--debug` warning.
        self.on_launch_shell(effects);
        match intent {
            LaunchIntent::Plain => {}
            LaunchIntent::Connect(target) => self.launch_connect(target, effects),
            LaunchIntent::Workspace(name) => self.launch_workspace(name, effects),
            // A viewer pane (a link that doesn't parse is a warning toast).
            LaunchIntent::Join(link) => self.share_join(link, effects),
        }
    }

    /// Draw the whole UI (the shell, `app/shell.rs`). Infallible: tiny areas
    /// degrade, they never panic. Session panes have no emulator here; the runtime
    /// uses [`App::render_with_panes`].
    pub fn render(&self, frame: &mut Frame<'_>) {
        self.render_shell(frame, &NoPanes);
        // Lock overlay and vault prompts on top.
        self.render_vault(frame);
        // `ui.ascii`.
        self.render_glyph_fallback(frame);
    }

    /// Draw the whole UI with session content from `panes` (the session registry).
    /// Returns the real cursor of the focused live pane (position and DECSCUSR shape);
    /// the position is already set on `frame`.
    pub fn render_with_panes(
        &self,
        frame: &mut Frame<'_>,
        panes: &dyn PaneSource,
    ) -> Option<PaneCursor> {
        let cursor = self.render_shell(frame, panes);
        // Lock overlay and vault prompts on top; no pane cursor under them.
        self.render_vault(frame);
        // `ui.ascii`.
        self.render_glyph_fallback(frame);
        if self.vault_hides_panes() {
            return None;
        }
        cursor
    }
}

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
        // `connect db` opens an (unsaved) SSH session instead of a toast.
        // `--workspace w` asks the service for the list instead of a toast.
        assert_eq!(app.toasts().len(), 1);
        assert_eq!(app.tabs().sessions.len(), 1);
    }
}

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
