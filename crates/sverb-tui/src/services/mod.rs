//! The effect executor.
//!
//! [`Services`] owns the handles side effects need (the store, session manager and
//! clipboard in later tasks). [`Services::execute`]
//! performs or spawns an effect and later reports its result as a [`UiEvent`] on the
//! bounded event channel. Blocking work (Argon2, SQLite, key generation) must go
//! through `tokio::task::spawn_blocking` (SPEC §2.1).
//!
//! Services never touch [`App`](crate::app::App). `Quit`, `Suspend`,
//! `SetMouseCapture`, `ScheduleTimer` and `CancelTimer` belong to the runtime loop
//! (M0-09: the timer service is `runtime::timers::Timers`) and are not executed here.

use sverb_core::error_report::ErrorReport;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::app::{Effect, LevelMsg, LogLevel, UiEvent};

// M1-08: OpenSession / SendToSession / CloseSession through the session manager.
pub mod sessions;
use self::sessions::SessionService;
// M1-04: first run, unlock, lock, password change; owns the keys.
pub mod vault;
use self::vault::VaultService;
// M4-07: runs the sync engine while the vault is unlocked (feature `sync`).
#[cfg(feature = "sync")]
pub mod sync;
// M1-11: CopyToClipboard (OSC 52 and/or the local clipboard).
pub mod clipboard;
use self::clipboard::ClipboardService;
// M3-05: StartRecording / StopRecording (encrypted session recordings).
pub mod recording;
use self::recording::RecordingService;
// M3-06: connection logs (the session manager's ConnLog sink) and retention.
pub mod connlog;
pub mod maintenance;
use self::connlog::ConnLogService;
// M1-13: the SSH connector's host resolver (vault, group chain, secrets).
pub mod ssh;
// M1-15: the known-hosts store of the host-key verifier; the Known Hosts view's effects.
pub mod known_hosts;
// M3-04: `Effect::OpenUrl` (confirmed links, the `open` crate).
pub mod opener;
use self::opener::UrlOpener;
// M2-08: port forwards (the session manager's forward hook; the Forwards view's effects).
pub mod forwards;
// M2-07: confirm_on_use prompts, the control socket, the vault key source.
pub mod agent;
use self::forwards::ForwardsService;
// M2-09: snippets (load / save, exec runs on hosts, exports, startup checks).
pub mod snippets;
// M2-11: import / export (the import wizard's effects, `sverb import` / `sverb export`).
pub mod import;
// M2-12: the command palette's recent picks (device-local `meta`).
pub mod palette;
// M3-03: workspaces (load, save, rename, delete, duplicate as synced items).
pub mod workspaces;
// M7-01: command history (captured commands, snippet runs, the per-host cap, purge).
pub mod history;

/// Sender half of the bounded UI event channel.
pub type EventSender = mpsc::Sender<UiEvent>;

/// Handles needed to execute effects.
#[derive(Debug, Default)]
pub struct Services {
    // M0-09: timers moved to the loop (`runtime::timers`).
    // M1-03: store; M1-11: clipboard.
    // M1-08: sessions (`None` in loop tests that run without a session manager).
    sessions: Option<SessionService>,
    // M1-04: the vault (and through it the store); `None` without a database.
    vault: Option<VaultService>,
    // M1-11
    /// `None` in loop tests: copies are logged and dropped.
    clipboard: Option<ClipboardService>,
    // M3-05
    /// `None` without a state dir (loop tests): recording requests fail visibly.
    recording: Option<RecordingService>,
    // M3-06
    /// `None` in loop tests: logs effects are dropped.
    connlog: Option<ConnLogService>,
    // M2-08
    /// Rules and running tunnels.
    forwards: ForwardsService,
    // M3-04
    /// `None` (tests, loop tests): links are never opened, only logged at debug.
    opener: Option<Box<dyn UrlOpener>>,
    // M2-07
    /// `confirm_on_use` answers, the control socket (`None` in tests).
    agent: Option<agent::AgentService>,
    // M7-01
    /// `None` in loop tests: history effects are dropped.
    history: Option<history::HistoryService>,
}

impl Services {
    /// Services with no handles yet.
    pub fn new() -> Self {
        Self::default()
    }

    // M1-08
    /// Execute session effects through `sessions`.
    #[must_use]
    pub fn with_sessions(mut self, sessions: SessionService) -> Self {
        // M2-08: SSH connections report to the forward manager (auto-start, reconnect).
        self.forwards.attach(&sessions);
        self.sessions = Some(sessions);
        self
    }

    // M1-11
    /// Execute `CopyToClipboard` through `clipboard`.
    #[must_use]
    pub fn with_clipboard(mut self, clipboard: ClipboardService) -> Self {
        self.clipboard = Some(clipboard);
        self
    }

    // M3-05
    /// Record sessions into `dir` (`Paths::recordings_dir`).
    #[must_use]
    pub fn with_recordings_dir(mut self, dir: std::path::PathBuf) -> Self {
        self.recording = Some(RecordingService::new(dir));
        self
    }

    // M3-06
    /// Execute `Effect::Logs` and name recordings through `connlog`. The caller also
    /// registers it as the session manager's ConnLog sink.
    #[must_use]
    pub fn with_connlog(mut self, connlog: ConnLogService) -> Self {
        self.connlog = Some(connlog);
        self
    }

    // M2-07
    /// Answer agent prompts through `agent` (and keep its control socket alive).
    #[must_use]
    pub fn with_agent(mut self, agent: agent::AgentService) -> Self {
        self.agent = Some(agent);
        self
    }

    // M7-01
    /// Execute `Effect::History` (and record snippet runs) through `history`.
    #[must_use]
    pub fn with_history(mut self, history: history::HistoryService) -> Self {
        self.history = Some(history);
        self
    }

    // M7-01
    /// The history service, if any.
    pub fn history(&self) -> Option<&history::HistoryService> {
        self.history.as_ref()
    }

    // M3-06
    /// The ConnLog service, if any.
    pub fn connlog(&self) -> Option<&ConnLogService> {
        self.connlog.as_ref()
    }

    // M1-08
    /// The session service, if any.
    pub fn sessions(&self) -> Option<&SessionService> {
        self.sessions.as_ref()
    }

    // M1-04
    /// Execute vault effects (and persist meta flags) through `vault`.
    #[must_use]
    pub fn with_vault(mut self, vault: VaultService) -> Self {
        self.vault = Some(vault);
        self
    }

    // M1-04
    /// [`Services::with_vault`] when `vault` is `Some`.
    #[must_use]
    pub fn with_vault_opt(mut self, vault: Option<VaultService>) -> Self {
        self.vault = vault;
        self
    }

    // M1-04
    /// The vault service, if any.
    pub fn vault(&self) -> Option<&VaultService> {
        self.vault.as_ref()
    }

    // M3-04
    /// Open confirmed links with `opener` (the runtime passes `opener::SystemOpener`).
    #[must_use]
    pub fn with_url_opener(mut self, opener: Box<dyn UrlOpener>) -> Self {
        self.opener = Some(opener);
        self
    }

    /// Execute `effect`. Must be called from inside a tokio runtime.
    pub fn execute(&mut self, effect: Effect, ev_tx: &EventSender) {
        match effect {
            Effect::Log(LevelMsg { level, msg }) => match level {
                LogLevel::Error => error!("{msg}"),
                LogLevel::Warn => warn!("{msg}"),
                LogLevel::Info => info!("{msg}"),
                LogLevel::Debug => debug!("{msg}"),
            },
            // M0-10 / M1-08: session input (never awaits the session); M1-03 persists
            // meta flags.
            Effect::SendToSession { id, input } => match &mut self.sessions {
                Some(sessions) => sessions.send(id, input),
                None => debug!(session = id.0, "session input dropped: no session manager"),
            },
            // M1-04: persisted through the vault service's store.
            Effect::SetMetaFlag(flag) => match &self.vault {
                Some(vault) => vault.set_meta_flag(flag),
                None => debug!(flag = flag.key(), "meta flag not persisted: no store"),
            },
            // M1-04
            Effect::Vault(op) => match &self.vault {
                Some(vault) => vault.execute(op, ev_tx),
                None => warn!("vault effect ignored: no vault service"),
            },
            // M1-08
            Effect::OpenSession {
                id,
                spec,
                cols,
                rows,
            } => match &mut self.sessions {
                Some(sessions) => sessions.open(id, spec, cols, rows),
                None => warn!(session = id.0, "cannot open session: no session manager"),
            },
            Effect::CloseSession(id) => match &mut self.sessions {
                Some(sessions) => sessions.close(id),
                None => debug!(session = id.0, "close ignored: no session manager"),
            },
            // M1-17: debounced pane resizes.
            Effect::ResizeSession { id, cols, rows } => match &mut self.sessions {
                Some(sessions) => sessions.resize(id, cols, rows),
                None => debug!(session = id.0, "resize ignored: no session manager"),
            },
            // M1-12
            Effect::ReconnectSession(id) => match &mut self.sessions {
                Some(sessions) => {
                    let _ = sessions.command(id, sverb_conn::SessionCmd::Reconnect);
                }
                None => debug!(session = id.0, "reconnect ignored: no session manager"),
            },
            // M1-11
            Effect::CopyToClipboard(text) => match &mut self.clipboard {
                Some(clipboard) => {
                    let report = clipboard.copy(&text);
                    debug!(?report, chars = text.chars().count(), "copied");
                }
                None => debug!("copy dropped: no clipboard service"),
            },
            // M3-05
            Effect::StartRecording {
                id,
                token,
                title,
                include_input,
            } => {
                let Some(sessions) = &mut self.sessions else {
                    warn!(session = id.0, "cannot record: no session manager");
                    return;
                };
                let key = self
                    .vault
                    .as_ref()
                    .and_then(VaultService::unlocked)
                    .map(|v| recording::recording_key(&v));
                let req = recording::StartRequest {
                    id,
                    token,
                    title,
                    include_input,
                };
                // M3-06: named after the session's ConnLog entry.
                let connlog = self.connlog.clone();
                let conn_id = connlog.as_ref().map(|c| c.recording_id(id));
                let on_created = move |entry, path| {
                    if let Some(connlog) = &connlog {
                        connlog.set_recording(entry, path);
                    }
                };
                match &self.recording {
                    Some(rec) => rec.start(req, key, conn_id, on_created, sessions),
                    None => sessions.notify(
                        id,
                        sverb_conn::SessionEvent::Recording(
                            sverb_conn::session::event::RecordingStatus::Failed {
                                token,
                                error: ErrorReport::msg("recording is not available here"),
                            },
                        ),
                    ),
                }
            }
            Effect::StopRecording(id) => match (&self.recording, &mut self.sessions) {
                (Some(rec), Some(sessions)) => rec.stop(id, sessions),
                (None, Some(sessions)) => {
                    let _ = sessions.command(id, sverb_conn::SessionCmd::StopRecording);
                }
                _ => debug!(session = id.0, "stop recording ignored: no session manager"),
            },
            // M3-06
            Effect::Logs(op) => match &self.connlog {
                Some(connlog) => connlog.execute(op),
                None => debug!(?op, "logs effect dropped: no connlog service"),
            },
            // M1-14: auth prompt answers; credentials saved after a successful login.
            Effect::AuthAnswer { id, reply } => match &mut self.sessions {
                Some(sessions) => ssh::send_auth_answer(sessions, id, reply),
                None => debug!(session = id.0, "auth answer dropped: no session manager"),
            },
            Effect::SaveCredential(req) => {
                let notify: Box<dyn Fn(crate::app::SessionId, sverb_conn::SessionEvent) + Send> =
                    match &self.sessions {
                        Some(sessions) => Box::new(sessions.clone_notifier()),
                        None => Box::new(|_, _| {}),
                    };
                ssh::save_credential(self.vault.as_ref(), req, notify);
            }
            // M0-09: timers are loop-owned too.
            // M1-15: a host-key prompt's answer; known-hosts requests.
            Effect::HostKeyDecision { id, decision } => match &mut self.sessions {
                Some(sessions) => {
                    let sent =
                        sessions.command(id, sverb_conn::SessionCmd::HostKeyDecision(decision));
                    if sent != sverb_conn::SendOutcome::Sent {
                        warn!(session = id.0, ?sent, "host-key decision not delivered");
                    }
                }
                None => debug!(session = id.0, "host-key decision ignored: no session manager"),
            },
            Effect::KnownHosts(op) => known_hosts::execute(self.vault.as_ref(), op, ev_tx),
            // M3-04: never logs the URL above debug (it can contain host names).
            Effect::OpenUrl(url) => opener::open(self.opener.as_deref_mut(), &url),
            // M2-08
            Effect::Forwards(op) => {
                self.forwards
                    .execute(op, self.vault.as_ref(), self.sessions.as_mut(), ev_tx);
            }
            // M2-09
            // M7-01: snippet runs typed into panes are recorded in the history.
            Effect::Snippets(crate::app::SnippetsEffect::History(record)) => {
                if let Some(history) = &self.history {
                    sverb_core::snippet::HistorySink::record(history, record);
                }
            }
            Effect::Snippets(op) => snippets::execute(self.vault.as_ref(), op, ev_tx),
            // M7-01
            Effect::History(op) => match &self.history {
                Some(history) => history.execute(op),
                None => debug!("history effect dropped: no history service"),
            },
            // M2-07
            Effect::AgentConfirm { id, allow } => match &self.agent {
                Some(agent) => agent.answer(id, allow),
                None => debug!(id, "agent confirm ignored: no agent service"),
            },
            // M2-11
            Effect::Import(op) => import::execute(self.vault.as_ref(), op, ev_tx),
            // M2-12
            Effect::Palette(op) => {
                palette::execute(self.vault.as_ref().map(VaultService::store), op, ev_tx);
            }
            // M3-03
            Effect::Workspaces(op) => workspaces::execute(self.vault.as_ref(), op, ev_tx),
            Effect::Quit { .. }
            | Effect::Suspend
            | Effect::SetMouseCapture(_)
            | Effect::ScheduleTimer { .. }
            | Effect::CancelTimer(_) => {
                warn!(?effect, "loop-owned effect sent to services; ignored");
            }
        }
    }
}
