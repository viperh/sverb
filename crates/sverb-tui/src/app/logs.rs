//! M3-06: connection logs in the reducer (SPEC §9.12).
//!
//! - The ConnLog service (`services::connlog`) reports [`ConnLogEvent`]s: the entry of
//!   each new attempt (`Started`, so the disconnected banner's `leader i` can jump to it,
//!   see [`App::show_conn_log`]), the whole list after unlock and maintenance (`Loaded`),
//!   and single updates (`Upserted`, `Removed`).
//! - The Logs view (`views::logs::LogsView`) leaves requests (`Enter` reconnect, `i`
//!   details, `p` replay, `e` export, `d` delete, `D` clear older…), taken here right
//!   after the key; its dialogs' keys are handled here too.
//! - Unlock (and every 24 h while unlocked) runs maintenance: unsaved entries are
//!   written, retention is applied and the list is reloaded. Locking drops the list.
//! - The replay player ticks on `TimerKind::ReplayTick`, at the delay the player asks for.

use std::{path::PathBuf, time::Duration};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use sverb_conn::{LocalSpec, SessionSpec, SshSpec};
use sverb_core::{config::ConfigDiff, error_report::ErrorReport, model::ItemId, vault::LockState};
use sverb_term::recording::Recording;

use super::{App, Effect, SessionId, TimerKind, ToastLevel};
use crate::views::{
    DialogKind, Section,
    logs::{
        LogEntry, LogsClear, LogsDelete, LogsDialog, LogsExport, LogsRequest, ReplayHandle,
        ReplayOutcome, ReplayView,
    },
};

/// How often maintenance (retention) runs while unlocked.
pub const MAINTENANCE_EVERY: Duration = Duration::from_secs(24 * 60 * 60);

/// Days offered by "clear older than…" when `logs.retention_days` is 0.
pub const DEFAULT_CLEAR_DAYS: u32 = 30;

/// From the ConnLog service.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnLogEvent {
    /// A session started a connection attempt; `id` is its ConnLog entry.
    Started {
        /// The session.
        session: SessionId,
        /// The entry.
        id: ItemId,
    },
    /// Every entry (after unlock and after maintenance).
    Loaded(Vec<LogEntry>),
    /// One entry was written (new, finalized, recording attached).
    Upserted(LogEntry),
    /// Entries were deleted (tombstoned).
    Removed(Vec<ItemId>),
    /// A recording was decrypted for the player.
    Replay {
        /// The entry.
        id: ItemId,
        /// Its host label.
        label: String,
        /// The decrypted recording.
        recording: Box<Recording>,
    },
    /// A recording was exported.
    Exported {
        /// The plain asciicast file.
        path: PathBuf,
        /// The recording had no final chunk (truncated).
        incomplete: bool,
    },
    /// Maintenance ran.
    Maintained {
        /// Entries tombstoned by `logs.retention_days`.
        tombstoned: usize,
        /// Recordings deleted by `recording.retention_days`.
        recordings_deleted: usize,
    },
    /// Something failed (a toast).
    Failed(ErrorReport),
}

/// Requests for the ConnLog service.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LogsEffect {
    /// `logs.sync` (entries written from now on are queued for sync only when on).
    SetSync(bool),
    /// Write unsaved entries, apply retention, reload (answered with `Maintained`,
    /// then `Loaded`).
    Maintain {
        /// `logs.retention_days` (0 = forever).
        logs_retention_days: u32,
        /// `recording.retention_days` (0 = until deleted).
        recording_retention_days: u32,
    },
    /// Tombstone entries (answered with `Removed`).
    Delete {
        /// The entries.
        ids: Vec<ItemId>,
        /// Also delete their recordings.
        delete_recordings: bool,
    },
    /// Tombstone every entry started more than `days` days ago.
    ClearOlderThan {
        /// Days.
        days: u32,
        /// Also delete their recordings.
        delete_recordings: bool,
    },
    /// Decrypt a recording for the player (answered with `Replay`).
    OpenReplay {
        /// The entry.
        id: ItemId,
        /// Its recording.
        path: PathBuf,
        /// Its host label.
        label: String,
    },
    /// Export a recording as plain asciicast (answered with `Exported`).
    Export {
        /// The recording.
        src: PathBuf,
        /// Destination as typed (`~/` and relative paths are resolved by the service).
        dst: String,
    },
}

/// Pane size used before the terminal size is known.
const FALLBACK_SIZE: (u16, u16) = (80, 24);

impl App {
    /// The Logs view state.
    pub fn logs(&self) -> &crate::views::logs::LogsView {
        &self.views.logs
    }

    /// `UiEvent::ConnLog`.
    pub(crate) fn on_conn_log(&mut self, ev: ConnLogEvent, effects: &mut Vec<Effect>) {
        let unlocked = self.lock_state() == LockState::Unlocked;
        match ev {
            ConnLogEvent::Started { session, id } => {
                self.views.logs.sessions.insert(session, id);
            }
            // Decrypted data is ignored while locked (the next unlock reloads it).
            ConnLogEvent::Loaded(entries) if unlocked => self.views.logs.set_entries(entries),
            ConnLogEvent::Upserted(entry) if unlocked => self.views.logs.upsert(entry),
            ConnLogEvent::Removed(ids) => self.views.logs.remove(&ids),
            ConnLogEvent::Replay {
                id: _,
                label,
                recording,
            } if unlocked => {
                let view = ReplayView::new(*recording, label);
                self.push_dialog(DialogKind::Logs(LogsDialog::Replay(ReplayHandle::new(
                    view,
                ))));
                effects.push(Effect::ScheduleTimer {
                    kind: TimerKind::ReplayTick,
                    after: Duration::from_millis(1),
                });
            }
            ConnLogEvent::Exported { path, incomplete } => {
                let mut msg = format!("Recording exported to {}", path.display());
                let level = if incomplete {
                    msg.push_str(" (incomplete: the recording was truncated)");
                    ToastLevel::Warning
                } else {
                    ToastLevel::Success
                };
                self.push_toast(level, msg, effects);
            }
            ConnLogEvent::Maintained {
                tombstoned,
                recordings_deleted,
            } => {
                effects.push(Effect::Log(super::LevelMsg {
                    level: super::LogLevel::Info,
                    msg: format!(
                        "log maintenance: {tombstoned} entries expired, \
                         {recordings_deleted} recordings deleted"
                    ),
                }));
            }
            ConnLogEvent::Failed(report) => self.push_error(&report, effects),
            _ => {}
        }
        self.needs_redraw = true;
    }

    /// After every event: unlocking runs maintenance (and arms the daily timer);
    /// locking forgets the decrypted list.
    pub(crate) fn logs_lock_transition(&mut self, was: LockState, effects: &mut Vec<Effect>) {
        let now = self.lock_state();
        if now == was {
            return;
        }
        match now {
            LockState::Unlocked => {
                effects.push(Effect::Logs(LogsEffect::SetSync(self.config.logs.sync)));
                self.run_logs_maintenance(effects);
            }
            _ => {
                self.views.logs.clear();
                effects.push(Effect::CancelTimer(TimerKind::LogsMaintenance));
                effects.push(Effect::CancelTimer(TimerKind::ReplayTick));
            }
        }
    }

    fn run_logs_maintenance(&mut self, effects: &mut Vec<Effect>) {
        effects.push(Effect::Logs(LogsEffect::Maintain {
            logs_retention_days: self.config.logs.retention_days,
            recording_retention_days: self.config.recording.retention_days,
        }));
        effects.push(Effect::ScheduleTimer {
            kind: TimerKind::LogsMaintenance,
            after: MAINTENANCE_EVERY,
        });
    }

    /// `logs.sync` applies to entries written from now on; a retention change applies
    /// at once.
    pub(crate) fn logs_on_config(&mut self, diff: &ConfigDiff, effects: &mut Vec<Effect>) {
        if self.lock_state() != LockState::Unlocked {
            return;
        }
        if diff.contains("logs.sync") {
            effects.push(Effect::Logs(LogsEffect::SetSync(self.config.logs.sync)));
        }
        if diff.contains("logs.retention_days") || diff.contains("recording.retention_days") {
            self.run_logs_maintenance(effects);
        }
    }

    /// `TimerKind::LogsMaintenance` and `TimerKind::ReplayTick`.
    pub(crate) fn on_logs_timer(
        &mut self,
        kind: TimerKind,
        at: std::time::Instant,
        effects: &mut Vec<Effect>,
    ) {
        match kind {
            TimerKind::LogsMaintenance if self.lock_state() == LockState::Unlocked => {
                self.run_logs_maintenance(effects);
            }
            TimerKind::ReplayTick => {
                let Some(handle) = self.replay_handle() else {
                    return;
                };
                let mut view = handle.lock();
                if view.tick(at) {
                    self.needs_redraw = true;
                }
                if let Some(after) = view.next_tick_in() {
                    effects.push(Effect::ScheduleTimer {
                        kind: TimerKind::ReplayTick,
                        after,
                    });
                }
            }
            _ => {}
        }
    }

    /// The open replay player, if it is the top dialog.
    fn replay_handle(&self) -> Option<ReplayHandle> {
        match self.dialogs.last().map(|d| &d.kind) {
            Some(DialogKind::Logs(LogsDialog::Replay(h))) => Some(h.clone()),
            _ => None,
        }
    }

    /// The disconnected banner's `leader i` (M1-16): show the Logs section with the
    /// session's current ConnLog entry selected. Returns `false` when the session has no
    /// entry (yet).
    pub fn show_conn_log(&mut self, session: SessionId) -> bool {
        let Some(id) = self.views.logs.sessions.get(&session).copied() else {
            return false;
        };
        self.open_section(Section::Logs);
        self.views.logs.focus(id);
        self.needs_redraw = true;
        true
    }

    /// Take the request the Logs view left after a key.
    pub(crate) fn take_logs_request(&mut self, effects: &mut Vec<Effect>) {
        let Some(request) = self.views.logs.request.take() else {
            return;
        };
        let entry = |app: &Self, id: ItemId| app.views.logs.get(id).cloned();
        match request {
            LogsRequest::Reconnect(id) => {
                if let Some(e) = entry(self, id) {
                    self.reconnect_log(&e, effects);
                }
            }
            LogsRequest::Details(id) => {
                if let Some(e) = entry(self, id) {
                    self.push_dialog(DialogKind::Logs(LogsDialog::Detail(Box::new(e))));
                }
            }
            LogsRequest::Replay(id) => match entry(self, id) {
                Some(LogEntry {
                    id,
                    log,
                    recording: Some(path),
                }) => effects.push(Effect::Logs(LogsEffect::OpenReplay {
                    id,
                    path,
                    label: if log.label.is_empty() {
                        "recording".to_owned()
                    } else {
                        log.label
                    },
                })),
                Some(_) => self.no_recording(effects),
                None => {}
            },
            LogsRequest::Export(id) => {
                if let Some(e) = entry(self, id) {
                    match &e.recording {
                        Some(src) => {
                            let path = default_export_name(&e);
                            self.push_dialog(DialogKind::Logs(LogsDialog::Export(LogsExport {
                                src: src.clone(),
                                path,
                            })));
                        }
                        None => self.no_recording(effects),
                    }
                }
            }
            LogsRequest::Delete(id) => {
                if let Some(e) = entry(self, id) {
                    self.push_dialog(DialogKind::Logs(LogsDialog::Delete(LogsDelete {
                        ids: vec![id],
                        label: e.host().to_owned(),
                        has_recording: e.recording.is_some(),
                    })));
                }
            }
            LogsRequest::ClearOlder => {
                let days = match self.config.logs.retention_days {
                    0 => DEFAULT_CLEAR_DAYS,
                    d => d,
                };
                self.push_dialog(DialogKind::Logs(LogsDialog::Clear(LogsClear {
                    days: days.to_string(),
                    delete_recordings: false,
                })));
            }
        }
        self.needs_redraw = true;
    }

    fn no_recording(&mut self, effects: &mut Vec<Effect>) {
        self.push_toast(
            ToastLevel::Info,
            "This entry has no recording".to_owned(),
            effects,
        );
    }

    /// Open a new session for the entry's host: a local shell for local entries, the
    /// recorded `user@host:port` for SSH ones.
    ///
    /// M1-07/M1-13: entries with a `host_id` should connect through the host (current
    /// settings, identities, jump hosts) once that path exists; until then the target
    /// recorded in the entry is used.
    pub(crate) fn reconnect_log(&mut self, entry: &LogEntry, effects: &mut Vec<Effect>) {
        // M1-07: a host that still exists connects through its current settings.
        if let Some(host) = entry.log.host_id
            && self.views.hosts.host(host).is_some()
        {
            self.connect_host(host, effects);
            return;
        }
        let spec = match (&entry.log.target, entry.log.host_id) {
            (None, None) => SessionSpec::Local(LocalSpec::default()),
            (Some(target), _) => match parse_target(target) {
                Some(ssh) => SessionSpec::Ssh(ssh),
                None => {
                    self.push_toast(
                        ToastLevel::Error,
                        format!("Cannot reconnect: bad target {target:?}"),
                        effects,
                    );
                    return;
                }
            },
            (None, Some(_)) => {
                self.push_toast(
                    ToastLevel::Info,
                    "That host no longer exists".to_owned(),
                    effects,
                );
                return;
            }
        };
        let id = loop {
            let id = self.ids.session();
            if !self.tabs.sessions.contains(&id) {
                break id;
            }
        };
        let main = self.shell_rects().main;
        let (cols, rows) = if main.width > 2 && main.height > 2 {
            (main.width - 2, main.height - 2)
        } else {
            FALLBACK_SIZE
        };
        effects.push(Effect::OpenSession {
            id,
            spec,
            cols,
            rows,
        });
        self.focus_session(id);
        // M3-05: the global flag (per-host settings arrive with M1-07/M1-13).
        self.auto_record(id, self.config.recording.enabled, effects);
    }

    /// Keys for an open Logs dialog (it is modal). Returns `false` when the top dialog
    /// is not a Logs dialog.
    pub(crate) fn on_logs_dialog_key(&mut self, key: KeyEvent, effects: &mut Vec<Effect>) -> bool {
        let Some(top) = self.dialogs.last_mut() else {
            return false;
        };
        let DialogKind::Logs(dialog) = &mut top.kind else {
            return false;
        };
        let plain = !key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT);
        let mut close = false;
        match dialog {
            LogsDialog::Detail(_) => {
                close = matches!(
                    key.code,
                    KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q' | 'i')
                );
            }
            LogsDialog::Delete(d) => match key.code {
                KeyCode::Char('y' | 'Y') if plain => {
                    effects.push(Effect::Logs(LogsEffect::Delete {
                        ids: d.ids.clone(),
                        delete_recordings: d.has_recording,
                    }));
                    close = true;
                }
                KeyCode::Char('k' | 'K') if plain && d.has_recording => {
                    effects.push(Effect::Logs(LogsEffect::Delete {
                        ids: d.ids.clone(),
                        delete_recordings: false,
                    }));
                    close = true;
                }
                KeyCode::Char('n' | 'N') | KeyCode::Esc => close = true,
                _ => {}
            },
            LogsDialog::Clear(c) => match key.code {
                KeyCode::Char(ch) if plain && ch.is_ascii_digit() && c.days.len() < 5 => {
                    c.days.push(ch);
                }
                KeyCode::Backspace => {
                    c.days.pop();
                }
                KeyCode::Tab => c.delete_recordings = !c.delete_recordings,
                KeyCode::Enter => {
                    if let Ok(days) = c.days.parse::<u32>()
                        && days > 0
                    {
                        effects.push(Effect::Logs(LogsEffect::ClearOlderThan {
                            days,
                            delete_recordings: c.delete_recordings,
                        }));
                        close = true;
                    }
                }
                KeyCode::Esc => close = true,
                _ => {}
            },
            LogsDialog::Export(x) => match key.code {
                KeyCode::Char(ch) if plain => x.path.push(ch),
                KeyCode::Backspace => {
                    x.path.pop();
                }
                KeyCode::Enter if !x.path.trim().is_empty() => {
                    effects.push(Effect::Logs(LogsEffect::Export {
                        src: x.src.clone(),
                        dst: x.path.trim().to_owned(),
                    }));
                    close = true;
                }
                KeyCode::Esc => close = true,
                _ => {}
            },
            LogsDialog::Replay(handle) => {
                let outcome = handle.lock().handle_key(key);
                match outcome {
                    ReplayOutcome::Consumed => effects.push(Effect::ScheduleTimer {
                        kind: TimerKind::ReplayTick,
                        after: Duration::from_millis(1),
                    }),
                    ReplayOutcome::Close => {
                        effects.push(Effect::CancelTimer(TimerKind::ReplayTick));
                        close = true;
                    }
                    ReplayOutcome::Ignored => {}
                }
            }
        }
        if close {
            self.dialogs.pop();
        }
        self.needs_redraw = true;
        true
    }
}

/// `sverb-<label>-<started>.cast` (file-name safe).
fn default_export_name(e: &LogEntry) -> String {
    let label: String = e
        .host()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let started = crate::views::logs::list::format_time(e.log.started_at, "%Y%m%d-%H%M%S", Some(0));
    format!("sverb-{label}-{started}.cast")
}

/// `[user@]host[:port]`, with `[v6]:port` for IPv6 addresses.
pub fn parse_target(target: &str) -> Option<SshSpec> {
    let (user, rest) = match target.split_once('@') {
        Some((u, r)) if !u.is_empty() => (Some(u.to_owned()), r),
        Some(_) => return None,
        None => (None, target),
    };
    let (host, port) = if let Some(v6) = rest.strip_prefix('[') {
        let (host, after) = v6.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None if after.is_empty() => 0,
            None => return None,
        };
        (host.to_owned(), port)
    } else {
        match rest.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (h.to_owned(), p.parse().ok()?),
            _ => (rest.to_owned(), 0),
        }
    };
    if host.is_empty() {
        return None;
    }
    Some(SshSpec {
        host,
        port: if port == 0 {
            sverb_core::model::DEFAULT_SSH_PORT
        } else {
            port
        },
        user,
        // M1-13
        ..SshSpec::default()
    })
}

#[cfg(test)]
#[path = "logs_tests.rs"]
mod tests;
