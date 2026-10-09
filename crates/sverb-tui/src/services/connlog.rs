//! The ConnLog service (SPEC §4.12, §9.12).
//!
//! - It is the session manager's [`ConnLogSink`]: every connection attempt becomes a
//!   `ConnLog` item, created when the attempt starts and finalized when it ends (result,
//!   `ended_at`, byte counts, error detail). The UI learns the entry of each attempt
//!   (`ConnLogEvent::Started`), so the disconnected banner can jump to it.
//! - Writes go through one writer task, in order, sealed with the personal vault's key
//!   (the vault service's [`UnlockedVault`]). While the vault is locked (sessions stay
//!   connected, SPEC §5.3) entries wait in memory and are written by the next
//!   maintenance run after unlock; entries still waiting at quit are lost (they cannot be
//!   encrypted without the keys), which is logged.
//! - **Sync:** entries are written with the dirty flag (and so queued in the outbox) only
//!   while `logs.sync` is on. Entries written while it was off stay local; turning it on
//!   later does not push them retroactively (only later writes of an entry queue it).
//! - Recordings: the recording service names a session's recording after its current
//!   (or next) ConnLog id ([`ConnLogService::recording_id`]) and records the file in
//!   `device_local.recording_dir` ([`ConnLogService::set_recording`]).
//! - It also serves the Logs view: the list (after unlock / maintenance), deletes (with or
//!   without the recordings), "clear older than", replay decryption and export.
//!
//! ConnLog items are not indexed by the search index (`ItemIndex` ignores the kind), so
//! no `index_upsert` / `index_remove` calls are made for them.

use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use sverb_conn::{Attempt, AttemptEnd, ConnLogSink};
use sverb_core::{
    error_report::ErrorReport,
    model::{ConnLog, ConnResult, HlcClock, ItemBody, ItemId, ItemKind, current_schema},
};
use sverb_store::Store;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};

use super::{
    EventSender, maintenance,
    recording::{export_recording, open_recording, recording_key},
    vault::{UnlockedVault, VaultService},
};
use crate::{
    app::{ConnLogEvent, LogsEffect, SessionId, UiEvent},
    views::logs::LogEntry,
};

/// How long quit waits for pending writes.
pub const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Milliseconds per day.
const DAY_MS: i64 = 86_400_000;

#[derive(Debug)]
struct Open {
    id: ItemId,
    log: ConnLog,
}

#[derive(Debug, Default)]
struct Attempts {
    /// The current attempt of each session.
    open: HashMap<u64, Open>,
    /// Ids handed out before the session's next attempt started (a recording started
    /// at once with the session).
    reserved: HashMap<u64, ItemId>,
}

#[derive(Debug)]
enum Job {
    Write(ItemId, ConnLog),
    SetRecording(ItemId, PathBuf),
    SetSync(bool),
    Maintain { logs_days: u32, recording_days: u32 },
    Delete { ids: Vec<ItemId>, recordings: bool },
    ClearOlder { days: u32, recordings: bool },
    Shutdown(oneshot::Sender<()>),
}

#[derive(Debug)]
struct Inner {
    vault: Option<VaultService>,
    tx: EventSender,
    jobs: mpsc::UnboundedSender<Job>,
    attempts: Mutex<Attempts>,
}

/// The ConnLog service. Cheap to clone.
#[derive(Debug, Clone)]
pub struct ConnLogService {
    inner: Arc<Inner>,
}

impl ConnLogService {
    /// A service writing through `vault` (`None`: nothing is persisted, the UI still
    /// gets the entries) and reporting on `tx`. Spawns the writer task: call inside a
    /// tokio runtime.
    pub fn new(vault: Option<VaultService>, tx: EventSender, sync: bool) -> Self {
        let (jobs, rx) = mpsc::unbounded_channel();
        let writer = Writer {
            vault: vault.clone(),
            tx: tx.clone(),
            sync,
            clock: None,
            unsaved: BTreeMap::new(),
            recordings: HashMap::new(),
        };
        tokio::spawn(writer.run(rx));
        Self {
            inner: Arc::new(Inner {
                vault,
                tx,
                jobs,
                attempts: Mutex::new(Attempts::default()),
            }),
        }
    }

    fn attempts(&self) -> std::sync::MutexGuard<'_, Attempts> {
        self.inner
            .attempts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn job(&self, job: Job) {
        if self.inner.jobs.send(job).is_err() {
            debug!("connlog job dropped: the writer has stopped");
        }
    }

    /// The ConnLog id a recording of `session` is named after: its current attempt's,
    /// or (reserved) the id its next attempt will get.
    pub fn recording_id(&self, session: SessionId) -> ItemId {
        let mut a = self.attempts();
        if let Some(open) = a.open.get(&session.0) {
            return open.id;
        }
        *a.reserved.entry(session.0).or_insert_with(ItemId::new)
    }

    /// The recording of entry `id` is `path` (`device_local.recording_dir`).
    pub fn set_recording(&self, id: ItemId, path: PathBuf) {
        self.job(Job::SetRecording(id, path));
    }

    /// Execute `Effect::Logs`.
    pub fn execute(&self, effect: LogsEffect) {
        match effect {
            LogsEffect::SetSync(on) => self.job(Job::SetSync(on)),
            LogsEffect::Maintain {
                logs_retention_days,
                recording_retention_days,
            } => self.job(Job::Maintain {
                logs_days: logs_retention_days,
                recording_days: recording_retention_days,
            }),
            LogsEffect::Delete {
                ids,
                delete_recordings,
            } => self.job(Job::Delete {
                ids,
                recordings: delete_recordings,
            }),
            LogsEffect::ClearOlderThan {
                days,
                delete_recordings,
            } => self.job(Job::ClearOlder {
                days,
                recordings: delete_recordings,
            }),
            LogsEffect::OpenReplay { id, path, label } => self.open_replay(id, path, label),
            LogsEffect::Export { src, dst } => self.export(src, &dst),
        }
    }

    fn key(&self) -> Option<sverb_crypto::Key32> {
        self.inner
            .vault
            .as_ref()
            .and_then(VaultService::unlocked)
            .map(|v| recording_key(&v))
    }

    fn open_replay(&self, id: ItemId, path: PathBuf, label: String) {
        let tx = self.inner.tx.clone();
        let Some(key) = self.key() else {
            send(&tx, failed("cannot replay: the vault is locked"));
            return;
        };
        tokio::spawn(async move {
            let opened = tokio::task::spawn_blocking(move || open_recording(&path, key)).await;
            let ev = match opened {
                Ok(Ok(recording)) => ConnLogEvent::Replay {
                    id,
                    label,
                    recording: Box::new(recording),
                },
                Ok(Err(err)) => failed(format!("cannot open the recording: {err}")),
                Err(err) => failed(format!("cannot open the recording: {err}")),
            };
            let _ = tx.send(UiEvent::ConnLog(ev)).await;
        });
    }

    fn export(&self, src: PathBuf, dst: &str) {
        let tx = self.inner.tx.clone();
        let Some(key) = self.key() else {
            send(&tx, failed("cannot export: the vault is locked"));
            return;
        };
        let dst = resolve_dst(dst);
        tokio::spawn(async move {
            let path = dst.clone();
            let done = tokio::task::spawn_blocking(move || export_recording(&src, &dst, key)).await;
            let ev = match done {
                Ok(Ok(incomplete)) => ConnLogEvent::Exported { path, incomplete },
                Ok(Err(err)) => failed(format!("cannot export the recording: {err}")),
                Err(err) => failed(format!("cannot export the recording: {err}")),
            };
            let _ = tx.send(UiEvent::ConnLog(ev)).await;
        });
    }

    /// Quit: attempts still open end now (`ended_at` = quit time), then wait (up to
    /// [`SHUTDOWN_TIMEOUT`]) for the writer to finish.
    pub async fn shutdown(&self) {
        let open: Vec<(u64, Open)> = self.attempts().open.drain().collect();
        for (_, open) in open {
            let mut log = open.log;
            log.ended_at = Some(sverb_core::model::UnixMillis::now());
            log.result = Some(ConnResult::Ok);
            self.job(Job::Write(open.id, log));
        }
        let (done, wait) = oneshot::channel();
        self.job(Job::Shutdown(done));
        if tokio::time::timeout(SHUTDOWN_TIMEOUT, wait).await.is_err() {
            warn!("connection log writes did not finish in time");
        }
    }
}

impl ConnLogSink for ConnLogService {
    fn attempt_started(&self, session: sverb_conn::SessionId, attempt: Attempt) {
        let log = ConnLog {
            host_id: attempt.host_id,
            started_at: attempt.started_at,
            label: attempt.label,
            target: attempt.target,
            ..ConnLog::default()
        };
        let id = {
            let mut a = self.attempts();
            let id = a.reserved.remove(&session.0).unwrap_or_else(ItemId::new);
            a.open.insert(
                session.0,
                Open {
                    id,
                    log: log.clone(),
                },
            );
            id
        };
        send(
            &self.inner.tx,
            ConnLogEvent::Started {
                session: SessionId(session.0),
                id,
            },
        );
        self.job(Job::Write(id, log));
    }

    fn attempt_ended(&self, session: sverb_conn::SessionId, end: AttemptEnd) {
        let Some(open) = self.attempts().open.remove(&session.0) else {
            return;
        };
        let mut log = open.log;
        log.ended_at = Some(end.ended_at);
        log.result = Some(end.result());
        log.bytes_in = end.bytes_in;
        log.bytes_out = end.bytes_out;
        log.error_detail = end.error_detail();
        self.job(Job::Write(open.id, log));
    }
}

fn failed(msg: impl Into<String>) -> ConnLogEvent {
    ConnLogEvent::Failed(ErrorReport::msg(msg))
}

/// Send to the UI without blocking the caller (session tasks call the sink).
fn send(tx: &EventSender, ev: ConnLogEvent) {
    match tx.try_send(UiEvent::ConnLog(ev)) {
        Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => {}
        Err(mpsc::error::TrySendError::Full(ev)) => {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                let tx = tx.clone();
                handle.spawn(async move {
                    let _ = tx.send(ev).await;
                });
            }
        }
    }
}

/// `~/x` → home; relative → the working directory.
fn resolve_dst(dst: &str) -> PathBuf {
    if let Some(rest) = dst.strip_prefix("~/")
        && let Some(home) = std::env::home_dir()
    {
        return home.join(rest);
    }
    let path = PathBuf::from(dst);
    if path.is_absolute() {
        return path;
    }
    std::env::current_dir().map_or(path.clone(), |cwd| cwd.join(&path))
}

/// The writer task's state.
struct Writer {
    vault: Option<VaultService>,
    tx: EventSender,
    sync: bool,
    clock: Option<HlcClock>,
    /// Entries that could not be written yet (vault locked), latest version.
    unsaved: BTreeMap<ItemId, ConnLog>,
    /// Known recording files by ConnLog id.
    recordings: HashMap<ItemId, PathBuf>,
}

impl Writer {
    async fn run(mut self, mut rx: mpsc::UnboundedReceiver<Job>) {
        while let Some(job) = rx.recv().await {
            match job {
                Job::Write(id, log) => self.write(id, log).await,
                Job::SetRecording(id, path) => self.set_recording(id, path).await,
                Job::SetSync(on) => self.sync = on,
                Job::Maintain {
                    logs_days,
                    recording_days,
                } => self.maintain(logs_days, recording_days).await,
                Job::Delete { ids, recordings } => self.delete(ids, recordings).await,
                Job::ClearOlder { days, recordings } => self.clear_older(days, recordings).await,
                Job::Shutdown(done) => {
                    if !self.unsaved.is_empty() {
                        warn!(
                            entries = self.unsaved.len(),
                            "connection log entries not saved: the vault is locked"
                        );
                    }
                    let _ = done.send(());
                    return;
                }
            }
        }
    }

    fn report(&self, msg: String) {
        warn!("{msg}");
        send(&self.tx, failed(msg));
    }

    fn entry(&self, id: ItemId, log: ConnLog) -> LogEntry {
        LogEntry {
            id,
            log,
            recording: self.recordings.get(&id).cloned(),
        }
    }

    /// The store and the unlocked vault, if both are there.
    fn unlocked(&self) -> Option<(Store, Arc<UnlockedVault>)> {
        let vault = self.vault.as_ref()?;
        Some((vault.store().clone(), vault.unlocked()?))
    }

    async fn write(&mut self, id: ItemId, log: ConnLog) {
        match self.unlocked() {
            Some((store, vault)) => {
                let clock = self.clock.get_or_insert_with(|| vault.hlc());
                if let Err(err) = persist(&store, &vault, clock, self.sync, id, &log).await {
                    self.unsaved.insert(id, log.clone());
                    self.report(format!("cannot save the connection log: {err}"));
                } else {
                    self.unsaved.remove(&id);
                }
            }
            None => {
                self.unsaved.insert(id, log.clone());
            }
        }
        send(&self.tx, ConnLogEvent::Upserted(self.entry(id, log)));
    }

    async fn set_recording(&mut self, id: ItemId, path: PathBuf) {
        self.recordings.insert(id, path.clone());
        if let Some(vault) = &self.vault {
            let dir = path.display().to_string();
            if let Err(err) = vault.store().set_recording_dir(id, Some(dir)).await {
                self.report(format!("cannot record the recording's path: {err}"));
            }
        }
    }

    /// Write unsaved entries, apply retention, reload the list.
    async fn maintain(&mut self, logs_days: u32, recording_days: u32) {
        let Some((store, vault)) = self.unlocked() else {
            return;
        };
        let clock = self.clock.get_or_insert_with(|| vault.hlc());
        for (id, log) in std::mem::take(&mut self.unsaved) {
            if let Err(err) = persist(&store, &vault, clock, self.sync, id, &log).await {
                warn!(%err, "cannot save a connection log entry");
                self.unsaved.insert(id, log);
            }
        }
        let retention = maintenance::Retention {
            logs_days,
            recording_days,
        };
        match maintenance::run(&store, &vault, clock, self.sync, retention, store.now()).await {
            Ok(report) => {
                for id in &report.recordings_deleted {
                    self.recordings.remove(id);
                }
                send(
                    &self.tx,
                    ConnLogEvent::Maintained {
                        tombstoned: report.tombstoned.len(),
                        recordings_deleted: report.recordings_deleted.len(),
                    },
                );
            }
            Err(err) => self.report(format!("log maintenance failed: {err}")),
        }
        self.load(&store, &vault).await;
    }

    async fn load(&mut self, store: &Store, vault: &Arc<UnlockedVault>) {
        let logs = match load_logs(store, vault).await {
            Ok(logs) => logs,
            Err(err) => return self.report(format!("cannot read the connection logs: {err}")),
        };
        match store.list_device_local().await {
            Ok(rows) => {
                self.recordings = rows
                    .into_iter()
                    .filter_map(|r| Some((r.item_id, PathBuf::from(r.recording_dir?))))
                    .collect();
            }
            Err(err) => warn!(%err, "cannot read recording paths"),
        }
        let mut entries: Vec<LogEntry> = logs
            .into_iter()
            .filter(|(id, _)| !self.unsaved.contains_key(id))
            .map(|(id, log)| self.entry(id, log))
            .collect();
        entries.extend(
            self.unsaved
                .iter()
                .map(|(id, log)| self.entry(*id, log.clone())),
        );
        send(&self.tx, ConnLogEvent::Loaded(entries));
    }

    async fn delete(&mut self, ids: Vec<ItemId>, recordings: bool) {
        let unlocked = self.unlocked();
        let mut removed = Vec::with_capacity(ids.len());
        for id in ids {
            let was_unsaved = self.unsaved.remove(&id).is_some();
            if let Some((store, vault)) = &unlocked {
                let clock = self.clock.get_or_insert_with(|| vault.hlc());
                if let Err(err) = tombstone(store, vault, clock, self.sync, id).await {
                    self.report(format!("cannot delete the connection log: {err}"));
                    continue;
                }
            } else if !was_unsaved {
                self.report("cannot delete: the vault is locked".to_owned());
                continue;
            }
            if recordings {
                self.delete_recording(id).await;
            }
            removed.push(id);
        }
        send(&self.tx, ConnLogEvent::Removed(removed));
    }

    async fn delete_recording(&mut self, id: ItemId) {
        let Some(vault) = &self.vault else {
            return;
        };
        let store = vault.store().clone();
        let path = match self.recordings.remove(&id) {
            Some(p) => Some(p),
            None => store
                .get_device_local(id)
                .await
                .ok()
                .flatten()
                .and_then(|r| r.recording_dir.map(PathBuf::from)),
        };
        let Some(path) = path else {
            return;
        };
        if let Err(err) = remove_file(&path) {
            self.report(format!("cannot delete {}: {err}", path.display()));
            return;
        }
        if let Err(err) = store.set_recording_dir(id, None).await {
            warn!(%err, "cannot clear the recording path");
        }
    }

    async fn clear_older(&mut self, days: u32, recordings: bool) {
        let Some((store, vault)) = self.unlocked() else {
            return self.report("cannot clear: the vault is locked".to_owned());
        };
        let cutoff = store.now() - i64::from(days) * DAY_MS;
        let ids = match load_logs(&store, &vault).await {
            Ok(logs) => logs
                .into_iter()
                .filter(|(_, log)| log.started_at.0 < cutoff)
                .map(|(id, _)| id)
                .collect(),
            Err(err) => return self.report(format!("cannot read the connection logs: {err}")),
        };
        self.delete(ids, recordings).await;
    }
}

/// Remove a file; a missing one is fine.
pub(crate) fn remove_file(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(err) if err.kind() != std::io::ErrorKind::NotFound => Err(err),
        _ => Ok(()),
    }
}

/// Write `log` as item `id` (created in the personal vault, or updated in place).
/// A deleted entry is never written again. Queued for sync only with `sync`.
///
/// # Errors
/// Store, sealing or decoding errors, as text.
pub async fn persist(
    store: &Store,
    vault: &Arc<UnlockedVault>,
    clock: &mut HlcClock,
    sync: bool,
    id: ItemId,
    log: &ConnLog,
) -> Result<(), String> {
    let existing = store.get_item(id).await.map_err(|e| e.to_string())?;
    let (vault_id, mut body) = match existing {
        Some(row) if row.deleted => return Ok(()),
        Some(row) => (row.vault_id, vault.open(&row).map_err(|e| e.to_string())?),
        None => (
            vault
                .personal_vault()
                .ok_or_else(|| "no personal vault".to_owned())?,
            ItemBody::new(ItemKind::ConnLog, current_schema(ItemKind::ConnLog)),
        ),
    };
    log.apply_to(&mut body, clock, vault.device_id());
    let (kv, env) = vault.seal(vault_id, id, &body).map_err(|e| e.to_string())?;
    store
        .write(move |w| w.put_item(vault_id, id, kv, &env, false, sync))
        .await
        .map_err(|e| e.to_string())
}

/// Tombstone item `id` (no-op if it is missing or already deleted).
///
/// # Errors
/// Store, sealing or decoding errors, as text.
pub async fn tombstone(
    store: &Store,
    vault: &Arc<UnlockedVault>,
    clock: &mut HlcClock,
    sync: bool,
    id: ItemId,
) -> Result<(), String> {
    let Some(row) = store.get_item(id).await.map_err(|e| e.to_string())? else {
        return Ok(());
    };
    if row.deleted {
        return Ok(());
    }
    let mut body = vault.open(&row).map_err(|e| e.to_string())?;
    body.delete(clock, vault.device_id());
    let vault_id = row.vault_id;
    let (kv, env) = vault.seal(vault_id, id, &body).map_err(|e| e.to_string())?;
    store
        .write(move |w| w.put_item(vault_id, id, kv, &env, true, sync))
        .await
        .map_err(|e| e.to_string())
}

/// Every live (not deleted) ConnLog item, decrypted off the async threads.
///
/// # Errors
/// Store errors, as text. Items that fail to decrypt or decode are skipped (logged).
pub async fn load_logs(
    store: &Store,
    vault: &Arc<UnlockedVault>,
) -> Result<Vec<(ItemId, ConnLog)>, String> {
    let rows = store.list_all_items().await.map_err(|e| e.to_string())?;
    let vault = Arc::clone(vault);
    tokio::task::spawn_blocking(move || {
        rows.into_iter()
            .filter(|r| !r.deleted)
            .filter_map(|row| match vault.open(&row) {
                Ok(body) if body.kind == ItemKind::ConnLog => match ConnLog::try_from(&body) {
                    Ok(log) => Some((row.id, log)),
                    Err(err) => {
                        warn!(item = %row.id.short(), %err, "unreadable connection log");
                        None
                    }
                },
                Ok(_) => None,
                Err(err) => {
                    debug!(item = %row.id.short(), %err, "item skipped");
                    None
                }
            })
            .collect()
    })
    .await
    .map_err(|e| e.to_string())
}
