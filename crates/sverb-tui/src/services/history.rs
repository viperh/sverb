//! M7-01: the history service (SPEC §9.10, §4.12 `HistoryEntry`, §15 `[history]`).
//!
//! - Executes `Effect::History`: records captured commands, loads the entries, purges a
//!   host, follows the `[history]` policy. It is also the snippet runs'
//!   [`HistorySink`] (their commands keep secret values as `{{name}}`, M2-09).
//! - Writes go through one writer task, in order, sealed with the personal vault's key.
//!   The service stamps `executed_at` (the reducer never reads the clock). While the vault
//!   is locked, entries wait in memory and are written by the next load (after unlock);
//!   entries still waiting at quit are lost.
//! - **Sync:** entries are written with the dirty flag (queued in the outbox) only while
//!   `history.sync` is on.
//! - **Cap:** after each write the host keeps its newest `history.max_entries_per_host`
//!   entries; older ones are tombstoned (`HistoryEvent::Removed`).
//! - `history.enabled = false`: nothing is recorded.
//!
//! History items are not indexed by the search index, and nothing here logs commands.

use std::sync::Arc;

use sverb_core::{
    error_report::ErrorReport,
    history::{StoredEntry, entries_of, trim_to_cap},
    model::{HistoryEntry, HlcClock, ItemBody, ItemId, ItemKind, UnixMillis, current_schema},
    snippet::{HistoryRecord, HistorySink},
};
use sverb_store::Store;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};

use super::{
    EventSender,
    connlog::tombstone,
    vault::{UnlockedVault, VaultService},
};
use crate::app::{
    UiEvent,
    history::{HistoryEffect, HistoryEvent, HistoryPolicy},
};

#[derive(Debug)]
enum Job {
    Load,
    Record(HistoryEntry),
    Purge(Option<ItemId>),
    Policy(HistoryPolicy),
    Shutdown(oneshot::Sender<()>),
}

/// The history service. Cheap to clone.
#[derive(Debug, Clone)]
pub struct HistoryService {
    jobs: mpsc::UnboundedSender<Job>,
}

impl HistoryService {
    /// A service writing through `vault` (`None`: nothing is persisted, the UI still gets
    /// the entries) and reporting on `tx`. Spawns the writer task: call inside a tokio
    /// runtime.
    pub fn new(vault: Option<VaultService>, tx: EventSender, policy: HistoryPolicy) -> Self {
        let (jobs, rx) = mpsc::unbounded_channel();
        let writer = Writer {
            vault,
            tx,
            policy,
            clock: None,
            unsaved: Vec::new(),
            known: None,
            last_at: i64::MIN,
        };
        tokio::spawn(writer.run(rx));
        Self { jobs }
    }

    fn job(&self, job: Job) {
        if self.jobs.send(job).is_err() {
            debug!("history job dropped: the writer has stopped");
        }
    }

    /// Execute `Effect::History`.
    pub fn execute(&self, effect: HistoryEffect) {
        self.job(match effect {
            HistoryEffect::Load => Job::Load,
            HistoryEffect::Record(entry) => Job::Record(entry),
            HistoryEffect::Purge { host } => Job::Purge(host),
            HistoryEffect::Policy(policy) => Job::Policy(policy),
        });
    }

    /// Quit: wait (up to 5 s) for pending writes.
    pub async fn shutdown(&self) {
        let (done, wait) = oneshot::channel();
        self.job(Job::Shutdown(done));
        if tokio::time::timeout(std::time::Duration::from_secs(5), wait)
            .await
            .is_err()
        {
            warn!("history writes did not finish in time");
        }
    }
}

impl HistorySink for HistoryService {
    fn record(&self, record: HistoryRecord) {
        self.job(Job::Record(HistoryEntry {
            command: record.command,
            host_id: record.host_id,
            verified: true,
            ..HistoryEntry::default()
        }));
    }
}

fn send(tx: &EventSender, ev: HistoryEvent) {
    match tx.try_send(UiEvent::History(ev)) {
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

struct Writer {
    vault: Option<VaultService>,
    tx: EventSender,
    policy: HistoryPolicy,
    clock: Option<HlcClock>,
    /// Entries recorded while the vault was locked.
    unsaved: Vec<StoredEntry>,
    /// Every live stored entry (for the cap), once loaded since the last unlock.
    known: Option<Vec<StoredEntry>>,
    /// The last `executed_at` handed out: times are strictly increasing, so the cap
    /// always knows which entry is older.
    last_at: i64,
}

impl Writer {
    async fn run(mut self, mut rx: mpsc::UnboundedReceiver<Job>) {
        while let Some(job) = rx.recv().await {
            match job {
                Job::Load => self.load().await,
                Job::Record(entry) => self.record(entry).await,
                Job::Purge(host) => self.purge(host).await,
                Job::Policy(policy) => self.policy = policy,
                Job::Shutdown(done) => {
                    if !self.unsaved.is_empty() {
                        warn!(
                            entries = self.unsaved.len(),
                            "history entries not saved: the vault is locked"
                        );
                    }
                    let _ = done.send(());
                    return;
                }
            }
        }
    }

    fn stamp(&mut self, now: i64) -> UnixMillis {
        self.last_at = now.max(self.last_at.saturating_add(1));
        UnixMillis(self.last_at)
    }

    fn report(&self, msg: String) {
        warn!("{msg}");
        send(&self.tx, HistoryEvent::Failed(ErrorReport::msg(msg)));
    }

    fn unlocked(&mut self) -> Option<(Store, Arc<UnlockedVault>)> {
        let vault = self.vault.as_ref()?;
        match vault.unlocked() {
            Some(v) => Some((vault.store().clone(), v)),
            None => {
                // Locked: what we knew is stale after the next unlock.
                self.known = None;
                None
            }
        }
    }

    async fn ensure_known(&mut self, store: &Store, vault: &Arc<UnlockedVault>) -> bool {
        if self.known.is_some() {
            return true;
        }
        match load_entries(store, vault).await {
            Ok(list) => {
                self.known = Some(list);
                true
            }
            Err(err) => {
                self.report(format!("cannot read the command history: {err}"));
                false
            }
        }
    }

    async fn record(&mut self, mut entry: HistoryEntry) {
        if !self.policy.enabled || self.policy.max_entries_per_host == 0 {
            return;
        }
        let id = ItemId::new();
        let Some((store, vault)) = self.unlocked() else {
            entry.executed_at = self.stamp(UnixMillis::now().0);
            let stored = StoredEntry { id, entry };
            self.unsaved.push(stored.clone());
            send(&self.tx, HistoryEvent::Added(stored));
            return;
        };
        entry.executed_at = self.stamp(store.now());
        let stored = StoredEntry { id, entry };
        self.write(&store, &vault, stored).await;
    }

    /// Persist one entry, then apply the host's cap.
    async fn write(&mut self, store: &Store, vault: &Arc<UnlockedVault>, stored: StoredEntry) {
        let known = self.ensure_known(store, vault).await;
        let clock = self.clock.get_or_insert_with(|| vault.hlc());
        if let Err(err) = persist(store, vault, clock, self.policy.sync, &stored).await {
            self.report(format!("cannot save the command history: {err}"));
            return;
        }
        let host = stored.entry.host_id;
        send(&self.tx, HistoryEvent::Added(stored.clone()));
        if !known {
            return;
        }
        let Some(list) = self.known.as_mut() else {
            return;
        };
        list.push(stored);
        let excess = trim_to_cap(list, host, self.policy.max_entries_per_host);
        if excess.is_empty() {
            return;
        }
        let mut removed = Vec::with_capacity(excess.len());
        for id in excess {
            match tombstone(store, vault, clock, self.policy.sync, id).await {
                Ok(()) => removed.push(id),
                Err(err) => warn!(%err, "cannot trim a history entry"),
            }
        }
        list.retain(|e| !removed.contains(&e.id));
        send(&self.tx, HistoryEvent::Removed(removed));
    }

    async fn load(&mut self) {
        let Some((store, vault)) = self.unlocked() else {
            return;
        };
        self.known = None;
        if !self.ensure_known(&store, &vault).await {
            return;
        }
        for stored in std::mem::take(&mut self.unsaved) {
            if self.policy.enabled {
                self.write(&store, &vault, stored).await;
            }
        }
        let list = self.known.clone().unwrap_or_default();
        send(&self.tx, HistoryEvent::Loaded(list));
    }

    async fn purge(&mut self, host: Option<ItemId>) {
        let before = self.unsaved.len();
        self.unsaved.retain(|e| e.entry.host_id != host);
        let mut count = before - self.unsaved.len();
        let Some((store, vault)) = self.unlocked() else {
            if count == 0 {
                self.report("cannot clear the history: the vault is locked".to_owned());
            } else {
                send(&self.tx, HistoryEvent::Purged { host, count });
            }
            return;
        };
        if !self.ensure_known(&store, &vault).await {
            return;
        }
        let ids = entries_of(self.known.as_deref().unwrap_or_default(), host);
        let clock = self.clock.get_or_insert_with(|| vault.hlc());
        let mut removed = Vec::with_capacity(ids.len());
        for id in ids {
            match tombstone(&store, &vault, clock, self.policy.sync, id).await {
                Ok(()) => removed.push(id),
                Err(err) => warn!(%err, "cannot delete a history entry"),
            }
        }
        if let Some(list) = self.known.as_mut() {
            list.retain(|e| !removed.contains(&e.id));
        }
        count += removed.len();
        send(&self.tx, HistoryEvent::Purged { host, count });
    }
}

/// Write `stored` as a new item in the personal vault. Queued for sync only with `sync`.
///
/// # Errors
/// Store or sealing errors, as text.
pub async fn persist(
    store: &Store,
    vault: &Arc<UnlockedVault>,
    clock: &mut HlcClock,
    sync: bool,
    stored: &StoredEntry,
) -> Result<(), String> {
    let vault_id = vault
        .personal_vault()
        .ok_or_else(|| "no personal vault".to_owned())?;
    let mut body = ItemBody::new(
        ItemKind::HistoryEntry,
        current_schema(ItemKind::HistoryEntry),
    );
    stored.entry.apply_to(&mut body, clock, vault.device_id());
    let id = stored.id;
    let (kv, env) = vault.seal(vault_id, id, &body).map_err(|e| e.to_string())?;
    store
        .write(move |w| w.put_item(vault_id, id, kv, &env, false, sync))
        .await
        .map_err(|e| e.to_string())
}

/// Every live history entry, decrypted off the async threads.
///
/// # Errors
/// Store errors, as text. Items that fail to decrypt or decode are skipped.
pub async fn load_entries(
    store: &Store,
    vault: &Arc<UnlockedVault>,
) -> Result<Vec<StoredEntry>, String> {
    let rows = store.list_all_items().await.map_err(|e| e.to_string())?;
    let vault = Arc::clone(vault);
    tokio::task::spawn_blocking(move || {
        rows.into_iter()
            .filter(|r| !r.deleted)
            .filter_map(|row| match vault.open(&row) {
                Ok(body) if body.kind == ItemKind::HistoryEntry => {
                    match HistoryEntry::try_from(&body) {
                        Ok(entry) => Some(StoredEntry { id: row.id, entry }),
                        Err(err) => {
                            warn!(item = %row.id.short(), %err, "unreadable history entry");
                            None
                        }
                    }
                }
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
