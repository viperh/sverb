//! M7-01 integration tests for the history service: T-08 (`history.sync = false` queues
//! nothing in the outbox), T-07 (the per-host cap trims the oldest, in the store), T-10
//! (purging a host tombstones its entries). Small Argon2 parameters, in-memory keyring.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sverb_core::model::{HistoryEntry, ItemId, VaultId};
use sverb_core::snippet::{HistoryRecord, HistorySink};
use sverb_core::vault::{Argon2Cost, MemKeyring};
use sverb_store::{ManualClock, Store};
use sverb_tui::app::history::{HistoryEffect, HistoryEvent, HistoryPolicy};
use sverb_tui::app::{UiEvent, UnlockRequest, VaultEffect, VaultEvent, VaultPassword};
use sverb_tui::services::history::{HistoryService, load_entries};
use sverb_tui::services::vault::{VaultEngine, VaultService};
use tokio::sync::mpsc::{Receiver, channel};

const PW: &str = "correct horse battery staple violin";
const T0: i64 = 1_800_000_000_000;

struct Fixture {
    dir: PathBuf,
    vault: VaultService,
    store: Store,
    personal: VaultId,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn fixture(tag: &str) -> Fixture {
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "m7-01-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let clock = Arc::new(ManualClock::new(T0));
    let store = Store::open_at(dir.join("sverb.db"), clock).unwrap();
    let engine = VaultEngine::new(store.clone(), Arc::new(MemKeyring::new()), Argon2Cost::TEST);
    let init = engine.initialize(PW, false).await.unwrap();
    let personal = init.vault.personal_vault().unwrap();
    drop(init);
    let vault = VaultService::new(engine);
    let (tx, mut rx) = channel(16);
    vault.execute(
        VaultEffect::Unlock(UnlockRequest::Password(VaultPassword::from(PW))),
        &tx,
    );
    while let Some(ev) = rx.recv().await {
        if matches!(ev, UiEvent::Vault(VaultEvent::Unlocked { .. })) {
            break;
        }
    }
    assert!(vault.is_unlocked());
    Fixture {
        dir,
        vault,
        store,
        personal,
    }
}

fn policy(sync: bool, max: u32) -> HistoryPolicy {
    HistoryPolicy {
        enabled: true,
        sync,
        max_entries_per_host: max,
    }
}

async fn wait(rx: &mut Receiver<UiEvent>, pred: impl Fn(&HistoryEvent) -> bool) -> HistoryEvent {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(UiEvent::History(ev)) = rx.recv().await
                && pred(&ev)
            {
                return ev;
            }
        }
    })
    .await
    .expect("timed out waiting for a history event")
}

fn entry(cmd: &str, host: Option<ItemId>) -> HistoryEntry {
    HistoryEntry {
        command: cmd.into(),
        host_id: host,
        ..HistoryEntry::default()
    }
}

async fn outbox(fx: &Fixture) -> Vec<ItemId> {
    fx.store
        .list_outbox(fx.personal)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.item_id)
        .collect()
}

async fn live(fx: &Fixture) -> Vec<HistoryEntry> {
    let vault = fx.vault.unlocked().unwrap();
    let mut list = load_entries(&fx.store, &vault).await.unwrap();
    list.sort_by_key(|e| e.id);
    list.into_iter().map(|s| s.entry).collect()
}

/// T-08
#[tokio::test]
async fn t08_no_outbox_rows_without_history_sync() {
    let fx = fixture("nosync").await;
    let (tx, mut rx) = channel(64);
    let svc = HistoryService::new(Some(fx.vault.clone()), tx, policy(false, 100));
    svc.execute(HistoryEffect::Record(entry("ls", None)));
    // Snippet runs go through the same sink.
    svc.record(HistoryRecord {
        command: "echo {{token}}".into(),
        host_id: None,
        snippet: None,
    });
    for _ in 0..2 {
        wait(&mut rx, |e| matches!(e, HistoryEvent::Added(_))).await;
    }
    svc.shutdown().await;
    let stored = live(&fx).await;
    assert_eq!(stored.len(), 2);
    assert!(
        stored.iter().any(|e| e.command == "echo {{token}}"),
        "secrets stay placeholders"
    );
    assert!(
        stored.iter().all(|e| e.executed_at.0 >= T0),
        "stamped by the service"
    );
    assert!(outbox(&fx).await.is_empty(), "nothing queued for sync");

    // With `history.sync` the next write is queued.
    let (tx, mut rx) = channel(64);
    let svc = HistoryService::new(Some(fx.vault.clone()), tx, policy(true, 100));
    svc.execute(HistoryEffect::Record(entry("pwd", None)));
    let HistoryEvent::Added(added) = wait(&mut rx, |e| matches!(e, HistoryEvent::Added(_))).await
    else {
        unreachable!()
    };
    svc.shutdown().await;
    assert_eq!(outbox(&fx).await, [added.id]);
}

/// T-07 (service): the host keeps its newest `max` entries; others are tombstoned.
#[tokio::test]
async fn t07_cap_trims_the_oldest_in_the_store() {
    let fx = fixture("cap").await;
    let (tx, mut rx) = channel(64);
    let svc = HistoryService::new(Some(fx.vault.clone()), tx, policy(false, 3));
    let h = Some(ItemId::new());
    for i in 0..5 {
        svc.execute(HistoryEffect::Record(entry(&format!("c{i}"), h)));
    }
    svc.execute(HistoryEffect::Record(entry("other", None)));
    let mut removed = 0;
    while removed < 2 {
        if let HistoryEvent::Removed(ids) =
            wait(&mut rx, |e| matches!(e, HistoryEvent::Removed(_))).await
        {
            removed += ids.len();
        }
    }
    svc.shutdown().await;
    let mut cmds: Vec<String> = live(&fx).await.into_iter().map(|e| e.command).collect();
    cmds.sort();
    assert_eq!(cmds, ["c2", "c3", "c4", "other"]);
}

/// T-10 (service): purging a host tombstones its entries only.
#[tokio::test]
async fn t10_purge_tombstones_the_hosts_entries() {
    let fx = fixture("purge").await;
    let (tx, mut rx) = channel(64);
    let svc = HistoryService::new(Some(fx.vault.clone()), tx, policy(false, 100));
    let a = Some(ItemId::new());
    for cmd in ["ls", "pwd"] {
        svc.execute(HistoryEffect::Record(entry(cmd, a)));
    }
    svc.execute(HistoryEffect::Record(entry("id", None)));
    svc.execute(HistoryEffect::Purge { host: a });
    let ev = wait(&mut rx, |e| matches!(e, HistoryEvent::Purged { .. })).await;
    assert_eq!(ev, HistoryEvent::Purged { host: a, count: 2 });
    svc.execute(HistoryEffect::Load);
    let HistoryEvent::Loaded(list) = wait(&mut rx, |e| matches!(e, HistoryEvent::Loaded(_))).await
    else {
        unreachable!()
    };
    svc.shutdown().await;
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].entry.command, "id");
    let rows = fx.store.list_all_items().await.unwrap();
    assert_eq!(
        rows.iter().filter(|r| r.deleted).count(),
        2,
        "tombstones, not deletes"
    );
}

#[tokio::test]
async fn disabled_history_records_nothing() {
    let fx = fixture("off").await;
    let (tx, mut rx) = channel(64);
    let mut p = policy(true, 100);
    p.enabled = false;
    let svc = HistoryService::new(Some(fx.vault.clone()), tx, p);
    svc.execute(HistoryEffect::Record(entry("ls", None)));
    svc.execute(HistoryEffect::Load);
    let HistoryEvent::Loaded(list) = wait(&mut rx, |e| matches!(e, HistoryEvent::Loaded(_))).await
    else {
        unreachable!()
    };
    svc.shutdown().await;
    assert!(list.is_empty());
    assert!(outbox(&fx).await.is_empty());
}
