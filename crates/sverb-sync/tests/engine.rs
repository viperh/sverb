//! `sverb-server` (in-memory backend, loopback HTTP). Test ids follow the
//! task file.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

mod common;

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::TimeDelta;
use common::{
    Device, TestServer, first_device, raw_refresh, seal, second_device, stored_refresh_token,
    wait_for,
};
use sverb_core::model::{ItemBody, ItemId, ItemKind};
use sverb_crypto::Key32;
use sverb_crypto::random::{os_rng, random_key32};
use sverb_proto::sync::VaultView;
use sverb_server::auth::store::mem::{MemItem, MemMember};
use sverb_sync::{EngineConfig, SyncEvent, SyncPolicy, SyncStatus, VaultKeySource};
use tokio::sync::mpsc;

fn text(b: &ItemBody, f: &str) -> Option<String> {
    b.get(f).and_then(|v| v.as_text()).map(ToOwned::to_owned)
}

fn quick(dev: &Device) -> EngineConfig {
    EngineConfig {
        push_debounce: Duration::from_millis(200),
        ..dev.config()
    }
}

/// Collects `Applied` item ids until the channel is idle.
fn drain_applied(rx: &mut mpsc::UnboundedReceiver<SyncEvent>) -> Vec<ItemId> {
    let mut out = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        if let SyncEvent::Applied { items, .. } = ev {
            out.extend(items);
        }
    }
    out
}

/// Create 3 items → pushed after the 2 s debounce; server head 3,
/// nothing dirty, outbox empty.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t01_single_device_push_after_debounce() {
    let server = TestServer::start().await;
    let (_acct, a) = first_device(&server, "t01@example.com").await;
    let handle = a.engine(a.config()).await.spawn();
    wait_for(Duration::from_secs(5), "startup synced", || async {
        handle.status() == SyncStatus::Synced
    })
    .await;

    let t0 = Instant::now();
    for i in 0..3 {
        a.edit(
            ItemId::new(),
            &[("label", &format!("host{i}")), ("hostname", "h.example")],
        )
        .await;
        handle.local_change();
    }
    // Not before the debounce.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        server.head(a.vault),
        0,
        "pushed before the debounce elapsed"
    );
    wait_for(Duration::from_secs(10), "pushed", || async {
        server.head(a.vault) == 3
    })
    .await;
    assert!(t0.elapsed() >= Duration::from_secs(2));
    wait_for(Duration::from_secs(5), "clean", || async {
        a.dirty_count().await == 0 && a.pending().await == 0
    })
    .await;
    wait_for(Duration::from_secs(5), "synced", || async {
        handle.status() == SyncStatus::Synced
    })
    .await;
    // The follow-up pull moved the cursor past our own revisions.
    wait_for(Duration::from_secs(5), "cursor at head", || async {
        a.cursor().await == 3
    })
    .await;
    handle.shutdown().await;
}

/// 10 edits within 1 s → one push request.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t02_debounce_coalesces_edits() {
    let server = TestServer::start().await;
    let (_acct, a) = first_device(&server, "t02@example.com").await;
    let handle = a.engine(a.config()).await.spawn();
    wait_for(Duration::from_secs(5), "startup", || async {
        handle.status() == SyncStatus::Synced
    })
    .await;
    let before = server.push_requests();
    let id = ItemId::new();
    for i in 0..10 {
        a.edit(id, &[("label", &format!("edit {i}"))]).await;
        handle.local_change();
        tokio::time::sleep(Duration::from_millis(90)).await;
    }
    wait_for(Duration::from_secs(10), "pushed", || async {
        a.pending().await == 0 && server.head(a.vault) >= 1
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        server.push_requests() - before,
        1,
        "exactly one push request"
    );
    assert_eq!(server.head(a.vault), 1);
    let pushed = server.push_bodies();
    assert_eq!(
        pushed.last().unwrap()["changes"].as_array().unwrap().len(),
        1
    );
    handle.shutdown().await;
}

/// A edits the port, B edits the user of the same host offline; after
/// reconnecting both have port + user.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t03_two_clients_field_merge() {
    let server = TestServer::start().await;
    let (acct, a) = first_device(&server, "t03@example.com").await;
    let b = second_device(&server, &acct).await;
    let id = ItemId::new();
    a.edit(
        id,
        &[
            ("label", "web"),
            ("hostname", "web.example"),
            ("port", "22"),
        ],
    )
    .await;
    let mut ea = a.engine(a.config()).await;
    let mut eb = b.engine(b.config()).await;
    assert_eq!(ea.sync_once().await, SyncStatus::Synced);
    assert_eq!(eb.sync_once().await, SyncStatus::Synced);
    assert_eq!(
        text(&b.body(id).await.unwrap(), "hostname").as_deref(),
        Some("web.example")
    );

    // Offline edits.
    a.edit(id, &[("port", "2222")]).await;
    b.edit(id, &[("user", "deploy")]).await;

    assert_eq!(ea.sync_once().await, SyncStatus::Synced);
    assert_eq!(eb.sync_once().await, SyncStatus::Synced);
    assert_eq!(ea.sync_once().await, SyncStatus::Synced);
    for d in [&a, &b] {
        let body = d.body(id).await.unwrap();
        assert_eq!(text(&body, "port").as_deref(), Some("2222"));
        assert_eq!(text(&body, "user").as_deref(), Some("deploy"));
        assert_eq!(d.dirty_count().await, 0);
    }
    assert_eq!(a.body(id).await, b.body(id).await);
}

/// B pushes with a stale base → conflict → merge → the retry succeeds
/// within 2 rounds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t04_conflict_retry() {
    let server = TestServer::start().await;
    let (acct, a) = first_device(&server, "t04@example.com").await;
    let b = second_device(&server, &acct).await;
    let id = ItemId::new();
    a.edit(id, &[("label", "db"), ("port", "5432")]).await;
    let mut ea = a.engine(a.config()).await;
    let mut eb = b.engine(b.config()).await;
    ea.sync_once().await;
    eb.sync_once().await;

    a.edit(id, &[("port", "6543")]).await;
    assert!(ea.push_now().await.unwrap());
    // B's base is now stale; push without pulling first.
    b.edit(id, &[("user", "postgres")]).await;
    let before = server.push_requests();
    assert!(eb.push_now().await.unwrap());
    assert_eq!(server.push_requests() - before, 2, "conflict, then success");
    assert_eq!(b.dirty_count().await, 0);
    assert_eq!(eb.status().await, SyncStatus::Synced);

    ea.sync_once().await;
    let body = a.body(id).await.unwrap();
    assert_eq!(text(&body, "port").as_deref(), Some("6543"));
    assert_eq!(text(&body, "user").as_deref(), Some("postgres"));
}

/// A crash after applying 2 of 5 items of a page rolls the page and
/// the cursor back; after a restart the re-pull applies everything once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t06_pull_page_atomicity() {
    let server = TestServer::start().await;
    let (acct, a) = first_device(&server, "t06@example.com").await;
    let b = second_device(&server, &acct).await;
    let ids: Vec<ItemId> = (0..5).map(|_| ItemId::new()).collect();
    for (i, id) in ids.iter().enumerate() {
        a.edit(*id, &[("label", &format!("h{i}"))]).await;
    }
    a.engine(a.config()).await.sync_once().await;
    assert_eq!(server.head(a.vault), 5);

    let before = b.cursor().await;
    let crashing = b
        .engine(EngineConfig {
            crash_after_items: Some(2),
            ..b.config()
        })
        .await;
    let res = tokio::spawn(async move {
        let mut e = crashing;
        e.pull_now().await
    })
    .await;
    assert!(res.unwrap_err().is_panic(), "the injected crash panics");
    assert_eq!(b.cursor().await, before, "cursor unchanged");
    assert!(
        b.store.list_items(b.vault).await.unwrap().is_empty(),
        "nothing applied"
    );

    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut e = b
        .engine_with(b.config(), Arc::new(sverb_sync::NoKeySource), Some(tx))
        .await;
    e.pull_now().await.unwrap();
    let applied = drain_applied(&mut rx);
    assert_eq!(applied.len(), 5, "each item applied exactly once");
    assert_eq!(applied.iter().collect::<HashSet<_>>().len(), 5);
    assert_eq!(b.cursor().await, 5);
    assert_eq!(b.snapshot().await.len(), 5);
}

/// Dirty local + remote change → merged, still dirty, the outbox base
/// rebased to the remote revision; the next push succeeds without conflict.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t07_pull_merges_into_dirty_item() {
    let server = TestServer::start().await;
    let (acct, a) = first_device(&server, "t07@example.com").await;
    let b = second_device(&server, &acct).await;
    let id = ItemId::new();
    a.edit(id, &[("label", "box"), ("port", "22")]).await;
    let mut ea = a.engine(a.config()).await;
    let mut eb = b.engine(b.config()).await;
    ea.sync_once().await;
    eb.sync_once().await;

    b.edit(id, &[("user", "root")]).await; // dirty, base 1
    a.edit(id, &[("port", "2200")]).await;
    ea.push_now().await.unwrap(); // revision 2

    eb.pull_now().await.unwrap();
    let row = b.store.get_item(id).await.unwrap().unwrap();
    assert!(row.dirty, "still dirty");
    let ob = b.store.list_outbox(b.vault).await.unwrap();
    assert_eq!(ob.len(), 1);
    assert_eq!(ob[0].base_revision, 2, "rebased onto the remote revision");
    let body = b.body(id).await.unwrap();
    assert_eq!(text(&body, "port").as_deref(), Some("2200"));
    assert_eq!(text(&body, "user").as_deref(), Some("root"));

    let before = server.push_requests();
    assert!(eb.push_now().await.unwrap());
    assert_eq!(server.push_requests() - before, 1, "no conflict round");
    assert_eq!(b.dirty_count().await, 0);
    ea.pull_now().await.unwrap();
    assert_eq!(a.body(id).await, b.body(id).await);
}

/// 410 Gone after server GC → full resync: clean local items deleted
/// on the server disappear, a dirty local item absent on the server is
/// pushed again as a new item.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t08_gone_full_resync() {
    let server = TestServer::start().await;
    let (acct, a) = first_device(&server, "t08@example.com").await;
    let b = second_device(&server, &acct).await;
    let (x, y, z) = (ItemId::new(), ItemId::new(), ItemId::new());
    a.edit(x, &[("label", "x")]).await;
    a.edit(y, &[("label", "y")]).await;
    a.edit(z, &[("label", "z")]).await;
    let mut ea = a.engine(a.config()).await;
    let mut eb = b.engine(b.config()).await;
    ea.sync_once().await;
    eb.sync_once().await;
    assert_eq!(b.cursor().await, 3);

    // A deletes X and Y; the server purges the tombstones (short horizon).
    a.delete(x).await;
    a.delete(y).await;
    ea.sync_once().await;
    let cutoff = server.clock_now() + TimeDelta::days(1);
    let gc = server
        .state
        .sync()
        .store()
        .gc_tombstones(cutoff)
        .await
        .unwrap();
    let _ = gc;
    assert!(server.item(a.vault, x).is_none() && server.item(a.vault, y).is_none());

    // Meanwhile B edited X offline (dirty, based on revision 1).
    b.edit(x, &[("hostname", "x.example")]).await;
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut eb = b
        .engine_with(b.config(), Arc::new(sverb_sync::NoKeySource), Some(tx))
        .await;
    assert_eq!(eb.sync_once().await, SyncStatus::Synced);

    assert!(
        b.store.get_item(y).await.unwrap().is_none(),
        "clean Y purged"
    );
    assert!(b.store.get_item(z).await.unwrap().is_some(), "Z kept");
    let bx = b.store.get_item(x).await.unwrap().unwrap();
    assert!(!bx.dirty, "X re-pushed");
    let sx = server.item(a.vault, x).expect("X is on the server again");
    assert!(!sx.deleted);
    assert_eq!(b.cursor().await, server.head(a.vault));
    let applied = drain_applied(&mut rx);
    assert!(applied.contains(&y), "the purge is reported to the index");
}

/// Server down for 3 edits → `offline (3 pending)`; back → `synced`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t09_offline_queue() {
    let server = TestServer::start().await;
    let (_acct, a) = first_device(&server, "t09@example.com").await;
    let mut cfg = quick(&a);
    cfg.retry.initial = Duration::from_millis(200);
    cfg.retry.max = Duration::from_secs(1);
    cfg.http_timeout = Duration::from_secs(2);
    let handle = a.engine(cfg).await.spawn();
    wait_for(Duration::from_secs(5), "startup", || async {
        handle.status() == SyncStatus::Synced
    })
    .await;

    server.stop().await;
    for i in 0..3 {
        a.edit(ItemId::new(), &[("label", &format!("off{i}"))])
            .await;
        handle.local_change();
    }
    wait_for(Duration::from_secs(10), "offline (3 pending)", || async {
        handle.status() == SyncStatus::Offline { pending: 3 }
    })
    .await;
    assert_eq!(handle.status().short(), "offline (3 pending)");

    server.restart().await;
    wait_for(Duration::from_secs(15), "synced again", || async {
        handle.status() == SyncStatus::Synced
    })
    .await;
    assert_eq!(server.head(a.vault), 3);
    assert_eq!(a.pending().await, 0);
    handle.shutdown().await;
}

/// B pushes → A applies within 1 s through the WS notification; with
/// the WS disabled, A applies within the (shortened) poll interval.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t10_ws_and_poll_triggered_pull() {
    let server = TestServer::start().await;
    let (acct, a) = first_device(&server, "t10@example.com").await;
    let b = second_device(&server, &acct).await;
    let a_ws = a
        .engine(EngineConfig {
            websocket: true,
            ..a.config()
        })
        .await
        .spawn();
    wait_for(Duration::from_secs(5), "A synced", || async {
        a_ws.status() == SyncStatus::Synced
    })
    .await;
    // Let the WS authenticate.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let id = ItemId::new();
    b.edit(id, &[("label", "via-ws")]).await;
    let mut eb = b.engine(b.config()).await;
    eb.push_now().await.unwrap();
    let t0 = Instant::now();
    wait_for(Duration::from_secs(1), "A applied via WS", || async {
        a.store.get_item(id).await.unwrap().is_some()
    })
    .await;
    assert!(t0.elapsed() <= Duration::from_secs(1));
    a_ws.shutdown().await;

    // Without WS: the fallback poll (shortened to 700 ms).
    let a_poll = a
        .engine(EngineConfig {
            websocket: false,
            poll_interval: Duration::from_millis(700),
            ..a.config()
        })
        .await
        .spawn();
    wait_for(Duration::from_secs(5), "A synced", || async {
        a_poll.status() == SyncStatus::Synced
    })
    .await;
    let id2 = ItemId::new();
    b.edit(id2, &[("label", "via-poll")]).await;
    eb.push_now().await.unwrap();
    let t0 = Instant::now();
    wait_for(Duration::from_secs(3), "A applied via poll", || async {
        a.store.get_item(id2).await.unwrap().is_some()
    })
    .await;
    assert!(t0.elapsed() <= Duration::from_millis(1500));
    a_poll.shutdown().await;
}

/// 401 → refresh, the new tokens persisted before the next request;
/// a refresh-token reuse → `NeedsLogin`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t11_token_refresh_and_reuse() {
    let server = TestServer::start().await;
    let (_acct, a) = first_device(&server, "t11@example.com").await;
    let mut e = a.engine(a.config()).await;
    assert_eq!(e.sync_once().await, SyncStatus::Synced);
    let (enc0, r1) = stored_refresh_token(&a).await;

    // The access token expires on the server (its clock moves 16 min).
    server.clock.advance(TimeDelta::minutes(16));
    a.edit(ItemId::new(), &[("label", "after-expiry")]).await;
    assert_eq!(e.sync_once().await, SyncStatus::Synced);
    assert_eq!(e.tokens().refresh_count(), 1);
    let (enc1, r2) = stored_refresh_token(&a).await;
    assert_ne!(enc0, enc1, "rotated tokens persisted");
    assert_ne!(r1, r2);
    // The refresh was persisted before the push that used the new token.
    let reqs = server.requests.lock().clone();
    let refresh_at = reqs
        .iter()
        .position(|r| r.path == "/v1/auth/refresh")
        .unwrap();
    let push_at = reqs
        .iter()
        .rposition(|r| r.method == "POST" && r.path.ends_with("/changes"))
        .unwrap();
    assert!(refresh_at < push_at);
    assert_eq!(server.head(a.vault), 1);

    // A restarted engine uses the persisted (rotated) tokens.
    let mut e2 = a.engine(a.config()).await;
    assert_eq!(e2.sync_once().await, SyncStatus::Synced);
    drop(e2);

    // Reuse: the old refresh token is replayed → the family is revoked.
    let (st, v) = raw_refresh(&server, &r1).await;
    assert_eq!(st, 401, "{v}");
    server.clock.advance(TimeDelta::minutes(16));
    a.edit(ItemId::new(), &[("label", "after-reuse")]).await;
    assert_eq!(e.sync_once().await, SyncStatus::NeedsLogin);
    assert_eq!(a.pending().await, 1, "the change stays queued");
}

/// A key source that knows the rotated key.
#[derive(Debug)]
struct Rotated(u32, Key32);

impl VaultKeySource for Rotated {
    fn open_grant(&self, _view: &VaultView, version: u32) -> Option<Key32> {
        (version == self.0).then(|| self.1.clone())
    }
}

/// A push during a rotation → paused; after the rotation completes the
/// pending item is re-encrypted under the new key version and pushed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t12_rotation_pauses_then_reencrypts() {
    let server = TestServer::start().await;
    let (acct, a) = first_device(&server, "t12@example.com").await;
    let vk2 = random_key32(&mut os_rng());
    let mut e = a
        .engine_with(a.config(), Arc::new(Rotated(2, vk2.clone())), None)
        .await;
    assert_eq!(e.sync_once().await, SyncStatus::Synced);

    let vault = a.vault.uuid();
    server.mem.with_data(|d| {
        d.vaults.get_mut(&vault).unwrap().rotation = Some(serde_json::json!({
            "by": acct.user_id, "new_key_version": 2, "started_at": "2026-10-08T00:00:00Z"
        }));
    });
    let id = ItemId::new();
    a.edit(id, &[("label", "during-rotation")]).await;
    let before = server.push_requests();
    e.push_now().await.unwrap();
    assert_eq!(server.push_requests() - before, 1);
    assert_eq!(server.head(a.vault), 0, "rejected with 409 rotating");
    // Paused: no more push attempts.
    e.push_now().await.unwrap();
    assert_eq!(server.push_requests() - before, 1, "paused");
    assert_eq!(a.pending().await, 1);

    // The rotation completes: key version 2, new grant.
    server.mem.with_data(|d| {
        let v = d.vaults.get_mut(&vault).unwrap();
        v.rotation = None;
        v.key_version = 2;
        d.vault_members.push(MemMember {
            vault_id: vault,
            user_id: acct.user_id,
            permission: "manage".into(),
            key_version: 2,
            wrapped_vault_key: vec![9; 48],
            wrapped_by: acct.user_id,
            signature: vec![3; 64],
        });
    });
    assert_eq!(e.sync_once().await, SyncStatus::Synced);
    let s = server.item(a.vault, id).expect("pushed");
    assert_eq!(s.key_version, 2);
    let local = a.store.get_item(id).await.unwrap().unwrap();
    assert_eq!(local.key_version, 2);
    assert!(!local.dirty);
    assert_eq!(
        a.key_version().await,
        2,
        "new key stored wrapped under the LMK"
    );
    // It opens with the new key.
    let plain = sverb_crypto::envelope::open_item(
        |v| (v == 2).then_some(&vk2),
        a.vault.as_bytes(),
        id.as_bytes(),
        &s.envelope,
    )
    .unwrap();
    let body = ItemBody::from_cbor(&plain).unwrap();
    assert_eq!(text(&body, "label").as_deref(), Some("during-rotation"));
}

/// A ConnLog with `logs.sync = false` is never pushed; `device_local`
/// and approvals never leave the device (request bodies inspected).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t13_device_local_exclusions() {
    let server = TestServer::start().await;
    let (_acct, a) = first_device(&server, "t13@example.com").await;
    let host = ItemId::new();
    let log = ItemId::new();
    let hist = ItemId::new();
    a.edit(
        host,
        &[
            ("label", "srv"),
            ("proxy.command", "nc -X 5 approved-proxy.example %h %p"),
        ],
    )
    .await;
    a.edit_kind(
        log,
        ItemKind::ConnLog,
        &[("summary", "connlog-secret-marker")],
    )
    .await;
    a.edit_kind(
        hist,
        ItemKind::HistoryEntry,
        &[("command", "history-secret-marker")],
    )
    .await;
    a.store
        .put_local_approval(host, "proxy.command".into(), [7u8; 32])
        .await
        .unwrap();
    a.store
        .touch_connected(host, 1_700_000_000_000)
        .await
        .unwrap();
    a.store
        .set_recording_dir(host, Some("/home/me/recordings-marker".into()))
        .await
        .unwrap();

    let mut e = a.engine(a.config()).await; // logs.sync = history.sync = false
    assert_eq!(e.sync_once().await, SyncStatus::Synced);
    let pushed: HashSet<String> = server
        .push_bodies()
        .iter()
        .flat_map(|b| b["changes"].as_array().unwrap().clone())
        .map(|c| c["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(pushed, HashSet::from([host.uuid().to_string()]));
    assert!(server.item(a.vault, log).is_none());
    assert!(server.item(a.vault, hist).is_none());
    let all = server
        .requests
        .lock()
        .iter()
        .map(|r| format!("{} {}", r.path, r.body))
        .collect::<Vec<_>>()
        .join("\n");
    for marker in [
        "recordings-marker",
        "approved-proxy",
        "connlog-secret-marker",
        "history-secret-marker",
        "frecency",
        "last_connected",
        "value_sha256",
    ] {
        assert!(!all.contains(marker), "{marker} left the device");
    }
    // Excluded items stay local and dirty, and don't count as pending.
    assert!(a.store.get_item(log).await.unwrap().unwrap().dirty);
    assert_eq!(a.pending().await, 0);

    // With logs.sync on, a new ConnLog is pushed.
    let log2 = ItemId::new();
    a.edit_kind(log2, ItemKind::ConnLog, &[("summary", "ok")])
        .await;
    let mut e = a
        .engine(EngineConfig {
            policy: SyncPolicy {
                history_sync: false,
                logs_sync: true,
            },
            ..a.config()
        })
        .await;
    e.sync_once().await;
    assert!(server.item(a.vault, log2).is_some());
    assert!(server.item(a.vault, hist).is_none());
}

/// An undecryptable remote item is skipped with an error badge; the
/// other items are applied.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t14_undecryptable_remote_item() {
    let server = TestServer::start().await;
    let (acct, a) = first_device(&server, "t14@example.com").await;
    let b = second_device(&server, &acct).await;
    let good: Vec<ItemId> = (0..3).map(|_| ItemId::new()).collect();
    for (i, id) in good.iter().enumerate() {
        a.edit(*id, &[("label", &format!("g{i}"))]).await;
    }
    a.engine(a.config()).await.sync_once().await;
    // A fourth item sealed under a wrong key, written straight into the server.
    let bad = ItemId::new();
    let wrong = random_key32(&mut os_rng());
    let env = seal(&wrong, a.vault, bad, 1, &ItemBody::new(ItemKind::Host, 1));
    server.mem.with_data(|d| {
        let v = d.vaults.get_mut(&a.vault.uuid()).unwrap();
        v.head_revision += 1;
        let rev = v.head_revision;
        d.items.insert(
            (a.vault.uuid(), bad.uuid()),
            MemItem {
                revision: rev,
                key_version: 1,
                envelope: env,
                deleted: false,
                updated_at: chrono::Utc::now(),
                updated_by_device: None,
            },
        );
    });
    let status = b.engine(b.config()).await.sync_once().await;
    match &status {
        SyncStatus::Error { message } => {
            assert!(
                message.contains("1 item could not be decrypted"),
                "{message}"
            );
        }
        other => panic!("expected an error badge, got {other:?}"),
    }
    assert_eq!(status.short(), "error");
    for id in &good {
        assert!(b.store.get_item(*id).await.unwrap().is_some());
    }
    assert!(b.store.get_item(bad).await.unwrap().is_none());
    assert_eq!(b.cursor().await, 4, "the cursor still advances");
}

/// T-15 (M4 exit criterion): two devices make 100 random offline edits each
/// over 20 items, reconnect, and converge to identical decrypted states.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t15_offline_devices_converge() {
    let server = TestServer::start().await;
    let (acct, a) = first_device(&server, "t15@example.com").await;
    let b = second_device(&server, &acct).await;
    let ids: Vec<ItemId> = (0..20).map(|_| ItemId::new()).collect();
    for (i, id) in ids.iter().enumerate() {
        a.edit(*id, &[("label", &format!("item{i}")), ("port", "22")])
            .await;
    }
    let mut ea = a.engine(a.config()).await;
    let mut eb = b.engine(b.config()).await;
    ea.sync_once().await;
    eb.sync_once().await;

    let fields = ["label", "port", "user", "hostname", "notes"];
    for (dev, seed) in [(&a, 7u64), (&b, 11u64)] {
        let mut rng = fastrand::Rng::with_seed(seed);
        for n in 0..100 {
            let id = ids[rng.usize(..ids.len())];
            match rng.u8(..10) {
                0 => {
                    if !dev.body(id).await.unwrap().is_deleted() {
                        dev.delete(id).await;
                    }
                }
                _ => {
                    let f = fields[rng.usize(..fields.len())];
                    dev.edit(id, &[(f, &format!("{seed}-{n}"))]).await;
                }
            }
        }
    }
    for _ in 0..2 {
        assert_eq!(ea.sync_once().await, SyncStatus::Synced);
        assert_eq!(eb.sync_once().await, SyncStatus::Synced);
    }
    ea.sync_once().await;
    let sa: BTreeMap<ItemId, ItemBody> = a.snapshot().await.into_iter().collect();
    let sb: BTreeMap<ItemId, ItemBody> = b.snapshot().await.into_iter().collect();
    assert_eq!(sa.len(), 20);
    assert_eq!(sa, sb, "identical decrypted states");
    assert_eq!(a.dirty_count().await + b.dirty_count().await, 0);
}

/// Locking stops sync (no pushes, no pulls); unlocking resumes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t16_lock_pauses_unlock_resumes() {
    let server = TestServer::start().await;
    let (acct, a) = first_device(&server, "t16@example.com").await;
    let b = second_device(&server, &acct).await;
    let cfg = EngineConfig {
        websocket: true,
        poll_interval: Duration::from_millis(300),
        ..quick(&a)
    };
    let handle = a.engine(cfg.clone()).await.spawn();
    wait_for(Duration::from_secs(5), "synced", || async {
        handle.status() == SyncStatus::Synced
    })
    .await;

    // Lock.
    handle.shutdown().await;
    let mine = ItemId::new();
    a.edit(mine, &[("label", "while-locked")]).await;
    let theirs = ItemId::new();
    b.edit(theirs, &[("label", "remote")]).await;
    b.engine(b.config()).await.push_now().await.unwrap();
    let head = server.head(a.vault);
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(
        server.item(a.vault, mine).is_none(),
        "nothing pushed while locked"
    );
    assert!(
        a.store.get_item(theirs).await.unwrap().is_none(),
        "nothing pulled"
    );
    assert_eq!(server.head(a.vault), head);

    // Unlock: a new engine resumes.
    let handle = a.engine(cfg).await.spawn();
    wait_for(Duration::from_secs(5), "resumed", || async {
        server.item(a.vault, mine).is_some() && a.store.get_item(theirs).await.unwrap().is_some()
    })
    .await;
    handle.shutdown().await;
}
