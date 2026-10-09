//! updates it incrementally, publishes snapshots to the reducer, and drops it on
//! lock. Small Argon2 parameters and an in-memory keyring.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use sverb_core::model::{HlcClock, Host, ItemBody, ItemId, ItemKind, VaultId};
use sverb_core::search::{Query, Scope, resolve_host_arg};
use sverb_core::secret::SecretString;
use sverb_core::vault::{Argon2Cost, LockState, MemKeyring};
use sverb_store::{ManualClock, Store};
use sverb_tui::app::{App, Config, UiEvent, UnlockRequest, VaultEffect, VaultEvent, VaultPassword};
use sverb_tui::services::vault::{VaultEngine, VaultService};
use tokio::sync::mpsc::Receiver;

const PW: &str = "correct horse battery staple violin";
const T0: i64 = 1_800_000_000_000;

struct Fixture {
    dir: PathBuf,
    clock: Arc<ManualClock>,
    keyring: MemKeyring,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "m1-05-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self {
            dir,
            clock: Arc::new(ManualClock::new(T0)),
            keyring: MemKeyring::new(),
        }
    }

    fn engine(&self) -> VaultEngine {
        let store = Store::open_at(self.dir.join("sverb.db"), self.clock.clone()).unwrap();
        VaultEngine::new(store, Arc::new(self.keyring.clone()), Argon2Cost::TEST)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn unlock(
    service: &VaultService,
    rx: &mut Receiver<UiEvent>,
    tx: &tokio::sync::mpsc::Sender<UiEvent>,
) -> Vec<UiEvent> {
    service.execute(
        VaultEffect::Unlock(UnlockRequest::Password(VaultPassword::from(PW))),
        tx,
    );
    let mut events = Vec::new();
    while let Some(ev) = rx.recv().await {
        let done = matches!(ev, UiEvent::IndexUpdated(_));
        events.push(ev);
        if done {
            break;
        }
    }
    events
}

// T-13 (plus build on unlock and incremental updates through the service)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t13_unlock_builds_index_and_lock_drops_it() {
    let fx = Fixture::new("t13");
    let init = fx.engine().initialize(PW, false).await.unwrap();
    let vault: VaultId = init.vault.personal_vault().unwrap();
    let device = init.vault.device_id();
    let mut clock = HlcClock::default();
    let tag = ItemId::new();
    let host = ItemId::new();
    let secret_host = ItemId::new();
    let mut tag_body = ItemBody::new(ItemKind::Tag, 1);
    tag_body.set("name", "prod", &mut clock, device);
    let mut host_body = ItemBody::new(ItemKind::Host, 1);
    Host {
        label: "prod-web-1".into(),
        address: "10.0.0.1".into(),
        tags: vec![tag],
        ..Host::default()
    }
    .apply_to(&mut host_body, &mut clock, device);
    let mut secret_body = ItemBody::new(ItemKind::Host, 1);
    Host {
        label: "db".into(),
        address: "10.0.0.2".into(),
        password: Some(SecretString::from("CANARY-PW")),
        ..Host::default()
    }
    .apply_to(&mut secret_body, &mut clock, device);
    let store = fx.engine().store().clone();
    for (id, body) in [
        (tag, &tag_body),
        (host, &host_body),
        (secret_host, &secret_body),
    ] {
        let (kv, env) = init.vault.seal(vault, id, body).unwrap();
        store
            .write(move |w| w.put_item(vault, id, kv, &env, false, true))
            .await
            .unwrap();
    }
    // Frecency makes `db` sort before `prod-web-1`.
    store.touch_connected(secret_host, T0).await.unwrap();
    drop(init);

    let service = VaultService::new(fx.engine());
    assert!(service.index_snapshot().is_none(), "no index while locked");
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let events = unlock(&service, &mut rx, &tx).await;
    assert!(matches!(
        events[0],
        UiEvent::Vault(VaultEvent::Unlocked { .. })
    ));
    let Some(UiEvent::IndexUpdated(snap)) = events.last().cloned() else {
        panic!("no IndexUpdated after unlock: {events:?}");
    };
    assert_eq!(snap.len(), 3);
    assert!(
        snap.entries()
            .iter()
            .all(|e| !e.search_text.contains("CANARY"))
    );
    let hits = snap.query(&Query::parse("#prod web"), Scope::Hosts);
    assert_eq!(
        hits.iter().map(|h| h.item_id).collect::<Vec<_>>(),
        vec![host]
    );
    assert_eq!(resolve_host_arg(&snap, "pw1"), Ok(host));
    let ordered: Vec<_> = snap
        .ordered(Scope::Hosts, &*snap)
        .iter()
        .map(|e| e.item_id)
        .collect();
    assert_eq!(ordered, vec![secret_host, host], "frecency first");
    assert!(snap.query(&Query::parse("@personal"), Scope::Hosts).len() == 2);

    // The reducer keeps the snapshot while unlocked.
    let mut app = App::new(Arc::new(Config::default())).with_vault();
    for ev in events {
        app.handle(ev);
    }
    assert_eq!(app.lock_state(), LockState::Unlocked);
    assert_eq!(app.index().map(|s| s.len()), Some(3));

    // Incremental: rename the tag, delete the host.
    let mut renamed = tag_body.clone();
    renamed.set("name", "production", &mut clock, device);
    service.index_upsert(tag, vault, &renamed, &tx);
    let Some(UiEvent::IndexUpdated(snap2)) = rx.recv().await else {
        panic!("no IndexUpdated after upsert");
    };
    assert_eq!(
        snap2
            .query(&Query::parse("#production"), Scope::Hosts)
            .len(),
        1
    );
    let mut deleted = secret_body.clone();
    deleted.delete(&mut clock, device);
    service.index_upsert(secret_host, vault, &deleted, &tx);
    let Some(UiEvent::IndexUpdated(snap3)) = rx.recv().await else {
        panic!("no IndexUpdated after delete");
    };
    assert!(snap3.get(secret_host).is_none());
    app.handle(UiEvent::IndexUpdated(Arc::clone(&snap3)));
    assert_eq!(app.index().map(|s| s.len()), Some(2));
    // An older snapshot never replaces a newer one.
    app.handle(UiEvent::IndexUpdated(Arc::clone(&snap)));
    assert_eq!(app.index().map(|s| s.version()), Some(snap3.version()));

    // Lock: the reducer and the service drop their snapshots; once the last test
    // handle is gone the entries are freed (and zeroized).
    let weak = Arc::downgrade(&service.index_snapshot().unwrap());
    app.handle(UiEvent::Vault(VaultEvent::LockRequested));
    assert_eq!(app.lock_state(), LockState::Locked);
    assert!(app.index().is_none(), "queries unavailable while locked");
    service.execute(VaultEffect::Lock, &tx);
    assert!(service.index_snapshot().is_none());
    assert!(service.update_index(|_| {}).is_none());
    drop((snap, snap2, snap3));
    assert_eq!(weak.strong_count(), 0, "no snapshot Arc survives the lock");
    assert!(weak.upgrade().is_none());

    // A snapshot that arrives after the lock is ignored by the reducer.
    let stale = sverb_core::search::ItemIndex::new().snapshot();
    app.handle(UiEvent::IndexUpdated(stale));
    assert!(app.index().is_none());

    // Unlocking again rebuilds it.
    let events = unlock(&service, &mut rx, &tx).await;
    let Some(UiEvent::IndexUpdated(again)) = events.last() else {
        panic!("no index after the second unlock");
    };
    assert_eq!(again.len(), 3, "rebuilt from the store");
}
