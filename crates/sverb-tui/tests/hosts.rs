//! M1-07 integration tests: the item service saves, edits, duplicates and deletes
//! hosts through the vault (T-04 … T-07). Small Argon2 parameters, in-memory keyring.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use sverb_core::model::{Host, ItemBody, ItemId, ItemKind};
use sverb_core::vault::{Argon2Cost, MemKeyring};
use sverb_store::{ManualClock, Store};
use sverb_tui::app::hosts::ItemEffect;
use sverb_tui::app::{
    App, Config, EffectId, EffectOutput, UiEvent, UnlockRequest, VaultEffect, VaultPassword,
};
use sverb_tui::services::vault::{VaultEngine, VaultService};
use sverb_tui::widgets::form::{FieldChanges, FieldValue};
use tokio::sync::mpsc::{Receiver, Sender};

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
            "m1-07-{tag}-{}-{}",
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

/// An initialized, unlocked service and its event channel (drained up to the
/// first index snapshot).
async fn unlocked(fx: &Fixture) -> (VaultService, Sender<UiEvent>, Receiver<UiEvent>) {
    fx.engine().initialize(PW, false).await.unwrap();
    let service = VaultService::new(fx.engine());
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    service.execute(
        VaultEffect::Unlock(UnlockRequest::Password(VaultPassword::from(PW))),
        &tx,
    );
    while let Some(ev) = rx.recv().await {
        if matches!(ev, UiEvent::IndexUpdated(_)) {
            break;
        }
    }
    (service, tx, rx)
}

fn changes(pairs: &[(&str, FieldValue)]) -> FieldChanges {
    FieldChanges(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect(),
    )
}

fn text(s: &str) -> FieldValue {
    FieldValue::Text(s.to_owned())
}

/// Wait for the `EffectDone` of `id` (other events are collected).
async fn done(rx: &mut Receiver<UiEvent>, id: EffectId, seen: &mut Vec<UiEvent>) -> EffectOutput {
    while let Some(ev) = rx.recv().await {
        if let UiEvent::EffectDone { id: got, result } = &ev
            && *got == id
        {
            return result.clone().unwrap();
        }
        seen.push(ev);
    }
    panic!("channel closed");
}

async fn raw_body(service: &VaultService, id: ItemId) -> (sverb_store::ItemRow, ItemBody) {
    let row = service.store().get_item(id).await.unwrap().unwrap();
    let body = service.unlocked().unwrap().open(&row).unwrap();
    (row, body)
}

// T-04
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t04_save_new_host_encrypted_indexed_and_listed() {
    let fx = Fixture::new("t04");
    let (service, tx, mut rx) = unlocked(&fx).await;
    let id = EffectId(1);
    service.execute(
        VaultEffect::Items(ItemEffect::Save {
            id,
            item: None,
            kind: ItemKind::Host,
            changes: changes(&[
                ("label", text("prod-web-1")),
                ("address", text("10.0.0.1")),
                ("password", FieldValue::Secret("CANARY-pw".into())),
            ]),
        }),
        &tx,
    );
    let mut seen = Vec::new();
    let EffectOutput::Item(item) = done(&mut rx, id, &mut seen).await else {
        panic!("no item id");
    };
    // Persisted encrypted (no plaintext in the envelope), dirty for a future sync.
    let (row, body) = raw_body(&service, item).await;
    assert!(row.dirty, "local writes are dirty (outbox rule)");
    let hay = String::from_utf8_lossy(&row.envelope);
    assert!(!hay.contains("prod-web-1") && !hay.contains("CANARY"));
    assert_eq!(Host::try_from(&body).unwrap().address, "10.0.0.1");
    assert_eq!(service.store().pending_count().await.unwrap(), 1);
    // The index is updated and the reducer's list shows the host.
    let snap = service.index_snapshot().unwrap();
    assert_eq!(snap.get(item).unwrap().display_label(), "prod-web-1");
    let mut app = App::new(Arc::new(Config::default()));
    let effects = app.handle(UiEvent::IndexUpdated(snap));
    assert!(
        effects.iter().any(|e| matches!(
            e,
            sverb_tui::app::Effect::Vault(VaultEffect::Items(ItemEffect::LoadHosts { .. }))
        )),
        "the catalog is (re)loaded: {effects:?}"
    );
    let labels: Vec<String> = app
        .views()
        .hosts
        .list
        .rows()
        .iter()
        .map(|r| r.label.clone())
        .collect();
    assert_eq!(labels, ["prod-web-1"]);
    // The catalog never carries the password.
    let ops = service.item_ops().unwrap();
    let cat = ops.catalog().await.unwrap();
    assert!(cat.hosts[&item].has_password);
    assert!(!format!("{cat:?}").contains("CANARY"));
}

// T-05
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t05_edit_port_stamps_only_port() {
    let fx = Fixture::new("t05");
    let (service, _tx, _rx) = unlocked(&fx).await;
    let ops = service.item_ops().unwrap();
    let w = ops
        .save_host(
            None,
            changes(&[
                ("label", text("db")),
                ("address", text("db.internal")),
                ("username", text("root")),
            ]),
        )
        .await
        .unwrap();
    let before = w.body.clone();
    let w2 = ops
        .save_host(
            Some(w.id),
            changes(&[("port", FieldValue::Number(Some(2222)))]),
        )
        .await
        .unwrap();
    let (_, after) = raw_body(&service, w.id).await;
    assert_eq!(after, w2.body);
    for (k, v) in &after.fields {
        if k == "port" {
            assert!(before.get_stamped("port").is_none());
            assert_eq!(Host::try_from(&after).unwrap().port, Some(2222));
            let _ = v;
        } else {
            assert_eq!(Some(v), before.get_stamped(k), "{k} was re-stamped");
        }
    }
    assert_eq!(after.fields.len(), before.fields.len() + 1);
}

// T-06
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t06_duplicate_copies_fields_with_a_new_id() {
    let fx = Fixture::new("t06");
    let (service, tx, mut rx) = unlocked(&fx).await;
    let ops = service.item_ops().unwrap();
    let w = ops
        .save_host(
            None,
            changes(&[
                ("label", text("x")),
                ("address", text("10.0.0.9")),
                ("port", FieldValue::Number(Some(2200))),
                ("password", FieldValue::Secret("pw".into())),
            ]),
        )
        .await
        .unwrap();
    service.execute(VaultEffect::Items(ItemEffect::Duplicate(w.id)), &tx);
    // The duplicate shows up in the index.
    // Only the duplicate went through the service's index.
    let Some(UiEvent::IndexUpdated(snap)) = rx.recv().await else {
        panic!("no index update");
    };
    let copy = snap
        .entries()
        .iter()
        .find(|e| e.item_id != w.id)
        .unwrap()
        .item_id;
    let (_, body) = raw_body(&service, copy).await;
    let a = Host::try_from(&w.body).unwrap();
    let b = Host::try_from(&body).unwrap();
    assert_eq!(b.label, "x (copy)");
    assert_eq!((b.address.as_str(), b.port), (a.address.as_str(), a.port));
    assert_eq!(b.password.unwrap().expose(), "pw");
    assert_eq!(body.fields.len(), w.body.fields.len());
}

// T-07
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t07_delete_tombstones() {
    let fx = Fixture::new("t07");
    let (service, tx, mut rx) = unlocked(&fx).await;
    let ops = service.item_ops().unwrap();
    let w = ops
        .save_host(None, changes(&[("address", text("gone.example"))]))
        .await
        .unwrap();
    service.index_upsert(w.id, w.vault, &w.body, &tx);
    let _ = rx.recv().await;
    assert!(service.index_snapshot().unwrap().get(w.id).is_some());
    service.execute(VaultEffect::Items(ItemEffect::Delete(w.id)), &tx);
    let Some(UiEvent::IndexUpdated(snap)) = rx.recv().await else {
        panic!("no index update");
    };
    assert!(snap.get(w.id).is_none(), "gone from the index");
    let mut app = App::new(Arc::new(Config::default()));
    app.handle(UiEvent::IndexUpdated(snap));
    assert!(
        app.views().hosts.list.rows().is_empty(),
        "gone from the list"
    );
    let (row, body) = raw_body(&service, w.id).await;
    assert!(row.deleted, "still in the DB with deleted = 1");
    assert!(body.is_deleted());
    assert!(ops.load(w.id).await.unwrap().is_none());
}
