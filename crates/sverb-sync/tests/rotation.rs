//! Vault key rotation on revoke (SPEC §13.2 steps 1–5, §19) end to end
//! against the in-process server (memory backend, loopback HTTP + WebSocket).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

mod common;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use common::{Account, Device, TestServer, first_device, wait_for};
use serde_json::Value;
use sverb_core::model::{ItemBody, ItemId, ItemKind, VaultId};
use sverb_crypto::random::os_rng;
use sverb_proto::ErrorCode;
use sverb_proto::orgs::{CreateInviteRequest, Role};
use sverb_proto::rotation::RotateRequest;
use sverb_proto::sync::{Permission, PushChange, PushRequest};
use sverb_sync::account::vaults::VaultAdmin;
use sverb_sync::rotation::{RotationError, RotationOptions, RotationPhase, RotationProgress};
use sverb_sync::trust::{PinSet, TrustedKeySource};
use sverb_sync::{
    ApiClient, EngineConfig, SyncEngine, SyncEvent, SyncStatus, TokenManager, VaultKeySource,
    VaultKeys,
};
use tokio::sync::mpsc;
use uuid::Uuid;

const WAIT: Duration = Duration::from_secs(15);

struct Member {
    acct: Account,
    dev: Device,
    tokens: Arc<TokenManager>,
    admin: VaultAdmin,
}

impl Member {
    async fn new(server: &TestServer, email: &str) -> Self {
        let (acct, dev) = first_device(server, email).await;
        let api = ApiClient::new(&server.url(), None, Duration::from_secs(10)).unwrap();
        let tokens = Arc::new(
            TokenManager::load(dev.store.clone(), dev.lmk.clone(), api)
                .await
                .unwrap(),
        );
        let admin = VaultAdmin::new(
            dev.store.clone(),
            dev.lmk.clone(),
            tokens.clone(),
            acct.user_id,
            acct.keys.clone(),
        );
        Self {
            acct,
            dev,
            tokens,
            admin,
        }
    }

    fn id(&self) -> Uuid {
        self.acct.user_id
    }

    /// An admin with a token manager freshly loaded from the store (an engine
    /// refresh rotated the refresh token held by `self.tokens`; reusing it would
    /// trip the server's reuse detection).
    async fn fresh_admin(&self, server: &TestServer) -> VaultAdmin {
        let api = ApiClient::new(&server.url(), None, Duration::from_secs(10)).unwrap();
        let tokens = Arc::new(
            TokenManager::load(self.dev.store.clone(), self.dev.lmk.clone(), api)
                .await
                .unwrap(),
        );
        VaultAdmin::new(
            self.dev.store.clone(),
            self.dev.lmk.clone(),
            tokens,
            self.id(),
            self.acct.keys.clone(),
        )
    }

    async fn token(&self) -> String {
        self.tokens.access().await.unwrap()
    }

    fn key_source(&self) -> Arc<dyn VaultKeySource> {
        Arc::new(TrustedKeySource::new(
            self.id(),
            self.acct.keys.clone(),
            PinSet::default(),
        ))
    }

    async fn engine(&self, websocket: bool) -> (SyncEngine, mpsc::UnboundedReceiver<SyncEvent>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let e = self
            .dev
            .engine_with(
                EngineConfig {
                    websocket,
                    ..self.dev.config()
                },
                self.key_source(),
                Some(tx),
            )
            .await;
        (e, rx)
    }

    async fn sync(&self) -> (SyncStatus, Vec<SyncEvent>) {
        let (mut e, mut rx) = self.engine(false).await;
        let st = e.sync_once().await;
        drop(e);
        let mut events = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            events.push(ev);
        }
        (st, events)
    }

    async fn keys(&self) -> VaultKeys {
        VaultKeys::load(&self.dev.store.list_vaults().await.unwrap(), &self.dev.lmk).0
    }

    async fn local_kv(&self, vault: VaultId) -> u32 {
        self.dev
            .store
            .get_vault(vault)
            .await
            .unwrap()
            .unwrap()
            .key_version
    }

    async fn body(&self, vault: VaultId, id: ItemId) -> Option<ItemBody> {
        let row = self.dev.store.get_item(id).await.unwrap()?;
        assert_eq!(row.vault_id, vault);
        self.keys().await.open(vault, id, &row.envelope).ok()
    }

    async fn edit(&self, vault: VaultId, id: ItemId, fields: &[(&str, &str)]) {
        let mut body = self
            .body(vault, id)
            .await
            .unwrap_or_else(|| ItemBody::new(ItemKind::Host, 1));
        {
            let mut clock = self.dev.hlc.lock();
            for (k, v) in fields {
                body.set(k, *v, &mut clock, self.dev.device);
            }
        }
        self.put(vault, id, &body).await;
    }

    async fn delete(&self, vault: VaultId, id: ItemId) {
        let mut body = self.body(vault, id).await.unwrap();
        {
            let mut clock = self.dev.hlc.lock();
            body.delete(&mut clock, self.dev.device);
        }
        self.put(vault, id, &body).await;
    }

    async fn put(&self, vault: VaultId, id: ItemId, body: &ItemBody) {
        let (kv, env) = self.keys().await.seal(vault, id, body).unwrap();
        self.dev
            .store
            .put_item(vault, id, kv, env, body.is_deleted(), true)
            .await
            .unwrap();
    }

    fn text(body: &ItemBody, field: &str) -> String {
        body.get(field)
            .and_then(|v| v.as_text())
            .unwrap_or_default()
            .to_owned()
    }
}

fn quiet() -> impl Fn(RotationProgress) + Send + Sync {
    |_| {}
}

/// `owner` creates an org; every other member joins with their role.
async fn org(owner: &Member, others: &[(&Member, Role)]) -> Uuid {
    let api = owner.tokens.api().clone();
    let org = api
        .create_org(&owner.token().await, "Acme")
        .await
        .unwrap()
        .id;
    for (m, role) in others {
        let inv = api
            .create_invite(
                &owner.token().await,
                org,
                &CreateInviteRequest {
                    email: Some(m.acct.email.clone()),
                    role: *role,
                },
            )
            .await
            .unwrap();
        let link = inv.link.unwrap();
        let token = link.rsplit('/').next().unwrap();
        api.accept_invite(&m.token().await, token).await.unwrap();
    }
    org
}

struct Scenario {
    server: TestServer,
    alice: Member,
    bob: Member,
    carol: Member,
    vault: VaultId,
    /// Live items (labels `item-0` …), then one tombstone.
    items: Vec<ItemId>,
    tombstone: ItemId,
}

/// Alice (owner, `manage`), Bob (`bob_perm`), Carol (`read`) share a vault
/// with `n` live items and one tombstone; Bob and Carol synced it.
async fn scenario(n: usize, bob_perm: Permission) -> Scenario {
    let server = TestServer::start().await;
    let alice = Member::new(&server, "alice@example.test").await;
    let bob = Member::new(&server, "bob@example.test").await;
    let carol = Member::new(&server, "carol@example.test").await;
    let org = org(&alice, &[(&bob, Role::Member), (&carol, Role::Member)]).await;
    let vault = alice.admin.create(org, "Ops").await.unwrap();
    let mut items = Vec::new();
    for i in 0..n {
        let id = ItemId::new();
        alice
            .edit(vault, id, &[("label", &format!("item-{i}"))])
            .await;
        items.push(id);
    }
    let tombstone = ItemId::new();
    alice.edit(vault, tombstone, &[("label", "gone")]).await;
    assert_eq!(alice.sync().await.0, SyncStatus::Synced);
    alice.delete(vault, tombstone).await;
    assert_eq!(alice.sync().await.0, SyncStatus::Synced);
    alice.admin.grant(vault, bob.id(), bob_perm).await.unwrap();
    alice
        .admin
        .grant(vault, carol.id(), Permission::Read)
        .await
        .unwrap();
    for m in [&bob, &carol] {
        assert_eq!(m.sync().await.0, SyncStatus::Synced);
        assert!(m.body(vault, items[0]).await.is_some());
    }
    Scenario {
        server,
        alice,
        bob,
        carol,
        vault,
        items,
        tombstone,
    }
}

fn server_kv(server: &TestServer, vault: VaultId) -> i32 {
    server
        .mem
        .with_data(|d| d.vaults.get(&vault.uuid()).unwrap().key_version)
}

fn rotation_json(server: &TestServer, vault: VaultId) -> Option<Value> {
    server
        .mem
        .with_data(|d| d.vaults.get(&vault.uuid()).unwrap().rotation.clone())
}

fn staged(server: &TestServer, vault: VaultId) -> usize {
    server.mem.with_data(|d| {
        d.rotation_staging
            .keys()
            .filter(|(v, _)| *v == vault.uuid())
            .count()
    })
}

/// `(user, key_version)` of every grant row of `vault`.
fn grant_rows(server: &TestServer, vault: VaultId) -> BTreeSet<(Uuid, i32)> {
    server.mem.with_data(|d| {
        d.vault_members
            .iter()
            .filter(|m| m.vault_id == vault.uuid())
            .map(|m| (m.user_id, m.key_version))
            .collect()
    })
}

/// `(revision, key_version)` of every server item of `vault`.
fn server_items(server: &TestServer, vault: VaultId) -> Vec<(Uuid, i64, i32)> {
    server.mem.with_data(|d| {
        d.items
            .iter()
            .filter(|((v, _), _)| *v == vault.uuid())
            .map(|((_, id), i)| (*id, i.revision, i.key_version))
            .collect()
    })
}

/// Item ids of every rotate `upload` request so far.
fn uploaded_ids(server: &TestServer) -> Vec<String> {
    server
        .requests
        .lock()
        .iter()
        .filter(|r| r.method == "POST" && r.path.ends_with("/rotate"))
        .filter_map(|r| serde_json::from_str::<Value>(&r.body).ok())
        .filter(|v| v["action"] == "upload")
        .flat_map(|v| {
            v["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|i| i["id"].as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        })
        .collect()
}

// Alice revokes Carol → the rotation completes; Bob decrypts everything
// with VK′; Carol can't pull; key version bumped, old grant rows gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t01_revoke_rotates() {
    let s = scenario(3, Permission::Write).await;
    let (server, alice, bob, carol, vault) = (&s.server, &s.alice, &s.bob, &s.carol, s.vault);
    let phases = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let p = phases.clone();
    let report = alice
        .admin
        .revoke_and_rotate(vault, carol.id(), &move |pr: RotationProgress| {
            p.lock().push(pr.phase);
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(report.key_version, 2);
    assert_eq!(report.items, 4, "3 items and the tombstone");
    assert_eq!(report.members, 2, "Alice and Bob");
    assert!(phases.lock().contains(&RotationPhase::Uploading));
    assert_eq!(phases.lock().last(), Some(&RotationPhase::Done));

    assert_eq!(server_kv(server, vault), 2);
    assert!(rotation_json(server, vault).is_none());
    assert_eq!(staged(server, vault), 0);
    assert_eq!(
        grant_rows(server, vault),
        BTreeSet::from([(alice.id(), 2), (bob.id(), 2)]),
        "old-version rows deleted, Carol gone"
    );
    assert!(
        server_items(server, vault)
            .iter()
            .all(|(_, _, kv)| *kv == 2)
    );
    // The audit log records the rotation (metadata only).
    assert!(server.mem.with_data(|d| {
        d.audit
            .iter()
            .any(|a| a.kind == "vault.rotated" && a.target == Some(vault.uuid()))
    }));

    // Bob switches to VK′: his stored key is version 2 and opens every item.
    let (st, events) = bob.sync().await;
    assert_eq!(st, SyncStatus::Synced);
    assert!(
        events.iter().any(
            |e| matches!(e, SyncEvent::KeyRotated { vault: v, key_version: 2 } if *v == vault)
        )
    );
    assert_eq!(bob.local_kv(vault).await, 2);
    for (i, id) in s.items.iter().enumerate() {
        let b = bob.body(vault, *id).await.expect("opens under VK′");
        assert_eq!(Member::text(&b, "label"), format!("item-{i}"));
    }
    assert!(bob.body(vault, s.tombstone).await.unwrap().is_deleted());
    for row in bob.dev.store.list_items(vault).await.unwrap() {
        assert_eq!(row.key_version, 2);
    }

    // Carol: no access anymore.
    let err = carol
        .tokens
        .api()
        .pull(&carol.token().await, vault.uuid(), 0, 500)
        .await
        .unwrap_err();
    assert!(err.is_status(404) || err.is_status(403), "{err}");
}

// A push during the rotation gets 409; after the commit Bob's pending
// edit is re-encrypted under VK′ and pushed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t02_push_during_rotation() {
    let s = scenario(2, Permission::Write).await;
    let (server, alice, bob, carol, vault) = (&s.server, &s.alice, &s.bob, &s.carol, s.vault);
    let target = s.items[0];
    alice.admin.revoke(vault, carol.id()).await.unwrap();
    // Begin, then stop before uploading anything (the window stays open).
    let err = alice
        .admin
        .rotate_with(
            vault,
            RotationOptions {
                stop_after_chunks: Some(0),
                ..RotationOptions::default()
            },
            &quiet(),
        )
        .await
        .unwrap_err();
    assert_eq!(err, RotationError::Interrupted);
    assert!(rotation_json(server, vault).is_some());

    // A raw push: 409 rotating.
    let raw = bob
        .tokens
        .api()
        .push(
            &bob.token().await,
            vault.uuid(),
            &PushRequest {
                changes: vec![PushChange {
                    id: Uuid::now_v7(),
                    base_revision: 0,
                    key_version: 1,
                    envelope: vec![1; 40],
                    deleted: false,
                }],
            },
        )
        .await
        .unwrap_err();
    assert_eq!(raw.code(), Some(ErrorCode::Rotating));
    assert!(raw.is_status(409));

    // Bob edits; his sync is paused (the edit stays queued), pulls still work.
    bob.edit(vault, target, &[("address", "10.9.9.9")]).await;
    let before = server.item(vault, target).unwrap();
    let (st, _) = bob.sync().await;
    assert_ne!(st, SyncStatus::Disabled);
    assert_eq!(bob.dev.pending().await, 1);
    assert_eq!(server.item(vault, target).unwrap(), before);

    // Alice resumes and commits.
    let r = alice.admin.rotate(vault, &quiet()).await.unwrap();
    assert!(r.resumed);
    assert_eq!(r.key_version, 2);

    // Bob: key switched, pending edit re-sealed under VK′ and pushed.
    let (st, _) = bob.sync().await;
    assert_eq!(st, SyncStatus::Synced);
    assert_eq!(bob.dev.pending().await, 0);
    let it = server.item(vault, target).unwrap();
    assert_eq!(it.key_version, 2);
    assert!(it.revision > before.revision);
    assert_eq!(alice.sync().await.0, SyncStatus::Synced);
    let b = alice.body(vault, target).await.unwrap();
    assert_eq!(Member::text(&b, "address"), "10.9.9.9");
    assert_eq!(Member::text(&b, "label"), "item-0");
}

// Commit with incomplete staging → 400 naming the missing count; nothing
// changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t03_incomplete_commit_rejected() {
    let s = scenario(2, Permission::Write).await;
    let (server, alice, carol, vault) = (&s.server, &s.alice, &s.carol, s.vault);
    alice.admin.revoke(vault, carol.id()).await.unwrap();
    // 3 server items (2 + tombstone); upload one chunk of 1.
    let err = alice
        .admin
        .rotate_with(
            vault,
            RotationOptions {
                chunk_items: 1,
                stop_after_chunks: Some(1),
            },
            &quiet(),
        )
        .await
        .unwrap_err();
    assert_eq!(err, RotationError::Interrupted);
    assert_eq!(staged(server, vault), 1);
    let items_before = server_items(server, vault);
    let grants_before = grant_rows(server, vault);
    let head_before = server.head(vault);

    // A raw commit with otherwise valid-looking wrapped keys.
    let wrapped_keys = vec![sverb_proto::rotation::RotationGrant {
        user: alice.id(),
        wrapped: vec![7; 80],
        signature: vec![9; 64],
    }];
    let err = alice
        .tokens
        .api()
        .rotate(
            &alice.token().await,
            vault.uuid(),
            &RotateRequest::Commit { wrapped_keys },
        )
        .await
        .unwrap_err();
    assert!(err.is_status(400), "{err}");
    assert_eq!(err.code(), Some(ErrorCode::Invalid));
    assert!(err.to_string().contains("2 of 3 items missing"), "{err}");
    // Rolled back: nothing moved.
    assert_eq!(server_items(server, vault), items_before);
    assert_eq!(grant_rows(server, vault), grants_before);
    assert_eq!(server.head(vault), head_before);
    assert_eq!(server_kv(server, vault), 1);
    assert!(rotation_json(server, vault).is_some());
    assert_eq!(staged(server, vault), 1);
}

// T-04 (§19): the rotating client dies mid-upload. Before 15 min another
// manage client's begin is refused; after 15 min it is prompted, restarts
// (the first attempt's staging is discarded) and completes. `admin gc` clears
// an abandoned rotation too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t04_abandoned_rotation_restarted() {
    let s = scenario(3, Permission::Manage).await;
    let (server, alice, bob, carol, vault) = (&s.server, &s.alice, &s.bob, &s.carol, s.vault);
    alice.admin.revoke(vault, carol.id()).await.unwrap();
    let killed = alice
        .admin
        .rotate_with(
            vault,
            RotationOptions {
                chunk_items: 2,
                stop_after_chunks: Some(1),
            },
            &quiet(),
        )
        .await
        .unwrap_err();
    assert_eq!(killed, RotationError::Interrupted);
    assert_eq!(staged(server, vault), 2);

    // Still active: Bob is refused.
    let busy = bob.admin.rotate(vault, &quiet()).await.unwrap_err();
    assert!(busy.is_busy(), "{busy}");
    let (_, events) = bob.sync().await;
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, SyncEvent::RotationAbandoned { .. }))
    );

    // 16 minutes later (server clock): abandoned; Bob's client is prompted.
    server.clock.advance(chrono::TimeDelta::minutes(16));
    let (_, events) = bob.sync().await;
    assert!(
        events
            .iter()
            .any(|e| matches!(e, SyncEvent::RotationAbandoned { vault: v } if *v == vault)),
        "{events:?}"
    );
    // Bob restarts: begin replaces Alice's rotation and discards her staging.
    let bob_admin = bob.fresh_admin(server).await;
    let err = bob_admin
        .rotate_with(
            vault,
            RotationOptions {
                stop_after_chunks: Some(0),
                ..RotationOptions::default()
            },
            &quiet(),
        )
        .await
        .unwrap_err();
    assert_eq!(err, RotationError::Interrupted);
    assert_eq!(
        staged(server, vault),
        0,
        "the first attempt's staging is gone"
    );
    let by = rotation_json(server, vault).unwrap()["by"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(by, bob.id().to_string());
    let r = bob_admin.rotate(vault, &quiet()).await.unwrap();
    assert!(r.resumed);
    assert_eq!(r.uploaded, 4);
    assert_eq!(server_kv(server, vault), 2);
    assert_eq!(
        grant_rows(server, vault),
        BTreeSet::from([(alice.id(), 2), (bob.id(), 2)])
    );
    // Alice's client follows the new key.
    assert_eq!(alice.sync().await.0, SyncStatus::Synced);
    assert_eq!(alice.local_kv(vault).await, 2);
    assert_eq!(
        Member::text(&alice.body(vault, s.items[2]).await.unwrap(), "label"),
        "item-2"
    );

    // `admin gc`: another abandoned rotation is discarded and pushes resume.
    let alice_admin = alice.fresh_admin(server).await;
    let err = alice_admin
        .rotate_with(
            vault,
            RotationOptions {
                chunk_items: 1,
                stop_after_chunks: Some(1),
            },
            &quiet(),
        )
        .await
        .unwrap_err();
    assert_eq!(err, RotationError::Interrupted);
    let store = server.state.sync().store();
    assert!(
        store
            .discard_abandoned_rotations(server.clock_now())
            .await
            .unwrap()
            .is_empty(),
        "not yet abandoned"
    );
    server.clock.advance(chrono::TimeDelta::minutes(15));
    let cleared = store
        .discard_abandoned_rotations(server.clock_now())
        .await
        .unwrap();
    assert_eq!(cleared, vec![vault.uuid()]);
    assert!(rotation_json(server, vault).is_none());
    assert_eq!(staged(server, vault), 0);
    bob.edit(vault, s.items[0], &[("address", "after-gc")])
        .await;
    assert_eq!(bob.sync().await.0, SyncStatus::Synced);
    assert_eq!(bob.dev.pending().await, 0);
}

// The same client crashes and restarts within 15 min → it resumes from
// its persisted progress (no item uploaded twice) and commits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t05_resume_after_crash() {
    let s = scenario(5, Permission::Write).await;
    let (server, alice, carol, vault) = (&s.server, &s.alice, &s.carol, s.vault);
    alice.admin.revoke(vault, carol.id()).await.unwrap();
    let opts = RotationOptions {
        chunk_items: 2,
        stop_after_chunks: Some(1),
    };
    assert_eq!(
        alice
            .admin
            .rotate_with(vault, opts, &quiet())
            .await
            .unwrap_err(),
        RotationError::Interrupted
    );
    assert!(alice.admin.has_pending_rotation(vault).await);
    assert_eq!(uploaded_ids(server).len(), 2);

    // "Restart": a fresh admin on the same store (only `meta` survives).
    let restarted = VaultAdmin::new(
        alice.dev.store.clone(),
        alice.dev.lmk.clone(),
        alice.tokens.clone(),
        alice.id(),
        alice.acct.keys.clone(),
    );
    server.clock.advance(chrono::TimeDelta::minutes(5));
    let r = restarted
        .rotate_with(
            vault,
            RotationOptions {
                chunk_items: 2,
                stop_after_chunks: None,
            },
            &quiet(),
        )
        .await
        .unwrap();
    assert!(r.resumed);
    assert_eq!(r.items, 6);
    assert_eq!(r.uploaded, 4, "only what was missing");
    let ids = uploaded_ids(server);
    let unique: BTreeSet<&String> = ids.iter().collect();
    assert_eq!(ids.len(), 6);
    assert_eq!(unique.len(), 6, "no item uploaded twice");
    assert!(!restarted.has_pending_rotation(vault).await);
    assert_eq!(server_kv(server, vault), 2);
    assert_eq!(s.bob.sync().await.0, SyncStatus::Synced);
    for (i, id) in s.items.iter().enumerate() {
        let b = s.bob.body(vault, *id).await.unwrap();
        assert_eq!(Member::text(&b, "label"), format!("item-{i}"));
    }
}

// Revisions after the commit are gap-free and above the old head; a
// puller with an old cursor receives every rotated item.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t06_fresh_gap_free_revisions() {
    let s = scenario(4, Permission::Write).await;
    let (server, alice, bob, carol, vault) = (&s.server, &s.alice, &s.bob, &s.carol, s.vault);
    let head = server.head(vault);
    let bob_cursor = bob
        .dev
        .store
        .get_vault(vault)
        .await
        .unwrap()
        .unwrap()
        .sync_cursor;
    assert_eq!(bob_cursor, head);
    alice
        .admin
        .revoke_and_rotate(vault, carol.id(), &quiet())
        .await
        .unwrap();
    let items = server_items(server, vault);
    let n = i64::try_from(items.len()).unwrap();
    let mut revs: Vec<i64> = items.iter().map(|(_, r, _)| *r).collect();
    revs.sort_unstable();
    assert_eq!(revs, ((head + 1)..=(head + n)).collect::<Vec<_>>());
    assert_eq!(server.head(vault), head + n);

    assert_eq!(bob.sync().await.0, SyncStatus::Synced);
    let rows = bob.dev.store.list_items(vault).await.unwrap();
    assert_eq!(rows.len(), items.len());
    for r in rows {
        assert!(r.revision > head, "rotated revision received");
        assert_eq!(r.key_version, 2);
    }
    assert_eq!(
        bob.dev
            .store
            .get_vault(vault)
            .await
            .unwrap()
            .unwrap()
            .sync_cursor,
        head + n
    );
}

// A remaining member's key changed (unpinned) → the client refuses to
// wrap for them and the commit is blocked (DECISION) until the new key is
// accepted; then the rotation resumes and commits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t07_changed_member_key_blocks_commit() {
    let s = scenario(2, Permission::Write).await;
    let (server, alice, bob, carol, vault) = (&s.server, &s.alice, &s.bob, &s.carol, s.vault);
    alice.admin.revoke(vault, carol.id()).await.unwrap();
    let other = sverb_crypto::account::generate_account_keys(&mut os_rng()).public();
    server.user_keys.lock().insert(
        bob.id(),
        sverb_proto::users::UserPublicKeys {
            user_id: bob.id(),
            email: Some(bob.acct.email.clone()),
            x25519_pub: other.x25519.to_vec(),
            ed25519_pub: other.ed25519.to_vec(),
        },
    );
    let err = alice.admin.rotate(vault, &quiet()).await.unwrap_err();
    let RotationError::UntrustedMembers(blocked) = &err else {
        panic!("{err:?}");
    };
    assert_eq!(blocked.len(), 1);
    assert_eq!(blocked[0].user, bob.id());
    assert!(err.to_string().contains("bob@example.test"), "{err}");
    // Nothing committed; the rotation stays open (pushes still paused).
    assert_eq!(server_kv(server, vault), 1);
    assert!(rotation_json(server, vault).is_some());
    assert_eq!(staged(server, vault), 3);
    assert!(alice.admin.has_pending_rotation(vault).await);

    // Resolved: Alice accepts Bob's new key (after comparing safety numbers).
    assert!(
        alice
            .admin
            .trust()
            .accept_new_key(bob.id(), true)
            .await
            .unwrap()
    );
    let r = alice.admin.rotate(vault, &quiet()).await.unwrap();
    assert!(r.resumed);
    assert_eq!(r.uploaded, 0, "everything was staged already");
    assert_eq!(r.members, 2);
    assert_eq!(server_kv(server, vault), 2);
}

// T-08 (M5 exit criterion): invite, grant, edits, revoke, rotation and
// continued sync for the remaining members, end to end (Bob's engine runs
// with the WebSocket and switches keys by itself).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t08_three_member_scenario() {
    let server = TestServer::start().await;
    let alice = Member::new(&server, "alice@example.test").await;
    let bob = Member::new(&server, "bob@example.test").await;
    let carol = Member::new(&server, "carol@example.test").await;
    let org = org(&alice, &[(&bob, Role::Member), (&carol, Role::Member)]).await;
    let vault = alice.admin.create(org, "Prod").await.unwrap();
    let web = ItemId::new();
    alice
        .edit(vault, web, &[("label", "web"), ("address", "10.0.0.1")])
        .await;
    assert_eq!(alice.sync().await.0, SyncStatus::Synced);
    alice
        .admin
        .grant(vault, bob.id(), Permission::Write)
        .await
        .unwrap();
    alice
        .admin
        .grant(vault, carol.id(), Permission::Read)
        .await
        .unwrap();

    let (bob_engine, mut bob_rx) = bob.engine(true).await;
    let bob_h = bob_engine.spawn();
    wait_for(WAIT, "bob adopts the vault and decrypts", || async {
        bob.dev.store.get_item(web).await.unwrap().is_some() && bob.body(vault, web).await.is_some()
    })
    .await;
    assert_eq!(carol.sync().await.0, SyncStatus::Synced);
    assert!(carol.body(vault, web).await.is_some());

    // Bob edits before the revocation.
    let db = ItemId::new();
    bob.edit(vault, db, &[("label", "db")]).await;
    assert_eq!(bob_h.sync_now().await, SyncStatus::Synced);
    assert_eq!(alice.sync().await.0, SyncStatus::Synced);
    assert!(alice.body(vault, db).await.is_some());

    // Alice revokes Carol; the rotation runs right away.
    let report = alice
        .admin
        .revoke_and_rotate(vault, carol.id(), &quiet())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(report.key_version, 2);

    // Bob's running engine switches to VK′ on `vault_access rotated`.
    wait_for(WAIT, "bob's device switches to key version 2", || async {
        bob.local_kv(vault).await == 2
    })
    .await;
    wait_for(WAIT, "bob's local items are under VK′", || async {
        bob.dev
            .store
            .list_items(vault)
            .await
            .unwrap()
            .iter()
            .all(|r| r.key_version == 2)
    })
    .await;
    let mut saw = false;
    while let Ok(ev) = bob_rx.try_recv() {
        saw |= matches!(ev, SyncEvent::KeyRotated { vault: v, .. } if v == vault);
    }
    assert!(saw, "KeyRotated reported");

    // Continued sync for the remaining members.
    bob.edit(vault, web, &[("address", "10.0.0.2")]).await;
    assert_eq!(bob_h.sync_now().await, SyncStatus::Synced);
    assert_eq!(alice.sync().await.0, SyncStatus::Synced);
    assert_eq!(alice.local_kv(vault).await, 2);
    assert_eq!(
        Member::text(&alice.body(vault, web).await.unwrap(), "address"),
        "10.0.0.2"
    );
    alice.edit(vault, db, &[("port", "5432")]).await;
    assert_eq!(alice.sync().await.0, SyncStatus::Synced);
    assert_eq!(bob_h.sync_now().await, SyncStatus::Synced);
    assert_eq!(
        Member::text(&bob.body(vault, db).await.unwrap(), "port"),
        "5432"
    );

    // Carol keeps what she had synced (unavoidable) but gets nothing new.
    let _ = carol.sync().await;
    let old = carol.dev.store.get_item(web).await.unwrap().unwrap();
    assert_eq!(old.key_version, 1);
    let b = carol.keys().await.open(vault, web, &old.envelope).unwrap();
    assert_eq!(Member::text(&b, "address"), "10.0.0.1");
    let err = carol
        .tokens
        .api()
        .pull(&carol.token().await, vault.uuid(), 0, 500)
        .await
        .unwrap_err();
    assert!(err.is_status(404) || err.is_status(403), "{err}");
    bob_h.shutdown().await;
}
