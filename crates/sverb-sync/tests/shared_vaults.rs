//! Shared vaults end to end against the in-process server (memory
//! receive and verify, read-only enforcement, move with references, credential
//! overrides, the admin reconcile and the 3-member scenario.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use common::{Account, Device, TestServer, first_device, wait_for};
use sverb_core::model::vault_refs::{RefPolicy, TransferMode, VaultScope, plan_transfer};
use sverb_core::model::{
    CredentialOverride, DeviceId, HlcClock, Host, Identity, ItemBody, ItemId, ItemKind, VaultId,
};
use sverb_core::resolve::overrides::{OverrideLayer, apply_override};
use sverb_core::resolve::{
    GlobalDefaults, LookupTable, SettingKey, Settings, Source, Target, resolve_settings,
};
use sverb_crypto::random::os_rng;
use sverb_proto::orgs::{CreateInviteRequest, Role};
use sverb_proto::sync::Permission;
use sverb_sync::account::vaults::{VaultAdmin, VaultAdminError, apply_transfer};
use sverb_sync::trust::{PinSet, TrustError, TrustedKeySource};
use sverb_sync::{
    ApiClient, EngineConfig, SyncEngine, SyncEvent, SyncHandle, SyncStatus, ToastLevel,
    TokenManager, VaultKeySource, VaultKeys,
};
use tokio::sync::mpsc;
use uuid::Uuid;

const WAIT: Duration = Duration::from_secs(10);

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

    async fn has_vault(&self, vault: VaultId) -> bool {
        self.dev.store.get_vault(vault).await.unwrap().is_some()
    }

    /// The decrypted local body of `id` in `vault`.
    async fn body(&self, vault: VaultId, id: ItemId) -> Option<ItemBody> {
        let row = self.dev.store.get_item(id).await.unwrap()?;
        assert_eq!(row.vault_id, vault);
        self.keys().await.open(vault, id, &row.envelope).ok()
    }

    /// Writes `fields` into `id` of `vault` as a local (dirty) edit.
    async fn edit(&self, vault: VaultId, id: ItemId, kind: ItemKind, fields: &[(&str, &str)]) {
        let mut body = self
            .body(vault, id)
            .await
            .unwrap_or_else(|| ItemBody::new(kind, 1));
        {
            let mut clock = self.dev.hlc.lock();
            for (k, v) in fields {
                body.set(k, *v, &mut clock, self.dev.device);
            }
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

    fn label(body: &ItemBody) -> String {
        body.get("label")
            .and_then(|v| v.as_text())
            .unwrap_or_default()
            .to_owned()
    }
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

fn adopted(events: &[SyncEvent], vault: VaultId) -> bool {
    events
        .iter()
        .any(|e| matches!(e, SyncEvent::VaultAdded { vault: v, .. } if *v == vault))
}

async fn spawn_ws(m: &Member) -> (SyncHandle, mpsc::UnboundedReceiver<SyncEvent>) {
    let (e, rx) = m.engine(true).await;
    let h = e.spawn();
    wait_for(WAIT, "engine synced", || {
        let s = h.status();
        async move { s == SyncStatus::Synced }
    })
    .await;
    // Let the WebSocket authenticate.
    tokio::time::sleep(Duration::from_millis(500)).await;
    (h, rx)
}

// Alice (admin) creates a shared vault, grants Bob `write` and Carol
// `read`; both receive it over the WebSocket and decrypt its items.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t01_create_grant_receive() {
    let server = TestServer::start().await;
    let alice = Member::new(&server, "alice@example.test").await;
    let bob = Member::new(&server, "bob@example.test").await;
    let carol = Member::new(&server, "carol@example.test").await;
    let org = org(&alice, &[(&bob, Role::Member), (&carol, Role::Member)]).await;

    let vault = alice.admin.create(org, "Ops").await.unwrap();
    assert!(alice.has_vault(vault).await);
    let host = ItemId::new();
    alice
        .edit(
            vault,
            host,
            ItemKind::Host,
            &[("label", "prod-db"), ("address", "10.0.0.5")],
        )
        .await;
    assert_eq!(alice.sync().await.0, SyncStatus::Synced);
    assert_eq!(server.head(vault), 1);
    // The server holds the creator's self-grant (an HPKE wrap), never the key.
    let (by, wrapped) = server.mem.with_data(|d| {
        let m = d
            .vault_members
            .iter()
            .find(|m| m.vault_id == vault.uuid())
            .unwrap();
        (m.wrapped_by, m.wrapped_vault_key.len())
    });
    assert_eq!(by, alice.id());
    assert!(wrapped > 32);

    let (bob_h, mut bob_rx) = spawn_ws(&bob).await;
    let (carol_h, mut carol_rx) = spawn_ws(&carol).await;
    assert!(!bob.has_vault(vault).await);

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

    for (m, who) in [(&bob, "bob"), (&carol, "carol")] {
        wait_for(WAIT, &format!("{who} decrypts the shared host"), || async {
            m.dev.store.get_item(host).await.unwrap().is_some()
                && m.body(vault, host).await.is_some()
        })
        .await;
        let b = m.body(vault, host).await.unwrap();
        assert_eq!(Member::label(&b), "prod-db");
    }
    let mut events = Vec::new();
    while let Ok(e) = bob_rx.try_recv() {
        events.push(e);
    }
    assert!(adopted(&events, vault), "{events:?}");
    let named = events
        .iter()
        .any(|e| matches!(e, SyncEvent::VaultAdded { name: Some(n), .. } if n == "Ops"));
    assert!(named, "the vault name opens with the key: {events:?}");
    let mut events = Vec::new();
    while let Ok(e) = carol_rx.try_recv() {
        events.push(e);
    }
    assert!(adopted(&events, vault));
    bob_h.shutdown().await;
    carol_h.shutdown().await;
}

// Granting to a member whose key changed on the server is refused
// client-side; the first grant pinned the key on first sight (TOFU).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t02_grant_refused_on_changed_key() {
    let server = TestServer::start().await;
    let alice = Member::new(&server, "alice@example.test").await;
    let bob = Member::new(&server, "bob@example.test").await;
    let org = org(&alice, &[(&bob, Role::Member)]).await;
    let v1 = alice.admin.create(org, "One").await.unwrap();
    let v2 = alice.admin.create(org, "Two").await.unwrap();

    // First sight: Bob's key is pinned and the grant goes through.
    alice
        .admin
        .grant(v1, bob.id(), Permission::Write)
        .await
        .unwrap();
    assert!(
        alice
            .admin
            .trust()
            .pins()
            .await
            .unwrap()
            .get(bob.id())
            .is_some()
    );

    // The server now presents another key for Bob.
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
    let err = alice
        .admin
        .grant(v2, bob.id(), Permission::Write)
        .await
        .unwrap_err();
    assert_eq!(
        err,
        VaultAdminError::Trust(TrustError::KeyChanged(bob.id()))
    );
    assert!(err.to_string().contains("changed"), "{err}");
    // Nothing reached the server.
    let granted = server.mem.with_data(|d| {
        d.vault_members
            .iter()
            .any(|m| m.vault_id == v2.uuid() && m.user_id == bob.id())
    });
    assert!(!granted);
    // Unknown users can't be granted at all (not an org member → 404 on keys).
    let stranger = Member::new(&server, "stranger@example.test").await;
    assert!(
        alice
            .admin
            .grant(v1, stranger.id(), Permission::Read)
            .await
            .is_err()
    );
}

// The server tampers with Bob's grant signature: Bob's client refuses the
// vault key, keeps the vault out, and reports an error.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t03_tampered_grant_refused() {
    let server = TestServer::start().await;
    let alice = Member::new(&server, "alice@example.test").await;
    let bob = Member::new(&server, "bob@example.test").await;
    let org = org(&alice, &[(&bob, Role::Member)]).await;
    let vault = alice.admin.create(org, "Ops").await.unwrap();
    alice
        .admin
        .grant(vault, bob.id(), Permission::Write)
        .await
        .unwrap();
    server.mem.with_data(|d| {
        let row = d
            .vault_members
            .iter_mut()
            .find(|m| m.vault_id == vault.uuid() && m.user_id == bob.id())
            .unwrap();
        row.signature[0] ^= 0x01;
    });

    let (status, events) = bob.sync().await;
    assert!(
        !bob.has_vault(vault).await,
        "the tampered key must not be stored"
    );
    match &status {
        SyncStatus::Error { message } => {
            assert!(message.contains("could not be verified"), "{message}");
        }
        other => panic!("expected an error status, got {other:?}"),
    }
    let toast = events.iter().any(|e| {
        matches!(e, SyncEvent::Toast { level: ToastLevel::Error, message } if message.contains("signature"))
    });
    assert!(toast, "{events:?}");
    assert!(!adopted(&events, vault));

    // A genuine re-grant is accepted on the next refresh.
    alice
        .admin
        .grant(vault, bob.id(), Permission::Write)
        .await
        .unwrap();
    let (status, events) = bob.sync().await;
    assert_eq!(status, SyncStatus::Synced);
    assert!(adopted(&events, vault));
}

// T-04 (sync half): Carol (read) edits locally; the push is refused (403), the
// change stays local and flagged; a forced push through the API is 403.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t04_read_member_cannot_push() {
    let server = TestServer::start().await;
    let alice = Member::new(&server, "alice@example.test").await;
    let carol = Member::new(&server, "carol@example.test").await;
    let org = org(&alice, &[(&carol, Role::Member)]).await;
    let vault = alice.admin.create(org, "Ops").await.unwrap();
    let host = ItemId::new();
    alice
        .edit(vault, host, ItemKind::Host, &[("label", "web")])
        .await;
    assert_eq!(alice.sync().await.0, SyncStatus::Synced);
    alice
        .admin
        .grant(vault, carol.id(), Permission::Read)
        .await
        .unwrap();
    assert_eq!(carol.sync().await.0, SyncStatus::Synced);

    // The permission is kept locally (the UI's "Read-only vault").
    assert_eq!(
        sverb_sync::account::vaults::local_permission(&carol.dev.store, vault)
            .await
            .unwrap(),
        Some(Permission::Read)
    );
    let members = carol.admin.members(vault).await.unwrap();
    let me = members
        .members
        .iter()
        .find(|m| m.user_id == carol.id())
        .unwrap();
    assert_eq!(me.effective(), Some(Permission::Read));

    carol
        .edit(vault, host, ItemKind::Host, &[("label", "hacked")])
        .await;
    let (status, events) = carol.sync().await;
    assert!(
        matches!(&status, SyncStatus::Error { message } if message.contains("read-only")),
        "{status:?}"
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, SyncEvent::ReadOnly { vault: v, .. } if *v == vault)),
        "{events:?}"
    );
    let server_item = server.item(vault, host).unwrap();
    assert_eq!(server_item.revision, 1);

    // A forced push straight through the API.
    let row = carol.dev.store.get_item(host).await.unwrap().unwrap();
    let err = carol
        .tokens
        .api()
        .push(
            &carol.token().await,
            vault.uuid(),
            &sverb_proto::sync::PushRequest {
                changes: vec![sverb_proto::sync::PushChange {
                    id: host.uuid(),
                    base_revision: 1,
                    key_version: 1,
                    envelope: row.envelope,
                    deleted: false,
                }],
            },
        )
        .await
        .unwrap_err();
    assert!(err.is_status(403), "{err:?}");
}

// Moving a personal host that uses a personal identity into a shared
// vault: blocked (the identity is listed); with "also copy the identity" the
// host and an identity copy land in the shared vault (Bob sees them) and the
// personal host is tombstoned.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t06_move_host_with_identity() {
    let server = TestServer::start().await;
    let alice = Member::new(&server, "alice@example.test").await;
    let bob = Member::new(&server, "bob@example.test").await;
    let org = org(&alice, &[(&bob, Role::Member)]).await;
    let shared = alice.admin.create(org, "Ops").await.unwrap();
    alice
        .admin
        .grant(shared, bob.id(), Permission::Write)
        .await
        .unwrap();
    let personal = alice.acct.vault;

    let ident = ItemId::new();
    let host = ItemId::new();
    let mut clock = HlcClock::default();
    let dev = alice.dev.device;
    let mut ib = ItemBody::new(ItemKind::Identity, 1);
    Identity {
        label: "deploy".into(),
        username: "deploy".into(),
        ..Identity::default()
    }
    .apply_to(&mut ib, &mut clock, dev);
    alice.put(personal, ident, &ib).await;
    let mut hb = ItemBody::new(ItemKind::Host, 1);
    Host {
        label: "web".into(),
        address: "web.example".into(),
        identity_id: Some(ident),
        ..Host::default()
    }
    .apply_to(&mut hb, &mut clock, dev);
    alice.put(personal, host, &hb).await;
    assert_eq!(alice.sync().await.0, SyncStatus::Synced);

    let items: BTreeMap<ItemId, (VaultId, &ItemBody)> =
        [(host, (personal, &hb)), (ident, (personal, &ib))].into();
    let blocked = plan_transfer(
        &[host],
        shared,
        VaultScope::Shared,
        TransferMode::Move,
        RefPolicy::Block,
        |id| items.get(&id).copied(),
        ItemId::new,
        &mut clock,
        dev,
    )
    .unwrap_err();
    assert!(blocked.to_string().contains("another vault"), "{blocked}");

    let plan = plan_transfer(
        &[host],
        shared,
        VaultScope::Shared,
        TransferMode::Move,
        RefPolicy::Copy,
        |id| items.get(&id).copied(),
        ItemId::new,
        &mut clock,
        dev,
    )
    .unwrap();
    apply_transfer(&alice.dev.store, &alice.keys().await, shared, &plan)
        .await
        .unwrap();
    assert_eq!(alice.sync().await.0, SyncStatus::Synced);

    let new_host = plan.id_map[&host];
    let new_ident = plan.id_map[&ident];
    // The source host is a tombstone on the server; the identity stays.
    assert!(server.item(personal, host).unwrap().deleted);
    assert!(!server.item(personal, ident).unwrap().deleted);
    // Bob sees the host and the identity copy, rewired.
    assert_eq!(bob.sync().await.0, SyncStatus::Synced);
    let h = Host::try_from(&bob.body(shared, new_host).await.unwrap()).unwrap();
    assert_eq!(h.label, "web");
    assert_eq!(h.identity_id, Some(new_ident));
    let i = Identity::try_from(&bob.body(shared, new_ident).await.unwrap()).unwrap();
    assert_eq!(i.username, "deploy");
}

/// The host `host` of `vault` on `m`'s device, resolved with `m`'s overrides.
async fn resolve_on(m: &Member, vault: VaultId, host: ItemId) -> sverb_core::resolve::ResolvedHost {
    let keys = m.keys().await;
    let mut table = LookupTable::default();
    let mut layers = Vec::new();
    let mut host_view = None;
    for row in m.dev.store.list_all_items().await.unwrap() {
        if row.deleted {
            continue;
        }
        let Ok(body) = keys.open(row.vault_id, row.id, &row.envelope) else {
            continue;
        };
        match body.kind {
            ItemKind::Identity => {
                table.insert_identity(row.id, &Identity::try_from(&body).unwrap())
            }
            ItemKind::CredentialOverride => {
                layers.push(OverrideLayer::new(
                    row.id,
                    &CredentialOverride::try_from(&body).unwrap(),
                ));
            }
            ItemKind::Host if row.id == host => {
                assert_eq!(row.vault_id, vault);
                host_view = Some(Host::try_from(&body).unwrap());
            }
            _ => {}
        }
    }
    let h = host_view.unwrap();
    let mut r = resolve_settings(
        &Target::of(&h),
        &Settings::from_host(&h),
        &table,
        None,
        &GlobalDefaults::default(),
    );
    if let Some(layer) = sverb_core::resolve::overrides::pick_override(host, &layers) {
        apply_override(&mut r, layer, &table);
    }
    r
}

// Bob's override username applies on Bob's device only; Alice still sees
// the shared value. Provenance "(your override)".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t07_credential_override() {
    let server = TestServer::start().await;
    let alice = Member::new(&server, "alice@example.test").await;
    let bob = Member::new(&server, "bob@example.test").await;
    let org = org(&alice, &[(&bob, Role::Member)]).await;
    let shared = alice.admin.create(org, "Ops").await.unwrap();
    let host = ItemId::new();
    alice
        .edit(
            shared,
            host,
            ItemKind::Host,
            &[
                ("label", "db"),
                ("address", "db.example"),
                ("username", "deploy"),
            ],
        )
        .await;
    assert_eq!(alice.sync().await.0, SyncStatus::Synced);
    alice
        .admin
        .grant(shared, bob.id(), Permission::Write)
        .await
        .unwrap();
    assert_eq!(bob.sync().await.0, SyncStatus::Synced);

    // Bob stores his override in his personal vault.
    let mut o = CredentialOverride::new(host);
    o.username = Some("bob".into());
    let item = ItemId::new();
    let body = o.to_body(&mut HlcClock::default(), DeviceId::new());
    bob.put(bob.acct.vault, item, &body).await;
    assert_eq!(bob.sync().await.0, SyncStatus::Synced);
    assert_eq!(alice.sync().await.0, SyncStatus::Synced);

    let rb = resolve_on(&bob, shared, host).await;
    assert_eq!(rb.username.as_deref(), Some("bob"));
    assert_eq!(rb.source(SettingKey::Username), &Source::Override { item });
    assert_eq!(rb.source(SettingKey::Username).to_string(), "your override");
    let ra = resolve_on(&alice, shared, host).await;
    assert_eq!(ra.username.as_deref(), Some("deploy"));
    assert_eq!(ra.source(SettingKey::Username), &Source::Host);
    // The override never left Bob's personal vault.
    assert!(alice.dev.store.get_item(item).await.unwrap().is_none());
    assert!(server.item(shared, item).is_none());
}

// An org admin without a grant ("needs key") is granted `manage` by a
// manage member's reconcile, then adopts the vault.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t09_admin_auto_grant() {
    let server = TestServer::start().await;
    let alice = Member::new(&server, "alice@example.test").await;
    let dave = Member::new(&server, "dave@example.test").await;
    let erin = Member::new(&server, "erin@example.test").await;
    let org = org(&alice, &[(&dave, Role::Admin), (&erin, Role::Member)]).await;
    let vault = alice.admin.create(org, "Ops").await.unwrap();

    let list = dave.admin.org_vaults(org).await.unwrap();
    assert_eq!(list.len(), 1);
    assert!(list[0].needs_key());
    assert_eq!(list[0].view.permission, Permission::Manage);
    assert_eq!(list[0].name, None);
    // A plain member doesn't see it.
    assert!(erin.admin.org_vaults(org).await.unwrap().is_empty());

    let report = alice.admin.reconcile_admins().await.unwrap();
    assert_eq!(report.granted, vec![(vault, dave.id())]);
    assert!(report.skipped.is_empty());
    // Idempotent.
    assert!(
        alice
            .admin
            .reconcile_admins()
            .await
            .unwrap()
            .granted
            .is_empty()
    );

    let (status, events) = dave.sync().await;
    assert_eq!(status, SyncStatus::Synced);
    assert!(adopted(&events, vault));
    let list = dave.admin.org_vaults(org).await.unwrap();
    assert!(!list[0].needs_key());
    assert_eq!(list[0].name.as_deref(), Some("Ops"));
    // Dave now manages: he can grant Erin.
    dave.admin
        .grant(vault, erin.id(), Permission::Read)
        .await
        .unwrap();
}

// T-10 (M5 exit criterion, part): three members: create, grant, edit, sync.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t10_three_member_scenario() {
    let server = TestServer::start().await;
    let alice = Member::new(&server, "alice@example.test").await;
    let bob = Member::new(&server, "bob@example.test").await;
    let carol = Member::new(&server, "carol@example.test").await;
    let org = org(&alice, &[(&bob, Role::Member), (&carol, Role::Member)]).await;
    let vault = alice.admin.create(org, "Team").await.unwrap();
    alice
        .admin
        .grant(vault, bob.id(), Permission::Write)
        .await
        .unwrap();
    alice
        .admin
        .grant(vault, carol.id(), Permission::Write)
        .await
        .unwrap();

    let h1 = ItemId::new();
    alice
        .edit(
            vault,
            h1,
            ItemKind::Host,
            &[("label", "one"), ("address", "a")],
        )
        .await;
    assert_eq!(alice.sync().await.0, SyncStatus::Synced);
    assert_eq!(bob.sync().await.0, SyncStatus::Synced);
    assert_eq!(carol.sync().await.0, SyncStatus::Synced);

    // Bob and Carol edit different fields of the same host; Carol adds one.
    bob.edit(vault, h1, ItemKind::Host, &[("label", "one-renamed")])
        .await;
    carol
        .edit(vault, h1, ItemKind::Host, &[("address", "b.example")])
        .await;
    let h2 = ItemId::new();
    carol
        .edit(vault, h2, ItemKind::Host, &[("label", "two")])
        .await;
    assert_eq!(bob.sync().await.0, SyncStatus::Synced);
    assert_eq!(carol.sync().await.0, SyncStatus::Synced);
    for m in [&alice, &bob, &carol] {
        assert_eq!(m.sync().await.0, SyncStatus::Synced);
    }
    for m in [&alice, &bob, &carol] {
        let b = m.body(vault, h1).await.unwrap();
        assert_eq!(Member::label(&b), "one-renamed");
        assert_eq!(b.get("address").unwrap().as_text(), Some("b.example"));
        assert_eq!(Member::label(&m.body(vault, h2).await.unwrap()), "two");
    }
    // Personal vaults stay personal.
    assert!(
        bob.dev
            .store
            .get_vault(alice.acct.vault)
            .await
            .unwrap()
            .is_none()
    );
}
