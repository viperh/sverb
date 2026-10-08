//! M4-08 integration tests: the account flows against the in-process
//! `sverb-server` (in-memory backend) on loopback, with real client stores.
//!
//! T-11 (CLI, non-TTY `sverb register`) lives in `crates/sverb/src/cli/tests.rs`;
//! T-03 (reducer) in `src/account/wizard.rs`. T-12 runs on the in-memory
//! backend's full state dump (no PostgreSQL / `pg_dump` here).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use common::{TestServer, raw_refresh, wait_for};
use parking_lot::Mutex;
use sverb_core::model::{DeviceId, HlcClock, ItemBody, ItemId, ItemKind, VaultId};
use sverb_core::vault::Argon2Cost;
use sverb_crypto::Key32;
use sverb_crypto::envelope::{open_item, seal_item};
use sverb_crypto::kdf::argon2id;
use sverb_crypto::opaque::SverbKsf;
use sverb_crypto::random::{os_rng, random_key32, random_salt16};
use sverb_crypto::wrap::{WrapPurpose, unwrap_key, unwrap_key32, wrap_key};
use sverb_proto::auth::DeviceInfo;
use sverb_store::meta::keys;
use sverb_store::{Store, SystemClock, VaultKind};
use sverb_sync::account::local::try_local_password;
use sverb_sync::account::{
    AccountConfig, AccountError, DuplicateChoice, LoginRequest, finish_registration, load_account,
    load_account_keys, logout, prepare_registration, recover_account, start_login,
};
use sverb_sync::{EngineConfig, SyncEngine, SyncStatus, shared_hlc};
use zeroize::Zeroizing;

const PW: &str = "Tangerine-Quokka-Velvet-93";
const PW2: &str = "Saffron-Glacier-Mosaic-41";
const PW3: &str = "Obsidian-Lantern-Harbor-77";

fn cfg(name: &str) -> AccountConfig {
    AccountConfig {
        ksf: Arc::new(SverbKsf::insecure_for_tests()),
        kdf_cost: Argon2Cost::TEST,
        device: DeviceInfo {
            name: name.into(),
            platform: "linux".into(),
        },
        tls: None,
        http_timeout: Duration::from_secs(30),
    }
}

/// A device initialized like M1-04 first run (master password, LMK,
/// personal vault, device id).
struct Local {
    _dir: tempfile::TempDir,
    store: Store,
    lmk: Key32,
    vault: VaultId,
    device: DeviceId,
    hlc: Mutex<HlcClock>,
}

impl Local {
    async fn init(password: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open_at(dir.path().join("sverb.db"), Arc::new(SystemClock)).unwrap();
        let mut rng = os_rng();
        let lmk = random_key32(&mut rng);
        let params = Argon2Cost::TEST.with_salt(random_salt16(&mut rng));
        let kek = argon2id(password.as_bytes(), &params.argon2()).unwrap();
        let lmk_pw = wrap_key(&kek, &WrapPurpose::Lmk, lmk.expose_secret(), &mut rng).unwrap();
        let vault = VaultId::new();
        let vk = random_key32(&mut rng);
        let wrapped = wrap_key(
            &lmk,
            &WrapPurpose::VaultKey(*vault.as_bytes()),
            vk.expose_secret(),
            &mut rng,
        )
        .unwrap();
        let device = DeviceId::new();
        let kdf = params.to_cbor();
        store
            .write(move |w| {
                w.set_meta(keys::KDF, &kdf)?;
                w.set_meta(keys::LMK_WRAPPED_PW, &lmk_pw)?;
                w.set_meta(keys::DEVICE_ID, device.as_bytes())?;
                w.create_vault(vault, VaultKind::Personal, None, 1, &wrapped)
            })
            .await
            .unwrap();
        Self {
            _dir: dir,
            store,
            lmk,
            vault,
            device,
            hlc: Mutex::new(HlcClock::default()),
        }
    }

    /// The current personal vault (it changes after an importing login).
    async fn personal(&self) -> (VaultId, Key32, u32) {
        let row = self
            .store
            .list_vaults()
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.kind == VaultKind::Personal)
            .unwrap();
        let vk = unwrap_key32(
            &self.lmk,
            &WrapPurpose::VaultKey(*row.id.as_bytes()),
            &row.wrapped_key,
        )
        .unwrap();
        (row.id, vk, row.key_version)
    }

    async fn put(&self, id: ItemId, kind: ItemKind, fields: &[(&str, ciborium::Value)]) {
        let (vault, vk, kv) = self.personal().await;
        let mut body = ItemBody::new(kind, 1);
        {
            let mut clock = self.hlc.lock();
            for (k, v) in fields {
                body.set(k, v.clone(), &mut clock, self.device);
            }
        }
        let env = seal_item(
            &vk,
            vault.as_bytes(),
            id.as_bytes(),
            kv,
            &body.to_cbor().unwrap(),
            &mut os_rng(),
        )
        .unwrap();
        self.store
            .put_item(vault, id, kv, env, false, true)
            .await
            .unwrap();
    }

    async fn host(&self, label: &str, addr: &str, user: &str) -> ItemId {
        let id = ItemId::new();
        self.put(
            id,
            ItemKind::Host,
            &[
                ("label", label.into()),
                ("address", addr.into()),
                ("username", user.into()),
            ],
        )
        .await;
        id
    }

    /// Every live item of the personal vault, decrypted.
    async fn items(&self) -> BTreeMap<ItemId, ItemBody> {
        let (vault, vk, _) = self.personal().await;
        self.store
            .list_items(vault)
            .await
            .unwrap()
            .into_iter()
            .filter(|r| !r.deleted)
            .map(|r| {
                let plain = open_item(
                    |_| Some(&vk),
                    vault.as_bytes(),
                    r.id.as_bytes(),
                    &r.envelope,
                )
                .unwrap();
                (r.id, ItemBody::from_cbor(&plain).unwrap())
            })
            .collect()
    }

    async fn kdf(&self) -> Vec<u8> {
        self.store.get_meta(keys::KDF).await.unwrap().unwrap()
    }

    async fn unlocks_with(&self, password: &str) -> bool {
        try_local_password(&self.store, password)
            .await
            .unwrap()
            .is_some_and(|k| k == self.lmk)
    }

    async fn engine(&self) -> SyncEngine {
        self.engine_with(false).await
    }

    async fn engine_with(&self, websocket: bool) -> SyncEngine {
        let src = load_account_keys(&self.store, &self.lmk)
            .await
            .unwrap()
            .map(|(a, k)| sverb_sync::account::GrantKeySource::new(a.user_id, k))
            .unwrap();
        SyncEngine::new(
            self.store.clone(),
            self.lmk.clone(),
            shared_hlc(HlcClock::default()),
            Arc::new(src),
            EngineConfig {
                websocket,
                ..EngineConfig::default()
            },
            None,
        )
        .await
        .unwrap()
    }

    async fn sync(&self) -> SyncStatus {
        self.engine().await.sync_once().await
    }

    async fn refresh_token(&self) -> String {
        let enc = self
            .store
            .get_sync_state()
            .await
            .unwrap()
            .unwrap()
            .tokens_enc
            .unwrap();
        let plain = unwrap_key(&self.lmk, &WrapPurpose::SyncTokens, &enc).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&plain).unwrap();
        v["refresh_token"].as_str().unwrap().to_owned()
    }
}

fn req(server: &TestServer, email: &str, password: &str) -> LoginRequest {
    LoginRequest {
        server_url: server.url(),
        email: email.into(),
        password: Zeroizing::new(password.into()),
        totp: None,
    }
}

/// Registers `dev` (its current master password is `password`). Returns the
/// recovery phrase.
async fn register(server: &TestServer, dev: &Local, email: &str, password: &str) -> String {
    let c = cfg("laptop");
    let prepared = prepare_registration(&dev.store, &server.url(), email, password, &c)
        .await
        .unwrap();
    assert_eq!(prepared.recovery_words().len(), 24);
    let phrase = prepared.recovery_phrase().to_string();
    finish_registration(&dev.store, &prepared, None, &c)
        .await
        .unwrap();
    phrase
}

/// A fresh device (§2.3: local vault initialized with the account password)
/// logged in to the account.
async fn fresh_login(server: &TestServer, email: &str, password: &str) -> Local {
    let dev = Local::init(password).await;
    let session = start_login(
        &dev.store,
        &dev.lmk,
        &req(server, email, password),
        &cfg("phone"),
    )
    .await
    .unwrap();
    assert!(!session.password_differs());
    assert_eq!(session.preview().duplicates.len(), 0);
    session.commit(&dev.store).await.unwrap();
    dev
}

fn server_count(server: &TestServer, vault: VaultId) -> usize {
    server.mem.with_data(|d| {
        d.items
            .iter()
            .filter(|((v, _), it)| *v == vault.uuid() && !it.deleted)
            .count()
    })
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

// T-01 (M4 exit criterion) + T-12: register from local-only with 500 items;
// the server gets the same ids, a second device sees them identically, and
// the server holds no plaintext.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t01_t12_register_500_items_then_second_device() {
    let server = TestServer::start().await;
    let a = Local::init(PW).await;
    let mut ids = Vec::new();
    for i in 0..500 {
        let id = ItemId::new();
        a.put(
            id,
            ItemKind::Host,
            &[
                ("label", format!("canary-label-{i:03}").into()),
                ("address", format!("canary-host-{i:03}.example").into()),
                ("password", format!("canary-secret-{i:03}").into()),
            ],
        )
        .await;
        ids.push(id);
    }
    let before = a.items().await;
    register(&server, &a, "five@example.test", PW).await;
    assert_eq!(a.personal().await.0, a.vault, "same vault id");
    assert_eq!(a.store.pending_count().await.unwrap(), 500);
    assert_eq!(a.sync().await, SyncStatus::Synced);
    assert_eq!(a.store.pending_count().await.unwrap(), 0);
    assert_eq!(server_count(&server, a.vault), 500);
    for id in &ids {
        assert!(
            server.item(a.vault, *id).is_some(),
            "same item ids on the server"
        );
    }

    let b = fresh_login(&server, "five@example.test", PW).await;
    assert_eq!(b.personal().await.0, a.vault);
    assert_eq!(b.sync().await, SyncStatus::Synced);
    assert_eq!(b.items().await, before, "decrypted identically");

    // T-12: no plaintext anywhere on the server.
    let dump = server.mem.with_data(|d| format!("{d:?}"));
    let blobs: Vec<Vec<u8>> = server.mem.with_data(|d| {
        d.items
            .values()
            .map(|i| i.envelope.clone())
            .chain(d.vaults.values().map(|v| format!("{v:?}").into_bytes()))
            .collect()
    });
    let requests: Vec<String> = server
        .requests
        .lock()
        .iter()
        .map(|r| r.body.clone())
        .collect();
    for i in [0, 1, 250, 499] {
        for canary in [
            format!("canary-label-{i:03}"),
            format!("canary-host-{i:03}"),
            format!("canary-secret-{i:03}"),
        ] {
            assert!(!dump.contains(&canary), "{canary} in the server state");
            assert!(
                !blobs.iter().any(|b| contains(b, canary.as_bytes())),
                "{canary} in a blob"
            );
            assert!(
                !requests.iter().any(|r| r.contains(&canary)),
                "{canary} sent in clear"
            );
        }
    }
    assert!(!dump.contains(PW) && !requests.iter().any(|r| r.contains(PW)));
}

// T-02: registration uses the existing master password; local unlock is
// unchanged (same `meta.kdf`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t02_register_keeps_the_master_password() {
    let server = TestServer::start().await;
    let a = Local::init(PW).await;
    let kdf = a.kdf().await;
    let c = cfg("laptop");
    let wrong = prepare_registration(&a.store, &server.url(), "t02@example.test", PW2, &c).await;
    assert_eq!(wrong.unwrap_err(), AccountError::WrongLocalPassword);
    register(&server, &a, "t02@example.test", PW).await;
    assert!(a.unlocks_with(PW).await);
    assert_eq!(a.kdf().await, kdf, "meta.kdf unchanged");
    let acct = load_account(&a.store).await.unwrap().unwrap();
    assert_eq!(acct.email, "t02@example.test");
    assert_eq!(acct.key_version, 1);
}

// T-04: login with a different local password → warning, then the local
// unlock needs the account password.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t04_login_adopts_the_account_password() {
    let server = TestServer::start().await;
    let a = Local::init(PW).await;
    register(&server, &a, "t04@example.test", PW).await;
    let b = Local::init(PW2).await;
    b.host("mine", "mine.example", "me").await;
    let session = start_login(
        &b.store,
        &b.lmk,
        &req(&server, "t04@example.test", PW),
        &cfg("b"),
    )
    .await
    .unwrap();
    assert!(session.password_differs(), "the warning is shown");
    assert!(b.unlocks_with(PW2).await, "nothing changed before commit");
    let done = session.commit(&b.store).await.unwrap();
    assert!(done.password_changed);
    assert!(b.unlocks_with(PW).await);
    assert!(!b.unlocks_with(PW2).await);
    let wrong = start_login(
        &b.store,
        &b.lmk,
        &req(&server, "t04@example.test", PW2),
        &cfg("b"),
    )
    .await;
    assert_eq!(wrong.unwrap_err(), AccountError::LoginFailed);
}

/// T-05 / T-06 setup: an account with 2 hosts; a local device with 10 hosts
/// (2 duplicates of the account's) referencing a local group and identity.
struct ImportFixture {
    server: TestServer,
    b: Local,
    old_vault: VaultId,
    group: ItemId,
    identity: ItemId,
    touched: ItemId,
}

async fn import_fixture(email: &str) -> ImportFixture {
    let server = TestServer::start().await;
    let a = Local::init(PW).await;
    a.host("db", "db.example.com", "root").await;
    a.host("web", "web.example.com", "deploy").await;
    register(&server, &a, email, PW).await;
    assert_eq!(a.sync().await, SyncStatus::Synced);

    let b = Local::init(PW).await;
    let group = ItemId::new();
    b.put(group, ItemKind::Group, &[("name", "prod".into())])
        .await;
    let identity = ItemId::new();
    b.put(
        identity,
        ItemKind::Identity,
        &[("label", "ops".into()), ("username", "ops".into())],
    )
    .await;
    let mut hosts = Vec::new();
    for (label, addr, user) in [
        ("db-local", "DB.example.com", "root"),
        ("web-local", "web.example.com", "deploy"),
    ] {
        hosts.push(b.host(label, addr, user).await);
    }
    for i in 0..8 {
        let id = ItemId::new();
        b.put(
            id,
            ItemKind::Host,
            &[
                ("label", format!("h{i}").into()),
                ("address", format!("h{i}.example").into()),
                ("group_id", group.into()),
                ("identity_id", identity.into()),
            ],
        )
        .await;
        hosts.push(id);
    }
    let touched = hosts[5];
    b.store.touch_connected(touched, 1_000).await.unwrap();
    let old_vault = b.vault;
    ImportFixture {
        server,
        b,
        old_vault,
        group,
        identity,
        touched,
    }
}

// T-05: preview shows 2 likely duplicates; "keep account" → 8 hosts (plus
// their group and identity) imported with new ids, references remapped,
// frecency kept, the old local vault deleted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t05_login_imports_local_items_with_preview() {
    let f = import_fixture("t05@example.test").await;
    let b = &f.b;
    let mut session = start_login(
        &b.store,
        &b.lmk,
        &req(&f.server, "t05@example.test", PW),
        &cfg("b"),
    )
    .await
    .unwrap();
    assert!(session.will_import());
    assert_eq!(session.preview().duplicates.len(), 2);
    assert_eq!(session.preview().new_items, 10);
    session.preview_mut().set_all(DuplicateChoice::KeepAccount);
    assert_eq!(session.preview().imported_count(), 10);
    let account_vault = session.account_vault();
    assert_ne!(account_vault, f.old_vault);
    let done = session.commit(&b.store).await.unwrap();
    assert_eq!(done.imported, 10);
    assert_eq!(done.replaced_vault, Some(f.old_vault));
    assert!(
        b.store.get_vault(f.old_vault).await.unwrap().is_none(),
        "old vault deleted"
    );

    let items = b.items().await;
    assert_eq!(
        items.len(),
        12,
        "2 account hosts + 8 hosts + group + identity"
    );
    assert!(
        !items.contains_key(&f.group) && !items.contains_key(&f.identity),
        "new ids"
    );
    let group = items
        .iter()
        .find(|(_, b)| b.kind == ItemKind::Group)
        .map(|(id, _)| *id)
        .unwrap();
    let identity = items
        .iter()
        .find(|(_, b)| b.kind == ItemKind::Identity)
        .map(|(id, _)| *id)
        .unwrap();
    let referencing: Vec<_> = items
        .values()
        .filter(|b| b.get("group_id").is_some())
        .collect();
    assert_eq!(referencing.len(), 8);
    for h in referencing {
        assert_eq!(h.get("group_id"), Some(&ciborium::Value::from(group)));
        assert_eq!(h.get("identity_id"), Some(&ciborium::Value::from(identity)));
    }
    let locals = b.store.list_device_local().await.unwrap();
    assert_eq!(locals.len(), 1);
    assert!(
        items.contains_key(&locals[0].item_id),
        "frecency moved to the new id"
    );
    assert_ne!(locals[0].item_id, f.touched);

    assert_eq!(b.sync().await, SyncStatus::Synced);
    assert_eq!(server_count(&f.server, account_vault), 12);
}

// T-06: a crash during the import transaction leaves the local vault intact;
// a retry succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t06_crash_during_import_then_retry() {
    let f = import_fixture("t06@example.test").await;
    let b = &f.b;
    let before = b.items().await;
    let kdf = b.kdf().await;
    let mut session = start_login(
        &b.store,
        &b.lmk,
        &req(&f.server, "t06@example.test", PW),
        &cfg("b"),
    )
    .await
    .unwrap();
    let account_vault = session.account_vault();
    session.set_crash_after(Some(3));
    let session = Arc::new(session);
    let (s2, store) = (session.clone(), b.store.clone());
    let res = tokio::spawn(async move { s2.commit(&store).await }).await;
    assert!(res.unwrap_err().is_panic(), "the injected crash panics");
    let mut session = Arc::try_unwrap(session).unwrap();
    assert_eq!(b.personal().await.0, f.old_vault);
    assert_eq!(b.items().await, before, "local vault intact");
    assert!(b.store.get_vault(account_vault).await.unwrap().is_none());
    assert!(b.store.get_sync_state().await.unwrap().is_none());
    assert!(load_account(&b.store).await.unwrap().is_none());
    assert_eq!(b.kdf().await, kdf);
    assert_eq!(
        b.store.list_device_local().await.unwrap()[0].item_id,
        f.touched
    );

    session.set_crash_after(None);
    let done = session.commit(&b.store).await.unwrap();
    assert_eq!(done.imported, 12, "keep both (default) for the duplicates");
    assert_eq!(b.items().await.len(), 14);
    assert_eq!(b.sync().await, SyncStatus::Synced);
    assert_eq!(server_count(&f.server, account_vault), 14);
}

// T-07: online password change. The old password stops working; device B
// gets `account_changed` → NeedsLogin, still unlocks with the old password,
// and after logging in with the new one syncs and unlocks with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t07_online_password_change() {
    let server = TestServer::start().await;
    let a = Local::init(PW).await;
    a.host("db", "db.example.com", "root").await;
    register(&server, &a, "t07@example.test", PW).await;
    assert_eq!(a.sync().await, SyncStatus::Synced);
    let b = fresh_login(&server, "t07@example.test", PW).await;
    let handle = b.engine_with(true).await.spawn();
    let mut status = handle.subscribe();
    wait_for(Duration::from_secs(10), "B synced", || {
        let s = handle.status();
        async move { s == SyncStatus::Synced }
    })
    .await;
    // Let the WebSocket connect.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let v = sverb_sync::account::change_password(&a.store, &a.lmk, PW, PW2, None, &cfg("a"))
        .await
        .unwrap();
    assert_eq!(v, 2);
    assert!(a.unlocks_with(PW2).await && !a.unlocks_with(PW).await);
    assert_eq!(
        load_account(&a.store).await.unwrap().unwrap().key_version,
        2
    );
    assert_eq!(
        a.sync().await,
        SyncStatus::Synced,
        "the changing device stays signed in"
    );

    let c = Local::init(PW).await;
    let old = start_login(
        &c.store,
        &c.lmk,
        &req(&server, "t07@example.test", PW),
        &cfg("c"),
    )
    .await;
    assert_eq!(
        old.unwrap_err(),
        AccountError::LoginFailed,
        "old password fails"
    );

    tokio::time::timeout(Duration::from_secs(10), async {
        while *status.borrow_and_update() != SyncStatus::NeedsLogin {
            status.changed().await.unwrap();
        }
    })
    .await
    .expect("B gets account_changed → NeedsLogin");
    handle.shutdown().await;
    assert!(
        b.unlocks_with(PW).await,
        "B still unlocks offline with the old password"
    );

    let session = start_login(
        &b.store,
        &b.lmk,
        &req(&server, "t07@example.test", PW2),
        &cfg("b"),
    )
    .await
    .unwrap();
    assert!(!session.will_import());
    assert!(session.password_differs());
    session.commit(&b.store).await.unwrap();
    assert_eq!(b.sync().await, SyncStatus::Synced);
    assert!(b.unlocks_with(PW2).await && !b.unlocks_with(PW).await);
    assert_eq!(b.items().await, a.items().await);
}

// T-08: a password change with the server unreachable is refused, and
// nothing changes locally.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t08_password_change_needs_the_server() {
    let server = TestServer::start().await;
    let a = Local::init(PW).await;
    register(&server, &a, "t08@example.test", PW).await;
    server.stop().await;
    let err = sverb_sync::account::change_password(&a.store, &a.lmk, PW, PW2, None, &cfg("a"))
        .await
        .unwrap_err();
    match &err {
        AccountError::Unreachable(m) => {
            assert!(
                m.contains(sverb_sync::account::password::NEEDS_SERVER),
                "{m}"
            );
        }
        other => panic!("expected Unreachable, got {other:?}"),
    }
    assert!(a.unlocks_with(PW).await && !a.unlocks_with(PW2).await);
    assert_eq!(
        load_account(&a.store).await.unwrap().unwrap().key_version,
        1
    );
}

// T-09: recovery with the 24 words → login with the new password works and
// the data is intact.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t09_recovery_resets_the_password() {
    let server = TestServer::start().await;
    let a = Local::init(PW).await;
    a.host("db", "db.example.com", "root").await;
    a.host("web", "web.example.com", "deploy").await;
    let email = "t09@example.test";
    let phrase = register(&server, &a, email, PW).await;
    assert_eq!(a.sync().await, SyncStatus::Synced);
    let data = a.items().await;

    let code = sverb_server::routes::account::issue_recovery_code(
        server.state.auth().store(),
        email,
        server.clock_now(),
    )
    .await
    .unwrap()
    .unwrap();
    let c = cfg("a");
    // A phrase of another account is refused.
    let (_, other) = sverb_crypto::recovery::recovery_key_generate(&mut os_rng());
    let bad = recover_account(&server.url(), email, &code, &other.phrase(), PW3, &c).await;
    assert!(
        matches!(bad, Err(AccountError::BadRecoveryPhrase(_))),
        "{bad:?}"
    );
    let wrong_code = recover_account(&server.url(), email, "nope", &phrase, PW3, &c).await;
    assert_eq!(wrong_code.unwrap_err(), AccountError::BadRecoveryCode);

    let r = recover_account(&server.url(), email, &code, &phrase, PW3, &c)
        .await
        .unwrap();
    assert_eq!(r.key_version, 2);
    let old = start_login(&a.store, &a.lmk, &req(&server, email, PW), &c).await;
    assert_eq!(old.unwrap_err(), AccountError::LoginFailed);

    // This device (unlocked, e.g. by the keyring) signs in with the new
    // password; the LMK is re-wrapped under it.
    let s = start_login(&a.store, &a.lmk, &req(&server, email, PW3), &c)
        .await
        .unwrap();
    assert!(s.password_differs() && !s.will_import());
    s.commit(&a.store).await.unwrap();
    assert!(a.unlocks_with(PW3).await);
    assert_eq!(a.sync().await, SyncStatus::Synced);
    assert_eq!(a.items().await, data);

    let n = fresh_login(&server, email, PW3).await;
    assert_eq!(n.items().await, data, "data intact on a new device");
}

// T-10: `logout --keep-local`: tokens revoked server-side, shared vaults
// removed, personal items kept; a later login re-syncs without duplicates.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t10_logout_keep_local() {
    let server = TestServer::start().await;
    let a = Local::init(PW).await;
    for i in 0..5 {
        a.host(&format!("h{i}"), &format!("h{i}.example"), "u")
            .await;
    }
    register(&server, &a, "t10@example.test", PW).await;
    assert_eq!(a.sync().await, SyncStatus::Synced);
    let data = a.items().await;

    // Fixture: a shared vault on this device.
    let shared = VaultId::new();
    let svk = random_key32(&mut os_rng());
    let wrapped = wrap_key(
        &a.lmk,
        &WrapPurpose::VaultKey(*shared.as_bytes()),
        svk.expose_secret(),
        &mut os_rng(),
    )
    .unwrap();
    a.store
        .create_vault(shared, VaultKind::Shared, None, 1, wrapped)
        .await
        .unwrap();
    let sid = ItemId::new();
    let mut body = ItemBody::new(ItemKind::Host, 1);
    body.set("label", "team", &mut HlcClock::default(), a.device);
    let env = seal_item(
        &svk,
        shared.as_bytes(),
        sid.as_bytes(),
        1,
        &body.to_cbor().unwrap(),
        &mut os_rng(),
    )
    .unwrap();
    a.store
        .put_item(shared, sid, 1, env, false, false)
        .await
        .unwrap();

    let refresh = a.refresh_token().await;
    let report = logout(&a.store, &a.lmk, &cfg("a")).await.unwrap();
    assert!(report.revoked, "{report:?}");
    assert_eq!(report.shared_removed, 1);
    assert_eq!(report.kept_items, 5);
    let (st, _) = raw_refresh(&server, &refresh).await;
    assert_eq!(st, 401, "tokens revoked server-side");
    assert!(a.store.get_vault(shared).await.unwrap().is_none());
    assert!(a.store.get_item(sid).await.unwrap().is_none());
    assert!(a.store.get_sync_state().await.unwrap().is_none());
    assert!(load_account(&a.store).await.unwrap().is_none());
    assert_eq!(a.items().await, data, "personal items intact");
    assert_eq!(
        a.store.pending_count().await.unwrap(),
        5,
        "queued for a later upload"
    );
    assert!(a.unlocks_with(PW).await);

    let s = start_login(
        &a.store,
        &a.lmk,
        &req(&server, "t10@example.test", PW),
        &cfg("a"),
    )
    .await
    .unwrap();
    assert!(!s.will_import());
    s.commit(&a.store).await.unwrap();
    assert_eq!(a.sync().await, SyncStatus::Synced);
    assert_eq!(a.store.pending_count().await.unwrap(), 0);
    assert_eq!(
        server_count(&server, a.vault),
        5,
        "no duplicates on the server"
    );
    assert_eq!(a.items().await, data, "no duplicates locally");
}

// §2.1.7: a server that is not `open` asks for an invite.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn register_needs_an_invite_on_a_closed_server() {
    let server = TestServer::start().await;
    server.mem.with_data(|d| {
        d.registration_mode = sverb_server::registration::RegistrationMode::InviteOnly;
    });
    let a = Local::init(PW).await;
    let c = cfg("a");
    let p = prepare_registration(&a.store, &server.url(), "inv@example.test", PW, &c)
        .await
        .unwrap();
    let err = finish_registration(&a.store, &p, None, &c)
        .await
        .unwrap_err();
    assert!(matches!(err, AccountError::InviteRequired(_)), "{err:?}");
    assert!(a.store.get_sync_state().await.unwrap().is_none());
    assert_eq!(a.store.pending_count().await.unwrap(), 0);
}

// M4-09 T-07 (logic): two logins give two devices; revoking the other one
// works; revoking this device logs it out locally. Also the local status
// (`sverb sync --status`, the Settings → Sync panel).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m4_09_devices_list_revoke_and_local_info() {
    use sverb_sync::account::{Revoked, list_devices, revoke_device};

    let server = TestServer::start().await;
    let a = Local::init(PW).await;
    a.host("h0", "h0.example", "u").await;

    // Local-only: no server, nothing signed in.
    let info = sverb_sync::local_info(&a.store).await.unwrap();
    assert!(!info.connected());
    assert!(!info.signed_in);
    assert_eq!(info.last_sync_ms, None);
    assert!(matches!(
        list_devices(&a.store, &a.lmk, &cfg("a")).await,
        Err(AccountError::NotSignedIn)
    ));

    register(&server, &a, "m409@example.test", PW).await;
    let info = sverb_sync::local_info(&a.store).await.unwrap();
    assert_eq!(info.server_url.as_deref(), Some(server.url().as_str()));
    assert!(info.signed_in);
    assert_eq!(info.email.as_deref(), Some("m409@example.test"));
    assert_eq!(info.pending_total(), 1, "queued until the first sync");
    assert_eq!(info.pending[0].vault, a.vault);
    assert_eq!(info.pending[0].kind, Some(VaultKind::Personal));
    assert_eq!(a.sync().await, SyncStatus::Synced);
    let info = sverb_sync::local_info(&a.store).await.unwrap();
    assert!(info.last_sync_ms.is_some_and(|t| t > 0));
    assert_eq!(info.pending_total(), 0);

    let b = fresh_login(&server, "m409@example.test", PW).await;
    let list = list_devices(&a.store, &a.lmk, &cfg("a")).await.unwrap();
    assert_eq!(list.len(), 2, "{list:?}");
    assert!(list[0].current, "this device first");
    assert!(!list[1].current);
    let other = list[1].id;
    let from_b = list_devices(&b.store, &b.lmk, &cfg("b")).await.unwrap();
    assert_eq!(from_b[0].id, other, "b sees itself as current");

    // Revoke b from a.
    assert_eq!(
        revoke_device(&a.store, &a.lmk, &cfg("a"), other)
            .await
            .unwrap(),
        Revoked::Other
    );
    let list = list_devices(&a.store, &a.lmk, &cfg("a")).await.unwrap();
    assert_eq!(list.len(), 1);
    assert!(
        list_devices(&b.store, &b.lmk, &cfg("b")).await.is_err(),
        "b's tokens are gone"
    );

    // Revoke a itself: logged out, personal data kept.
    let me = list[0].id;
    let r = revoke_device(&a.store, &a.lmk, &cfg("a"), me)
        .await
        .unwrap();
    assert!(
        matches!(r, Revoked::ThisDevice(ref rep) if rep.kept_items == 1),
        "{r:?}"
    );
    assert!(a.store.get_sync_state().await.unwrap().is_none());
    assert!(!sverb_sync::local_info(&a.store).await.unwrap().connected());
}
