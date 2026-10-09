//! M1-04 integration tests for the vault engine and service (T-01, T-03, T-04, T-06,
//! T-07, T-08, T-09, T-13, T-14, T-15, T-17, T-18). Small Argon2 parameters
//! (`Argon2Cost::TEST`) and an in-memory keyring: the OS keyring is never touched.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sverb_core::model::{HlcClock, ItemBody, ItemId, ItemKind};
use sverb_core::vault::{Argon2Cost, KdfParams, MemKeyring, VaultError};
use sverb_store::meta::keys;
use sverb_store::{ManualClock, Store, SyncState, VaultKind};
use sverb_tui::app::{UiEvent, UnlockRequest, VaultEffect, VaultEvent, VaultPassword};
use sverb_tui::services::vault::{UnlockMethod, VaultEngine, VaultService};

const PW: &str = "correct horse battery staple violin";
const PW2: &str = "tangerine submarine quietly orbits jupiter";
const T0: i64 = 1_800_000_000_000;

fn temp_dir(tag: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "m1-04-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Fixture {
    dir: PathBuf,
    clock: Arc<ManualClock>,
    keyring: MemKeyring,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        Self {
            dir: temp_dir(tag),
            clock: Arc::new(ManualClock::new(T0)),
            keyring: MemKeyring::new(),
        }
    }

    fn db(&self) -> PathBuf {
        self.dir.join("sverb.db")
    }

    /// A fresh store connection and engine (like a process restart).
    fn engine(&self) -> VaultEngine {
        let store = Store::open_at(self.db(), self.clock.clone()).unwrap();
        VaultEngine::new(store, Arc::new(self.keyring.clone()), Argon2Cost::TEST)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn wrong_password(err: &VaultError) -> Option<u32> {
    match err {
        VaultError::WrongPassword { failures, .. } => Some(*failures),
        _ => None,
    }
}

async fn meta(store: &Store, key: &str) -> Option<Vec<u8>> {
    store.get_meta(key).await.unwrap()
}

fn read_all(dir: &Path) -> Vec<u8> {
    let mut all = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            all.extend(std::fs::read(&path).unwrap());
        }
    }
    all
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// T-01
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t01_first_run_creates_meta_vault_and_device() {
    let fx = Fixture::new("t01");
    let engine = fx.engine();
    assert!(!engine.status().await.unwrap().initialized);
    let init = engine.initialize(PW, false).await.unwrap();
    assert!(init.keyring_error.is_none());
    let store = engine.store();
    let kdf = KdfParams::from_cbor(&meta(store, keys::KDF).await.unwrap()).unwrap();
    assert_eq!(kdf.cost(), Argon2Cost::TEST);
    assert!(meta(store, keys::LMK_WRAPPED_PW).await.is_some());
    assert!(meta(store, keys::LMK_WRAPPED_KEYRING).await.is_none());
    assert_eq!(
        meta(store, keys::DEVICE_ID).await.map(|d| d.len()),
        Some(16)
    );
    assert!(meta(store, keys::DB_ID).await.is_some());
    assert!(meta(store, keys::HLC_LAST).await.is_some());
    let vaults = store.list_vaults().await.unwrap();
    assert_eq!(vaults.len(), 1);
    assert_eq!(vaults[0].kind, VaultKind::Personal);
    assert_eq!(vaults[0].key_version, 1);
    assert_eq!(init.vault.personal_vault(), Some(vaults[0].id));
    assert_eq!(init.vault.method(), UnlockMethod::Created);

    // No plaintext LMK anywhere in the database files (db, -wal, -shm).
    let lmk = init.vault.lmk().expose_secret().to_vec();
    assert!(!contains(&read_all(&fx.dir), &lmk));

    // A second first run is refused.
    assert_eq!(
        engine.initialize(PW, false).await.err(),
        Some(VaultError::AlreadyInitialized)
    );
    // Weak passwords never reach Argon2.
    let fx2 = Fixture::new("t01-weak");
    let e2 = fx2.engine();
    assert!(matches!(
        e2.initialize("password123", false).await,
        Err(VaultError::WeakPassword(_))
    ));
    assert_eq!(e2.kdf_runs(), 0);
}

// T-03
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t03_unlock_success_and_item_roundtrip() {
    let fx = Fixture::new("t03");
    let init = fx.engine().initialize(PW, false).await.unwrap();
    let vault_id = init.vault.personal_vault().unwrap();
    let mut body = ItemBody::new(ItemKind::Host, 1);
    let mut clock = HlcClock::default();
    body.set("label", "db-prod", &mut clock, init.vault.device_id());
    let item = ItemId::new();
    let (kv, env) = init.vault.seal(vault_id, item, &body).unwrap();
    let store = fx.engine().store().clone();
    store
        .write(move |w| w.put_item(vault_id, item, kv, &env, false, true))
        .await
        .unwrap();
    drop(init);

    let engine = fx.engine();
    let unlocked = engine.unlock_with_password(PW).await.unwrap();
    assert_eq!(unlocked.method(), UnlockMethod::Password);
    assert_eq!(unlocked.vault_ids(), [vault_id]);
    assert_eq!(unlocked.item_count(), 1);
    assert_eq!(unlocked.undecryptable_count(), 0);
    let row = engine.store().get_item(item).await.unwrap().unwrap();
    assert_eq!(unlocked.open(&row).unwrap(), body);
    assert!(!engine.store().is_read_only(item));
}

// T-04
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t04_wrong_password_is_an_opaque_auth_failure_and_counted() {
    let fx = Fixture::new("t04");
    fx.engine().initialize(PW, false).await.unwrap();
    let engine = fx.engine();
    let err = engine.unlock_with_password("not it").await.unwrap_err();
    assert_eq!(wrong_password(&err), Some(1));
    assert_eq!(err.to_string(), "wrong master password");
    assert_eq!(
        meta(engine.store(), keys::UNLOCK_FAILURES).await,
        Some(1u32.to_be_bytes().to_vec())
    );
    // A tampered wrap fails exactly the same way (no distinguishable error).
    let mut wrapped = meta(engine.store(), keys::LMK_WRAPPED_PW).await.unwrap();
    let last = wrapped.len() - 1;
    wrapped[last] ^= 1;
    engine
        .store()
        .set_meta(keys::LMK_WRAPPED_PW, wrapped)
        .await
        .unwrap();
    let err = engine.unlock_with_password(PW).await.unwrap_err();
    assert_eq!(wrong_password(&err), Some(2));
}

async fn fail(engine: &VaultEngine, clock: &ManualClock) -> VaultError {
    // Wait out any delay first, so every attempt really runs Argon2.
    clock.advance(60_000);
    engine.unlock_with_password("nope").await.unwrap_err()
}

// T-06
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t06_backoff_persists_across_restart() {
    let fx = Fixture::new("t06");
    fx.engine().initialize(PW, false).await.unwrap();
    let engine = fx.engine();
    for n in 1..=6 {
        let err = fail(&engine, &fx.clock).await;
        assert_eq!(wrong_password(&err), Some(n));
        let expected = match n {
            5 => Some(Duration::from_secs(1)),
            6 => Some(Duration::from_secs(2)),
            _ => None,
        };
        assert!(
            matches!(err, VaultError::WrongPassword { retry_after, .. } if retry_after == expected)
        );
    }
    drop(engine);

    // "Restart": a new store connection and engine. The next attempt before
    // `next_allowed_at` is refused without running Argon2 — even with the right password.
    let engine = fx.engine();
    let status = engine.status().await.unwrap();
    assert_eq!(status.backoff.failures, 6);
    assert_eq!(status.retry_after, Some(Duration::from_secs(2)));
    let err = engine.unlock_with_password(PW).await.unwrap_err();
    assert!(
        matches!(err, VaultError::Backoff { retry_after } if retry_after <= Duration::from_secs(2))
    );
    assert_eq!(engine.kdf_runs(), 0);
    fx.clock.advance(1_000);
    assert!(matches!(
        engine.unlock_with_password(PW).await,
        Err(VaultError::Backoff { .. })
    ));
    assert_eq!(engine.kdf_runs(), 0);
}

// T-07
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t07_success_resets_the_counter() {
    let fx = Fixture::new("t07");
    fx.engine().initialize(PW, false).await.unwrap();
    let engine = fx.engine();
    for _ in 0..5 {
        fail(&engine, &fx.clock).await;
    }
    fx.clock.advance(60_000);
    engine.unlock_with_password(PW).await.unwrap();
    let status = engine.status().await.unwrap();
    assert_eq!(status.backoff.failures, 0);
    assert_eq!(status.retry_after, None);
    assert!(meta(engine.store(), keys::UNLOCK_FAILURES).await.is_none());
    // The next failure is #1 again (no delay).
    let err = engine.unlock_with_password("nope").await.unwrap_err();
    assert!(matches!(
        err,
        VaultError::WrongPassword {
            failures: 1,
            retry_after: None
        }
    ));
}

// T-08
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t08_keyring_unlock_and_fallback() {
    let fx = Fixture::new("t08");
    let init = fx.engine().initialize(PW, true).await.unwrap();
    assert!(init.keyring_error.is_none());
    drop(init);
    assert_eq!(fx.keyring.accounts().len(), 1);

    let engine = fx.engine();
    assert!(engine.status().await.unwrap().keyring_enabled);
    let unlocked = engine.unlock_with_keyring().await.unwrap();
    assert_eq!(unlocked.method(), UnlockMethod::Keyring);
    assert_eq!(engine.kdf_runs(), 0, "no password prompt, no Argon2");
    drop(unlocked);

    // Entry deleted behind sverb's back: keyring unlock fails, the password still works.
    let account = engine.keyring_account().await.unwrap().unwrap();
    fx.keyring.remove(&account);
    assert!(matches!(
        engine.unlock_with_keyring().await,
        Err(VaultError::Keyring(_))
    ));
    engine.unlock_with_password(PW).await.unwrap();

    // Without keyring unlock enabled.
    let fx2 = Fixture::new("t08-off");
    fx2.engine().initialize(PW, false).await.unwrap();
    assert_eq!(
        fx2.engine().unlock_with_keyring().await.err(),
        Some(VaultError::KeyringNotEnabled)
    );
    // An unavailable keyring at first run: created without it, with a note.
    let fx3 = Fixture::new("t08-unavailable");
    fx3.keyring.set_unavailable(true);
    let init = fx3.engine().initialize(PW, true).await.unwrap();
    assert!(init.keyring_error.is_some());
    assert!(!fx3.engine().status().await.unwrap().keyring_enabled);
}

// T-08 (service): keyring unlock through the effect, then the password fallback.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t08_service_reports_keyring_failure() {
    let fx = Fixture::new("t08-svc");
    fx.engine().initialize(PW, true).await.unwrap();
    let service = VaultService::new(fx.engine());
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    service.execute(VaultEffect::Unlock(UnlockRequest::Keyring), &tx);
    assert!(matches!(
        rx.recv().await,
        Some(UiEvent::Vault(VaultEvent::Unlocked {
            via_keyring: true,
            ..
        }))
    ));
    assert!(matches!(rx.recv().await, Some(UiEvent::Meta(_))));
    // M1-05: the search index built during unlock follows.
    assert!(matches!(rx.recv().await, Some(UiEvent::IndexUpdated(_))));
    service.lock();
    for account in fx.keyring.accounts() {
        fx.keyring.remove(&account);
    }
    service.execute(VaultEffect::Unlock(UnlockRequest::Keyring), &tx);
    assert!(matches!(
        rx.recv().await,
        Some(UiEvent::Vault(VaultEvent::UnlockFailed(
            sverb_tui::app::UnlockFailure::Keyring(_)
        )))
    ));
    assert!(!service.is_unlocked());
}

// T-09
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t09_two_homes_use_distinct_keyring_accounts() {
    let shared = MemKeyring::new();
    let mut a = Fixture::new("t09-a");
    let mut b = Fixture::new("t09-b");
    a.keyring = shared.clone();
    b.keyring = shared.clone();
    a.engine().initialize(PW, true).await.unwrap();
    b.engine().initialize(PW2, true).await.unwrap();
    let accounts = shared.accounts();
    assert_eq!(accounts.len(), 2, "{accounts:?}");
    assert!(accounts.iter().all(|acc| acc.starts_with("lmk-kek:")));
    assert_ne!(
        a.engine().keyring_account().await.unwrap(),
        b.engine().keyring_account().await.unwrap()
    );
    a.engine().unlock_with_keyring().await.unwrap();
    b.engine().unlock_with_keyring().await.unwrap();
}

// T-13
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t13_lock_drops_every_key() {
    let fx = Fixture::new("t13");
    fx.engine().initialize(PW, false).await.unwrap();
    let service = VaultService::new(fx.engine());
    assert_eq!(service.live_keys(), 0);
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    service.execute(
        VaultEffect::Unlock(UnlockRequest::Password(VaultPassword::from(PW))),
        &tx,
    );
    assert!(matches!(
        rx.recv().await,
        Some(UiEvent::Vault(VaultEvent::Unlocked {
            via_keyring: false,
            ..
        }))
    ));
    assert!(matches!(rx.recv().await, Some(UiEvent::Meta(_))));
    // M1-05: the search index built during unlock follows.
    assert!(matches!(rx.recv().await, Some(UiEvent::IndexUpdated(_))));
    assert!(service.is_unlocked());
    assert_eq!(service.live_keys(), 2, "LMK + one vault key");
    service.execute(VaultEffect::Lock, &tx);
    assert!(!service.is_unlocked());
    assert_eq!(service.live_keys(), 0);

    // Wrong password through the service: counted, nothing loaded.
    service.execute(
        VaultEffect::Unlock(UnlockRequest::Password(VaultPassword::from("nope"))),
        &tx,
    );
    assert!(matches!(
        rx.recv().await,
        Some(UiEvent::Vault(VaultEvent::UnlockFailed(
            sverb_tui::app::UnlockFailure::WrongPassword { failures: 1, .. }
        )))
    ));
    assert_eq!(service.live_keys(), 0);
}

// T-14
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t14_change_password() {
    let fx = Fixture::new("t14");
    fx.engine().initialize(PW, true).await.unwrap();
    let engine = fx.engine();
    let old_kdf = KdfParams::from_cbor(&meta(engine.store(), keys::KDF).await.unwrap()).unwrap();
    let unlocked = engine.unlock_with_password(PW).await.unwrap();
    // Wrong current password and weak new passwords are refused.
    assert!(
        wrong_password(
            &engine
                .change_password(&unlocked, Some("nope"), PW2)
                .await
                .unwrap_err()
        )
        .is_some()
    );
    assert!(matches!(
        engine
            .change_password(&unlocked, Some(PW), "password123")
            .await,
        Err(VaultError::WeakPassword(_))
    ));
    // Without the current password only after a keyring unlock.
    assert_eq!(
        engine.change_password(&unlocked, None, PW2).await.err(),
        Some(VaultError::KeyringNotEnabled)
    );
    fx.clock.advance(60_000);
    engine
        .change_password(&unlocked, Some(PW), PW2)
        .await
        .unwrap();
    drop(unlocked);

    let engine = fx.engine();
    let new_kdf = KdfParams::from_cbor(&meta(engine.store(), keys::KDF).await.unwrap()).unwrap();
    assert_ne!(old_kdf.salt, new_kdf.salt, "a new salt");
    assert!(wrong_password(&engine.unlock_with_password(PW).await.unwrap_err()).is_some());
    engine.unlock_with_password(PW2).await.unwrap();
    engine.unlock_with_keyring().await.unwrap();
}

// T-15
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t15_keyring_recovery_sets_a_new_password() {
    let fx = Fixture::new("t15");
    fx.engine().initialize(PW, true).await.unwrap();
    // The user forgot PW. Keyring unlock, then a new password without the old one,
    // through the service (the UI's flow).
    let service = VaultService::new(fx.engine());
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    service.execute(VaultEffect::Unlock(UnlockRequest::Keyring), &tx);
    assert!(matches!(
        rx.recv().await,
        Some(UiEvent::Vault(VaultEvent::Unlocked { .. }))
    ));
    let _meta = rx.recv().await;
    // M1-05: the search index snapshot.
    let _index = rx.recv().await;
    service.execute(
        VaultEffect::ChangePassword {
            current: None,
            new: VaultPassword::from(PW2),
        },
        &tx,
    );
    assert_eq!(
        rx.recv().await,
        Some(UiEvent::Vault(VaultEvent::PasswordChanged))
    );
    service.lock();
    let engine = fx.engine();
    assert!(wrong_password(&engine.unlock_with_password(PW).await.unwrap_err()).is_some());
    engine.unlock_with_password(PW2).await.unwrap();
}

// T-18: unlock never contacts a server. A sync server URL points at a local listener;
// it must see no connection attempt during first run, password and keyring unlock.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t18_unlock_is_offline() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("https://{}", listener.local_addr().unwrap());
    let fx = Fixture::new("t18");
    let engine = fx.engine();
    engine
        .store()
        .set_sync_state(SyncState {
            server_url: Some(url),
            ..SyncState::default()
        })
        .await
        .unwrap();
    engine.initialize(PW, true).await.unwrap();
    fx.engine().unlock_with_password(PW).await.unwrap();
    fx.engine().unlock_with_keyring().await.unwrap();
    let attempts = std::iter::from_fn(|| listener.accept().ok()).count();
    assert_eq!(attempts, 0, "unlock contacted the sync server");
}

// T-17 (informative): production parameters. Ignored by default because debug builds
// run Argon2 far slower than release; run with
// `cargo test -p sverb-tui --release --test vault -- --ignored t17 --nocapture`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "informative perf check with production Argon2 parameters"]
async fn t17_production_unlock_time() {
    let fx = Fixture::new("t17");
    let store = Store::open_at(fx.db(), fx.clock.clone()).unwrap();
    let engine = VaultEngine::new(store, Arc::new(fx.keyring.clone()), Argon2Cost::PRODUCTION);
    engine.initialize(PW, false).await.unwrap();
    let started = Instant::now();
    engine.unlock_with_password(PW).await.unwrap();
    let took = started.elapsed();
    eprintln!("T-17: unlock with m=256 MiB, t=3, p=1 took {took:?} (target 0.3–2 s)");
}
