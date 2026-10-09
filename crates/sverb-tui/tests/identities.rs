//! M2-02 integration tests: identities through the item service (T-01, T-02, T-04,
//! T-05) and the vault scoping of saves. Small Argon2 parameters, in-memory keyring.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use sverb_core::model::{Host, Identity, ItemId, ItemKind, Key, KeyAlgorithm};
use sverb_core::resolve::{GlobalDefaults, ResolveWarning, SettingKey, Source};
use sverb_core::secret::SecretString;
use sverb_core::vault::{Argon2Cost, MemKeyring};
use sverb_store::{ManualClock, Store};
use sverb_tui::app::{UiEvent, UnlockRequest, VaultEffect, VaultPassword};
use sverb_tui::services::vault::items::{ItemError, ItemOps};
use sverb_tui::services::vault::{VaultEngine, VaultService};
use sverb_tui::widgets::form::{FieldChanges, FieldValue};

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
            "m2-02-{tag}-{}-{}",
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

async fn ops(fx: &Fixture) -> (VaultService, ItemOps) {
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
    let ops = service.item_ops().unwrap();
    (service, ops)
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

async fn key(ops: &ItemOps, label: &str) -> ItemId {
    ops.save(ItemKind::Key, None, None, |body, clock, device| {
        Key {
            label: label.to_owned(),
            algorithm: KeyAlgorithm::Ed25519,
            private_key: SecretString::from("-----BEGIN OPENSSH PRIVATE KEY-----"),
            public_key: "ssh-ed25519 AAAA test".to_owned(),
            passphrase: None,
            certificate_ids: Vec::new(),
            agent_forwardable: false,
            confirm_on_use: false,
            read_only: false,
        }
        .apply_to(body, clock, device);
        Ok(())
    })
    .await
    .unwrap()
    .id
}

async fn identity(
    ops: &ItemOps,
    user: &str,
    password: Option<&str>,
    key: Option<ItemId>,
) -> ItemId {
    let (user, password) = (user.to_owned(), password.map(str::to_owned));
    ops.save_identity(None, None, move |i| {
        i.label = "ops".to_owned();
        i.username = user;
        i.password = password.as_deref().map(SecretString::from);
        i.key_id = key;
        Ok(())
    })
    .await
    .unwrap()
    .id
}

async fn host(
    ops: &ItemOps,
    label: &str,
    identity: Option<ItemId>,
    group: Option<ItemId>,
) -> ItemId {
    ops.save_host(
        None,
        changes(&[
            ("label", text(label)),
            ("address", text(&format!("{label}.example"))),
            ("identity_id", FieldValue::Reference(identity)),
            ("group_id", FieldValue::Reference(group)),
        ]),
    )
    .await
    .unwrap()
    .id
}

async fn group(ops: &ItemOps, name: &str, identity: Option<ItemId>, user: &str) -> ItemId {
    ops.save_group(
        None,
        changes(&[
            ("name", text(name)),
            ("identity_id", FieldValue::Reference(identity)),
            ("username", text(user)),
        ]),
    )
    .await
    .unwrap()
    .id
}

async fn host_view(ops: &ItemOps, id: ItemId) -> Host {
    Host::try_from(&ops.load(id).await.unwrap().unwrap().body).unwrap()
}

// M2-02 T-01
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t01_identity_shared_by_three_hosts() {
    let fx = Fixture::new("t01");
    let (_s, ops) = ops(&fx).await;
    let k = key(&ops, "laptop").await;
    let ident = identity(&ops, "deploy", None, Some(k)).await;
    let mut hosts = Vec::new();
    for label in ["a", "b", "c"] {
        hosts.push(host(&ops, label, Some(ident), None).await);
    }
    let cat = ops.catalog().await.unwrap();
    for h in &hosts {
        let r = cat.resolve(&cat.hosts[h], &GlobalDefaults::default());
        assert_eq!(r.username.as_deref(), Some("deploy"));
        assert_eq!(r.key_id, Some(k));
        assert_eq!(r.identity_id, Some(ident));
        assert_eq!(r.source(SettingKey::Username), &Source::Host);
    }
}

// M2-02 T-02
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t02_editing_the_identity_changes_every_host_without_writing_them() {
    let fx = Fixture::new("t02");
    let (_s, ops) = ops(&fx).await;
    let ident = identity(&ops, "deploy", None, None).await;
    let mut hosts = Vec::new();
    for label in ["a", "b", "c"] {
        hosts.push(host(&ops, label, Some(ident), None).await);
    }
    let mut before = Vec::new();
    for h in &hosts {
        before.push(ops.load(*h).await.unwrap().unwrap().body);
    }
    ops.save_identity(Some(ident), None, |i| {
        i.username = "release".to_owned();
        Ok(())
    })
    .await
    .unwrap();
    let cat = ops.catalog().await.unwrap();
    for (h, old) in hosts.iter().zip(before) {
        let r = cat.resolve(&cat.hosts[h], &GlobalDefaults::default());
        assert_eq!(r.username.as_deref(), Some("release"));
        // The host items are untouched: same fields, same stamps.
        assert!(ops.load(*h).await.unwrap().unwrap().body == old);
    }
}

// M2-02 T-04
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t04_delete_with_convert_copies_inline_credentials() {
    let fx = Fixture::new("t04");
    let (_s, ops) = ops(&fx).await;
    let k = key(&ops, "laptop").await;
    let ident = identity(&ops, "deploy", Some("s3cret"), Some(k)).await;
    let g = group(&ops, "prod", Some(ident), "").await;
    let direct = [
        host(&ops, "a", Some(ident), None).await,
        host(&ops, "b", Some(ident), None).await,
    ];
    let via_group = host(&ops, "c", None, Some(g)).await;
    let other = host(&ops, "d", None, None).await;

    let writes = ops.delete_identity(ident, true).await.unwrap();
    assert_eq!(writes.len(), 4, "three hosts and the tombstone");
    assert_eq!(writes.last().unwrap().id, ident);

    for h in direct.into_iter().chain([via_group]) {
        let v = host_view(&ops, h).await;
        assert_eq!(v.username.as_deref(), Some("deploy"));
        assert_eq!(v.password.as_ref().map(|p| p.expose()), Some("s3cret"));
        assert_eq!(v.key_id, Some(k));
        assert_eq!(v.identity_id, None);
    }
    let untouched = host_view(&ops, other).await;
    assert_eq!(untouched.username, None);
    assert!(untouched.password.is_none());
    // The identity is tombstoned.
    assert!(ops.load(ident).await.unwrap().is_none());
    assert!(matches!(
        ops.load_identity(ident).await,
        Err(ItemError::NotFound)
    ));
    // Resolution is unchanged for the converted hosts.
    let cat = ops.catalog().await.unwrap();
    let r = cat.resolve(&cat.hosts[&via_group], &GlobalDefaults::default());
    assert_eq!(r.username.as_deref(), Some("deploy"));
    assert_eq!(r.source(SettingKey::Username), &Source::Host);
}

// M2-02 T-05
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t05_delete_without_convert_falls_back_to_the_next_level() {
    let fx = Fixture::new("t05");
    let (_s, ops) = ops(&fx).await;
    let ident = identity(&ops, "deploy", Some("s3cret"), None).await;
    let g = group(&ops, "prod", None, "fallback").await;
    let h = host(&ops, "a", Some(ident), Some(g)).await;
    let before = ops.load(h).await.unwrap().unwrap().body;

    let writes = ops.delete_identity(ident, false).await.unwrap();
    assert_eq!(writes.len(), 1);
    // The host keeps its (now dangling) reference; nothing on it changes.
    assert!(ops.load(h).await.unwrap().unwrap().body == before);

    let cat = ops.catalog().await.unwrap();
    let r = cat.resolve(&cat.hosts[&h], &GlobalDefaults::default());
    assert_eq!(r.username.as_deref(), Some("fallback"));
    assert!(matches!(
        r.source(SettingKey::Username),
        Source::Group { .. }
    ));
    assert_eq!(r.password, None);
    assert_eq!(r.identity_id, None);
    assert!(r.warnings.contains(&ResolveWarning::MissingIdentity(ident)));
    assert_eq!(
        ResolveWarning::MissingIdentity(ident).chip(),
        "missing identity"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn identity_needs_a_label_and_duplicates_keep_fields() {
    let fx = Fixture::new("label");
    let (_s, ops) = ops(&fx).await;
    let err = ops
        .save_identity(None, None, |i| {
            i.username = "x".to_owned();
            Ok(())
        })
        .await
        .unwrap_err();
    assert!(matches!(err, ItemError::Invalid(ref e) if e[0].field == "label"));
    let ident = identity(&ops, "deploy", Some("pw"), None).await;
    let copy = ops.duplicate(ident).await.unwrap();
    let (_, dup) = ops.load_identity(copy.id).await.unwrap();
    let dup: Identity = dup;
    assert_eq!(dup.label, "ops (copy)");
    assert_eq!(dup.username, "deploy");
    assert_eq!(dup.password.as_ref().map(|p| p.expose()), Some("pw"));
}
