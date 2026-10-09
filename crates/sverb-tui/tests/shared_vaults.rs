//! Shared vaults through the TUI's vault and item services: adopting a
//! vault key while unlocked, names, the read-only permission, vault badges
//! and the selector's data, move with a referenced identity,
//! credential overrides and the cross-vault rule on save.
//! Small Argon2 parameters, in-memory keyring, no network.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use sverb_core::model::vault_refs::RefPolicy;
use sverb_core::model::{ItemId, ItemKind, Key, KeyAlgorithm, VaultId};
use sverb_core::resolve::{GlobalDefaults, SettingKey, Source};
use sverb_core::secret::SecretString;
use sverb_core::vault::{Argon2Cost, MemKeyring};
use sverb_crypto::envelope::seal_item;
use sverb_crypto::random::{os_rng, random_key32};
use sverb_crypto::wrap::{WrapPurpose, wrap_key};
use sverb_store::{ManualClock, Store, VaultKind};
use sverb_tui::app::{UiEvent, UnlockRequest, VaultEffect, VaultPassword};
use sverb_tui::services::vault::items::{ItemError, ItemOps};
use sverb_tui::services::vault::shared::{META_VAULT_NAME_PREFIX, META_VAULT_PERMISSION_PREFIX};
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
            "m5-02-{tag}-{}-{}",
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

async fn unlocked(fx: &Fixture) -> VaultService {
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
    service
}

/// A shared vault added to the store while unlocked (what the sync engine does
/// after verifying a grant), with its sealed name.
async fn add_shared_vault(service: &VaultService, name: &str) -> VaultId {
    let vault = VaultId::new();
    let vk = random_key32(&mut os_rng());
    let lmk = service.unlocked().unwrap().lmk().clone();
    let wrapped = wrap_key(
        &lmk,
        &WrapPurpose::VaultKey(*vault.as_bytes()),
        vk.expose_secret(),
        &mut os_rng(),
    )
    .unwrap();
    let store = service.store();
    store
        .create_vault(vault, VaultKind::Shared, None, 1, wrapped)
        .await
        .unwrap();
    let name_enc = seal_item(
        &vk,
        vault.as_bytes(),
        vault.as_bytes(),
        1,
        name.as_bytes(),
        &mut os_rng(),
    )
    .unwrap();
    store
        .set_meta(
            &format!("{META_VAULT_NAME_PREFIX}{}", vault.uuid()),
            name_enc,
        )
        .await
        .unwrap();
    assert_eq!(service.adopt_new_vaults().await, vec![vault]);
    assert!(service.adopt_new_vaults().await.is_empty(), "idempotent");
    vault
}

async fn set_permission(service: &VaultService, vault: VaultId, perm: &str) {
    service
        .store()
        .set_meta(
            &format!("{META_VAULT_PERMISSION_PREFIX}{}", vault.uuid()),
            perm.as_bytes().to_vec(),
        )
        .await
        .unwrap();
}

fn text(s: &str) -> FieldValue {
    FieldValue::Text(s.to_owned())
}

async fn host(
    ops: &ItemOps,
    label: &str,
    user: Option<&str>,
    identity: Option<ItemId>,
) -> Result<ItemId, ItemError> {
    let mut c = vec![
        ("label".to_owned(), text(label)),
        ("address".to_owned(), text(&format!("{label}.example"))),
        ("identity_id".to_owned(), FieldValue::Reference(identity)),
    ];
    if let Some(u) = user {
        c.push(("username".to_owned(), text(u)));
    }
    Ok(ops
        .save_host(None, FieldChanges(c.into_iter().collect()))
        .await?
        .id)
}

async fn identity(ops: &ItemOps, vault: Option<VaultId>, label: &str, user: &str) -> ItemId {
    let (label, user) = (label.to_owned(), user.to_owned());
    ops.save_identity(None, vault, move |i| {
        i.label = label;
        i.username = user;
        Ok(())
    })
    .await
    .unwrap()
    .id
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

// T-05 (data): names, shared flags and badges; the selector sends new hosts to
// the selected vault.
#[tokio::test]
async fn t05_names_badges_and_selected_vault() {
    let fx = Fixture::new("t05");
    let service = unlocked(&fx).await;
    let shared = add_shared_vault(&service, "Ops").await;
    let ops = service.item_ops().unwrap();
    let personal = ops.vault().personal_vault().unwrap();
    let mine = host(&ops, "laptop", None, None).await.unwrap();
    service.set_new_item_vault(Some(shared));
    let ops = service.item_ops().unwrap();
    let team = host(&ops, "prod-db", None, None).await.unwrap();
    service.set_new_item_vault(None);

    let cat = service.item_ops().unwrap().catalog().await.unwrap();
    assert_eq!(cat.vault_names[&shared], "Ops");
    assert_eq!(cat.vault_names[&personal], "Personal");
    assert_eq!(cat.hosts[&team].vault, shared);
    assert_eq!(cat.hosts[&mine].vault, personal);
    assert_eq!(cat.vault_badge(shared), Some("Ops"));
    assert_eq!(cat.vault_badge(personal), None);
}

// T-04 (TUI): a read member can't write the vault; the catalog marks it.
#[tokio::test]
async fn t04_read_only_vault_refuses_writes() {
    let fx = Fixture::new("t04");
    let service = unlocked(&fx).await;
    let shared = add_shared_vault(&service, "Ops").await;
    service.set_new_item_vault(Some(shared));
    let ops = service.item_ops().unwrap();
    let h = host(&ops, "web", None, None).await.unwrap();
    set_permission(&service, shared, "read").await;
    let err = ops
        .save_host(
            Some(h),
            FieldChanges(
                [("label".to_owned(), text("renamed"))]
                    .into_iter()
                    .collect(),
            ),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, ItemError::ReadOnlyVault), "{err}");
    assert!(host(&ops, "new", None, None).await.is_err());
    let cat = ops.catalog().await.unwrap();
    assert!(cat.is_read_only_vault(shared));
    set_permission(&service, shared, "write").await;
    assert!(host(&ops, "new", None, None).await.is_ok());
}

// Move a personal host using a personal identity to a shared vault:
// blocked, then with "also copy" the host and an identity copy are in the shared
// vault and the personal host is gone.
#[tokio::test]
async fn t06_move_with_reference() {
    let fx = Fixture::new("t06");
    let service = unlocked(&fx).await;
    let shared = add_shared_vault(&service, "Ops").await;
    let ops = service.item_ops().unwrap();
    let ident = identity(&ops, None, "deploy", "deploy").await;
    let h = host(&ops, "web", None, Some(ident)).await.unwrap();

    let err = ops
        .transfer(&[h], shared, false, RefPolicy::Block)
        .await
        .unwrap_err();
    let ItemError::Blocked(refs) = &err else {
        panic!("expected Blocked, got {err}");
    };
    assert_eq!(refs, &vec!["identity “deploy”".to_owned()]);
    assert!(ops.load(h).await.unwrap().is_some(), "nothing moved");

    let written = ops
        .transfer(&[h], shared, false, RefPolicy::Copy)
        .await
        .unwrap();
    assert_eq!(
        written.len(),
        3,
        "host copy, identity copy, source tombstone"
    );
    assert!(ops.load(h).await.unwrap().is_none(), "source tombstoned");
    assert!(ops.load(ident).await.unwrap().is_some(), "identity kept");
    let cat = ops.catalog().await.unwrap();
    let (new_host, summary) = cat.hosts.iter().find(|(_, s)| s.label == "web").unwrap();
    assert_ne!(*new_host, h);
    assert_eq!(summary.vault, shared);
    let new_ident = summary.identity_id.unwrap();
    assert_ne!(new_ident, ident);
    assert_eq!(cat.identity_vaults[&new_ident], shared);
    assert_eq!(
        cat.resolve(summary, &GlobalDefaults::default())
            .username
            .as_deref(),
        Some("deploy")
    );
}

// T-07 (TUI): the override's identity supplies the user on this device;
// provenance "your override"; removing it restores the shared value.
#[tokio::test]
async fn t07_override_through_the_catalog() {
    let fx = Fixture::new("t07");
    let service = unlocked(&fx).await;
    let shared = add_shared_vault(&service, "Ops").await;
    service.set_new_item_vault(Some(shared));
    let ops = service.item_ops().unwrap();
    let h = host(&ops, "db", Some("deploy"), None).await.unwrap();
    let mine = identity(&ops, None, "me", "bob").await;

    ops.set_override(h, Some(mine)).await.unwrap();
    let cat = ops.catalog().await.unwrap();
    let r = cat.resolve(&cat.hosts[&h], &GlobalDefaults::default());
    assert_eq!(r.username.as_deref(), Some("bob"));
    assert!(matches!(
        r.source(SettingKey::Username),
        Source::Override { .. }
    ));
    assert_eq!(r.source(SettingKey::Username).to_string(), "your override");
    // Setting it again updates the one override.
    ops.set_override(h, Some(mine)).await.unwrap();
    let overrides = ops.list(&[ItemKind::CredentialOverride]).await.unwrap();
    assert_eq!(overrides.len(), 1);
    assert_eq!(overrides[0].vault, ops.vault().personal_vault().unwrap());

    ops.set_override(h, None).await.unwrap();
    let cat = ops.catalog().await.unwrap();
    let r = cat.resolve(&cat.hosts[&h], &GlobalDefaults::default());
    assert_eq!(r.username.as_deref(), Some("deploy"));
    assert!(cat.overrides.is_empty());
}

// T-08 (TUI): a shared host can't reference a personal key on save.
#[tokio::test]
async fn t08_shared_host_rejects_personal_key() {
    let fx = Fixture::new("t08");
    let service = unlocked(&fx).await;
    let shared = add_shared_vault(&service, "Ops").await;
    let ops = service.item_ops().unwrap();
    let personal_key = key(&ops, "mine").await;
    service.set_new_item_vault(Some(shared));
    let ops = service.item_ops().unwrap();
    let err = ops
        .save_host(
            None,
            FieldChanges(
                [
                    ("label".to_owned(), text("db")),
                    ("address".to_owned(), text("db.example")),
                    (
                        "key_id".to_owned(),
                        FieldValue::Reference(Some(personal_key)),
                    ),
                ]
                .into_iter()
                .collect(),
            ),
        )
        .await
        .unwrap_err();
    let ItemError::Invalid(errors) = &err else {
        panic!("expected Invalid, got {err}");
    };
    assert_eq!(errors[0].field, "key_id");
    // In the personal vault the same host is fine.
    service.set_new_item_vault(None);
    let ops = service.item_ops().unwrap();
    assert!(
        ops.save_host(
            None,
            FieldChanges(
                [
                    ("label".to_owned(), text("db")),
                    ("address".to_owned(), text("db.example")),
                    (
                        "key_id".to_owned(),
                        FieldValue::Reference(Some(personal_key))
                    ),
                ]
                .into_iter()
                .collect(),
            ),
        )
        .await
        .is_ok()
    );
}
