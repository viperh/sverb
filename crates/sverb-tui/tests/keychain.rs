//! parameters, in-memory keyring): import (passphrase, agent reference, duplicates,
//! nothing saved on failure — T-04/T-05/T-06), export (0600, round trip, re-encrypt,
//! overwrite — T-09), passphrase changes, certificates (T-07 attach / reject),
//! flags and deletes.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use sverb_core::keychain::{self, import};
use sverb_core::model::{ItemId, ItemKind, Key, KeyAlgorithm};
use sverb_core::vault::{Argon2Cost, MemKeyring};
use sverb_store::{ManualClock, Store};
use sverb_tui::app::keychain::keys::{
    ExportHow, GenerateSpec, ImportSource, ImportSpec, KeyFlag, KeychainEffect, KeychainOutcome,
};
use sverb_tui::app::{UiEvent, UnlockRequest, VaultEffect, VaultPassword};
use sverb_tui::services::vault::items::{ItemOps, keychain::run};
use sverb_tui::services::vault::{VaultEngine, VaultService};
use sverb_tui::widgets::form::SecretValue;

const PW: &str = "correct horse battery staple violin";
const PASS: &str = "sverb-test";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/keys")
        .join(name)
}

struct Fixture {
    dir: PathBuf,
    keyring: MemKeyring,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "m2-03-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self {
            dir,
            keyring: MemKeyring::new(),
        }
    }

    fn engine(&self) -> VaultEngine {
        let clock = Arc::new(ManualClock::new(1_800_000_000_000));
        let store = Store::open_at(self.dir.join("sverb.db"), clock).unwrap();
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

async fn exec(ops: &ItemOps, op: KeychainEffect) -> KeychainOutcome {
    run(ops, op, |_| {}).await.outcome
}

fn import_spec(path: &Path) -> ImportSpec {
    ImportSpec {
        source: ImportSource::File(path.to_str().unwrap().to_owned()),
        label: None,
        passphrase: None,
        allow_agent_ref: false,
        allow_duplicate: false,
    }
}

async fn count(ops: &ItemOps, kind: ItemKind) -> usize {
    ops.list(&[kind]).await.unwrap().len()
}

async fn import_ok(ops: &ItemOps, spec: ImportSpec) -> ItemId {
    match exec(ops, KeychainEffect::Import { token: 1, spec }).await {
        KeychainOutcome::Imported { item, .. } => item,
        other => panic!("{other:?}"),
    }
}

/// T-04 / T-05 / T-06 at the service: passphrase steps save nothing, a `.pub` needs
/// confirming, a duplicate is reported.
#[tokio::test]
async fn import_steps_and_nothing_saved_on_failure() {
    let fx = Fixture::new("import");
    let (_s, ops) = ops(&fx).await;

    let mut spec = import_spec(&fixture("pkcs8_rsa_enc.pem"));
    let out = exec(
        &ops,
        KeychainEffect::Import {
            token: 1,
            spec: spec.clone(),
        },
    )
    .await;
    assert_eq!(out, KeychainOutcome::NeedsPassphrase);
    spec.passphrase = Some(SecretValue::from("wrong"));
    let out = exec(
        &ops,
        KeychainEffect::Import {
            token: 1,
            spec: spec.clone(),
        },
    )
    .await;
    assert_eq!(out, KeychainOutcome::WrongPassphrase);
    assert_eq!(count(&ops, ItemKind::Key).await, 0, "no partial item");

    spec.passphrase = Some(SecretValue::from(PASS));
    let id = import_ok(&ops, spec.clone()).await;
    let key = ops.load_key(id).await.unwrap();
    assert_eq!(key.algorithm, KeyAlgorithm::Rsa2048);
    assert_eq!(key.passphrase.as_ref().map(|p| p.expose()), Some(PASS));
    assert!(keychain::export::is_encrypted(&key));
    assert_eq!(key.label, "pkcs8_rsa_enc.pem");

    // Duplicate (the same RSA key as PKCS#1).
    let out = exec(
        &ops,
        KeychainEffect::Import {
            token: 2,
            spec: import_spec(&fixture("pkcs1_rsa.pem")),
        },
    )
    .await;
    assert_eq!(
        out,
        KeychainOutcome::Duplicate {
            existing: id,
            label: "pkcs8_rsa_enc.pem".into()
        }
    );
    let mut anyway = import_spec(&fixture("pkcs1_rsa.pem"));
    anyway.allow_duplicate = true;
    import_ok(&ops, anyway).await;
    assert_eq!(count(&ops, ItemKind::Key).await, 2);

    // A public key: confirm first, then an agent reference.
    let mut spec = import_spec(&fixture("agent_ref.pub"));
    let out = exec(
        &ops,
        KeychainEffect::Import {
            token: 3,
            spec: spec.clone(),
        },
    )
    .await;
    assert!(
        matches!(out, KeychainOutcome::ConfirmAgentRef { .. }),
        "{out:?}"
    );
    spec.allow_agent_ref = true;
    let id = import_ok(&ops, spec).await;
    let key = ops.load_key(id).await.unwrap();
    assert!(key.is_agent_ref());
    assert!(key.private_key.expose().is_empty());
    assert_eq!(key.label, "hw@sverb");

    // Pasted text with an explicit label.
    let text = std::fs::read_to_string(fixture("sec1_p256.pem")).unwrap();
    let id = import_ok(
        &ops,
        ImportSpec {
            source: ImportSource::Text(SecretValue::from(text.as_str())),
            label: Some("pasted".into()),
            ..import_spec(Path::new("x"))
        },
    )
    .await;
    assert_eq!(ops.load_key(id).await.unwrap().label, "pasted");
    // Garbage: a message, nothing saved.
    let out = exec(
        &ops,
        KeychainEffect::Import {
            token: 4,
            spec: ImportSpec {
                source: ImportSource::Text(SecretValue::from("nope")),
                ..import_spec(Path::new("x"))
            },
        },
    )
    .await;
    assert!(matches!(out, KeychainOutcome::Failed(m) if m.contains("not a key")));
    assert_eq!(count(&ops, ItemKind::Key).await, 4);
}

/// Export private → 0600, round trip, re-encrypt; overwrite needs confirming.
/// Change passphrase.
#[tokio::test]
async fn generate_export_and_change_passphrase() {
    let fx = Fixture::new("export");
    let (_s, ops) = ops(&fx).await;
    let out = exec(
        &ops,
        KeychainEffect::Generate {
            token: 1,
            spec: GenerateSpec {
                algorithm: KeyAlgorithm::Ed25519,
                label: "gen".into(),
                comment: "me@host-sverb".into(),
                passphrase: Some(SecretValue::from(PASS)),
                remember: true,
            },
        },
    )
    .await;
    let KeychainOutcome::Generated {
        item, public_key, ..
    } = out
    else {
        panic!("{out:?}");
    };
    assert!(public_key.ends_with(" me@host-sverb"));
    let key: Key = ops.load_key(item).await.unwrap();
    assert!(keychain::export::is_encrypted(&key));

    let path = fx.dir.join("id_gen");
    let p = path.to_str().unwrap().to_owned();
    let export = |overwrite: bool, how: ExportHow| KeychainEffect::ExportPrivate {
        token: 2,
        item,
        path: p.clone(),
        overwrite,
        how,
        passphrase: None,
    };
    let out = exec(&ops, export(false, ExportHow::Keep)).await;
    assert!(
        matches!(out, KeychainOutcome::Exported { private: true, .. }),
        "{out:?}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let back = import::import_file(&p, Some(PASS), import::ImportOptions::default()).unwrap();
    assert!(keychain::same_public_key(&back.public_key, &public_key));
    // Exists → confirm; then re-encrypt with a new passphrase.
    let out = exec(&ops, export(false, ExportHow::Decrypted)).await;
    assert!(matches!(out, KeychainOutcome::Exists { .. }), "{out:?}");
    let out = exec(
        &ops,
        export(true, ExportHow::Reencrypt(SecretValue::from("other"))),
    )
    .await;
    assert!(matches!(out, KeychainOutcome::Exported { .. }), "{out:?}");
    let text = import::read_key_file(&p).unwrap();
    import::check_passphrase(text.expose(), "other").unwrap();
    assert!(import::check_passphrase(text.expose(), PASS).is_err());

    // Public key export.
    let pub_path = fx.dir.join("id_gen.pub");
    let out = exec(
        &ops,
        KeychainEffect::ExportPublic {
            token: 3,
            item,
            path: pub_path.to_str().unwrap().to_owned(),
            overwrite: false,
        },
    )
    .await;
    assert!(matches!(
        out,
        KeychainOutcome::Exported { private: false, .. }
    ));
    assert!(keychain::same_public_key(
        &std::fs::read_to_string(&pub_path).unwrap(),
        &public_key
    ));

    // The stored passphrase decrypts; the new one is stored.
    let out = exec(
        &ops,
        KeychainEffect::ChangePassphrase {
            token: 4,
            item,
            old: None,
            new: Some(SecretValue::from("second")),
            remember: true,
        },
    )
    .await;
    assert_eq!(out, KeychainOutcome::PassphraseChanged);
    let key = ops.load_key(item).await.unwrap();
    assert_eq!(key.passphrase.as_ref().map(|p| p.expose()), Some("second"));
    assert!(import::check_passphrase(key.private_key.expose(), PASS).is_err());
    import::check_passphrase(key.private_key.expose(), "second").unwrap();
    // A wrong current passphrase changes nothing.
    let out = exec(
        &ops,
        KeychainEffect::ChangePassphrase {
            token: 5,
            item,
            old: Some(SecretValue::from("bad")),
            new: None,
            remember: false,
        },
    )
    .await;
    assert_eq!(out, KeychainOutcome::WrongPassphrase);
    let after = ops.load_key(item).await.unwrap();
    assert_eq!(after.private_key.expose(), key.private_key.expose());
}

/// T-07 (attach): a matching certificate attaches (also found by public key); a
/// certificate for another key is rejected. Flags and deletes.
#[tokio::test]
async fn certificates_flags_and_deletes() {
    let fx = Fixture::new("certs");
    let (_s, ops) = ops(&fx).await;
    let key = import_ok(&ops, import_spec(&fixture("id_cert.pub")).with_agent_ref()).await;
    let other = import_ok(&ops, import_spec(&fixture("openssh_ed25519"))).await;
    let cert_path = fixture("id_cert-cert.pub").to_str().unwrap().to_owned();

    let out = exec(
        &ops,
        KeychainEffect::AttachCert {
            token: 1,
            key: Some(other),
            source: ImportSource::File(cert_path.clone()),
        },
    )
    .await;
    assert!(
        matches!(&out, KeychainOutcome::Failed(m) if m.contains("different key")),
        "{out:?}"
    );
    assert_eq!(count(&ops, ItemKind::Certificate).await, 0);

    let out = exec(
        &ops,
        KeychainEffect::AttachCert {
            token: 2,
            key: None,
            source: ImportSource::File(cert_path),
        },
    )
    .await;
    let KeychainOutcome::CertAttached {
        item: cert,
        key_label,
    } = out
    else {
        panic!("{out:?}");
    };
    assert_eq!(key_label, "cert@sverb");
    assert_eq!(ops.load_key(key).await.unwrap().certificate_ids, [cert]);

    // Flags.
    exec(
        &ops,
        KeychainEffect::SetFlag {
            item: key,
            flag: KeyFlag::Forwardable,
            value: true,
        },
    )
    .await;
    assert!(ops.load_key(key).await.unwrap().agent_forwardable);

    // Delete the certificate (detached), then the key with its certificates.
    exec(&ops, KeychainEffect::DeleteCert(cert)).await;
    assert!(ops.load_key(key).await.unwrap().certificate_ids.is_empty());
    assert_eq!(count(&ops, ItemKind::Certificate).await, 0);
    let out = exec(
        &ops,
        KeychainEffect::AttachCert {
            token: 3,
            key: Some(key),
            source: ImportSource::File(fixture("id_cert-cert.pub").to_str().unwrap().into()),
        },
    )
    .await;
    assert!(matches!(out, KeychainOutcome::CertAttached { .. }));
    exec(&ops, KeychainEffect::DeleteKey(key)).await;
    assert_eq!(count(&ops, ItemKind::Certificate).await, 0);
    assert_eq!(count(&ops, ItemKind::Key).await, 1);
}

trait AgentRef {
    fn with_agent_ref(self) -> Self;
}

impl AgentRef for ImportSpec {
    fn with_agent_ref(mut self) -> Self {
        self.allow_agent_ref = true;
        self
    }
}

/// §9.4: an agent reference key resolves to its public line for the auth chain, which
/// then signs through the system agent with that key only.
#[tokio::test]
async fn agent_reference_key_material() {
    let fx = Fixture::new("material");
    let (_s, ops) = ops(&fx).await;
    let id = import_ok(
        &ops,
        import_spec(&fixture("agent_ref.pub")).with_agent_ref(),
    )
    .await;
    let items = ops.list(&[ItemKind::Key]).await.unwrap();
    let km = sverb_tui::services::ssh::key_material(id, &items).unwrap();
    let public = sverb_conn::ssh::auth::agent_reference(&km).expect("an agent reference");
    let expected = std::fs::read_to_string(fixture("agent_ref.pub")).unwrap();
    assert!(keychain::same_public_key(
        &public.to_openssh().unwrap(),
        &expected
    ));
    // A regular key keeps its private key.
    let id = import_ok(&ops, import_spec(&fixture("openssh_ed25519"))).await;
    let items = ops.list(&[ItemKind::Key]).await.unwrap();
    let km = sverb_tui::services::ssh::key_material(id, &items).unwrap();
    assert!(sverb_conn::ssh::auth::agent_reference(&km).is_none());
    assert!(
        km.private_key
            .expose()
            .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
    );
}
