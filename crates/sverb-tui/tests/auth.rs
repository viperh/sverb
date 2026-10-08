//! M1-14 integration tests: the SSH resolver reads the configured key's material
//! (private key, stored passphrase, attached certificates) from the vault, and the
//! credential saves behind "save to vault" change only the saved field. Small Argon2
//! parameters, in-memory keyring.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use sverb_conn::{SshSpec, ssh::HostResolver};
use sverb_core::config::Config;
use sverb_core::model::{Certificate, Host, ItemBody, ItemKind, Key, KeyAlgorithm};
use sverb_core::secret::SecretString;
use sverb_core::vault::{Argon2Cost, MemKeyring};
use sverb_store::{ManualClock, Store};
use sverb_tui::app::{UiEvent, UnlockRequest, VaultEffect, VaultPassword};
use sverb_tui::services::ssh::{
    KEY_FILE_FIELD, VaultHostResolver, import_key_file, import_key_file_change, save_key_changes,
};
use sverb_tui::services::vault::items::ItemOps;
use sverb_tui::services::vault::{VaultEngine, VaultService};
use sverb_tui::widgets::form::{FieldChanges, FieldValue, SecretValue};

const PW: &str = "correct horse battery staple violin";
const T0: i64 = 1_800_000_000_000;

/// A throwaway test key (`sverb_conn::ssh::test_keys::ED25519`).
const ED25519: &str = r"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCUGFv1LS0DzHr9tq0M9zmIq8W3phuN+6/cdfXRExC3GQAAAJBjY6kqY2Op
KgAAAAtzc2gtZWQyNTUxOQAAACCUGFv1LS0DzHr9tq0M9zmIq8W3phuN+6/cdfXRExC3GQ
AAAECNrfUW5v3vgsVq8yfKi8Z9xeSjRfy2RJXNZEne8/bZAJQYW/UtLQPMev22rQz3OYir
xbemG437r9x19dETELcZAAAACnBsYWluQHRlc3QBAgM=
-----END OPENSSH PRIVATE KEY-----";
/// Its certificate (`ED25519_CERT`).
const ED25519_CERT: &str = r"ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIGeuzsfSxQcAPQ5DzaMRwsKod7MRj56rMmXoCNcKpQQ6AAAAIJQYW/UtLQPMev22rQz3OYirxbemG437r9x19dETELcZAAAAAAAAAAAAAAABAAAACHRlc3RjZXJ0AAAACQAAAAVzdmVyYgAAAABqxZoAAAAAAH2S7oAAAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACBcPKEi6ySaR0oTjdIz1e1EOteubZHlru92Reqr4LFMCAAAAFMAAAALc3NoLWVkMjU1MTkAAABAzGOnabAjYmRIU8nEnikNC//AN8AQOIFygFI7FCiPOWTW2pdcsyQj08p4CORbMqbhYVl3a/Z7Z1fSBW+JJx0RDg== plain@test";

struct Fixture {
    dir: PathBuf,
    clock: Arc<ManualClock>,
    keyring: MemKeyring,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "m1-14-{tag}-{}-{}",
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

fn test_key(passphrase: Option<&str>) -> Key {
    Key {
        label: "work".into(),
        algorithm: KeyAlgorithm::Ed25519,
        private_key: SecretString::from(ED25519),
        public_key: "ssh-ed25519 AAAA".into(),
        passphrase: passphrase.map(SecretString::from),
        certificate_ids: Vec::new(),
        agent_forwardable: false,
        confirm_on_use: false,
        read_only: false,
    }
}

fn changes(pairs: Vec<(&str, FieldValue)>) -> FieldChanges {
    FieldChanges(pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}

/// The resolver hands the chain the key, its stored passphrase and its certificates.
#[tokio::test]
async fn resolver_reads_key_material() {
    let fx = Fixture::new("resolve");
    let (service, ops) = ops(&fx).await;
    let key = ops
        .save(ItemKind::Key, None, None, |body, clock, device| {
            test_key(Some("pp")).apply_to(body, clock, device);
            Ok(())
        })
        .await
        .unwrap();
    let cert = Certificate {
        label: "work cert".into(),
        cert: ED25519_CERT.into(),
        key_id: Some(key.id),
        read_only: false,
    };
    ops.save(ItemKind::Certificate, None, None, |body, clock, device| {
        cert.apply_to(body, clock, device);
        Ok(())
    })
    .await
    .unwrap();
    let host = Host {
        label: "db".into(),
        address: "10.0.0.5".into(),
        username: Some("deploy".into()),
        key_id: Some(key.id),
        algorithms: Some(sverb_core::model::AlgoOverrides {
            host_key: Some(vec!["ssh-rsa".into()]),
            ..Default::default()
        }),
        ..Host::default()
    };
    let host = ops
        .save(ItemKind::Host, None, None, |body, clock, device| {
            host.apply_to(body, clock, device);
            Ok(())
        })
        .await
        .unwrap();

    let mut config = Config::default();
    config.ssh.max_auth_attempts = 3;
    config.ssh.use_system_agent = false;
    let resolver = VaultHostResolver::new(Some(service), Arc::new(config));
    let t = resolver
        .resolve(&SshSpec {
            host_id: Some(host.id),
            ..SshSpec::default()
        })
        .await
        .unwrap();
    assert_eq!(t.auth.key_id, Some(key.id));
    let km = t.auth.key.as_ref().unwrap();
    assert_eq!(km.key_id, Some(key.id));
    assert_eq!(km.label, "work");
    assert_eq!(km.private_key.expose(), ED25519);
    assert_eq!(km.passphrase.as_ref().unwrap().expose(), "pp");
    assert_eq!(km.certificates, [ED25519_CERT.to_owned()]);
    assert_eq!(t.auth.max_attempts, 3);
    assert!(!t.auth.use_system_agent);
    assert!(t.auth.allow_ssh_rsa);
}

/// T-10 (vault side): the saves the auth flow emits change only the saved field.
#[tokio::test]
async fn saving_credentials_changes_only_that_field() {
    let fx = Fixture::new("save");
    let (_service, ops) = ops(&fx).await;
    let key = ops
        .save(ItemKind::Key, None, None, |body, clock, device| {
            test_key(None).apply_to(body, clock, device);
            Ok(())
        })
        .await
        .unwrap();
    let saved = save_key_changes(
        &ops,
        Some(key.id),
        changes(vec![(
            "passphrase",
            FieldValue::Secret(SecretValue::from("typed")),
        )]),
    )
    .await
    .unwrap();
    let changed: Vec<&str> = changed_fields(&key.body, &saved.body);
    assert_eq!(changed, ["passphrase"]);
    let k = Key::try_from(&saved.body).unwrap();
    assert_eq!(k.passphrase.unwrap().expose(), "typed");
    assert_eq!(k.private_key.expose(), ED25519);

    // Anything but the passphrase is refused.
    assert!(
        save_key_changes(
            &ops,
            Some(key.id),
            changes(vec![("label", FieldValue::Text("x".into()))])
        )
        .await
        .is_err()
    );

    // A host password is saved inline through the host save (only `password`).
    let host = ops
        .save(ItemKind::Host, None, None, |body, clock, device| {
            Host {
                label: "db".into(),
                address: "db".into(),
                ..Host::default()
            }
            .apply_to(body, clock, device);
            Ok(())
        })
        .await
        .unwrap();
    let saved = ops
        .save_host(
            Some(host.id),
            changes(vec![(
                "password",
                FieldValue::Secret(SecretValue::from("hunter2")),
            )]),
        )
        .await
        .unwrap();
    assert_eq!(changed_fields(&host.body, &saved.body), ["password"]);
}

fn changed_fields<'a>(before: &'a ItemBody, after: &'a ItemBody) -> Vec<&'a str> {
    after
        .fields
        .iter()
        .filter(|(k, v)| before.fields.get(*k) != Some(*v))
        .map(|(k, _)| k.as_str())
        .collect()
}

/// The M1 key-file import (task §2.6): an OpenSSH key file becomes Key fields.
#[test]
fn imports_an_openssh_key_file() {
    let fx = Fixture::new("import");
    let path = fx.dir.join("id_ed25519");
    std::fs::write(&path, ED25519).unwrap();
    let key = import_key_file(path.to_str().unwrap()).unwrap();
    assert_eq!(key.algorithm, KeyAlgorithm::Ed25519);
    assert_eq!(key.label, "plain@test");
    assert!(key.public_key.starts_with("ssh-ed25519 "));
    assert!(import_key_file(fx.dir.join("missing").to_str().unwrap()).is_err());
}

/// The host form's key-file field: on save the file becomes a Key item and the host
/// points at it.
#[tokio::test]
async fn host_save_imports_the_key_file() {
    let fx = Fixture::new("import-save");
    let (_service, ops) = ops(&fx).await;
    let path = fx.dir.join("id_ed25519");
    std::fs::write(&path, ED25519).unwrap();
    let mut ch = changes(vec![
        ("label", FieldValue::Text("db".into())),
        (
            KEY_FILE_FIELD,
            FieldValue::Text(path.to_str().unwrap().into()),
        ),
    ]);
    let written = import_key_file_change(&ops, &mut ch)
        .await
        .unwrap()
        .unwrap();
    let key = Key::try_from(&written.body).unwrap();
    assert_eq!(key.private_key.expose(), ED25519);
    assert_eq!(
        ch.get("key_id"),
        Some(&FieldValue::Reference(Some(written.id)))
    );
    assert!(ch.get(KEY_FILE_FIELD).is_none());

    // A bad path is a field error; no path is a no-op.
    let mut bad = changes(vec![(
        KEY_FILE_FIELD,
        FieldValue::Text("/nonexistent".into()),
    )]);
    assert!(import_key_file_change(&ops, &mut bad).await.is_err());
    let mut none = changes(vec![("label", FieldValue::Text("x".into()))]);
    assert!(
        import_key_file_change(&ops, &mut none)
            .await
            .unwrap()
            .is_none()
    );
}
