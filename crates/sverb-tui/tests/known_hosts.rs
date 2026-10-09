//! replaces and reloads KnownHost items (T-13 with `hash_known_hosts`); the Known
//! Hosts view's import and export. Small Argon2 parameters, in-memory keyring, files
//! in the target's temp dir (never the user's `~/.ssh`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sverb_conn::ssh::{HostKeyTarget, HostKeyVerifier, KnownHostsStore, ServerKey};
use sverb_core::config::Config;
use sverb_core::known_hosts::{hashed, lookup, parse_known_hosts};
use sverb_core::model::{ItemKind, KnownHost, KnownHostMarker};
use sverb_core::vault::{Argon2Cost, MemKeyring};
use sverb_store::{ManualClock, Store};
use sverb_tui::app::{
    KnownHostsEffect, KnownHostsEvent, UiEvent, UnlockRequest, VaultEffect, VaultPassword,
};
use sverb_tui::services::known_hosts::{VaultKnownHosts, execute, verifier};
use sverb_tui::services::vault::items::ItemOps;
use sverb_tui::services::vault::{VaultEngine, VaultService};
use tokio::sync::mpsc;

const PW: &str = "correct horse battery staple violin";
const ED1: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBhYxpK5M9dWWLkngJsG1h11alcrHTyZO7bn447uw5it";
const ED2: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEIsaL0r6CYoLA9Pw7UTwU0s+Jt/BSebghUqZ1D8Q7Tg";

struct Fixture {
    dir: PathBuf,
    clock: Arc<ManualClock>,
    keyring: MemKeyring,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "m1-15-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self {
            dir,
            clock: Arc::new(ManualClock::new(1_800_000_000_000)),
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

async fn unlocked(fx: &Fixture) -> (VaultService, ItemOps) {
    fx.engine().initialize(PW, false).await.unwrap();
    let service = VaultService::new(fx.engine());
    let (tx, mut rx) = mpsc::channel(64);
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

async fn known(ops: &ItemOps) -> Vec<KnownHost> {
    ops.list(&[ItemKind::KnownHost])
        .await
        .unwrap()
        .iter()
        .map(|i| KnownHost::try_from(&i.body).unwrap())
        .collect()
}

/// The next `UiEvent::KnownHosts`.
async fn next_event(rx: &mut mpsc::Receiver<UiEvent>) -> KnownHostsEvent {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let UiEvent::KnownHosts(ev) = rx.recv().await.unwrap() {
                return ev;
            }
        }
    })
    .await
    .unwrap()
}

fn server_key(line: &str) -> ServerKey {
    let info = sverb_core::known_hosts::PresentedKey::from_openssh(line)
        .unwrap()
        .info();
    ServerKey {
        key_type: info.key_type,
        fingerprint: info.fingerprint,
        openssh: line.to_owned(),
        certificate: false,
    }
}

/// Accept & save writes a KnownHost item; replacing a changed key deletes the old one;
/// the next connection's `prepare` reloads them.
#[tokio::test]
async fn verifier_saves_replaces_and_reloads() {
    let fx = Fixture::new("save");
    let (vault, ops) = unlocked(&fx).await;
    let (tx, mut rx) = mpsc::channel(64);
    let v = verifier(Some(vault.clone()), &Config::default(), Some(tx));
    let target = HostKeyTarget {
        host: "db.example".into(),
        port: 2222,
    };

    v.remember(&target, &server_key(ED1));
    assert!(matches!(
        next_event(&mut rx).await,
        KnownHostsEvent::Saved { ref host, auto: false } if host == "[db.example]:2222"
    ));
    let saved = known(&ops).await;
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].host_pattern, "[db.example]:2222");
    assert_eq!(v.known_key_types(&target), ["ssh-ed25519"]);

    // A fresh store sees it after `prepare`.
    let (tx2, _rx2) = mpsc::channel(64);
    let v2 = verifier(Some(vault.clone()), &Config::default(), Some(tx2));
    assert!(v2.known_key_types(&target).is_empty());
    v2.prepare(&target).await;
    assert_eq!(v2.known_key_types(&target), ["ssh-ed25519"]);

    // The key changed and the user replaced it: one entry, the new key.
    v2.remember(&target, &server_key(ED2));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let entries = known(&ops).await;
        if entries.len() == 1 && ED2.ends_with(&entries[0].public_key) {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "{entries:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// With `ssh.hash_known_hosts = true` the saved entry is hashed and matches on
/// lookup.
#[tokio::test]
async fn t13_hashed_saves() {
    let fx = Fixture::new("hash");
    let (vault, ops) = unlocked(&fx).await;
    let mut config = Config::default();
    config.ssh.hash_known_hosts = true;
    let (tx, mut rx) = mpsc::channel(64);
    let v = verifier(Some(vault), &config, Some(tx));
    let target = HostKeyTarget {
        host: "secret.example".into(),
        port: 22,
    };
    v.remember(&target, &server_key(ED1));
    let _ = next_event(&mut rx).await;
    let saved = known(&ops).await;
    assert_eq!(saved.len(), 1);
    assert!(hashed::is_hashed(&saved[0].host_pattern), "{saved:?}");
    assert!(!saved[0].host_pattern.contains("secret"));
    assert_eq!(lookup(&saved, "secret.example", 22).matching.len(), 1);
    assert!(lookup(&saved, "other.example", 22).is_empty());
}

/// The view's import (duplicates and malformed lines skipped) and export.
#[tokio::test]
async fn import_and_export() {
    let fx = Fixture::new("io");
    let (vault, ops) = unlocked(&fx).await;
    let (tx, mut rx) = mpsc::channel(64);
    let source = fx.dir.join("known_hosts");
    std::fs::write(
        &source,
        format!(
            "# test\na.example {ED1}\na.example {ED1}\n@cert-authority *.test {ED2} ca\nbroken ssh-ed25519\n"
        ),
    )
    .unwrap();
    execute(
        Some(&vault),
        KnownHostsEffect::Import {
            path: source.display().to_string(),
        },
        &tx,
    );
    assert_eq!(
        next_event(&mut rx).await,
        KnownHostsEvent::Imported {
            added: 2,
            skipped: 1,
            warnings: 1
        }
    );
    let entries = known(&ops).await;
    assert_eq!(entries.len(), 2);
    assert!(
        entries
            .iter()
            .any(|e| e.marker == KnownHostMarker::CertAuthority)
    );

    // Importing again adds nothing.
    execute(
        Some(&vault),
        KnownHostsEffect::Import {
            path: source.display().to_string(),
        },
        &tx,
    );
    assert!(matches!(
        next_event(&mut rx).await,
        KnownHostsEvent::Imported {
            added: 0,
            skipped: 3,
            ..
        }
    ));

    let target = fx.dir.join("exported");
    execute(
        Some(&vault),
        KnownHostsEffect::Export {
            path: target.display().to_string(),
        },
        &tx,
    );
    assert!(matches!(
        next_event(&mut rx).await,
        KnownHostsEvent::Exported { count: 2, .. }
    ));
    let (back, warnings) = parse_known_hosts(&std::fs::read_to_string(&target).unwrap());
    assert!(warnings.is_empty());
    assert_eq!(back.len(), 2);

    // Load lists them for the view.
    execute(Some(&vault), KnownHostsEffect::Load, &tx);
    assert!(matches!(
        next_event(&mut rx).await,
        KnownHostsEvent::Loaded(ref list) if list.len() == 2
    ));

    // A missing file is an error, not a panic.
    execute(
        Some(&vault),
        KnownHostsEffect::Import {
            path: fx.dir.join("missing").display().to_string(),
        },
        &tx,
    );
    assert!(matches!(
        next_event(&mut rx).await,
        KnownHostsEvent::Failed(_)
    ));
}

/// Without a vault the store keeps saves in memory (quick connects before unlock).
#[tokio::test]
async fn memory_only_without_a_vault() {
    let store = VaultKnownHosts::new(None, None);
    let entry = KnownHost {
        host_pattern: "h".into(),
        key_type: "ssh-ed25519".into(),
        public_key: ED1.split_whitespace().nth(1).unwrap().into(),
        ..KnownHost::default()
    };
    store.save("h", entry.clone(), Vec::new(), false);
    store.refresh().await;
    assert_eq!(store.entries(), [entry]);
}
