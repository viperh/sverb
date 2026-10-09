//! (export file modes and refusal), T-17 (approvals at confirmation), one transaction.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use sverb_conn::forward::{ApprovalStore, MemoryApprovals, RiskyValue};
use sverb_conn::proxy::{Approval, COMMAND_FIELD, LocalApprovals, StampApprovals, ValueOrigin};
use sverb_core::importers::{ConflictPolicy, PlanStatus};
use sverb_core::model::{Host, ItemKind, Proxy};
use sverb_core::secret::SecretString;
use sverb_core::vault::{Argon2Cost, MemKeyring};
use sverb_store::Store;

use super::*;

const PW: &str = "correct horse battery staple 42";

struct Home(PathBuf);

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn service(tag: &str) -> (ImportService, Home) {
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "sverb-m2-11-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
    let store = Store::open_at(dir.join("sverb.db"), Arc::new(sverb_store::SystemClock))
        .unwrap_or_else(|e| panic!("{e}"));
    let engine = VaultEngine::new(store, Arc::new(MemKeyring::new()), Argon2Cost::TEST);
    let vault = engine
        .initialize(PW, false)
        .await
        .unwrap_or_else(|e| panic!("{e}"))
        .vault;
    (ImportService::new(engine, Arc::new(vault)), Home(dir))
}

fn fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(rel)
}

/// The database files' bytes (the "DB hash" of T-10, compared exactly).
fn db_hash(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut names: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| rd.filter_map(Result::ok).map(|e| e.path()).collect())
        .unwrap_or_default();
    names.sort();
    names
        .into_iter()
        .filter(|n| n.to_string_lossy().contains("sverb.db"))
        .map(|n| {
            let bytes = std::fs::read(&n).unwrap_or_default();
            (n, bytes)
        })
        .collect()
}

async fn apply(svc: &ImportService, source: &SourceSpec, policy: ConflictPolicy) -> ApplyReport {
    let plan = svc
        .preview(source, None, None)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    svc.apply(plan, None, None, policy, KeyChoice::default(), None)
        .await
        .unwrap_or_else(|e| panic!("{e}"))
}

#[tokio::test]
async fn t10_dry_run_writes_nothing() {
    let (svc, home) = service("t10").await;
    let source = SourceSpec::SshConfig(Some(fixture("ssh_config/wildcard")));
    // Settle the database (WAL checkpoint state) before hashing.
    let _ = svc.existing(None).await;
    let before = db_hash(&home.0);
    let plan = svc
        .preview(&source, None, None)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(plan.counts().new > 0);
    let _ = svc.preview(&source, None, None).await;
    assert_eq!(db_hash(&home.0), before);
    assert!(svc.items().await.unwrap_or_default().is_empty());
}

#[tokio::test]
async fn csv_import_then_duplicates() {
    let (svc, _home) = service("csv").await;
    let source = SourceSpec::Csv(fixture("csv/hosts.csv"));
    let report = apply(&svc, &source, ConflictPolicy::Skip).await;
    assert_eq!(report.created, 9);
    let items = svc.items().await.unwrap_or_default();
    assert_eq!(items.len(), 9);
    // Again: everything is a duplicate, nothing is written.
    let plan = svc
        .preview(&source, None, None)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(plan.counts().new, 0, "{}", plan.render_table());
    let report = svc
        .apply(
            plan,
            None,
            None,
            ConflictPolicy::Skip,
            KeyChoice::default(),
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(report.created, 0);
    assert_eq!(svc.items().await.unwrap_or_default().len(), 9);
}

#[tokio::test]
async fn t11_backup_roundtrip() {
    let (svc, home) = service("t11-a").await;
    apply(
        &svc,
        &SourceSpec::SshConfig(Some(fixture("ssh_config/proxyjump"))),
        ConflictPolicy::Skip,
    )
    .await;
    apply(
        &svc,
        &SourceSpec::Csv(fixture("csv/hosts.csv")),
        ConflictPolicy::Skip,
    )
    .await;
    let before = svc.items().await.unwrap_or_default();
    assert!(before.len() > 10);
    let file = home.0.join("all.sverb-backup");
    let kdf = BackupKdf {
        m_kib: sverb_crypto::kdf::Argon2Params::MIN_M_KIB,
        t: 1,
        p: 1,
    };
    let n = svc
        .export_backup(&file, SecretString::from(PW), false, false, kdf)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(n, before.len());
    let saved = std::env::temp_dir().join(format!("m2-11-t11-{}.sverb-backup", std::process::id()));
    std::fs::copy(&file, &saved).unwrap_or_else(|e| panic!("{e}"));
    drop(svc);
    drop(home); // wipe the home

    let (svc, _home2) = service("t11-b").await;
    let source = SourceSpec::Backup {
        path: saved.clone(),
        password: SecretString::from(PW),
    };
    let report = apply(&svc, &source, ConflictPolicy::Skip).await;
    let _ = std::fs::remove_file(&saved);
    assert_eq!(report.created, before.len());
    let after = svc.items().await.unwrap_or_default();
    assert_eq!(after.len(), before.len());
    for b in &before {
        let a = after
            .iter()
            .find(|a| a.id == b.id)
            .unwrap_or_else(|| panic!("{} missing", b.id));
        assert_eq!(a.body, b.body, "fields and stamps preserved");
    }
}

#[tokio::test]
async fn t14_export_modes_and_refusal() {
    let (svc, home) = service("t14").await;
    apply(
        &svc,
        &SourceSpec::Csv(fixture("csv/hosts.csv")),
        ConflictPolicy::Skip,
    )
    .await;
    let cfg = home.0.join("exported_config");
    let n = svc
        .export_ssh_config(&cfg, false)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(n, 3);
    let csv = home.0.join("hosts.csv");
    svc.export_csv(&csv, false)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let text = std::fs::read_to_string(&csv).unwrap_or_default();
    assert!(text.contains("Prod/Web"), "{text}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&cfg)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0);
        assert_eq!(mode, 0o600);
    }
    let err = svc.export_ssh_config(&cfg, false).await.err();
    assert!(err.is_some_and(|e| e.0.contains("already exists")));
    assert!(svc.export_ssh_config(&cfg, true).await.is_ok());
    let weak = svc
        .export_backup(
            &home.0.join("b"),
            SecretString::from("password"),
            false,
            false,
            BackupKdf::default(),
        )
        .await;
    assert!(weak.is_err());
    assert!(!home.0.join("b").exists());
}

#[tokio::test]
async fn t17_proxy_command_approved_at_confirmation() {
    let (svc, _home) = service("t17").await;
    let report = apply(
        &svc,
        &SourceSpec::SshConfig(Some(fixture("ssh_config/proxyjump"))),
        ConflictPolicy::Skip,
    )
    .await;
    let cmd = "ssh -W %h:%p bastion.example.com";
    let note = report
        .approvals
        .iter()
        .find(|a| a.field == "proxy.command")
        .unwrap_or_else(|| panic!("no approval: {:?}", report.approvals));
    assert_eq!(note.value, cmd);
    let items = svc.items().await.unwrap_or_default();
    let host = items
        .iter()
        .find(|i| i.id == note.item_id)
        .unwrap_or_else(|| panic!("host missing"));
    let h = Host::try_from(&host.body).unwrap_or_default();
    assert!(matches!(h.proxy, Some(Proxy::Command(ref c)) if c == cmd));
    let stamp = host.body.get_stamped("proxy.command").map(|s| s.device);
    let origin = ValueOrigin {
        item_id: Some(host.id),
        written_by: stamp,
        this_device: Some(svc.vault.device_id()),
    };
    assert_eq!(
        StampApprovals.check(COMMAND_FIELD, cmd, &origin),
        Approval::Approved
    );

    // Forwards: non-loopback binds go to the forward approval store.
    let store = MemoryApprovals::default();
    let plan = svc
        .preview(
            &SourceSpec::SshConfig(Some(fixture("ssh_config/forwards"))),
            None,
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let report = svc
        .apply(
            plan,
            None,
            None,
            ConflictPolicy::Skip,
            KeyChoice::default(),
            Some(&store),
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let n = report
        .approvals
        .iter()
        .find(|a| a.field == "bind_addr")
        .unwrap_or_else(|| panic!("none"));
    assert!(store.is_approved(&RiskyValue {
        rule: n.item_id,
        field: "bind_addr",
        value: "0.0.0.0:8080".to_owned(),
        synced: false,
    }));
}

#[tokio::test]
async fn conflict_overwrite_and_rollback() {
    let (svc, _home) = service("conflict").await;
    apply(
        &svc,
        &SourceSpec::Csv(fixture("csv/hosts.csv")),
        ConflictPolicy::Skip,
    )
    .await;
    let dir = svc.items().await.unwrap_or_default();
    let web = dir
        .iter()
        .find(|i| {
            i.body.kind == ItemKind::Host && Host::try_from(&i.body).is_ok_and(|h| h.label == "Web")
        })
        .map(|i| i.id);
    let tmp = std::env::temp_dir().join(format!("sverb-m2-11-conf-{}.csv", std::process::id()));
    std::fs::write(
        &tmp,
        "address,label,username,port\nweb.example.com,Web renamed,alice,22\n",
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let source = SourceSpec::Csv(tmp.clone());
    let plan = svc
        .preview(&source, None, None)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(matches!(plan.items[0].status, PlanStatus::Conflict(id, _) if Some(id) == web));
    let report = apply(&svc, &source, ConflictPolicy::Overwrite).await;
    let _ = std::fs::remove_file(&tmp);
    assert_eq!(report.updated, 1);
    let items = svc.items().await.unwrap_or_default();
    let h = items
        .iter()
        .find(|i| Some(i.id) == web)
        .map(|i| Host::try_from(&i.body).unwrap_or_default());
    assert_eq!(h.map(|h| h.label), Some("Web renamed".to_owned()));
}

#[tokio::test]
async fn identity_files_import_as_keys() {
    let (svc, home) = service("keys").await;
    let key = fixture("keys/openssh_ed25519");
    let cfg = home.0.join("config");
    std::fs::write(
        &cfg,
        format!(
            "Host a\n IdentityFile {}\nHost b\n IdentityFile {}\n",
            key.display(),
            key.display()
        ),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let source = SourceSpec::SshConfig(Some(cfg));
    let plan = svc
        .preview(&source, None, None)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let files = svc.identity_files(&plan);
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].state, IdentityFileState::Ready);
    let report = svc
        .apply(
            plan,
            None,
            None,
            ConflictPolicy::Skip,
            KeyChoice {
                import: true,
                ..KeyChoice::default()
            },
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(report.keys_imported, 1);
    let items = svc.items().await.unwrap_or_default();
    let key_id = items
        .iter()
        .find(|i| i.body.kind == ItemKind::Key)
        .map(|i| i.id);
    let hosts: Vec<Host> = items
        .iter()
        .filter(|i| i.body.kind == ItemKind::Host)
        .filter_map(|i| Host::try_from(&i.body).ok())
        .collect();
    assert_eq!(hosts.len(), 2);
    assert!(hosts.iter().all(|h| h.key_id == key_id && key_id.is_some()));
}
