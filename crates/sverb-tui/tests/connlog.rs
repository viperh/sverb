//! , retention, deleting with the recording (T-08, service
//! side). Small Argon2 parameters and an in-memory keyring.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sverb_conn::{
    Attempt, AttemptEnd, AttemptOutcome, ConnLogSink, DisconnectReason, SessionId, TransportKind,
};
use sverb_core::error_report::ErrorReport;
use sverb_core::model::{ConnLog, ConnResult, ItemId, UnixMillis, VaultId};
use sverb_core::vault::{Argon2Cost, MemKeyring};
use sverb_store::{ManualClock, Store};
use sverb_tui::app::{
    ConnLogEvent, LogsEffect, UiEvent, UnlockRequest, VaultEffect, VaultEvent, VaultPassword,
};
use sverb_tui::services::connlog::{ConnLogService, persist};
use sverb_tui::services::vault::{VaultEngine, VaultService};
use sverb_tui::views::logs::LogEntry;
use tokio::sync::mpsc::{Receiver, channel};

const PW: &str = "correct horse battery staple violin";
/// The store's clock (2027-01-15).
const T0: i64 = 1_800_000_000_000;
const DAY: i64 = 86_400_000;

struct Fixture {
    dir: PathBuf,
    vault: VaultService,
    store: Store,
    personal: VaultId,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn fixture(tag: &str) -> Fixture {
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "m3-06-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let clock = Arc::new(ManualClock::new(T0));
    let store = Store::open_at(dir.join("sverb.db"), clock).unwrap();
    let engine = VaultEngine::new(store.clone(), Arc::new(MemKeyring::new()), Argon2Cost::TEST);
    let init = engine.initialize(PW, false).await.unwrap();
    let personal = init.vault.personal_vault().unwrap();
    drop(init);
    let vault = VaultService::new(engine);
    let (tx, mut rx) = channel(16);
    vault.execute(
        VaultEffect::Unlock(UnlockRequest::Password(VaultPassword::from(PW))),
        &tx,
    );
    while let Some(ev) = rx.recv().await {
        if matches!(ev, UiEvent::Vault(VaultEvent::Unlocked { .. })) {
            break;
        }
    }
    assert!(vault.is_unlocked());
    Fixture {
        dir,
        vault,
        store,
        personal,
    }
}

/// The next ConnLog event matching `pred` (others are skipped).
async fn wait(rx: &mut Receiver<UiEvent>, pred: impl Fn(&ConnLogEvent) -> bool) -> ConnLogEvent {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(UiEvent::ConnLog(ev)) = rx.recv().await
                && pred(&ev)
            {
                return ev;
            }
        }
    })
    .await
    .expect("timed out waiting for a ConnLog event")
}

/// The final `Upserted` of entry `id`.
async fn finalized(rx: &mut Receiver<UiEvent>, id: ItemId) -> LogEntry {
    let ConnLogEvent::Upserted(entry) = wait(
        rx,
        |ev| matches!(ev, ConnLogEvent::Upserted(e) if e.id == id && e.log.result.is_some()),
    )
    .await
    else {
        unreachable!()
    };
    entry
}

/// The stored, decrypted entry.
async fn stored(fx: &Fixture, id: ItemId) -> (ConnLog, bool) {
    let row = fx.store.get_item(id).await.unwrap().expect("no row");
    let body = fx.vault.unlocked().unwrap().open(&row).unwrap();
    (ConnLog::try_from(&body).unwrap(), row.deleted)
}

async fn outbox(fx: &Fixture) -> Vec<ItemId> {
    fx.store
        .list_outbox(fx.personal)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.item_id)
        .collect()
}

fn attempt(label: &str, target: Option<&str>) -> Attempt {
    Attempt {
        kind: TransportKind::Ssh,
        host_id: None,
        label: label.to_owned(),
        target: target.map(str::to_owned),
        started_at: UnixMillis::now(),
    }
}

fn end(outcome: AttemptOutcome, bytes: (u64, u64), error: Option<ErrorReport>) -> AttemptEnd {
    AttemptEnd {
        outcome,
        ended_at: UnixMillis::now(),
        bytes_in: bytes.0,
        bytes_out: bytes.1,
        error,
    }
}

/// Run one attempt through the sink; returns its id.
async fn run_attempt(
    svc: &ConnLogService,
    rx: &mut Receiver<UiEvent>,
    session: u64,
    outcome: AttemptOutcome,
    error: Option<ErrorReport>,
) -> ItemId {
    svc.attempt_started(SessionId(session), attempt("db", Some("root@db:22")));
    let ConnLogEvent::Started { id, .. } =
        wait(rx, |ev| matches!(ev, ConnLogEvent::Started { .. })).await
    else {
        unreachable!()
    };
    svc.attempt_ended(SessionId(session), end(outcome, (10, 2), error));
    finalized(rx, id).await;
    id
}

/// A successful (local) session → `Ok` with `ended_at` and non-zero bytes.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t02_successful_session_is_logged_ok() {
    use sverb_conn::{LocalConnector, LocalOptions, LocalSpec, SessionManager, SessionSpec};

    let fx = fixture("t02").await;
    let (tx, mut rx) = channel(64);
    let svc = ConnLogService::new(Some(fx.vault.clone()), tx, false);
    let (sess_tx, _sess_rx) = tokio::sync::mpsc::unbounded_channel();
    let manager = SessionManager::new(sess_tx);
    manager.register_connector(
        TransportKind::Local,
        Arc::new(LocalConnector::new(LocalOptions::default())),
    );
    manager.set_connlog_sink(Arc::new(svc.clone()));
    // A "shell" that prints its working directory and exits 0.
    let spec = LocalSpec {
        shell: Some("/bin/pwd".to_owned()),
        ..LocalSpec::default()
    };
    let handle = manager.open(SessionSpec::Local(spec)).unwrap();
    let ConnLogEvent::Started { session, id } =
        wait(&mut rx, |ev| matches!(ev, ConnLogEvent::Started { .. })).await
    else {
        unreachable!()
    };
    assert_eq!(session.0, handle.id.0);
    let entry = finalized(&mut rx, id).await;
    assert_eq!(entry.log.result, Some(ConnResult::Ok));
    assert!(entry.log.ended_at.is_some());
    assert!(entry.log.bytes_in > 0, "{:?}", entry.log);
    assert_eq!(entry.log.label, "local");
    assert_eq!(entry.log.host_id, None);
    let (log, deleted) = stored(&fx, id).await;
    assert!(!deleted);
    assert_eq!(log, entry.log, "what the UI shows is what is stored");
    manager.shutdown(Duration::from_secs(2)).await;
    svc.shutdown().await;
}

/// An authentication failure → `AuthFailed` with the error detail (the actor
/// side, a connector returning `ConnectError { Auth, report }`, is covered in
/// `sverb-conn`'s `connlog::actor_tests`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t03_auth_failure_has_error_detail() {
    let fx = fixture("t03").await;
    let (tx, mut rx) = channel(64);
    let svc = ConnLogService::new(Some(fx.vault.clone()), tx, false);
    let report = ErrorReport::from_messages(["Permission denied", "tried: publickey, password"]);
    let id = run_attempt(
        &svc,
        &mut rx,
        1,
        AttemptOutcome::Disconnected(DisconnectReason::Auth),
        Some(report),
    )
    .await;
    let (log, _) = stored(&fx, id).await;
    assert_eq!(log.result, Some(ConnResult::AuthFailed));
    assert_eq!(
        log.error_detail,
        Some(vec![
            "Permission denied".to_owned(),
            "tried: publickey, password".to_owned()
        ])
    );
    assert_eq!(log.target.as_deref(), Some("root@db:22"));
    assert_eq!((log.bytes_in, log.bytes_out), (10, 2));
    svc.shutdown().await;
}

/// `logs.sync = false` → no outbox row; `true` → queued.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t04_outbox_only_with_logs_sync() {
    let fx = fixture("t04").await;
    let (tx, mut rx) = channel(64);
    let svc = ConnLogService::new(Some(fx.vault.clone()), tx, false);
    let ok = AttemptOutcome::UserClosed { connected: true };
    let local = run_attempt(&svc, &mut rx, 1, ok, None).await;
    assert!(stored(&fx, local).await.0.result == Some(ConnResult::Ok));
    assert_eq!(outbox(&fx).await, Vec::<ItemId>::new());
    assert_eq!(fx.store.pending_count().await.unwrap(), 0);

    svc.execute(LogsEffect::SetSync(true));
    let synced = run_attempt(&svc, &mut rx, 2, ok, None).await;
    assert_eq!(
        outbox(&fx).await,
        vec![synced],
        "only the entry written with sync on"
    );
    svc.shutdown().await;
}

/// Retention 90 days tombstones a 100-day-old entry and keeps a 10-day-old one;
/// retention 0 keeps everything.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t05_retention() {
    let fx = fixture("t05").await;
    let unlocked = fx.vault.unlocked().unwrap();
    let mut clock = unlocked.hlc();
    let (old, recent) = (ItemId::new(), ItemId::new());
    for (id, age) in [(old, 100), (recent, 10)] {
        let log = ConnLog {
            label: format!("{age} days"),
            started_at: UnixMillis(T0 - age * DAY),
            ended_at: Some(UnixMillis(T0 - age * DAY + 1000)),
            result: Some(ConnResult::Ok),
            ..ConnLog::default()
        };
        persist(&fx.store, &unlocked, &mut clock, false, id, &log)
            .await
            .unwrap();
    }
    let (tx, mut rx) = channel(64);
    let svc = ConnLogService::new(Some(fx.vault.clone()), tx, false);

    // Retention 0: kept.
    svc.execute(LogsEffect::Maintain {
        logs_retention_days: 0,
        recording_retention_days: 0,
    });
    let ev = wait(&mut rx, |ev| matches!(ev, ConnLogEvent::Maintained { .. })).await;
    assert_eq!(
        ev,
        ConnLogEvent::Maintained {
            tombstoned: 0,
            recordings_deleted: 0
        }
    );
    let ConnLogEvent::Loaded(entries) =
        wait(&mut rx, |ev| matches!(ev, ConnLogEvent::Loaded(_))).await
    else {
        unreachable!()
    };
    assert_eq!(entries.len(), 2);

    // Retention 90: the old one is tombstoned.
    svc.execute(LogsEffect::Maintain {
        logs_retention_days: 90,
        recording_retention_days: 0,
    });
    let ev = wait(&mut rx, |ev| matches!(ev, ConnLogEvent::Maintained { .. })).await;
    assert_eq!(
        ev,
        ConnLogEvent::Maintained {
            tombstoned: 1,
            recordings_deleted: 0
        }
    );
    let ConnLogEvent::Loaded(entries) =
        wait(&mut rx, |ev| matches!(ev, ConnLogEvent::Loaded(_))).await
    else {
        unreachable!()
    };
    assert_eq!(entries.iter().map(|e| e.id).collect::<Vec<_>>(), [recent]);
    assert!(fx.store.get_item(old).await.unwrap().unwrap().deleted);
    assert!(!fx.store.get_item(recent).await.unwrap().unwrap().deleted);
    // Not synced (logs.sync off): the tombstone stays local.
    assert!(outbox(&fx).await.is_empty());
    svc.shutdown().await;
}

/// T-08 (service side): deleting with "also delete recording" removes the file and its
/// `device_local` path; the entry is tombstoned.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t08_delete_removes_the_recording() {
    let fx = fixture("t08").await;
    let (tx, mut rx) = channel(64);
    let svc = ConnLogService::new(Some(fx.vault.clone()), tx, false);
    // A recording started with the session is named after the session's next entry.
    let reserved = svc.recording_id(sverb_tui::app::SessionId(1));
    let rec = fx.dir.join("rec.cast.sv");
    std::fs::write(&rec, b"ciphertext").unwrap();
    svc.set_recording(reserved, rec.clone());
    let ok = AttemptOutcome::UserClosed { connected: true };
    let id = run_attempt(&svc, &mut rx, 1, ok, None).await;
    assert_eq!(id, reserved, "the attempt took the reserved id");
    assert_eq!(
        fx.store
            .get_device_local(id)
            .await
            .unwrap()
            .and_then(|r| r.recording_dir),
        Some(rec.display().to_string())
    );

    svc.execute(LogsEffect::Delete {
        ids: vec![id],
        delete_recordings: true,
    });
    let ev = wait(&mut rx, |ev| matches!(ev, ConnLogEvent::Removed(_))).await;
    assert_eq!(ev, ConnLogEvent::Removed(vec![id]));
    assert!(!rec.exists(), "the recording is gone");
    assert_eq!(
        fx.store
            .get_device_local(id)
            .await
            .unwrap()
            .and_then(|r| r.recording_dir),
        None
    );
    assert!(stored(&fx, id).await.1, "tombstoned");

    // Keeping the recording leaves the file.
    let id2 = run_attempt(&svc, &mut rx, 2, ok, None).await;
    let rec2 = fx.dir.join("rec2.cast.sv");
    std::fs::write(&rec2, b"ciphertext").unwrap();
    svc.set_recording(id2, rec2.clone());
    svc.execute(LogsEffect::Delete {
        ids: vec![id2],
        delete_recordings: false,
    });
    wait(&mut rx, |ev| matches!(ev, ConnLogEvent::Removed(_))).await;
    assert!(rec2.exists());
    svc.shutdown().await;
}

/// Entries of attempts made while the vault is locked are written after unlock.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn locked_attempts_are_written_after_unlock() {
    let fx = fixture("locked").await;
    let (tx, mut rx) = channel(64);
    let svc = ConnLogService::new(Some(fx.vault.clone()), tx, false);
    fx.vault.lock();
    let ok = AttemptOutcome::UserClosed { connected: true };
    let id = run_attempt(&svc, &mut rx, 1, ok, None).await;
    assert!(
        fx.store.get_item(id).await.unwrap().is_none(),
        "not written while locked"
    );

    let (vtx, mut vrx) = channel(16);
    fx.vault.execute(
        VaultEffect::Unlock(UnlockRequest::Password(VaultPassword::from(PW))),
        &vtx,
    );
    while let Some(ev) = vrx.recv().await {
        if matches!(ev, UiEvent::Vault(VaultEvent::Unlocked { .. })) {
            break;
        }
    }
    // (Retention 0: the attempt's real-time `started_at` predates the store's test clock.)
    svc.execute(LogsEffect::Maintain {
        logs_retention_days: 0,
        recording_retention_days: 0,
    });
    let ConnLogEvent::Loaded(entries) =
        wait(&mut rx, |ev| matches!(ev, ConnLogEvent::Loaded(_))).await
    else {
        unreachable!()
    };
    assert_eq!(entries.iter().map(|e| e.id).collect::<Vec<_>>(), [id]);
    assert_eq!(stored(&fx, id).await.0.result, Some(ConnResult::Ok));
    svc.shutdown().await;
}
