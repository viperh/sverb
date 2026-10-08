//! M1-03 integration tests (T-01 … T-14; T-10 is a unit test in `device_local.rs`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sverb_core::model::{DeviceId, ItemId, VaultId};
use sverb_core::paths::{MapEnv, Paths};
use sverb_crypto::Key32;
use sverb_crypto::envelope::seal_item;
use sverb_crypto::random::os_rng;
use sverb_store::{
    Clock, ManualClock, RemoteItem, SCHEMA_VERSION, Store, StoreError, SyncState, VaultKind,
};

const KV: u32 = 1;

fn vk() -> Key32 {
    Key32::from_bytes([7; 32])
}

fn seal(vault: VaultId, item: ItemId, body: &[u8]) -> Vec<u8> {
    seal_item(
        &vk(),
        vault.as_bytes(),
        item.as_bytes(),
        KV,
        body,
        &mut os_rng(),
    )
    .unwrap()
}

fn open(dir: &Path) -> (Store, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new(1_000));
    let store = Store::open_at(dir.join("sverb.db"), clock.clone()).unwrap();
    (store, clock)
}

async fn with_vault(store: &Store) -> VaultId {
    let vault = VaultId::new();
    store
        .create_vault(vault, VaultKind::Personal, None, KV, vec![9; 72])
        .await
        .unwrap();
    vault
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

async fn table_names(store: &Store) -> Vec<String> {
    store
        .read(|r| {
            let mut stmt = r
                .conn()
                .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")?;
            let names = stmt
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(names)
        })
        .await
        .unwrap()
}

async fn user_version(store: &Store) -> i64 {
    store
        .read(|r| {
            Ok(r.conn()
                .query_row("PRAGMA user_version", [], |row| row.get(0))?)
        })
        .await
        .unwrap()
}

// T-01: fresh DB in a temp SVERB_HOME: 8 tables (M2-10: local_approvals; M5-03: pinned_keys), user_version 3, mode 0600.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t01_fresh_db() {
    let home = tempfile::tempdir().unwrap();
    let paths = Paths::resolve(&MapEnv::new().var("SVERB_HOME", home.path())).unwrap();
    let store = Store::open(&paths).unwrap();
    assert_eq!(store.path(), paths.db_file());

    let mut tables = table_names(&store).await;
    tables.retain(|t| !t.starts_with("sqlite_"));
    let mut expected: Vec<String> = sverb_store::schema::TABLES
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    expected.sort();
    assert_eq!(tables, expected);
    assert_eq!(user_version(&store).await, 3);
    assert_eq!(SCHEMA_VERSION, 3);

    // Force WAL/SHM to exist, then check modes.
    with_vault(&store).await;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let db = paths.db_file();
        for p in [db.clone(), sibling(&db, "-wal"), sibling(&db, "-shm")] {
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{}", p.display());
        }
    }
}

// T-02: PRAGMAs on the writer and on every reader.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t02_pragmas() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());

    fn pragmas(conn: &rusqlite::Connection) -> (String, i64, i64, i64, i64) {
        let q = |p: &str| -> i64 {
            conn.query_row(&format!("PRAGMA {p}"), [], |r| r.get(0))
                .unwrap()
        };
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        (
            mode,
            q("foreign_keys"),
            q("temp_store"),
            q("synchronous"),
            q("busy_timeout"),
        )
    }

    let w = store.write(|w| Ok(pragmas(w.conn()))).await.unwrap();
    assert_eq!(w, ("wal".to_owned(), 1, 2, 1, 5000));

    // Hold 4 reads open at once so each runs on a distinct pooled connection.
    let barrier = Arc::new(std::sync::Barrier::new(sverb_store::READER_POOL_SIZE));
    let mut handles = Vec::new();
    for _ in 0..sverb_store::READER_POOL_SIZE {
        let store = store.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            store
                .read(move |r| {
                    barrier.wait();
                    Ok(pragmas(r.conn()))
                })
                .await
                .unwrap()
        }));
    }
    for h in handles {
        assert_eq!(h.await.unwrap(), ("wal".to_owned(), 1, 2, 1, 5000));
    }
}

// T-03: a newer schema refuses to open and the file is byte-for-byte unchanged.
#[test]
fn t03_newer_schema_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sverb.db");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE future (x); PRAGMA user_version = 99;")
            .unwrap();
    }
    let before = std::fs::read(&path).unwrap();
    let err = Store::open_at(&path, Arc::new(ManualClock::new(0))).unwrap_err();
    match &err {
        StoreError::NewerSchema { found, supported } => {
            assert_eq!((*found, *supported), (99, 3));
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(
        err.to_string().contains(
            "This database was created by a newer sverb (schema 99). Please update sverb."
        )
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(!sibling(&path, "-wal").exists());
}

// T-04: a failing second migration leaves the DB at the latest version (3 since M5-03), no partial tables.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t04_migration_atomicity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sverb.db");
    drop(Store::open_at(&path, Arc::new(ManualClock::new(0))).unwrap());

    let err = Store::open_with_migrations(
        &path,
        Arc::new(ManualClock::new(0)),
        &["CREATE TABLE half_done (x); THIS IS NOT SQL;"],
    )
    .unwrap_err();
    assert!(matches!(err, StoreError::Sqlite(_)), "{err:?}");

    let (store, _) = open(dir.path());
    assert_eq!(user_version(&store).await, 3);
    assert!(!table_names(&store).await.contains(&"half_done".to_owned()));
}

// T-05: ten dirty writes, then a later enqueue with base 9 → one row, base 7.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t05_outbox_coalescing() {
    let dir = tempfile::tempdir().unwrap();
    let (store, clock) = open(dir.path());
    let vault = with_vault(&store).await;
    let item = ItemId::new();

    // The item is at server revision 7.
    let env = seal(vault, item, b"v0");
    store
        .apply_remote(
            vault,
            vec![RemoteItem {
                id: item,
                revision: 7,
                key_version: KV,
                envelope: env,
                deleted: false,
                local_pending: false,
            }],
            7,
        )
        .await
        .unwrap();

    for i in 0..10 {
        clock.advance(10);
        let env = seal(vault, item, format!("edit {i}").as_bytes());
        store
            .put_item(vault, item, KV, env, false, true)
            .await
            .unwrap();
    }
    // Simulate the revision moving to 9 underneath, then another edit.
    store
        .write(move |w| {
            w.conn().execute(
                "UPDATE items SET revision = 9 WHERE id = ?1",
                [item.as_bytes()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    clock.advance(10);
    store
        .put_item(vault, item, KV, seal(vault, item, b"edit 10"), false, true)
        .await
        .unwrap();
    store.enqueue(item, vault, 9).await.unwrap();

    let rows = store.list_outbox(vault).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].base_revision, 7);
    assert_eq!(rows[0].queued_at, clock.now_millis());
    assert_eq!(store.pending_count().await.unwrap(), 1);
    // M4-09
    assert_eq!(store.pending_by_vault().await.unwrap(), [(vault, 1)]);
    let dirty = store.list_dirty(vault).await.unwrap();
    assert_eq!(dirty.len(), 1);
    assert!(dirty[0].dirty);
}

// T-06: rebase updates the base; later enqueues keep it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t06_rebase() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    let vault = with_vault(&store).await;
    let item = ItemId::new();
    // M4-09: queuing a local change wakes outbox listeners (the sync engine).
    let mut changes = store.outbox_changes();
    assert!(!changes.has_changed().unwrap());
    store
        .put_item(vault, item, KV, seal(vault, item, b"a"), false, true)
        .await
        .unwrap();
    assert!(changes.has_changed().unwrap());
    changes.mark_unchanged();
    assert_eq!(store.list_outbox(vault).await.unwrap()[0].base_revision, 0);
    store.set_meta("x", vec![1]).await.unwrap();
    assert!(!changes.has_changed().unwrap(), "no outbox row, no wake-up");

    store.rebase(item, 12).await.unwrap();
    store
        .put_item(vault, item, KV, seal(vault, item, b"b"), false, true)
        .await
        .unwrap();
    store.enqueue(item, vault, 3).await.unwrap();
    assert_eq!(store.list_outbox(vault).await.unwrap()[0].base_revision, 12);

    assert!(matches!(
        store.rebase(ItemId::new(), 1).await,
        Err(StoreError::NotFound)
    ));
    assert_eq!(store.bump_attempts(item).await.unwrap(), 1);
    assert_eq!(store.bump_attempts(item).await.unwrap(), 2);
    store.dequeue(item).await.unwrap();
    assert_eq!(store.pending_count().await.unwrap(), 0);
    assert!(store.pending_by_vault().await.unwrap().is_empty());
}

// T-07: an error in the 3rd item of 5 rolls back the whole page and the cursor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t07_apply_remote_atomic() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    let vault = with_vault(&store).await;

    let mut page: Vec<RemoteItem> = (1..=5)
        .map(|rev| {
            let id = ItemId::new();
            RemoteItem {
                id,
                revision: rev,
                key_version: KV,
                envelope: seal(vault, id, b"remote"),
                deleted: false,
                local_pending: false,
            }
        })
        .collect();
    page[2].envelope = Vec::new(); // the 3rd item fails

    let err = store
        .apply_remote(vault, page.clone(), 5)
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::InvalidEnvelope(_)), "{err:?}");
    assert!(store.list_items(vault).await.unwrap().is_empty());
    assert_eq!(
        store.get_vault(vault).await.unwrap().unwrap().sync_cursor,
        0
    );

    // The fixed page applies fully.
    let id = page[2].id;
    page[2].envelope = seal(vault, id, b"remote");
    store.apply_remote(vault, page, 5).await.unwrap();
    assert_eq!(store.list_items(vault).await.unwrap().len(), 5);
    assert_eq!(
        store.get_vault(vault).await.unwrap().unwrap().sync_cursor,
        5
    );
}

// apply_remote with a merged dirty item keeps it dirty and rebases; mark_pushed
// cleans only when no newer edit happened.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn apply_remote_rebases_and_mark_pushed() {
    let dir = tempfile::tempdir().unwrap();
    let (store, clock) = open(dir.path());
    let vault = with_vault(&store).await;
    let item = ItemId::new();
    store
        .put_item(vault, item, KV, seal(vault, item, b"local"), false, true)
        .await
        .unwrap();

    let merged = RemoteItem {
        id: item,
        revision: 4,
        key_version: KV,
        envelope: seal(vault, item, b"merged"),
        deleted: false,
        local_pending: true,
    };
    store.apply_remote(vault, vec![merged], 4).await.unwrap();
    let row = store.get_item(item).await.unwrap().unwrap();
    assert!(row.dirty);
    assert_eq!(row.revision, 4);
    let ob = store.list_outbox(vault).await.unwrap();
    assert_eq!(ob[0].base_revision, 4);

    // Push of that state succeeds, but the user edited meanwhile → stays dirty.
    let pushed_at = ob[0].queued_at;
    clock.advance(5);
    store
        .put_item(vault, item, KV, seal(vault, item, b"newer"), false, true)
        .await
        .unwrap();
    store.mark_pushed(item, 5, pushed_at).await.unwrap();
    let row = store.get_item(item).await.unwrap().unwrap();
    assert!(row.dirty);
    let ob = store.list_outbox(vault).await.unwrap();
    assert_eq!(ob[0].base_revision, 5);

    // Pushing the latest state cleans it.
    store.mark_pushed(item, 6, ob[0].queued_at).await.unwrap();
    let row = store.get_item(item).await.unwrap().unwrap();
    assert!(!row.dirty);
    assert_eq!(row.revision, 6);
    assert_eq!(store.pending_count().await.unwrap(), 0);
}

// T-08: delete_vault removes its items and outbox rows in one transaction.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t08_delete_vault_cascade() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    let a = with_vault(&store).await;
    let b = with_vault(&store).await;
    for vault in [a, b] {
        for _ in 0..3 {
            let id = ItemId::new();
            store
                .put_item(vault, id, KV, seal(vault, id, b"x"), false, true)
                .await
                .unwrap();
            store.touch_connected(id, 1).await.unwrap();
        }
    }
    store.delete_vault(a).await.unwrap();

    assert!(store.list_items(a).await.unwrap().is_empty());
    assert!(store.list_outbox(a).await.unwrap().is_empty());
    assert_eq!(store.list_items(b).await.unwrap().len(), 3);
    assert_eq!(store.list_outbox(b).await.unwrap().len(), 3);
    assert_eq!(store.list_device_local().await.unwrap().len(), 3);
    assert_eq!(store.list_vaults().await.unwrap().len(), 1);
    assert!(matches!(
        store.delete_vault(a).await,
        Err(StoreError::NotFound)
    ));

    // Atomicity: a failing step after delete_vault inside the same transaction
    // leaves everything in place.
    let err = store
        .write(move |w| {
            w.delete_vault(b)?;
            Err::<(), _>(StoreError::Busy)
        })
        .await;
    assert!(err.is_err());
    assert_eq!(store.list_items(b).await.unwrap().len(), 3);
    assert_eq!(store.list_outbox(b).await.unwrap().len(), 3);
}

// T-09: 8 concurrent readers + 1 writer for 2 s; no BUSY, consistent counts.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn t09_concurrency() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    let vault = with_vault(&store).await;
    let deadline = Instant::now() + Duration::from_secs(2);

    let writer = {
        let store = store.clone();
        tokio::spawn(async move {
            let mut written = 0_u64;
            while Instant::now() < deadline {
                let id = ItemId::new();
                let env = seal(vault, id, b"payload");
                store
                    .put_item(vault, id, KV, env, false, true)
                    .await
                    .unwrap();
                written += 1;
            }
            written
        })
    };
    let mut readers = Vec::new();
    for _ in 0..8 {
        let store = store.clone();
        readers.push(tokio::spawn(async move {
            let mut last = 0_u64;
            let mut reads = 0_u64;
            while Instant::now() < deadline {
                let (items, outbox) = store
                    .read(move |r| Ok((r.list_items(vault)?.len() as u64, r.pending_count()?)))
                    .await
                    .unwrap();
                // One snapshot: every item is dirty and queued exactly once.
                assert_eq!(items, outbox);
                assert!(items >= last);
                last = items;
                reads += 1;
            }
            reads
        }));
    }
    let written = writer.await.unwrap();
    for r in readers {
        assert!(r.await.unwrap() > 0);
    }
    assert!(written > 0);
    assert_eq!(store.list_items(vault).await.unwrap().len() as u64, written);
    assert_eq!(store.pending_count().await.unwrap(), written);
}

// T-11: read-only items reject put_item.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t11_read_only_item() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    let vault = with_vault(&store).await;
    let item = ItemId::new();
    store
        .put_item(vault, item, KV, seal(vault, item, b"v1"), false, false)
        .await
        .unwrap();

    store.set_read_only(item, true);
    assert!(store.is_read_only(item));
    let err = store
        .put_item(vault, item, KV, seal(vault, item, b"v2"), false, true)
        .await
        .unwrap_err();
    assert!(
        matches!(err, StoreError::ReadOnlyItem(id) if id == item),
        "{err:?}"
    );
    assert_eq!(store.pending_count().await.unwrap(), 0);

    store.set_read_only(item, false);
    store
        .put_item(vault, item, KV, seal(vault, item, b"v2"), false, true)
        .await
        .unwrap();
}

fn assert_no_canary(path: &Path, canary: &[u8]) {
    for p in [
        path.to_path_buf(),
        sibling(path, "-wal"),
        sibling(path, "-shm"),
        sibling(path, "-journal"),
    ] {
        if let Ok(bytes) = std::fs::read(&p) {
            assert!(
                !bytes.windows(canary.len()).any(|w| w == canary),
                "canary found in {}",
                p.display()
            );
        }
    }
}

// T-12: no plaintext on disk (DB, WAL, SHM), also after the TEMP index.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t12_no_plaintext_on_disk() {
    const CANARY: &str = "PLAINTEXT-CANARY-42";
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    let vault = with_vault(&store).await;

    let mut rows = Vec::new();
    for i in 0..50 {
        let id = ItemId::new();
        let label = format!("{CANARY} host {i}");
        let body = format!("label={label};address={CANARY}.example.com");
        store
            .put_item(vault, id, KV, seal(vault, id, body.as_bytes()), false, true)
            .await
            .unwrap();
        rows.push(sverb_store::IndexRow {
            item_id: id,
            vault_id: vault,
            kind: 0,
            label,
            search: CANARY.to_owned(),
        });
    }
    // Plaintext is refused outright.
    let id = ItemId::new();
    let err = store
        .put_item(vault, id, KV, CANARY.as_bytes().to_vec(), false, true)
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::InvalidEnvelope(_)));
    assert_no_canary(store.path(), CANARY.as_bytes());

    store.rebuild_temp_index(rows).await.unwrap();
    let hits = store
        .query_temp_index("canary-42 host 7".to_owned())
        .await
        .unwrap();
    assert_eq!(hits.len(), 1);
    // More writes while the index exists, then a checkpoint.
    let id = ItemId::new();
    store
        .put_item(
            vault,
            id,
            KV,
            seal(vault, id, CANARY.as_bytes()),
            false,
            true,
        )
        .await
        .unwrap();
    {
        // Checkpoint from a separate connection so the main file is rewritten too.
        let conn = rusqlite::Connection::open(store.path()).unwrap();
        conn.query_row("PRAGMA wal_checkpoint(FULL)", [], |_| Ok(()))
            .unwrap();
    }
    assert_no_canary(store.path(), CANARY.as_bytes());

    // The index never shows up as a persistent table.
    let tables = table_names(&store).await;
    assert!(!tables.contains(&"item_index".to_owned()));

    store.drop_temp_index().await.unwrap();
    assert!(
        store
            .query_temp_index(CANARY.to_owned())
            .await
            .unwrap()
            .is_empty()
    );
    let path = store.path().to_path_buf();
    drop(store);
    assert_no_canary(&path, CANARY.as_bytes());
}

// T-13: random bytes → Corrupt with a helpful message, no panic.
#[test]
fn t13_corrupt_db() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sverb.db");
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let bytes: Vec<u8> = (0..8192)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect();
    std::fs::write(&path, &bytes).unwrap();
    let err = Store::open_at(&path, Arc::new(ManualClock::new(0))).unwrap_err();
    assert!(matches!(err, StoreError::Corrupt(_)), "{err:?}");
    let msg = err.to_string();
    assert!(msg.contains("backup"), "{msg}");
    assert!(msg.contains("sverb.db"), "{msg}");
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

// T-14: sync_state is a singleton; the API only touches row 1.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t14_sync_state_singleton() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    assert_eq!(store.get_sync_state().await.unwrap(), None);

    let state = SyncState {
        server_url: Some("https://sync.example".into()),
        device_id: Some(DeviceId::new()),
        tokens_enc: Some(vec![1, 2, 3]),
    };
    store.set_sync_state(state.clone()).await.unwrap();
    let state2 = SyncState {
        tokens_enc: Some(vec![4]),
        ..state.clone()
    };
    store.set_sync_state(state2.clone()).await.unwrap();
    assert_eq!(store.get_sync_state().await.unwrap(), Some(state2));

    let err = store
        .write(|w| {
            w.conn().execute(
                "INSERT INTO sync_state (id, server_url) VALUES (2, 'x')",
                [],
            )?;
            Ok(())
        })
        .await
        .unwrap_err();
    match err {
        StoreError::Sqlite(e) => {
            assert_eq!(
                e.sqlite_error_code(),
                Some(rusqlite::ErrorCode::ConstraintViolation)
            );
        }
        other => panic!("unexpected {other:?}"),
    }
    let n: i64 = store
        .read(|r| {
            Ok(r.conn()
                .query_row("SELECT COUNT(*) FROM sync_state", [], |row| row.get(0))?)
        })
        .await
        .unwrap();
    assert_eq!(n, 1);
}

// meta and device_local round trips.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn meta_and_device_local() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = open(dir.path());
    use sverb_store::meta::keys;
    assert_eq!(store.get_meta(keys::KDF).await.unwrap(), None);
    store.set_meta(keys::KDF, vec![1, 2]).await.unwrap();
    store.set_meta(keys::KDF, vec![3]).await.unwrap();
    assert_eq!(store.get_meta(keys::KDF).await.unwrap(), Some(vec![3]));
    store.delete_meta(keys::KDF).await.unwrap();
    assert_eq!(store.get_meta(keys::KDF).await.unwrap(), None);

    let item = ItemId::new();
    const DAY: i64 = 86_400_000;
    assert!((store.touch_connected(item, 0).await.unwrap() - 1.0).abs() < 1e-9);
    assert!((store.touch_connected(item, 14 * DAY).await.unwrap() - 1.5).abs() < 1e-9);
    store
        .set_recording_dir(item, Some("/rec".into()))
        .await
        .unwrap();
    let dl = store.get_device_local(item).await.unwrap().unwrap();
    assert_eq!(dl.last_connected_at, Some(14 * DAY));
    assert_eq!(dl.recording_dir.as_deref(), Some("/rec"));
    assert!((dl.score_at(28 * DAY) - 0.75).abs() < 1e-9);

    // Data survives a reopen.
    drop(store);
    let (store, _) = open(dir.path());
    assert!(store.get_device_local(item).await.unwrap().is_some());
}
