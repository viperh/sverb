//! Connection management: one writer behind a `tokio::sync::Mutex`,
//! a pool of [`READER_POOL_SIZE`] read-only connections, and the PRAGMAs every
//! connection gets.
//!
//! All SQLite work runs in `tokio::task::spawn_blocking`. Writes go through
//! [`Store::write`], which holds the writer mutex for the whole (IMMEDIATE)
//! transaction; reads go through [`Store::read`], which borrows a pooled reader
//! and runs the closure inside a deferred transaction (one consistent snapshot).

use std::collections::HashSet;
use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Mutex, RwLock};
use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use sverb_core::model::ItemId;
use sverb_core::paths::Paths;
use tokio::sync::Semaphore;

use crate::clock::{Clock, SystemClock};
use crate::error::{Result, StoreError};
use crate::schema::{self, SCHEMA_VERSION};

/// Number of pooled reader connections.
pub const READER_POOL_SIZE: usize = 4;

/// `PRAGMA busy_timeout`, in milliseconds.
pub const BUSY_TIMEOUT_MS: u64 = 5000;

/// The client database.
///
/// Cheap to clone; all clones share the same connections.
#[derive(Clone)]
pub struct Store {
    pub(crate) inner: Arc<Inner>,
}

pub(crate) struct Inner {
    path: PathBuf,
    writer: Arc<tokio::sync::Mutex<Connection>>,
    readers: Mutex<Vec<Connection>>,
    reader_permits: Arc<Semaphore>,
    clock: Arc<dyn Clock>,
    /// Items whose decrypted body has a newer item schema than this build
    /// (`sverb_core::model::migrate::is_read_only`). Filled by the vault service
    /// after decrypting; in memory only, rebuilt on every unlock.
    read_only: RwLock<HashSet<ItemId>>,
    /// The device's `local_approvals`, in memory (§17.1); persists through a weak
    /// handle back to this store (`approvals::StoreSink`).
    pub(crate) approvals: Arc<sverb_core::resolve::approval::DeviceApprovals>,
    /// Bumped after every committed write that queued an outbox row
    /// ([`Store::outbox_changes`]).
    outbox: tokio::sync::watch::Sender<u64>,
}

/// A non-owning handle to a [`Store`] (no reference cycle through its approvals).
#[derive(Clone)]
pub(crate) struct WeakStore(std::sync::Weak<Inner>);

impl WeakStore {
    pub(crate) fn upgrade(&self) -> Option<Store> {
        self.0.upgrade().map(|inner| Store { inner })
    }
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store")
            .field("path", &self.inner.path)
            .field("clock", &self.inner.clock)
            .finish_non_exhaustive()
    }
}

/// Read access inside [`Store::read`] (or [`WriteTx::as_read`]).
///
/// Repository read methods (`get_item`, `list_vaults`, …) are defined on this
/// type in their modules.
#[derive(Clone, Copy)]
pub struct ReadTx<'a> {
    pub(crate) conn: &'a Connection,
}

impl fmt::Debug for ReadTx<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadTx").finish_non_exhaustive()
    }
}

impl<'a> ReadTx<'a> {
    /// The raw connection, for queries the repository API does not cover.
    pub fn conn(&self) -> &'a Connection {
        self.conn
    }
}

/// One write transaction inside [`Store::write`]. Committed when the closure
/// returns `Ok`, rolled back when it returns `Err` (or panics).
///
/// Repository write methods (`put_item`, `enqueue`, `set_meta`, …) are defined on
/// this type in their modules, so callers can combine several in one transaction.
pub struct WriteTx<'a> {
    pub(crate) conn: &'a Connection,
    pub(crate) now: i64,
    pub(crate) read_only: &'a RwLock<HashSet<ItemId>>,
    /// Set when this transaction queued an outbox row.
    pub(crate) enqueued: &'a std::cell::Cell<bool>,
}

impl fmt::Debug for WriteTx<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WriteTx")
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

impl WriteTx<'_> {
    /// The raw connection (inside the transaction), for statements the repository
    /// API does not cover. Never write decrypted data to a non-TEMP table.
    pub fn conn(&self) -> &Connection {
        self.conn
    }

    /// The transaction's timestamp (UNIX ms from the store's clock, read once
    /// when the transaction started).
    pub fn now(&self) -> i64 {
        self.now
    }

    /// Read access inside this transaction (sees its uncommitted writes).
    pub fn as_read(&self) -> ReadTx<'_> {
        ReadTx { conn: self.conn }
    }

    pub(crate) fn ensure_writable(&self, item: ItemId) -> Result<()> {
        if self.read_only.read().contains(&item) {
            return Err(StoreError::ReadOnlyItem(item));
        }
        Ok(())
    }
}

impl Store {
    /// Opens (creating and migrating if needed) the database at
    /// [`Paths::db_file`], with the system clock.
    ///
    /// This blocks (file I/O and migrations); from async code call it inside
    /// `spawn_blocking`.
    ///
    /// # Errors
    /// [`StoreError::NewerSchema`] (file untouched), [`StoreError::Corrupt`],
    /// [`StoreError::Io`] or a SQLite/migration error.
    pub fn open(paths: &Paths) -> Result<Self> {
        Self::open_at(paths.db_file(), Arc::new(SystemClock))
    }

    /// Opens the database at `path` with an explicit clock.
    ///
    /// # Errors
    /// As [`Store::open`].
    pub fn open_at(path: impl AsRef<Path>, clock: Arc<dyn Clock>) -> Result<Self> {
        Self::open_with_migrations(path, clock, &[])
    }

    /// [`Store::open_at`] with extra migrations appended after the built-in ones.
    /// Test hook; not part of the stable API.
    ///
    /// # Errors
    /// As [`Store::open`].
    #[doc(hidden)]
    pub fn open_with_migrations(
        path: impl AsRef<Path>,
        clock: Arc<dyn Clock>,
        extra: &[&'static str],
    ) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        open_inner(&path, clock, extra).map_err(|e| match e {
            StoreError::Corrupt(reason) => {
                StoreError::Corrupt(format!("{} ({reason})", path.display()))
            }
            other => other,
        })
    }

    /// The database file path.
    pub fn path(&self) -> &Path {
        &self.inner.path
    }

    /// Changes whenever a committed write queued an outbox row (a local change to
    /// push). The sync engine's push debounce listens to it.
    pub fn outbox_changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.inner.outbox.subscribe()
    }

    /// The current time from the store's clock (UNIX ms).
    pub fn now(&self) -> i64 {
        self.inner.clock.now_millis()
    }

    /// Runs `f` in one IMMEDIATE write transaction on the writer connection.
    ///
    /// The writer mutex is held for the whole call, so writes are serialized.
    /// `Ok` commits, `Err` rolls back. A panic in `f` rolls back and is resumed in
    /// the caller.
    ///
    /// # Errors
    /// Whatever `f` returns, or a SQLite error from begin/commit.
    pub async fn write<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&WriteTx<'_>) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let mut guard = self.inner.writer.clone().lock_owned().await;
        let inner = Arc::clone(&self.inner);
        join(tokio::task::spawn_blocking(move || {
            let tx = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let enqueued = std::cell::Cell::new(false);
            let out = {
                let w = WriteTx {
                    conn: &tx,
                    now: inner.clock.now_millis(),
                    read_only: &inner.read_only,
                    enqueued: &enqueued,
                };
                f(&w)?
            };
            tx.commit()?;
            // Wake the sync engine's push debounce.
            if enqueued.get() {
                inner.outbox.send_modify(|n| *n = n.wrapping_add(1));
            }
            Ok(out)
        }))
        .await
    }

    /// Runs `f` on a pooled read-only connection, inside a deferred transaction
    /// (a consistent snapshot). At most [`READER_POOL_SIZE`] reads run at once;
    /// further callers wait.
    ///
    /// # Errors
    /// Whatever `f` returns, or a SQLite error.
    pub async fn read<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(ReadTx<'_>) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let permit = Arc::clone(&self.inner.reader_permits)
            .acquire_owned()
            .await
            .map_err(|_| StoreError::Task("reader pool closed".into()))?;
        let inner = Arc::clone(&self.inner);
        join(tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut pooled = Pooled {
                conn: inner.readers.lock().pop(),
                inner: &inner,
            };
            let conn = pooled
                .conn
                .as_mut()
                .ok_or_else(|| StoreError::Task("reader pool empty".into()))?;
            let tx = conn.transaction()?;
            let out = f(ReadTx { conn: &tx })?;
            tx.finish()?;
            Ok(out)
        }))
        .await
    }

    /// Runs `f` on the writer connection **outside** a transaction. Used for
    /// TEMP-table work (`index.rs`), which must stay on one connection.
    pub(crate) async fn with_writer_conn<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let guard = self.inner.writer.clone().lock_owned().await;
        join(tokio::task::spawn_blocking(move || f(&guard))).await
    }

    /// Marks `item` read-only (its body has a newer item schema) or clears the
    /// mark. [`WriteTx::put_item`] then refuses to overwrite it. In memory only:
    /// the vault service sets it while decrypting, on every unlock.
    pub fn set_read_only(&self, item: ItemId, read_only: bool) {
        let mut set = self.inner.read_only.write();
        if read_only {
            set.insert(item);
        } else {
            set.remove(&item);
        }
    }

    /// Whether `item` is marked read-only.
    pub fn is_read_only(&self, item: ItemId) -> bool {
        self.inner.read_only.read().contains(&item)
    }
}

/// Returns a reader to the pool even if the closure panics.
struct Pooled<'a> {
    conn: Option<Connection>,
    inner: &'a Inner,
}

impl Drop for Pooled<'_> {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            self.inner.readers.lock().push(conn);
        }
    }
}

async fn join<T>(handle: tokio::task::JoinHandle<Result<T>>) -> Result<T> {
    match handle.await {
        Ok(res) => res,
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        Err(e) => Err(StoreError::Task(e.to_string())),
    }
}

fn open_inner(path: &Path, clock: Arc<dyn Clock>, extra: &[&'static str]) -> Result<Store> {
    let supported = SCHEMA_VERSION + i64::try_from(extra.len()).unwrap_or(0);

    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }

    // A newer (or corrupt) database must not be touched at all, not even by
    // switching it to WAL, so look at it through a read-only connection first.
    if path.exists()
        && std::fs::metadata(path)?.len() > 0
        && let Some(found) = probe_user_version(path)?
        && found > supported
    {
        return Err(StoreError::NewerSchema { found, supported });
    }

    create_private(path)?;

    let mut writer = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    writer.busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MS))?;
    // Re-check on the real connection (another process may have migrated since).
    let found: i64 = writer.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if found > supported {
        return Err(StoreError::NewerSchema { found, supported });
    }
    configure_writer(&writer)?;
    schema::migrations(extra).to_latest(&mut writer)?;
    restrict_siblings(path)?;

    let mut readers = Vec::with_capacity(READER_POOL_SIZE);
    for _ in 0..READER_POOL_SIZE {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        configure_reader(&conn)?;
        readers.push(conn);
    }

    let approval_rows = crate::approvals::load_rows(&writer)?;

    tracing::debug!(schema = supported, "store opened");
    Ok(Store {
        inner: Arc::new_cyclic(|weak| Inner {
            path: path.to_path_buf(),
            writer: Arc::new(tokio::sync::Mutex::new(writer)),
            readers: Mutex::new(readers),
            reader_permits: Arc::new(Semaphore::new(READER_POOL_SIZE)),
            clock,
            read_only: RwLock::new(HashSet::new()),
            approvals: crate::approvals::device_approvals(WeakStore(weak.clone()), approval_rows),
            outbox: tokio::sync::watch::channel(0).0,
        }),
    })
}

/// `PRAGMA user_version` through a read-only connection. `Ok(None)` when the
/// probe cannot run for a reason other than corruption (the normal open then
/// reports it); `Err(Corrupt)` for a damaged file.
fn probe_user_version(path: &Path) -> Result<Option<i64>> {
    let conn = match Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) {
        Ok(conn) => conn,
        Err(e) => {
            return match StoreError::from(e) {
                c @ StoreError::Corrupt(_) => Err(c),
                other => {
                    tracing::debug!(error = %other, "read-only schema probe skipped");
                    Ok(None)
                }
            };
        }
    };
    let _ = conn.busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MS));
    match conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0)) {
        Ok(v) => Ok(Some(v)),
        Err(e) => match StoreError::from(e) {
            c @ StoreError::Corrupt(_) => Err(c),
            other => {
                tracing::debug!(error = %other, "read-only schema probe failed");
                Ok(None)
            }
        },
    }
}

/// PRAGMAs shared by every connection (§5.2). `temp_store = MEMORY` keeps TEMP
/// tables (the decrypted `item_index`) and sort spills off disk.
fn configure_common(conn: &Connection) -> Result<()> {
    conn.busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MS))?;
    conn.execute_batch(
        "PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;
         PRAGMA temp_store = MEMORY;",
    )?;
    Ok(())
}

fn configure_writer(conn: &Connection) -> Result<()> {
    let mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        tracing::warn!(%mode, "SQLite refused WAL journal mode");
    }
    configure_common(conn)
}

fn configure_reader(conn: &Connection) -> Result<()> {
    // Readers are read-only; the journal mode is a property of the file and was
    // set by the writer.
    configure_common(conn)
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut s: OsString = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

/// Creates the database file with mode 0600 (Unix) if it does not exist, and
/// tightens the mode of an existing one.
#[cfg(unix)]
fn create_private(path: &Path) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn create_private(_path: &Path) -> Result<()> {
    Ok(())
}

/// SQLite creates `-wal`/`-shm` with the main file's mode; tighten them anyway
/// in case they predate us.
#[cfg(unix)]
fn restrict_siblings(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for suffix in ["-wal", "-shm", "-journal"] {
        let p = sibling(path, suffix);
        if p.exists() {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn restrict_siblings(path: &Path) -> Result<()> {
    let _ = sibling(path, "-wal");
    Ok(())
}
