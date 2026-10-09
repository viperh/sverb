//! Vault sync: list, pull, push, quota and tombstone GC (SPEC §10.3–§10.5,
//! §12.1–§12.3, §13.2; task M4-04).
//!
//! * [`vaults`]: `GET /v1/vaults` (memberships with wrapped keys);
//! * [`pull`]: `GET /v1/vaults/{id}/changes` (§12.2, `410 Gone` below the
//!   GC floor);
//! * [`push`]: `POST /v1/vaults/{id}/changes` (§12.3): batch limits, the
//!   per-change decision shared by both backends, and the PostgreSQL
//!   transaction with the §12.1 vault-row lock;
//! * [`quota`]: storage quota (§10.5);
//! * [`gc`]: tombstone GC raising `vaults.gc_floor_revision` (§12.2) and the
//!   optional background job;
//! * [`mem`]: the in-memory model (tests without PostgreSQL), which models
//!   the vault row lock with a per-vault async mutex.
//!
//! # Gap-free revisions (§12.1)
//!
//! A push transaction locks the vault row **before** it reads anything it
//! decides on, and keeps the lock until commit:
//!
//! 1. `SELECT … FROM vaults WHERE id = $1 FOR UPDATE` (the same row lock the
//!    spec's `UPDATE vaults SET head_revision = head_revision + $n` takes;
//!    taking it first also makes the rotation and key-version checks, the
//!    quota sum and the conflict check of items that don't exist yet
//!    race-free, which item-row locks alone can't do for absent rows);
//! 2. `SELECT … FROM items … FOR UPDATE` for the batch's ids;
//! 3. decide per change ([`push::plan`]); `n` = accepted count;
//! 4. `UPDATE vaults SET head_revision = head_revision + n … RETURNING
//!    head_revision` and assign `head-n+1 ..= head` in batch order;
//! 5. upsert the accepted items, `COMMIT`, then notify ([`ChangeNotifier`]).
//!
//! Pushes to one vault are therefore serialized: push B can only take the
//! lock after push A committed, so B's revisions are both larger than A's
//! and committed after them. PostgreSQL makes a commit visible before it
//! releases the transaction's locks, so any snapshot that sees one of B's
//! revisions also sees all of A's. A puller that reads
//! `revision > cursor ORDER BY revision` can thus never see revision `k+1`
//! without `k`, and never advances its cursor past a revision it has not
//! received. Rejected changes don't consume revisions because `n` is
//! computed before the `UPDATE`.

pub mod gc;
pub mod mem;
pub mod pull;
pub mod push;
pub mod quota;
// M5-04: vault key rotation (begin, upload, commit, abandonment).
pub mod rotation;
// M5-02: shared vaults (create, grants, revoke, membership listings).
pub mod shared;
pub mod vaults;

use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};
use sqlx_postgres::PgPool;
use sverb_proto::sync::{
    Permission, PullResponse, PushChange, PushResult, RemoteItem, VaultKind, VaultView,
};
use uuid::Uuid;

use crate::auth::store::AccessCtx;
use crate::auth::{AuthRuntime, AuthStore};
use crate::config::Config;
use crate::error::ApiError;

pub use gc::GcOutcome;
pub use mem::MemSync;

type Res<T> = Result<T, ApiError>;

/// Per-vault byte cap for shared vaults (v1: shared vaults are not counted
/// against any user's quota, see [`quota`]).
pub const SHARED_VAULT_CAP_BYTES: u64 = 1024 * 1024 * 1024;

const MIB: u64 = 1024 * 1024;

/// The push limits (§10.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncLimits {
    /// Per-user quota over the envelopes of the user's personal vaults.
    pub personal_quota_bytes: u64,
    /// Cap per shared vault.
    pub shared_vault_cap_bytes: u64,
}

impl SyncLimits {
    /// The limits configured in `config` (`storage_quota_mib`).
    #[must_use]
    pub const fn from_config(config: &Config) -> Self {
        Self {
            personal_quota_bytes: config.limits.storage_quota_mib.saturating_mul(MIB),
            shared_vault_cap_bytes: SHARED_VAULT_CAP_BYTES,
        }
    }
}

/// Receives a hint after every push commit that accepted changes. M4-05
/// installs the WebSocket hub / `NOTIFY` publisher here; the default does
/// nothing. Called **after** commit, never inside the transaction, so a
/// slow subscriber can't extend the vault lock.
pub trait ChangeNotifier: Send + Sync + std::fmt::Debug {
    /// `vault_id` now has `head_revision`.
    fn vault_changed(&self, vault_id: Uuid, head_revision: u64);
}

/// The default notifier (M4-05 replaces it).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopNotifier;

impl ChangeNotifier for NoopNotifier {
    fn vault_changed(&self, _vault_id: Uuid, _head_revision: u64) {}
}

/// What a push did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushOutcome {
    /// One result per change, in request order.
    pub results: Vec<PushResult>,
    /// The new head revision, when at least one change was accepted.
    pub new_head: Option<u64>,
}

/// The persistence backend for sync, mirroring [`AuthStore`]: the same
/// database (PostgreSQL), or the in-memory model on the auth store's tables.
#[derive(Debug, Clone)]
pub enum SyncStore {
    /// PostgreSQL.
    Postgres(PgPool),
    /// In-memory model (tests).
    Memory(Arc<MemSync>),
}

impl SyncStore {
    /// The sync backend matching an auth backend.
    #[must_use]
    pub fn for_auth(auth: &AuthStore) -> Self {
        match auth {
            AuthStore::Postgres(pool) => Self::Postgres(pool.clone()),
            AuthStore::Memory(m) => Self::Memory(Arc::new(MemSync::new(m.clone()))),
        }
    }

    /// The vaults `user_id` is a member of.
    ///
    /// # Errors
    /// Database errors.
    pub async fn list_vaults(&self, user_id: Uuid) -> Res<Vec<VaultView>> {
        match self {
            Self::Postgres(pool) => vaults::pg_list(pool, user_id).await,
            Self::Memory(m) => Ok(m.list_vaults(user_id)),
        }
    }

    /// One pull page (§12.2).
    ///
    /// # Errors
    /// `NotFound` (no such vault or not a member), `Gone` (below the GC
    /// floor), database errors.
    pub async fn pull(
        &self,
        user_id: Uuid,
        vault_id: Uuid,
        since: i64,
        limit: u32,
    ) -> Res<PullResponse> {
        match self {
            Self::Postgres(pool) => pull::pg_pull(pool, user_id, vault_id, since, limit).await,
            Self::Memory(m) => m.pull(user_id, vault_id, since, limit),
        }
    }

    /// Applies a validated batch ([`push::validate_batch`]) in one
    /// transaction (§12.3).
    ///
    /// # Errors
    /// `NotFound`, `Forbidden` (read member), `Rotating`, `Invalid`
    /// (key-version mismatch), database errors.
    pub async fn push(
        &self,
        ctx: AccessCtx,
        vault_id: Uuid,
        changes: &[PushChange],
        limits: SyncLimits,
        now: DateTime<Utc>,
    ) -> Res<PushOutcome> {
        match self {
            Self::Postgres(pool) => push::pg_push(pool, ctx, vault_id, changes, limits, now).await,
            Self::Memory(m) => m.push(ctx, vault_id, changes, limits, now).await,
        }
    }

    /// Purges tombstones last written before `cutoff` and raises each
    /// affected vault's GC floor (one transaction per vault).
    ///
    /// # Errors
    /// Database errors.
    pub async fn gc_tombstones(&self, cutoff: DateTime<Utc>) -> Res<GcOutcome> {
        match self {
            Self::Postgres(pool) => gc::pg_purge_tombstones(pool, cutoff)
                .await
                .map_err(ApiError::from),
            Self::Memory(m) => Ok(m.gc_tombstones(cutoff).await),
        }
    }
}

/// Sync state shared by the handlers (part of `AppState`).
#[derive(Debug)]
pub struct SyncRuntime {
    store: SyncStore,
    limits: SyncLimits,
    notifier: RwLock<Arc<dyn ChangeNotifier>>,
}

impl SyncRuntime {
    /// A runtime on `store`.
    #[must_use]
    pub fn new(store: SyncStore, limits: SyncLimits) -> Self {
        Self {
            store,
            limits,
            notifier: RwLock::new(Arc::new(NoopNotifier)),
        }
    }

    /// The runtime matching the auth runtime's backend.
    #[must_use]
    pub fn for_auth(auth: &AuthRuntime, config: &Config) -> Self {
        Self::new(
            SyncStore::for_auth(auth.store()),
            SyncLimits::from_config(config),
        )
    }

    /// The store.
    #[must_use]
    pub const fn store(&self) -> &SyncStore {
        &self.store
    }

    /// The limits.
    #[must_use]
    pub const fn limits(&self) -> SyncLimits {
        self.limits
    }

    /// Replaces the change notifier (M4-05, tests).
    pub fn set_notifier(&self, notifier: Arc<dyn ChangeNotifier>) {
        if let Ok(mut n) = self.notifier.write() {
            *n = notifier;
        }
    }

    /// Notifies after a commit.
    pub fn notify(&self, vault_id: Uuid, head_revision: u64) {
        let n = self.notifier.read().map(|n| n.clone());
        if let Ok(n) = n {
            n.vault_changed(vault_id, head_revision);
        }
    }
}

// ------------------------------------------------------------ shared types

/// The caller's view of a vault row, read under the vault lock by push.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultAccess {
    /// Kind.
    pub kind: VaultKind,
    /// Owner (personal vaults).
    pub owner_user_id: Option<Uuid>,
    /// Current key version.
    pub key_version: i32,
    /// `rotation IS NOT NULL`.
    pub rotating: bool,
    /// Head revision.
    pub head_revision: i64,
    /// The caller's permission (from the membership row with the highest
    /// key version).
    pub permission: Permission,
}

/// `BIGINT` revision → wire (negative values can't occur; clamp to 0).
#[must_use]
pub fn rev_to_wire(rev: i64) -> u64 {
    u64::try_from(rev).unwrap_or(0)
}

/// Wire revision → `BIGINT` (values beyond `i64::MAX` saturate).
#[must_use]
pub fn rev_from_wire(rev: u64) -> i64 {
    i64::try_from(rev).unwrap_or(i64::MAX)
}

/// `INT` key version → wire.
#[must_use]
pub fn kv_to_wire(kv: i32) -> u32 {
    u32::try_from(kv).unwrap_or(0)
}

/// Builds a [`RemoteItem`] from column values.
#[must_use]
pub fn remote_item(
    id: Uuid,
    revision: i64,
    key_version: i32,
    envelope: Vec<u8>,
    deleted: bool,
) -> RemoteItem {
    RemoteItem {
        id,
        revision: rev_to_wire(revision),
        key_version: kv_to_wire(key_version),
        envelope,
        deleted,
    }
}

/// The error for "no such vault" and "not a member" alike (§10.4: don't
/// reveal existence).
#[must_use]
pub fn vault_not_found() -> ApiError {
    ApiError::NotFound("no such vault".into())
}
