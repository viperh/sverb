//! In-memory model of the sync backend, on the tables of the auth model
//! ([`MemStore`]), so registration, account deletion and sync share one
//! "database".
//!
//! It models the PostgreSQL concurrency semantics the protocol relies on:
//! * **committed state**: the `MemStore` tables; readers (pull, list) take
//!   one consistent snapshot of them, like a `REPEATABLE READ` transaction,
//!   and never wait for writers;
//! * **the vault row lock**: one async mutex per vault. A push takes it
//!   before reading anything it decides on (`SELECT … FOR UPDATE`) and
//!   holds it, across real `.await` points, until its writes are applied
//!   (`COMMIT`);
//! * **uncommitted writes are invisible**: a push computes its revisions and
//!   rows privately and applies them in one step at commit, so a concurrent
//!   pull sees all of a batch or none of it;
//! * **lost-update detection**: at commit the model checks that the head
//!   revision did not move while the lock was held, and fails loudly if it
//!   did (that would mean the locking is broken).
//!
//! [`MemSync::pause_next_commit`] stops the next push right before its
//! commit, with the lock held, so tests can observe the intermediate state.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};

use chrono::{DateTime, Utc};
use sverb_proto::sync::{Permission, PullResponse, PushChange, RemoteItem, VaultKind, VaultView};
use tokio::sync::oneshot;
use uuid::Uuid;

use super::gc::GcOutcome;
use super::push::{accepted, assign, check_access, plan};
use super::quota::{self, QuotaBudget, QuotaScope};
use super::vaults::{MembershipRow, build_views};
use super::{PushOutcome, Res, SyncLimits, VaultAccess, pull, remote_item, rev_to_wire};
use crate::auth::store::AccessCtx;
use crate::auth::store::mem::{MemData, MemItem, MemStore};
use crate::error::ApiError;

/// Handle on a paused push (see [`MemSync::pause_next_commit`]).
#[derive(Debug)]
pub struct PausedCommit {
    /// Resolves when the push reached its commit point (lock held).
    pub reached: oneshot::Receiver<()>,
    /// Send (or drop) to let it commit.
    pub resume: oneshot::Sender<()>,
}

#[derive(Debug)]
struct PausePoint {
    reached: oneshot::Sender<()>,
    resume: oneshot::Receiver<()>,
}

/// The in-memory sync backend.
#[derive(Debug)]
pub struct MemSync {
    db: Arc<MemStore>,
    row_locks: Mutex<HashMap<Uuid, Arc<tokio::sync::Mutex<()>>>>,
    pause: Mutex<Option<PausePoint>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn access(d: &MemData, vault_id: Uuid, user_id: Uuid) -> Option<VaultAccess> {
    let v = d.vaults.get(&vault_id)?;
    let member = d
        .vault_members
        .iter()
        .filter(|m| m.vault_id == vault_id && m.user_id == user_id)
        .max_by_key(|m| m.key_version)?;
    Some(VaultAccess {
        kind: if v.personal {
            VaultKind::Personal
        } else {
            VaultKind::Shared
        },
        owner_user_id: v.owner_user_id,
        key_version: v.key_version,
        rotating: v.rotation.is_some(),
        head_revision: v.head_revision,
        // The CHECK constraint of `vault_members.permission`.
        permission: Permission::parse(&member.permission).unwrap_or(Permission::Read),
    })
}

fn usage(d: &MemData, scope: QuotaScope) -> u64 {
    d.items
        .iter()
        .filter(|((vault, _), _)| match scope {
            QuotaScope::Vault(id) => *vault == id,
            QuotaScope::User(owner) => d
                .vaults
                .get(vault)
                .is_some_and(|v| v.personal && v.owner_user_id == Some(owner)),
        })
        .map(|(_, i)| i.envelope.len() as u64)
        .sum()
}

fn item_view(id: Uuid, i: &MemItem) -> RemoteItem {
    remote_item(id, i.revision, i.key_version, i.envelope.clone(), i.deleted)
}

impl MemSync {
    /// The model on `db`'s tables.
    #[must_use]
    pub fn new(db: Arc<MemStore>) -> Self {
        Self {
            db,
            row_locks: Mutex::new(HashMap::new()),
            pause: Mutex::new(None),
        }
    }

    /// The underlying tables.
    #[must_use]
    pub fn db(&self) -> &Arc<MemStore> {
        &self.db
    }

    /// Makes the next push that accepts changes stop right before its
    /// commit, holding the vault lock, until `resume` is sent or dropped.
    pub fn pause_next_commit(&self) -> PausedCommit {
        let (reached_tx, reached_rx) = oneshot::channel();
        let (resume_tx, resume_rx) = oneshot::channel();
        *lock(&self.pause) = Some(PausePoint {
            reached: reached_tx,
            resume: resume_rx,
        });
        PausedCommit {
            reached: reached_rx,
            resume: resume_tx,
        }
    }

    // M5-04: rotation takes the same lock.
    pub(super) fn row_lock(&self, vault_id: Uuid) -> Arc<tokio::sync::Mutex<()>> {
        lock(&self.row_locks).entry(vault_id).or_default().clone()
    }

    pub(super) fn list_vaults(&self, user_id: Uuid) -> Vec<VaultView> {
        let rows = self.db.with_data(|d| {
            d.vault_members
                .iter()
                .filter(|m| m.user_id == user_id)
                .filter_map(|m| {
                    let v = d.vaults.get(&m.vault_id)?;
                    Some(MembershipRow {
                        vault_id: m.vault_id,
                        kind: if v.personal {
                            VaultKind::Personal
                        } else {
                            VaultKind::Shared
                        },
                        org_id: v.org_id,
                        name_enc: v.name_enc.clone(),
                        key_version: v.key_version,
                        head_revision: v.head_revision,
                        rotation: v.rotation.clone(),
                        permission: Permission::parse(&m.permission).unwrap_or(Permission::Read),
                        grant_key_version: m.key_version,
                        wrapped_vault_key: m.wrapped_vault_key.clone(),
                        wrapped_by: m.wrapped_by,
                        signature: m.signature.clone(),
                    })
                })
                .collect()
        });
        build_views(rows)
    }

    pub(super) fn pull(
        &self,
        user_id: Uuid,
        vault_id: Uuid,
        since: i64,
        limit: u32,
    ) -> Res<PullResponse> {
        // One snapshot: floor, head and page are mutually consistent.
        self.db.with_data(|d| {
            let a = access(d, vault_id, user_id).ok_or_else(super::vault_not_found)?;
            let floor = d.vaults.get(&vault_id).map_or(0, |v| v.gc_floor_revision);
            pull::check_floor(since, floor)?;
            let mut items: Vec<RemoteItem> = d
                .items
                .range((vault_id, Uuid::nil())..=(vault_id, Uuid::max()))
                .filter(|(_, i)| i.revision > since)
                .map(|((_, id), i)| item_view(*id, i))
                .collect();
            items.sort_by_key(|i| i.revision);
            items.truncate(limit as usize + 1);
            Ok(pull::page(items, a.head_revision, limit))
        })
    }

    async fn pause_point(&self) {
        let p = lock(&self.pause).take();
        if let Some(p) = p {
            let _ = p.reached.send(());
            let _ = p.resume.await;
        }
    }

    pub(super) async fn push(
        &self,
        ctx: AccessCtx,
        vault_id: Uuid,
        changes: &[PushChange],
        limits: SyncLimits,
        now: DateTime<Utc>,
    ) -> Res<PushOutcome> {
        // Membership pre-check without the lock (as on PostgreSQL).
        if self
            .db
            .with_data(|d| access(d, vault_id, ctx.user_id))
            .is_none()
        {
            return Err(super::vault_not_found());
        }

        // BEGIN; SELECT … FROM vaults WHERE id = $1 FOR UPDATE
        let row_lock = self.row_lock(vault_id);
        let _row = row_lock.lock().await;
        tokio::task::yield_now().await;

        // Fresh READ COMMITTED reads under the lock.
        let (access, existing, budget) = self.db.with_data(|d| {
            let a = access(d, vault_id, ctx.user_id).ok_or_else(super::vault_not_found)?;
            let existing: HashMap<Uuid, RemoteItem> = changes
                .iter()
                .filter_map(|c| {
                    d.items
                        .get(&(vault_id, c.id))
                        .map(|i| (c.id, item_view(c.id, i)))
                })
                .collect();
            let (scope, limit) = quota::scope(vault_id, &a, limits);
            Ok::<_, ApiError>((a, existing, QuotaBudget::new(usage(d, scope), limit)))
        })?;
        check_access(&access, changes)?;

        let decisions = plan(changes, &existing, budget);
        let n = accepted(&decisions);
        if n == 0 {
            let (results, _) = assign(changes, decisions, access.head_revision);
            return Ok(PushOutcome {
                results,
                new_head: None,
            });
        }
        // UPDATE vaults SET head_revision = head_revision + n RETURNING …
        // (private to this transaction until commit).
        let new_head = access.head_revision + n;
        let (results, revs) = assign(changes, decisions, new_head);
        tokio::task::yield_now().await;
        self.pause_point().await;

        // COMMIT: all writes become visible at once, then the lock goes.
        self.db.with_data(|d| {
            let v = d
                .vaults
                .get_mut(&vault_id)
                .ok_or_else(super::vault_not_found)?;
            if v.head_revision != access.head_revision {
                return Err(ApiError::internal(std::io::Error::other(
                    "lost update: the vault head moved while its row lock was held",
                )));
            }
            v.head_revision = new_head;
            let key_version = v.key_version;
            for (c, rev) in changes.iter().zip(&revs) {
                if let Some(rev) = rev {
                    d.items.insert(
                        (vault_id, c.id),
                        MemItem {
                            revision: *rev,
                            key_version,
                            envelope: c.envelope.clone(),
                            deleted: c.deleted,
                            updated_at: now,
                            updated_by_device: Some(ctx.device_id),
                        },
                    );
                }
            }
            Ok(())
        })?;
        drop(_row);
        Ok(PushOutcome {
            results,
            new_head: Some(rev_to_wire(new_head)),
        })
    }

    pub(super) async fn gc_tombstones(&self, cutoff: DateTime<Utc>) -> GcOutcome {
        let candidates: BTreeSet<Uuid> = self.db.with_data(|d| {
            d.items
                .iter()
                .filter(|(_, i)| i.deleted && i.updated_at < cutoff)
                .map(|((v, _), _)| *v)
                .collect()
        });
        let mut out = GcOutcome::default();
        for vault_id in candidates {
            let row_lock = self.row_lock(vault_id);
            let _row = row_lock.lock().await;
            self.db.with_data(|d| {
                if !d.vaults.contains_key(&vault_id) {
                    return;
                }
                let purged: Vec<(Uuid, i64)> = d
                    .items
                    .range((vault_id, Uuid::nil())..=(vault_id, Uuid::max()))
                    .filter(|(_, i)| i.deleted && i.updated_at < cutoff)
                    .map(|((_, id), i)| (*id, i.revision))
                    .collect();
                let Some(max_rev) = purged.iter().map(|(_, r)| *r).max() else {
                    return;
                };
                for (id, _) in &purged {
                    d.items.remove(&(vault_id, *id));
                }
                if let Some(v) = d.vaults.get_mut(&vault_id) {
                    v.gc_floor_revision = v.gc_floor_revision.max(max_rev);
                }
                out.vaults += 1;
                out.purged_tombstones += purged.len() as u64;
            });
        }
        out
    }
}
