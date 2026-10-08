//! Push (§12.3, §12.5).
//!
//! For a vault with outbox rows, batches of at most 500 changes and 8 MiB of
//! envelopes are built from the items table (`{id, base_revision,
//! key_version, envelope, deleted}`) and posted. Results, one transaction per
//! batch:
//! * `ok` → `items.revision = revision`, clean, outbox row removed (unless
//!   the item was edited again meanwhile: then it stays queued, rebased).
//!   The cursor is **not** moved: pull applies our own revisions
//!   idempotently, so revisions of other devices in between are never
//!   skipped;
//! * `conflict` with `current` → `merge(local, current)`, re-seal, rebase
//!   the outbox onto `current.revision`, retry next round; after
//!   [`MAX_CONFLICT_ROUNDS`] the item is reported and stays dirty.
//!   `conflict` without `current` (the server purged the tombstone) →
//!   rebase onto 0 and retry as a new item;
//! * `forbidden` (or a whole-request 403) → read-only membership: the change
//!   is kept locally and not uploaded;
//! * `too_large` → error toast, kept dirty and held back.
//!
//! `409 rotating` pauses the vault until the vault list shows the rotation
//! finished; pending items are then re-sealed under the new key version
//! (here, when the batch is built) and pushed (§13.2).
//! Transport errors bump `outbox.attempts`; the engine retries with backoff.
//! Device-local kinds are filtered here too (§12.6): `HistoryEntry` /
//! `ConnLog` are only pushed with `history.sync` / `logs.sync`.

use std::collections::HashSet;

use sverb_core::model::{ItemId, VaultId, merge};
use sverb_proto::ErrorCode;
use sverb_proto::sync::{
    MAX_BATCH_BYTES, MAX_BATCH_ITEMS, MAX_ENVELOPE_BYTES, PushChange, PushRequest, PushResponse,
    PushStatus,
};
use sverb_store::{RemoteItem as StoreItem, StoreError};

use crate::engine::{BlockReason, Ctx, MAX_CONFLICT_ROUNDS, label_of, observe_body};
use crate::error::SyncError;
use crate::pull::wire_rev;
use crate::status::{SyncEvent, ToastLevel};

/// One queued change ready to post.
#[derive(Debug, Clone)]
pub(crate) struct Prepared {
    pub(crate) id: ItemId,
    pub(crate) queued_at: i64,
    pub(crate) label: String,
    pub(crate) change: PushChange,
}

/// What preparing found besides the changes.
#[derive(Debug, Default)]
struct Preparation {
    changes: Vec<Prepared>,
    undecryptable: Vec<ItemId>,
    too_large: Vec<(ItemId, String)>,
    excluded: usize,
}

/// What a batch result did.
#[derive(Debug, Default)]
struct BatchReport {
    ok: Vec<ItemId>,
    conflicts: Vec<(ItemId, String)>,
    forbidden: Vec<ItemId>,
    too_large: Vec<(ItemId, String, String)>,
    applied: Vec<ItemId>,
    resurrected: Vec<String>,
    undecryptable: Vec<ItemId>,
    skew: Option<sverb_core::model::ClockSkew>,
}

/// Splits changes into batches within the §10.5 limits.
pub(crate) fn batches(changes: Vec<Prepared>) -> Vec<Vec<Prepared>> {
    let mut out: Vec<Vec<Prepared>> = Vec::new();
    let mut cur: Vec<Prepared> = Vec::new();
    let mut bytes = 0usize;
    for p in changes {
        let len = p.change.envelope.len();
        if !cur.is_empty() && (cur.len() >= MAX_BATCH_ITEMS || bytes + len > MAX_BATCH_BYTES) {
            out.push(std::mem::take(&mut cur));
            bytes = 0;
        }
        bytes += len;
        cur.push(p);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

impl Ctx {
    /// Builds the changes of `vault` (re-sealing items under the current
    /// key version, dropping excluded kinds from the outbox).
    async fn prepare(&self, vault: VaultId) -> Result<Preparation, SyncError> {
        let keys = self.keys.clone();
        let policy = self.config.policy;
        let blocked: HashSet<ItemId> = self.blocked.keys().copied().collect();
        let prep = self
            .store
            .write(move |w| {
                let k = keys.read();
                let current = k.current_version(vault);
                let mut prep = Preparation::default();
                for row in w.as_read().list_outbox(vault)? {
                    let id = row.item_id;
                    if blocked.contains(&id) {
                        continue;
                    }
                    let Some(item) = w.as_read().get_item(id)? else {
                        w.dequeue(id)?;
                        continue;
                    };
                    if item.vault_id != vault {
                        continue;
                    }
                    let body = match k.open(vault, id, &item.envelope) {
                        Ok(b) => b,
                        Err(e) => {
                            tracing::warn!(item = %id, error = %e, "queued item does not decrypt; not pushed");
                            prep.undecryptable.push(id);
                            continue;
                        }
                    };
                    // §12.6: device-local kinds never leave the device unless
                    // enabled. The item stays dirty (pushed if enabled later).
                    if !policy.allows(body.kind) {
                        w.dequeue(id)?;
                        prep.excluded += 1;
                        continue;
                    }
                    let label = label_of(Some(&body), id);
                    let (key_version, envelope) = if Some(item.key_version) == current {
                        (item.key_version, item.envelope)
                    } else {
                        // Rotation: re-encrypt under the new vault key.
                        match k.seal(vault, id, &body) {
                            Ok((kv, env)) => {
                                w.reseal_item(id, kv, &env)?;
                                (kv, env)
                            }
                            Err(e) => {
                                tracing::warn!(item = %id, error = %e, "re-seal failed");
                                prep.undecryptable.push(id);
                                continue;
                            }
                        }
                    };
                    if envelope.len() > MAX_ENVELOPE_BYTES {
                        prep.too_large.push((id, label));
                        continue;
                    }
                    prep.changes.push(Prepared {
                        id,
                        queued_at: row.queued_at,
                        label,
                        change: PushChange {
                            id: id.uuid(),
                            base_revision: u64::try_from(row.base_revision).unwrap_or(0),
                            key_version,
                            envelope,
                            deleted: item.deleted,
                        },
                    });
                }
                Ok(prep)
            })
            .await?;
        Ok(prep)
    }

    /// Pushes `vault`'s outbox; `true` when something was accepted.
    pub(crate) async fn push_vault(&mut self, vault: VaultId) -> Result<bool, SyncError> {
        let mut accepted = false;
        for _round in 0..MAX_CONFLICT_ROUNDS {
            if self.rotating.contains(&vault) {
                tracing::debug!(%vault, "pushes paused during key rotation");
                return Ok(accepted);
            }
            let prep = self.prepare(vault).await?;
            if prep.excluded > 0 {
                tracing::debug!(%vault, n = prep.excluded, "device-local items not pushed");
            }
            for id in prep.undecryptable {
                self.block(id, BlockReason::Undecryptable);
            }
            for (id, label) in prep.too_large {
                self.too_large(id, &label, "envelope exceeds 1 MiB");
            }
            if prep.changes.is_empty() {
                break;
            }
            let mut any_conflict = false;
            for batch in batches(prep.changes) {
                let req = PushRequest {
                    changes: batch.iter().map(|p| p.change.clone()).collect(),
                };
                let req = std::sync::Arc::new(req);
                let res = self
                    .call(|api, t| {
                        let req = std::sync::Arc::clone(&req);
                        async move { api.push(&t, vault.uuid(), &req).await }
                    })
                    .await;
                match res {
                    Ok(resp) => {
                        let (ok, conflicts) = self.apply_results(vault, batch, resp).await?;
                        accepted |= ok;
                        any_conflict |= conflicts;
                    }
                    Err(e) if e.code() == Some(ErrorCode::Rotating) => {
                        tracing::info!(%vault, "vault key rotation in progress; pushes paused");
                        self.rotating.insert(vault);
                        return Ok(accepted);
                    }
                    Err(e) if e.code() == Some(ErrorCode::Forbidden) => {
                        let ids: Vec<ItemId> = batch.iter().map(|p| p.id).collect();
                        self.read_only(vault, ids);
                    }
                    Err(e)
                        if e.code() == Some(ErrorCode::Invalid)
                            && e.to_string().contains("key_version") =>
                    {
                        // Stale vault key: refresh the vault list, retry next round.
                        tracing::info!(%vault, "stale key version; refreshing vault keys");
                        self.refresh_vaults().await?;
                        any_conflict = true;
                    }
                    Err(e) => {
                        if e.is_offline() {
                            let ids: Vec<ItemId> = batch.iter().map(|p| p.id).collect();
                            let _ = self
                                .store
                                .write(move |w| {
                                    for id in ids {
                                        match w.bump_attempts(id) {
                                            Ok(_) | Err(StoreError::NotFound) => {}
                                            Err(e) => return Err(e),
                                        }
                                    }
                                    Ok(())
                                })
                                .await;
                        }
                        return Err(e);
                    }
                }
            }
            if !any_conflict {
                break;
            }
        }
        Ok(accepted)
    }

    fn too_large(&mut self, id: ItemId, label: &str, why: &str) {
        self.block(id, BlockReason::TooLarge(why.to_owned()));
        self.toast(
            ToastLevel::Error,
            format!("‘{label}’ was not uploaded: {why}. It is kept on this device."),
        );
    }

    fn read_only(&mut self, vault: VaultId, ids: Vec<ItemId>) {
        for id in &ids {
            self.block(*id, BlockReason::ReadOnly);
        }
        self.toast(
            ToastLevel::Error,
            format!(
                "You have read-only access to vault {}. Your local change was not uploaded.",
                vault.short()
            ),
        );
        self.emit(SyncEvent::ReadOnly { vault, items: ids });
    }

    /// Applies one batch's results in one transaction. Returns (anything
    /// accepted, any conflict to retry).
    async fn apply_results(
        &mut self,
        vault: VaultId,
        batch: Vec<Prepared>,
        resp: PushResponse,
    ) -> Result<(bool, bool), SyncError> {
        let keys = self.keys.clone();
        let hlc = self.hlc.clone();
        let report = self
            .store
            .write(move |w| {
                let k = keys.read();
                let mut h = hlc.lock();
                let cursor = w.as_read().get_vault(vault)?.map_or(0, |v| v.sync_cursor);
                let mut report = BatchReport::default();
                for (p, r) in batch.iter().zip(resp.results.iter()) {
                    if r.id != p.change.id {
                        tracing::warn!(item = %p.id, "push result out of order; ignored");
                        continue;
                    }
                    match r.status {
                        PushStatus::Ok => {
                            let Some(rev) = r.revision else { continue };
                            match w.mark_pushed(p.id, wire_rev(rev), p.queued_at) {
                                Ok(()) | Err(StoreError::NotFound) => report.ok.push(p.id),
                                Err(e) => return Err(e),
                            }
                        }
                        PushStatus::Conflict => {
                            report.conflicts.push((p.id, p.label.clone()));
                            let Some(cur) = &r.current else {
                                // Purged tombstone: push again as a new item.
                                match w.rebase(p.id, 0) {
                                    Ok(()) | Err(StoreError::NotFound) => {}
                                    Err(e) => return Err(e),
                                }
                                continue;
                            };
                            let Some(local) = w.as_read().get_item(p.id)? else { continue };
                            let remote = match k.open(vault, p.id, &cur.envelope) {
                                Ok(b) => b,
                                Err(e) => {
                                    tracing::warn!(item = %p.id, error = %e, "server copy does not decrypt");
                                    report.undecryptable.push(p.id);
                                    continue;
                                }
                            };
                            if let Some(s) = observe_body(&mut h, &remote) {
                                report.skew.get_or_insert(s);
                            }
                            let Ok(local_body) = k.open(vault, p.id, &local.envelope) else {
                                report.undecryptable.push(p.id);
                                continue;
                            };
                            let revision = wire_rev(cur.revision);
                            let item = if merge(&remote, &local_body).changed() {
                                let out = merge(&local_body, &remote);
                                if out.resurrected {
                                    report.resurrected.push(label_of(Some(&out.body), p.id));
                                }
                                let Ok((key_version, envelope)) = k.seal(vault, p.id, &out.body) else {
                                    report.undecryptable.push(p.id);
                                    continue;
                                };
                                StoreItem {
                                    id: p.id,
                                    revision,
                                    key_version,
                                    envelope,
                                    deleted: out.body.is_deleted(),
                                    local_pending: true,
                                }
                            } else {
                                // Nothing local to add: take the server's copy, clean.
                                StoreItem {
                                    id: p.id,
                                    revision,
                                    key_version: cur.key_version,
                                    envelope: cur.envelope.clone(),
                                    deleted: cur.deleted,
                                    local_pending: false,
                                }
                            };
                            // Same transaction; the cursor is left where it is.
                            w.apply_remote(vault, std::slice::from_ref(&item), cursor)?;
                            report.applied.push(p.id);
                        }
                        PushStatus::Forbidden => report.forbidden.push(p.id),
                        PushStatus::TooLarge => report.too_large.push((
                            p.id,
                            p.label.clone(),
                            r.message.clone().unwrap_or_else(|| "too large".into()),
                        )),
                    }
                }
                Ok(report)
            })
            .await?;

        for id in &report.ok {
            self.conflicts.remove(id);
        }
        let mut retry = false;
        for (id, label) in &report.conflicts {
            let n = self.conflicts.entry(*id).or_insert(0);
            *n += 1;
            if *n >= MAX_CONFLICT_ROUNDS {
                self.block(*id, BlockReason::Conflict);
                self.toast(
                    ToastLevel::Error,
                    format!("‘{label}’ could not be synced: it kept conflicting. It is kept on this device."),
                );
            } else {
                retry = true;
            }
        }
        if !report.forbidden.is_empty() {
            self.read_only(vault, report.forbidden.clone());
        }
        for (id, label, why) in &report.too_large {
            self.too_large(*id, label, why);
        }
        for id in &report.undecryptable {
            self.block(*id, BlockReason::Undecryptable);
        }
        self.warn_skew(report.skew);
        for label in &report.resurrected {
            self.toast(
                ToastLevel::Info,
                format!("‘{label}’ was restored because it was edited on another device after being deleted"),
            );
        }
        if !report.applied.is_empty() {
            self.emit(SyncEvent::Applied {
                vault,
                items: report.applied,
            });
        }
        Ok((!report.ok.is_empty(), retry))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(len: usize) -> Prepared {
        let id = ItemId::new();
        Prepared {
            id,
            queued_at: 0,
            label: String::new(),
            change: PushChange {
                id: id.uuid(),
                base_revision: 0,
                key_version: 1,
                envelope: vec![0; len],
                deleted: false,
            },
        }
    }

    #[test]
    fn batches_respect_count_and_bytes() {
        let b = batches((0..1200).map(|_| p(10)).collect());
        assert_eq!(
            b.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![500, 500, 200]
        );
        let mib = 1024 * 1024;
        let b = batches((0..20).map(|_| p(mib)).collect());
        assert!(b.iter().all(|x| x.len() <= 8));
        assert_eq!(b.iter().map(Vec::len).sum::<usize>(), 20);
        assert!(batches(Vec::new()).is_empty());
    }

    #[test]
    fn policy_filters_device_local_kinds() {
        use crate::engine::SyncPolicy;
        use sverb_core::model::ItemKind;
        let off = SyncPolicy::default();
        assert!(off.allows(ItemKind::Host));
        assert!(!off.allows(ItemKind::ConnLog));
        assert!(!off.allows(ItemKind::HistoryEntry));
        let on = SyncPolicy {
            history_sync: true,
            logs_sync: true,
        };
        assert!(on.allows(ItemKind::ConnLog) && on.allows(ItemKind::HistoryEntry));
    }
}
