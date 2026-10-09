//! Pull (§12.2): `GET changes?since=cursor&limit=500`, one SQLite transaction
//! per page together with the cursor update.
//!
//! Per item, inside the page transaction:
//! 1. decrypt it (the vault key of its `key_version`) and observe its stamps
//!    in the HLC (one skew toast per engine);
//! 2. not dirty locally → replace the local copy (envelope as received);
//! 3. dirty locally → `merge(local, remote)`, re-seal locally, keep dirty and
//!    rebase the outbox onto the incoming revision (if the local copy adds
//!    nothing to the remote one, it simply becomes clean);
//! 4. advance the cursor (`head_revision` on the last page, else the page's
//!    last revision).
//!
//! An item that does not decrypt (wrong key, tampered) is skipped and
//! logged; the status shows "N items could not be decrypted". `410 Gone`
//! starts a full resync ([`crate::resync`]).

use sverb_core::model::{ClockSkew, HlcClock, ItemId, VaultId, merge};
use sverb_proto::ErrorCode;
use sverb_proto::sync::RemoteItem as WireItem;
use sverb_store::{ReadTx, RemoteItem as StoreItem, StoreError};

use crate::engine::{Ctx, label_of, observe_body};
use crate::error::SyncError;
use crate::keys::VaultKeys;
use crate::status::{SyncEvent, ToastLevel};

/// What a page transaction did.
#[derive(Debug, Default)]
pub(crate) struct PageReport {
    /// Items written or purged locally (for the search index).
    pub(crate) applied: Vec<ItemId>,
    /// Remote items that decrypted (clears earlier failures).
    pub(crate) decrypted: Vec<ItemId>,
    /// Remote items that did not decrypt (skipped).
    pub(crate) undecryptable: Vec<ItemId>,
    /// Labels of locally deleted items an incoming edit restored.
    pub(crate) resurrected: Vec<String>,
    /// The first clock skew seen.
    pub(crate) skew: Option<ClockSkew>,
}

pub(crate) fn wire_rev(rev: u64) -> i64 {
    i64::try_from(rev).unwrap_or(i64::MAX)
}

/// Decides what to store for one incoming item (steps 1–3). `None`: skip it
/// (it does not decrypt).
pub(crate) fn incoming(
    r: ReadTx<'_>,
    keys: &VaultKeys,
    hlc: &mut HlcClock,
    vault: VaultId,
    item: &WireItem,
    report: &mut PageReport,
) -> Result<Option<StoreItem>, StoreError> {
    let id = ItemId::from_uuid(item.id);
    let remote = match keys.open(vault, id, &item.envelope) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(item = %id, %vault, error = %e, "remote item could not be decrypted; skipped");
            report.undecryptable.push(id);
            return Ok(None);
        }
    };
    report.decrypted.push(id);
    if let Some(s) = observe_body(hlc, &remote) {
        report.skew.get_or_insert(s);
    }
    let revision = wire_rev(item.revision);
    let as_received = StoreItem {
        id,
        revision,
        key_version: item.key_version,
        envelope: item.envelope.clone(),
        deleted: item.deleted,
        local_pending: false,
    };
    let Some(local) = r.get_item(id)? else {
        return Ok(Some(as_received));
    };
    if !local.dirty || local.vault_id != vault {
        return Ok(Some(as_received));
    }
    let Ok(local_body) = keys.open(vault, id, &local.envelope) else {
        tracing::warn!(item = %id, "local copy does not decrypt; taking the server's");
        return Ok(Some(as_received));
    };
    // The local copy adds nothing: the result equals the remote one.
    if !merge(&remote, &local_body).changed() {
        return Ok(Some(as_received));
    }
    let out = merge(&local_body, &remote);
    if out.resurrected {
        report.resurrected.push(label_of(Some(&out.body), id));
    }
    match keys.seal(vault, id, &out.body) {
        Ok((key_version, envelope)) => Ok(Some(StoreItem {
            id,
            revision,
            key_version,
            envelope,
            deleted: out.body.is_deleted(),
            local_pending: true,
        })),
        Err(e) => {
            tracing::warn!(item = %id, error = %e, "re-sealing the merge failed; keeping the local copy");
            Ok(None)
        }
    }
}

impl Ctx {
    /// Pulls `vault` until the server has no more pages.
    pub(crate) async fn pull_vault(&mut self, vault: VaultId) -> Result<(), SyncError> {
        loop {
            let Some(row) = self.store.get_vault(vault).await? else {
                return Ok(());
            };
            let cursor = row.sync_cursor;
            let since = u64::try_from(cursor).unwrap_or(0);
            let limit = self.config.page_limit;
            let res = self
                .call(move |api, t| async move { api.pull(&t, vault.uuid(), since, limit).await })
                .await;
            let page = match res {
                Err(e) if e.code() == Some(ErrorCode::Gone) => {
                    return self.full_resync(vault).await;
                }
                Err(e) if e.code() == Some(ErrorCode::NotFound) => {
                    if self.unknown_vaults.insert(vault) {
                        tracing::warn!(%vault, "vault is not on the server (or no longer a member)");
                    }
                    return Ok(());
                }
                other => other?,
            };
            // M5-04: items under a key version this engine doesn't hold yet (a
            // rotation committed and `vault_changed` overtook `vault_access
            // rotated`): fetch the new key first; without it, stop here so the
            // cursor never moves past items that can't be opened.
            if self.needs_newer_key(vault, &page.items) {
                self.refresh_vaults().await?;
                if self.needs_newer_key(vault, &page.items) {
                    tracing::info!(%vault, "items under a newer vault key; pull paused until the key is available");
                    return Ok(());
                }
            }
            let more = page.more && !page.items.is_empty();
            let new_cursor = if more {
                page.items.last().map_or(page.head_revision, |i| i.revision)
            } else {
                page.head_revision
            };
            self.apply_page(vault, cursor, page.items, wire_rev(new_cursor))
                .await?;
            if !more {
                return Ok(());
            }
        }
    }

    // M5-04
    /// Whether `items` include a key version newer than the loaded ones.
    fn needs_newer_key(&self, vault: VaultId, items: &[WireItem]) -> bool {
        let k = self.keys.read();
        let current = k.current_version(vault).unwrap_or(0);
        items.iter().any(|i| i.key_version > current)
    }

    async fn apply_page(
        &mut self,
        vault: VaultId,
        cursor: i64,
        items: Vec<WireItem>,
        new_cursor: i64,
    ) -> Result<(), SyncError> {
        if items.is_empty() && new_cursor == cursor {
            return Ok(());
        }
        let keys = self.keys.clone();
        let hlc = self.hlc.clone();
        let crash = self.config.crash_after_items;
        let report = self
            .store
            .write(move |w| {
                let k = keys.read();
                let mut h = hlc.lock();
                let mut report = PageReport::default();
                let mut page = Vec::with_capacity(items.len());
                for it in &items {
                    if let Some(si) = incoming(w.as_read(), &k, &mut h, vault, it, &mut report)? {
                        page.push(si);
                    }
                }
                if let Some(n) = crash {
                    w.apply_remote(vault, &page[..n.min(page.len())], cursor)?;
                    #[allow(clippy::panic)]
                    {
                        panic!("injected crash after {n} items (test hook)");
                    }
                }
                w.apply_remote(vault, &page, new_cursor)?;
                report.applied = page.iter().map(|p| p.id).collect();
                Ok(report)
            })
            .await?;
        self.after_page(vault, report);
        Ok(())
    }

    /// Bookkeeping and events after a committed page.
    pub(crate) fn after_page(&mut self, vault: VaultId, report: PageReport) {
        for id in &report.decrypted {
            self.undecryptable.remove(id);
        }
        self.undecryptable
            .extend(report.undecryptable.iter().copied());
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
    }
}
