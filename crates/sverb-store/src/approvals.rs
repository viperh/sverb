//! M2-10: the `local_approvals` table (SPEC §17.1): the device-local allowlist of
//! values that act on this machine.
//!
//! One row per `(item_id, field)`, holding the SHA-256 of the exact value the user
//! approved (the hash is computed by `sverb_core::resolve::approval`). A changed value
//! no longer matches its row and is asked for again; approving it again upserts the
//! row. The table is never synced: rows are not items, have no envelope and never
//! enter the outbox.
//!
//! Every [`Store`] carries the device's [`DeviceApprovals`] ([`Store::device_approvals`]),
//! loaded when the store opens: the connector, the forward manager and the UI check
//! against it synchronously; approvals made through it are written back here
//! (`StoreSink`, a spawned write). [`Store::approve_local`] and
//! [`Store::revoke_local`] write first and then update it, for callers that must know
//! the row is stored (the CLI, the form save path).

use std::sync::Arc;

use rusqlite::{Connection, OptionalExtension, params};
use sverb_core::model::ItemId;
use sverb_core::resolve::approval::{
    ApprovalSink, DeviceApprovals, LocalAction, ValueHash, value_sha256,
};

use crate::db::{ReadTx, Store, WeakStore, WriteTx};
use crate::error::{Result, StoreError};
use crate::vaults::id16;

/// One row of `local_approvals`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalApproval {
    /// The item defining the value (host, group, vault defaults or forward).
    pub item_id: ItemId,
    /// The field (`proxy.command`, `bind_addr`, `dest_host`, `agent_forwarding`).
    pub field: String,
    /// SHA-256 of the approved value.
    pub value_sha256: [u8; 32],
    /// When it was approved (UNIX ms).
    pub approved_at: i64,
}

type RawApproval = (Vec<u8>, String, Vec<u8>, i64);

fn decode(raw: RawApproval) -> Result<LocalApproval> {
    let (id, field, hash, approved_at) = raw;
    let value_sha256: [u8; 32] = hash
        .try_into()
        .map_err(|_| StoreError::Corrupt("local_approvals.value_sha256 is not 32 bytes".into()))?;
    Ok(LocalApproval {
        item_id: ItemId::from_bytes(id16(id, "local_approvals.item_id")?),
        field,
        value_sha256,
        approved_at,
    })
}

const COLS: &str = "item_id, field, value_sha256, approved_at";

fn raw(r: &rusqlite::Row<'_>) -> rusqlite::Result<RawApproval> {
    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
}

impl ReadTx<'_> {
    /// The approval row of `(item, field)`.
    pub fn get_local_approval(&self, item: ItemId, field: &str) -> Result<Option<LocalApproval>> {
        let found = self
            .conn
            .prepare_cached(&format!(
                "SELECT {COLS} FROM local_approvals WHERE item_id = ?1 AND field = ?2"
            ))?
            .query_row(params![item.as_bytes(), field], raw)
            .optional()?;
        found.map(decode).transpose()
    }

    /// Every approval row, ordered by item and field.
    pub fn list_local_approvals(&self) -> Result<Vec<LocalApproval>> {
        let mut stmt = self.conn.prepare_cached(&format!(
            "SELECT {COLS} FROM local_approvals ORDER BY item_id, field"
        ))?;
        let raws = stmt
            .query_map([], raw)?
            .collect::<rusqlite::Result<Vec<RawApproval>>>()?;
        raws.into_iter().map(decode).collect()
    }
}

impl WriteTx<'_> {
    /// Approve `value_sha256` for `(item, field)` at the transaction's time (upsert:
    /// a new value replaces the previous approval).
    pub fn put_local_approval(
        &self,
        item: ItemId,
        field: &str,
        value_sha256: &[u8; 32],
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO local_approvals (item_id, field, value_sha256, approved_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(item_id, field) DO UPDATE SET
                value_sha256 = excluded.value_sha256,
                approved_at = excluded.approved_at",
            params![item.as_bytes(), field, &value_sha256[..], self.now],
        )?;
        Ok(())
    }

    /// Revoke the approval of `(item, field)`. Returns whether a row existed.
    pub fn delete_local_approval(&self, item: ItemId, field: &str) -> Result<bool> {
        let n = self.conn.execute(
            "DELETE FROM local_approvals WHERE item_id = ?1 AND field = ?2",
            params![item.as_bytes(), field],
        )?;
        Ok(n > 0)
    }

    /// Revoke every approval of `item` (e.g. after it was purged). Returns the count.
    pub fn delete_local_approvals_of(&self, item: ItemId) -> Result<usize> {
        Ok(self.conn.execute(
            "DELETE FROM local_approvals WHERE item_id = ?1",
            params![item.as_bytes()],
        )?)
    }
}

impl Store {
    /// See [`WriteTx::put_local_approval`]; also updates
    /// [`Store::device_approvals`].
    pub async fn put_local_approval(
        &self,
        item: ItemId,
        field: String,
        value_sha256: [u8; 32],
    ) -> Result<()> {
        let f = field.clone();
        self.write(move |w| w.put_local_approval(item, &f, &value_sha256))
            .await?;
        self.inner.approvals.remember(item, &field, value_sha256);
        Ok(())
    }

    /// See [`WriteTx::delete_local_approval`]; also updates
    /// [`Store::device_approvals`].
    pub async fn delete_local_approval(&self, item: ItemId, field: String) -> Result<bool> {
        self.revoke_local(item, field).await
    }

    /// See [`ReadTx::get_local_approval`].
    pub async fn get_local_approval(
        &self,
        item: ItemId,
        field: String,
    ) -> Result<Option<LocalApproval>> {
        self.read(move |r| r.get_local_approval(item, &field)).await
    }

    /// See [`ReadTx::list_local_approvals`].
    pub async fn list_local_approvals(&self) -> Result<Vec<LocalApproval>> {
        self.read(|r| r.list_local_approvals()).await
    }
}

// ---------------------------------------------------------------------- M2-10 runtime

/// Every row as `(item, field, hash)`, read on `conn` (at open).
pub(crate) fn load_rows(conn: &Connection) -> Result<Vec<(ItemId, String, ValueHash)>> {
    let mut stmt = conn.prepare(&format!("SELECT {COLS} FROM local_approvals"))?;
    let raws = stmt
        .query_map([], raw)?
        .collect::<rusqlite::Result<Vec<RawApproval>>>()?;
    raws.into_iter()
        .map(|r| decode(r).map(|a| (a.item_id, a.field, a.value_sha256)))
        .collect()
}

/// The [`DeviceApprovals`] of a store being opened.
pub(crate) fn device_approvals(
    store: WeakStore,
    rows: Vec<(ItemId, String, ValueHash)>,
) -> Arc<DeviceApprovals> {
    let approvals = DeviceApprovals::with_sink(Arc::new(StoreSink(store)));
    approvals.load(rows);
    Arc::new(approvals)
}

/// Persists [`DeviceApprovals`] changes: a write spawned on the current Tokio
/// runtime (the in-memory view is already updated). Without a runtime, or once the
/// store is gone, the change stays in memory and is logged.
struct StoreSink(WeakStore);

impl std::fmt::Debug for StoreSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StoreSink")
    }
}

impl StoreSink {
    fn spawn<F>(&self, what: &'static str, f: F)
    where
        F: FnOnce(&WriteTx<'_>) -> Result<()> + Send + 'static,
    {
        let (Some(store), Ok(rt)) = (self.0.upgrade(), tokio::runtime::Handle::try_current())
        else {
            tracing::warn!(what, "local approval not persisted (no store or runtime)");
            return;
        };
        rt.spawn(async move {
            if let Err(e) = store.write(f).await {
                tracing::warn!(what, error = %e, "local approval not persisted");
            }
        });
    }
}

impl ApprovalSink for StoreSink {
    fn approved(&self, item: ItemId, field: &str, hash: ValueHash) {
        let field = field.to_owned();
        self.spawn("approve", move |w| {
            w.put_local_approval(item, &field, &hash)
        });
    }

    fn revoked(&self, item: ItemId, field: &str) {
        let field = field.to_owned();
        self.spawn("revoke", move |w| {
            w.delete_local_approval(item, &field).map(|_| ())
        });
    }
}

impl Store {
    /// The device's approvals (shared by every clone of this store).
    pub fn device_approvals(&self) -> Arc<DeviceApprovals> {
        Arc::clone(&self.inner.approvals)
    }

    /// Approve `action` and wait until the row is stored; then the in-memory view
    /// has it too.
    ///
    /// # Errors
    /// Storage failures (nothing is approved).
    pub async fn approve_local(&self, action: &LocalAction) -> Result<()> {
        self.approve_all_local(std::slice::from_ref(action)).await
    }

    /// [`Store::approve_local`] for several values, in one transaction.
    ///
    /// # Errors
    /// Storage failures (nothing is approved).
    pub async fn approve_all_local(&self, actions: &[LocalAction]) -> Result<()> {
        if actions.is_empty() {
            return Ok(());
        }
        let rows: Vec<(ItemId, &'static str, ValueHash)> = actions
            .iter()
            .map(|a| (a.item_id, a.field(), value_sha256(&a.value)))
            .collect();
        let written = rows.clone();
        self.write(move |w| {
            for (item, field, hash) in &written {
                w.put_local_approval(*item, field, hash)?;
            }
            Ok(())
        })
        .await?;
        for (item, field, hash) in rows {
            self.inner.approvals.remember(item, field, hash);
        }
        Ok(())
    }

    /// Revoke `(item, field)` and wait until it is deleted. Returns whether a row
    /// existed.
    ///
    /// # Errors
    /// Storage failures.
    pub async fn revoke_local(&self, item: ItemId, field: String) -> Result<bool> {
        let f = field.clone();
        let existed = self
            .write(move |w| w.delete_local_approval(item, &f))
            .await?;
        self.inner.approvals.forget(item, &field);
        Ok(existed)
    }

    /// Re-read the table into [`Store::device_approvals`] (after another process,
    /// such as `sverb approve`, wrote to it). Session denials are kept.
    ///
    /// # Errors
    /// Storage failures.
    pub async fn reload_device_approvals(&self) -> Result<()> {
        let rows = self.list_local_approvals().await?;
        self.inner.approvals.replace(
            rows.into_iter()
                .map(|r| (r.item_id, r.field, r.value_sha256)),
        );
        Ok(())
    }
}
