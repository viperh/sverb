//! The `items` table: encrypted item envelopes, server revisions and the dirty
//! flag (§5.2, §12.1–12.3).
//!
//! **Plaintext guarantee:** the store only ever receives envelopes (bytes sealed by
//! `sverb_crypto::envelope::seal_item`). Every write checks that the bytes look like
//! an envelope ([`check_envelope`]), so a plaintext body handed over by mistake is
//! refused instead of reaching disk. Encryption is the vault service's job (M1-04).

use rusqlite::{OptionalExtension, Row, params};
use sverb_core::model::{ItemId, VaultId};
use sverb_crypto::envelope::{FORMAT_V1, MIN_LEN, parse_header};

use crate::db::{ReadTx, Store, WriteTx};
use crate::error::{Result, StoreError};
use crate::vaults::id16;

/// One row of `items`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemRow {
    /// Item id.
    pub id: ItemId,
    /// The vault it belongs to.
    pub vault_id: VaultId,
    /// Server revision; 0 = never synced.
    pub revision: i64,
    /// Vault key version the envelope is sealed under.
    pub key_version: u32,
    /// The encrypted `ItemBody`.
    pub envelope: Vec<u8>,
    /// Tombstone flag (mirrors the body's `deleted` stamp, for cheap filtering).
    pub deleted: bool,
    /// Pending push.
    pub dirty: bool,
    /// Last local write, UNIX ms.
    pub updated_at: i64,
}

/// One item of a pulled page, as the sync engine (M4-07) wants it stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteItem {
    /// Item id.
    pub id: ItemId,
    /// The server revision of the incoming item.
    pub revision: i64,
    /// Vault key version of `envelope`.
    pub key_version: u32,
    /// The envelope to store: the server's as received, or the locally re-sealed
    /// merge result when `local_pending` is set.
    pub envelope: Vec<u8>,
    /// Tombstone flag.
    pub deleted: bool,
    /// `false`: the local copy was clean (or the merge result equals the remote),
    /// so the item becomes clean and any outbox row is dropped (§12.2 step 2).
    /// `true`: the envelope is a merge of a dirty local copy; the item stays dirty
    /// and its outbox row is rebased onto `revision` (§12.2 step 3).
    pub local_pending: bool,
}

/// Checks that `envelope` is shaped like a sealed item and that a v1 header
/// matches `key_version`. Unknown format bytes from newer builds are accepted.
///
/// # Errors
/// [`StoreError::InvalidEnvelope`].
pub fn check_envelope(envelope: &[u8], key_version: u32) -> Result<()> {
    if envelope.len() < MIN_LEN {
        return Err(StoreError::InvalidEnvelope("too short to be an envelope"));
    }
    if envelope[0] == FORMAT_V1 {
        let header =
            parse_header(envelope).map_err(|_| StoreError::InvalidEnvelope("malformed header"))?;
        if header.key_version != key_version {
            return Err(StoreError::InvalidEnvelope(
                "header key_version does not match the declared key_version",
            ));
        }
    }
    Ok(())
}

const ITEM_COLS: &str = "id, vault_id, revision, key_version, envelope, deleted, dirty, updated_at";

type RawItem = (Vec<u8>, Vec<u8>, i64, i64, Vec<u8>, bool, bool, i64);

fn raw_item(row: &Row<'_>) -> rusqlite::Result<RawItem> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
    ))
}

fn decode_item(raw: RawItem) -> Result<ItemRow> {
    let (id, vault_id, revision, key_version, envelope, deleted, dirty, updated_at) = raw;
    Ok(ItemRow {
        id: ItemId::from_bytes(id16(id, "items.id")?),
        vault_id: VaultId::from_bytes(id16(vault_id, "items.vault_id")?),
        revision,
        key_version: u32::try_from(key_version)
            .map_err(|_| StoreError::Corrupt("invalid items.key_version".into()))?,
        envelope,
        deleted,
        dirty,
        updated_at,
    })
}

impl ReadTx<'_> {
    fn query_items(&self, where_sql: &str, args: impl rusqlite::Params) -> Result<Vec<ItemRow>> {
        let mut stmt = self
            .conn
            .prepare_cached(&format!("SELECT {ITEM_COLS} FROM items {where_sql}"))?;
        let raws = stmt
            .query_map(args, raw_item)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        raws.into_iter().map(decode_item).collect()
    }

    /// One item (tombstones included).
    pub fn get_item(&self, id: ItemId) -> Result<Option<ItemRow>> {
        let raw = self
            .conn
            .prepare_cached(&format!("SELECT {ITEM_COLS} FROM items WHERE id = ?1"))?
            .query_row(params![id.as_bytes()], raw_item)
            .optional()?;
        raw.map(decode_item).transpose()
    }

    /// All items of a vault (tombstones included), in id order.
    pub fn list_items(&self, vault: VaultId) -> Result<Vec<ItemRow>> {
        self.query_items("WHERE vault_id = ?1 ORDER BY id", params![vault.as_bytes()])
    }

    /// Every item of every vault (for the index rebuild on unlock).
    pub fn list_all_items(&self) -> Result<Vec<ItemRow>> {
        self.query_items("ORDER BY id", [])
    }

    /// Dirty items of a vault (pending push).
    pub fn list_dirty(&self, vault: VaultId) -> Result<Vec<ItemRow>> {
        self.query_items(
            "WHERE dirty = 1 AND vault_id = ?1 ORDER BY id",
            params![vault.as_bytes()],
        )
    }

    /// Number of items (tombstones included).
    pub fn item_count(&self) -> Result<u64> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM items", [], |r| r.get(0))?;
        Ok(u64::try_from(n).unwrap_or(0))
    }
}

impl WriteTx<'_> {
    /// Upserts a local write of an item: sets `updated_at` and, with `mark_dirty`,
    /// sets `dirty = 1` and enqueues it in the outbox with the item's current
    /// server revision as base (coalescing keeps an older base, §5.2).
    ///
    /// A clean write (`mark_dirty = false`) never clears an existing dirty flag.
    ///
    /// # Errors
    /// [`StoreError::ReadOnlyItem`] for items marked read-only,
    /// [`StoreError::InvalidEnvelope`], or a SQLite error (e.g. unknown vault).
    pub fn put_item(
        &self,
        vault: VaultId,
        id: ItemId,
        key_version: u32,
        envelope: &[u8],
        deleted: bool,
        mark_dirty: bool,
    ) -> Result<()> {
        self.ensure_writable(id)?;
        check_envelope(envelope, key_version)?;
        self.conn.execute(
            "INSERT INTO items (id, vault_id, key_version, envelope, deleted, dirty, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET
                vault_id = excluded.vault_id,
                key_version = excluded.key_version,
                envelope = excluded.envelope,
                deleted = excluded.deleted,
                dirty = MAX(items.dirty, excluded.dirty),
                updated_at = excluded.updated_at",
            params![
                id.as_bytes(),
                vault.as_bytes(),
                key_version,
                envelope,
                deleted,
                mark_dirty,
                self.now
            ],
        )?;
        if mark_dirty {
            let revision: i64 = self.conn.query_row(
                "SELECT revision FROM items WHERE id = ?1",
                params![id.as_bytes()],
                |r| r.get(0),
            )?;
            self.enqueue(id, vault, revision)?;
        }
        Ok(())
    }

    /// Applies one pulled page and advances the vault cursor to `new_cursor`, in
    /// this transaction (§12.2). Any error rolls back the whole page and the cursor.
    ///
    /// Read-only marks do not apply: remote data is authoritative.
    ///
    /// # Errors
    /// [`StoreError::InvalidEnvelope`], [`StoreError::NotFound`] (unknown vault),
    /// or a SQLite error.
    pub fn apply_remote(&self, vault: VaultId, page: &[RemoteItem], new_cursor: i64) -> Result<()> {
        for item in page {
            check_envelope(&item.envelope, item.key_version)?;
            self.conn.execute(
                "INSERT INTO items (id, vault_id, revision, key_version, envelope, deleted, dirty, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(id) DO UPDATE SET
                    vault_id = excluded.vault_id,
                    revision = excluded.revision,
                    key_version = excluded.key_version,
                    envelope = excluded.envelope,
                    deleted = excluded.deleted,
                    dirty = excluded.dirty,
                    updated_at = excluded.updated_at",
                params![
                    item.id.as_bytes(),
                    vault.as_bytes(),
                    item.revision,
                    item.key_version,
                    item.envelope,
                    item.deleted,
                    item.local_pending,
                    self.now
                ],
            )?;
            if item.local_pending {
                // Rebase, or queue if the row was somehow missing.
                self.enqueue(item.id, vault, item.revision)?;
                self.rebase(item.id, item.revision)?;
            } else {
                self.dequeue(item.id)?;
            }
        }
        self.set_sync_cursor(vault, new_cursor)
    }

    /// Records a successful push of `id` at server `revision` (§12.3 `ok`).
    ///
    /// If the outbox row is still the one that was pushed (`queued_at` equals
    /// `pushed_queued_at`), the item becomes clean and the row is removed.
    /// If the item was edited again meanwhile, it stays dirty and the row is
    /// rebased onto `revision`.
    pub fn mark_pushed(&self, id: ItemId, revision: i64, pushed_queued_at: i64) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE items SET revision = ?2 WHERE id = ?1",
            params![id.as_bytes(), revision],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        let queued: Option<i64> = self
            .conn
            .query_row(
                "SELECT queued_at FROM outbox WHERE item_id = ?1",
                params![id.as_bytes()],
                |r| r.get(0),
            )
            .optional()?;
        match queued {
            Some(q) if q != pushed_queued_at => self.rebase(id, revision),
            _ => {
                self.conn.execute(
                    "UPDATE items SET dirty = 0 WHERE id = ?1",
                    params![id.as_bytes()],
                )?;
                self.dequeue(id)
            }
        }
    }

    // M4-07
    /// Replaces the envelope of `id` with the same body re-sealed under another
    /// vault key version (key rotation, §12.3 / §13.2). Leaves `revision`, `dirty`,
    /// the outbox row and `updated_at` alone, and ignores read-only marks (the body
    /// is unchanged).
    ///
    /// # Errors
    /// [`StoreError::InvalidEnvelope`], [`StoreError::NotFound`], or a SQLite error.
    pub fn reseal_item(&self, id: ItemId, key_version: u32, envelope: &[u8]) -> Result<()> {
        check_envelope(envelope, key_version)?;
        let n = self.conn.execute(
            "UPDATE items SET key_version = ?2, envelope = ?3 WHERE id = ?1",
            params![id.as_bytes(), key_version, envelope],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    // M4-08
    /// Marks every item of `vault` as never synced (§11.2.1 registration, §1.1
    /// `logout --keep-local`): `revision = 0`, dirty, queued with
    /// `base_revision = 0` (existing outbox rows are rebased to 0), and the
    /// vault's cursor back to 0. Returns the number of items.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] (unknown vault), or a SQLite error.
    pub fn reset_sync(&self, vault: VaultId) -> Result<u64> {
        let v = vault.as_bytes();
        let n = self.conn.execute(
            "UPDATE items SET revision = 0, dirty = 1 WHERE vault_id = ?1",
            params![v],
        )?;
        self.conn.execute(
            "INSERT INTO outbox (item_id, vault_id, base_revision, queued_at)
             SELECT id, vault_id, 0, ?2 FROM items WHERE vault_id = ?1
             ON CONFLICT(item_id) DO UPDATE SET
                base_revision = 0,
                vault_id = excluded.vault_id,
                attempts = 0",
            params![v, self.now],
        )?;
        self.set_sync_cursor(vault, 0)?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    /// Removes an item and its outbox and device-local rows from this device
    /// (e.g. a clean item absent from the server after a full resync, §12.2).
    /// This is not a tombstone; use [`WriteTx::put_item`] with `deleted` for that.
    pub fn purge_item(&self, id: ItemId) -> Result<()> {
        let b = id.as_bytes();
        self.conn
            .execute("DELETE FROM outbox WHERE item_id = ?1", params![b])?;
        self.conn
            .execute("DELETE FROM device_local WHERE item_id = ?1", params![b])?;
        let n = self
            .conn
            .execute("DELETE FROM items WHERE id = ?1", params![b])?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }
}

impl Store {
    /// See [`WriteTx::put_item`].
    pub async fn put_item(
        &self,
        vault: VaultId,
        id: ItemId,
        key_version: u32,
        envelope: Vec<u8>,
        deleted: bool,
        mark_dirty: bool,
    ) -> Result<()> {
        self.write(move |w| w.put_item(vault, id, key_version, &envelope, deleted, mark_dirty))
            .await
    }

    /// See [`ReadTx::get_item`].
    pub async fn get_item(&self, id: ItemId) -> Result<Option<ItemRow>> {
        self.read(move |r| r.get_item(id)).await
    }

    /// See [`ReadTx::list_items`].
    pub async fn list_items(&self, vault: VaultId) -> Result<Vec<ItemRow>> {
        self.read(move |r| r.list_items(vault)).await
    }

    /// See [`ReadTx::list_all_items`].
    pub async fn list_all_items(&self) -> Result<Vec<ItemRow>> {
        self.read(|r| r.list_all_items()).await
    }

    /// See [`ReadTx::list_dirty`].
    pub async fn list_dirty(&self, vault: VaultId) -> Result<Vec<ItemRow>> {
        self.read(move |r| r.list_dirty(vault)).await
    }

    /// See [`WriteTx::apply_remote`].
    pub async fn apply_remote(
        &self,
        vault: VaultId,
        page: Vec<RemoteItem>,
        new_cursor: i64,
    ) -> Result<()> {
        self.write(move |w| w.apply_remote(vault, &page, new_cursor))
            .await
    }

    /// See [`WriteTx::mark_pushed`].
    pub async fn mark_pushed(
        &self,
        id: ItemId,
        revision: i64,
        pushed_queued_at: i64,
    ) -> Result<()> {
        self.write(move |w| w.mark_pushed(id, revision, pushed_queued_at))
            .await
    }

    /// See [`WriteTx::purge_item`].
    pub async fn purge_item(&self, id: ItemId) -> Result<()> {
        self.write(move |w| w.purge_item(id)).await
    }
}
