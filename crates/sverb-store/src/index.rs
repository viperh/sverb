//! The optional `item_index` TEMP table (§5.2) for SQL-side filtering.
//!
//! **Decision:** the decrypted search index lives in Rust memory
//! (nucleo). This TEMP table is optional. A TEMP table exists only on the
//! connection that created it, so it lives on the **writer** connection, and
//! `temp_store = MEMORY` keeps it off disk (not even temp files).
//!
//! No decrypted data is ever written to a non-TEMP table: the persistent tables
//! ([`crate::schema::TABLES`]) only hold envelopes, ids, revisions, wrapped keys
//! and device-local metadata. Test T-12 greps the database files for a canary.

use rusqlite::{Connection, params};
use sverb_core::model::{ItemId, VaultId};

use crate::db::Store;
use crate::error::{Result, StoreError};

/// One decrypted index row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexRow {
    /// Item id.
    pub item_id: ItemId,
    /// Its vault.
    pub vault_id: VaultId,
    /// `ItemKind` as an integer.
    pub kind: i64,
    /// Decrypted label.
    pub label: String,
    /// Decrypted search text (address, tags, group path…).
    pub search: String,
}

const CREATE: &str = "CREATE TEMP TABLE IF NOT EXISTS item_index (
    item_id BLOB PRIMARY KEY, vault_id BLOB, kind INTEGER, label TEXT, search TEXT)";

fn ensure_memory_temp_store(conn: &Connection) -> Result<()> {
    let mode: i64 = conn.query_row("PRAGMA temp_store", [], |r| r.get(0))?;
    if mode != 2 {
        return Err(StoreError::Corrupt(format!(
            "temp_store is {mode}, not MEMORY; refusing to create the decrypted index"
        )));
    }
    Ok(())
}

fn upsert_rows(conn: &Connection, rows: &[IndexRow]) -> Result<()> {
    let mut stmt = conn.prepare_cached(
        "INSERT OR REPLACE INTO temp.item_index (item_id, vault_id, kind, label, search)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )?;
    for row in rows {
        stmt.execute(params![
            row.item_id.as_bytes(),
            row.vault_id.as_bytes(),
            row.kind,
            row.label,
            row.search
        ])?;
    }
    Ok(())
}

impl Store {
    /// (Re)creates `temp.item_index` on the writer connection with `rows`
    /// (full rebuild at unlock).
    pub async fn rebuild_temp_index(&self, rows: Vec<IndexRow>) -> Result<()> {
        self.with_writer_conn(move |conn| {
            ensure_memory_temp_store(conn)?;
            conn.execute_batch(CREATE)?;
            conn.execute("DELETE FROM temp.item_index", [])?;
            upsert_rows(conn, &rows)
        })
        .await
    }

    /// Inserts or replaces rows of `temp.item_index` (incremental update).
    pub async fn upsert_temp_index(&self, rows: Vec<IndexRow>) -> Result<()> {
        self.with_writer_conn(move |conn| {
            ensure_memory_temp_store(conn)?;
            conn.execute_batch(CREATE)?;
            upsert_rows(conn, &rows)
        })
        .await
    }

    /// Item ids whose label or search text contains `needle` (SQL `LIKE`,
    /// case-insensitive for ASCII). Empty if the index does not exist.
    pub async fn query_temp_index(&self, needle: String) -> Result<Vec<ItemId>> {
        self.with_writer_conn(move |conn| {
            let exists: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_temp_master WHERE name = 'item_index')",
                [],
                |r| r.get(0),
            )?;
            if !exists {
                return Ok(Vec::new());
            }
            let escaped = needle
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            let pattern = format!("%{escaped}%");
            let mut stmt = conn.prepare_cached(
                "SELECT item_id FROM temp.item_index
                 WHERE label LIKE ?1 ESCAPE '\\' OR search LIKE ?1 ESCAPE '\\' ORDER BY label",
            )?;
            let ids = stmt
                .query_map(params![pattern], |r| r.get::<_, Vec<u8>>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            ids.into_iter()
                .map(|b| crate::vaults::id16(b, "item_index.item_id").map(ItemId::from_bytes))
                .collect()
        })
        .await
    }

    /// Drops `temp.item_index` (on lock).
    pub async fn drop_temp_index(&self) -> Result<()> {
        self.with_writer_conn(|conn| {
            conn.execute_batch("DROP TABLE IF EXISTS temp.item_index")?;
            Ok(())
        })
        .await
    }
}
