//! The `vaults` table: wrapped vault keys and per-vault sync cursors.

use rusqlite::{OptionalExtension, Row, params};
use sverb_core::model::{OrgId, VaultId};

use crate::db::{ReadTx, Store, WriteTx};
use crate::error::{Result, StoreError};

/// Vault kind, stored as an integer (`0` personal, `1` shared).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VaultKind {
    /// The user's own vault.
    Personal,
    /// A team vault shared through an org (§13).
    Shared,
}

impl VaultKind {
    /// The stored integer.
    pub const fn as_i64(self) -> i64 {
        match self {
            Self::Personal => 0,
            Self::Shared => 1,
        }
    }

    /// Parses the stored integer.
    pub const fn from_i64(v: i64) -> Option<Self> {
        match v {
            0 => Some(Self::Personal),
            1 => Some(Self::Shared),
            _ => None,
        }
    }
}

/// One row of `vaults`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultRow {
    /// Vault id.
    pub id: VaultId,
    /// Personal or shared.
    pub kind: VaultKind,
    /// Owning org for shared vaults.
    pub org_id: Option<OrgId>,
    /// Version of the vault key `wrapped_key` holds.
    pub key_version: u32,
    /// The vault key, wrapped (under the LMK or the account keys). Never plaintext.
    pub wrapped_key: Vec<u8>,
    /// Highest server revision applied locally (§12.1).
    pub sync_cursor: i64,
}

pub(crate) fn id16(bytes: Vec<u8>, what: &str) -> Result<[u8; 16]> {
    bytes
        .try_into()
        .map_err(|_| StoreError::Corrupt(format!("{what} is not a 16-byte id")))
}

fn vault_from_row(row: &Row<'_>) -> rusqlite::Result<RawVault> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
    ))
}

type RawVault = (
    Vec<u8>,
    Option<i64>,
    Option<Vec<u8>>,
    Option<i64>,
    Vec<u8>,
    i64,
);

fn decode_vault(raw: RawVault) -> Result<VaultRow> {
    let (id, kind, org, key_version, wrapped_key, sync_cursor) = raw;
    Ok(VaultRow {
        id: VaultId::from_bytes(id16(id, "vaults.id")?),
        kind: kind
            .and_then(VaultKind::from_i64)
            .ok_or_else(|| StoreError::Corrupt("unknown vaults.kind".into()))?,
        org_id: org
            .map(|o| id16(o, "vaults.org_id").map(OrgId::from_bytes))
            .transpose()?,
        key_version: key_version
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| StoreError::Corrupt("invalid vaults.key_version".into()))?,
        wrapped_key,
        sync_cursor,
    })
}

const VAULT_COLS: &str = "id, kind, org_id, key_version, wrapped_key, sync_cursor";

impl ReadTx<'_> {
    /// All vaults, in id order.
    pub fn list_vaults(&self) -> Result<Vec<VaultRow>> {
        let mut stmt = self
            .conn
            .prepare_cached(&format!("SELECT {VAULT_COLS} FROM vaults ORDER BY id"))?;
        let raws = stmt
            .query_map([], vault_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        raws.into_iter().map(decode_vault).collect()
    }

    /// One vault.
    pub fn get_vault(&self, id: VaultId) -> Result<Option<VaultRow>> {
        let raw = self
            .conn
            .prepare_cached(&format!("SELECT {VAULT_COLS} FROM vaults WHERE id = ?1"))?
            .query_row(params![id.as_bytes()], vault_from_row)
            .optional()?;
        raw.map(decode_vault).transpose()
    }
}

impl WriteTx<'_> {
    /// Inserts a vault. `wrapped_key` must already be wrapped.
    pub fn create_vault(
        &self,
        id: VaultId,
        kind: VaultKind,
        org_id: Option<OrgId>,
        key_version: u32,
        wrapped_key: &[u8],
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO vaults (id, kind, org_id, key_version, wrapped_key) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                id.as_bytes(),
                kind.as_i64(),
                org_id.as_ref().map(|o| o.as_bytes().as_slice()),
                key_version,
                wrapped_key
            ],
        )?;
        Ok(())
    }

    /// Replaces the wrapped vault key (rewrap or rotation).
    pub fn update_wrapped_key(
        &self,
        id: VaultId,
        key_version: u32,
        wrapped_key: &[u8],
    ) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE vaults SET key_version = ?2, wrapped_key = ?3 WHERE id = ?1",
            params![id.as_bytes(), key_version, wrapped_key],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Sets the vault's sync cursor.
    pub fn set_sync_cursor(&self, id: VaultId, cursor: i64) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE vaults SET sync_cursor = ?2 WHERE id = ?1",
            params![id.as_bytes(), cursor],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Deletes the vault with its items, their outbox rows and their
    /// device-local rows (all inside this transaction).
    pub fn delete_vault(&self, id: VaultId) -> Result<()> {
        let v = id.as_bytes();
        self.conn.execute(
            "DELETE FROM device_local WHERE item_id IN (SELECT id FROM items WHERE vault_id = ?1)",
            params![v],
        )?;
        self.conn
            .execute("DELETE FROM outbox WHERE vault_id = ?1", params![v])?;
        self.conn
            .execute("DELETE FROM items WHERE vault_id = ?1", params![v])?;
        let n = self
            .conn
            .execute("DELETE FROM vaults WHERE id = ?1", params![v])?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }
}

impl Store {
    /// See [`WriteTx::create_vault`].
    pub async fn create_vault(
        &self,
        id: VaultId,
        kind: VaultKind,
        org_id: Option<OrgId>,
        key_version: u32,
        wrapped_key: Vec<u8>,
    ) -> Result<()> {
        self.write(move |w| w.create_vault(id, kind, org_id, key_version, &wrapped_key))
            .await
    }

    /// See [`ReadTx::list_vaults`].
    pub async fn list_vaults(&self) -> Result<Vec<VaultRow>> {
        self.read(|r| r.list_vaults()).await
    }

    /// See [`ReadTx::get_vault`].
    pub async fn get_vault(&self, id: VaultId) -> Result<Option<VaultRow>> {
        self.read(move |r| r.get_vault(id)).await
    }

    /// See [`WriteTx::update_wrapped_key`].
    pub async fn update_wrapped_key(
        &self,
        id: VaultId,
        key_version: u32,
        wrapped_key: Vec<u8>,
    ) -> Result<()> {
        self.write(move |w| w.update_wrapped_key(id, key_version, &wrapped_key))
            .await
    }

    /// See [`WriteTx::set_sync_cursor`].
    pub async fn set_sync_cursor(&self, id: VaultId, cursor: i64) -> Result<()> {
        self.write(move |w| w.set_sync_cursor(id, cursor)).await
    }

    /// See [`WriteTx::delete_vault`].
    pub async fn delete_vault(&self, id: VaultId) -> Result<()> {
        self.write(move |w| w.delete_vault(id)).await
    }
}
