//! The `sync_state` singleton (row `id = 1`, enforced by a CHECK constraint).
//!
//! `tokens_enc` is stored exactly as given; the caller AEADs the tokens under
//! the LMK first (M4-07).

use rusqlite::{OptionalExtension, params};
use sverb_core::model::DeviceId;

use crate::db::{ReadTx, Store, WriteTx};
use crate::error::Result;
use crate::vaults::id16;

/// The sync configuration of this device.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncState {
    /// Server base URL (no default, §1.1).
    pub server_url: Option<String>,
    /// Server-assigned device id.
    pub device_id: Option<DeviceId>,
    /// Access and refresh tokens, AEAD'd under the LMK by the caller.
    pub tokens_enc: Option<Vec<u8>>,
}

impl ReadTx<'_> {
    /// The singleton row, if set.
    pub fn get_sync_state(&self) -> Result<Option<SyncState>> {
        let raw = self
            .conn
            .query_row(
                "SELECT server_url, device_id, tokens_enc FROM sync_state WHERE id = 1",
                [],
                |r| {
                    Ok((
                        r.get::<_, Option<String>>(0)?,
                        r.get::<_, Option<Vec<u8>>>(1)?,
                        r.get::<_, Option<Vec<u8>>>(2)?,
                    ))
                },
            )
            .optional()?;
        raw.map(|(server_url, device_id, tokens_enc)| {
            Ok(SyncState {
                server_url,
                device_id: device_id
                    .map(|d| id16(d, "sync_state.device_id").map(DeviceId::from_bytes))
                    .transpose()?,
                tokens_enc,
            })
        })
        .transpose()
    }
}

impl WriteTx<'_> {
    /// Replaces the singleton row.
    pub fn set_sync_state(&self, state: &SyncState) -> Result<()> {
        self.conn.execute(
            "INSERT INTO sync_state (id, server_url, device_id, tokens_enc) VALUES (1, ?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET
                server_url = excluded.server_url,
                device_id = excluded.device_id,
                tokens_enc = excluded.tokens_enc",
            params![
                state.server_url,
                state.device_id.as_ref().map(|d| d.as_bytes().as_slice()),
                state.tokens_enc
            ],
        )?;
        Ok(())
    }

    /// Removes the singleton row (sync disabled / logged out).
    pub fn clear_sync_state(&self) -> Result<()> {
        self.conn.execute("DELETE FROM sync_state", [])?;
        Ok(())
    }
}

impl Store {
    /// See [`ReadTx::get_sync_state`].
    pub async fn get_sync_state(&self) -> Result<Option<SyncState>> {
        self.read(|r| r.get_sync_state()).await
    }

    /// See [`WriteTx::set_sync_state`].
    pub async fn set_sync_state(&self, state: SyncState) -> Result<()> {
        self.write(move |w| w.set_sync_state(&state)).await
    }

    /// See [`WriteTx::clear_sync_state`].
    pub async fn clear_sync_state(&self) -> Result<()> {
        self.write(|w| w.clear_sync_state()).await
    }
}
