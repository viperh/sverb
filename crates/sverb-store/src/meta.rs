//! The `meta` key/value table: device-level settings and wrapped secrets.
//!
//! Values are opaque bytes. Anything secret (the wrapped LMK) is stored already
//! wrapped by the caller.

use rusqlite::{OptionalExtension, params};

use crate::db::{ReadTx, Store, WriteTx};
use crate::error::Result;

/// Well-known `meta` keys.
pub mod keys {
    /// KDF parameters and salt for the password KEK.
    pub const KDF: &str = "kdf";
    /// The LMK wrapped under the password KEK.
    pub const LMK_WRAPPED_PW: &str = "lmk_wrapped_pw";
    /// The LMK wrapped under the OS-keyring KEK.
    pub const LMK_WRAPPED_KEYRING: &str = "lmk_wrapped_keyring";
    /// Consecutive failed unlock attempts.
    pub const UNLOCK_FAILURES: &str = "unlock_failures";
    /// Earliest time (UNIX ms) the next unlock attempt is allowed.
    pub const UNLOCK_NEXT_ALLOWED_AT: &str = "unlock_next_allowed_at";
    /// This device's id.
    pub const DEVICE_ID: &str = "device_id";
    /// Last HLC timestamp issued by this device.
    pub const HLC_LAST: &str = "hlc_last";
    /// Random id of this database (UUID text), so several `SVERB_HOME`s use distinct
    /// OS-keyring accounts (`lmk-kek:<db_id>`).
    pub const DB_ID: &str = "db_id";
}

impl ReadTx<'_> {
    /// The value for `key`.
    pub fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .conn
            .prepare_cached("SELECT value FROM meta WHERE key = ?1")?
            .query_row(params![key], |r| r.get(0))
            .optional()?)
    }
}

impl WriteTx<'_> {
    /// Sets `key` to `value`.
    pub fn set_meta(&self, key: &str, value: &[u8]) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Removes `key` (a no-op if absent).
    pub fn delete_meta(&self, key: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM meta WHERE key = ?1", params![key])?;
        Ok(())
    }
}

impl Store {
    /// See [`ReadTx::get_meta`].
    pub async fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let key = key.to_owned();
        self.read(move |r| r.get_meta(&key)).await
    }

    /// See [`WriteTx::set_meta`].
    pub async fn set_meta(&self, key: &str, value: Vec<u8>) -> Result<()> {
        let key = key.to_owned();
        self.write(move |w| w.set_meta(&key, &value)).await
    }

    /// See [`WriteTx::delete_meta`].
    pub async fn delete_meta(&self, key: &str) -> Result<()> {
        let key = key.to_owned();
        self.write(move |w| w.delete_meta(&key)).await
    }
}
