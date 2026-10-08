//! The `device_local` table (§12.6): per-item data that never leaves this
//! device — last connection time, frecency and the recording directory.
//!
//! # Frecency
//!
//! The spec does not define a formula; sverb uses an exponentially decaying
//! connect count with a **14-day half-life**. On each connect at time `t`:
//!
//! ```text
//! frecency = frecency_prev * 0.5^(Δdays / 14) + 1      Δdays = (t - last_connected_at) / 1 day
//! ```
//!
//! (`Δdays` is clamped at 0 if the clock went backwards.) To rank items at time
//! `now`, decay the stored value to `now` with [`DeviceLocal::score_at`]; that
//! makes rankings comparable between items last used at different times.

use rusqlite::{OptionalExtension, params};
use sverb_core::model::ItemId;

use crate::db::{ReadTx, Store, WriteTx};
use crate::error::Result;
use crate::vaults::id16;

/// Frecency half-life, in days.
pub const FRECENCY_HALF_LIFE_DAYS: f64 = 14.0;

const DAY_MS: f64 = 86_400_000.0;

/// `value` (last bumped at `then`) decayed to `now`.
pub fn decay(value: f64, then: i64, now: i64) -> f64 {
    #[allow(clippy::cast_precision_loss)]
    let days = (now.saturating_sub(then)).max(0) as f64 / DAY_MS;
    value * 0.5_f64.powf(days / FRECENCY_HALF_LIFE_DAYS)
}

/// The frecency after a connect at `now`, given the previous value and time.
pub fn bump_frecency(prev: Option<(f64, i64)>, now: i64) -> f64 {
    prev.map_or(0.0, |(value, then)| decay(value, then, now)) + 1.0
}

/// One row of `device_local`.
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceLocal {
    /// The item.
    pub item_id: ItemId,
    /// Last successful connect, UNIX ms.
    pub last_connected_at: Option<i64>,
    /// Stored frecency (as of `last_connected_at`).
    pub frecency: f64,
    /// Per-host recording directory override.
    pub recording_dir: Option<String>,
}

impl DeviceLocal {
    /// The frecency decayed to `now`, for ranking.
    pub fn score_at(&self, now: i64) -> f64 {
        match self.last_connected_at {
            Some(then) => decay(self.frecency, then, now),
            None => self.frecency,
        }
    }
}

type RawLocal = (Vec<u8>, Option<i64>, Option<f64>, Option<String>);

fn decode(raw: RawLocal) -> Result<DeviceLocal> {
    let (id, last_connected_at, frecency, recording_dir) = raw;
    Ok(DeviceLocal {
        item_id: ItemId::from_bytes(id16(id, "device_local.item_id")?),
        last_connected_at,
        frecency: frecency.unwrap_or(0.0),
        recording_dir,
    })
}

const COLS: &str = "item_id, last_connected_at, frecency, recording_dir";

impl ReadTx<'_> {
    /// The device-local row of an item.
    pub fn get_device_local(&self, item: ItemId) -> Result<Option<DeviceLocal>> {
        let raw = self
            .conn
            .prepare_cached(&format!(
                "SELECT {COLS} FROM device_local WHERE item_id = ?1"
            ))?
            .query_row(params![item.as_bytes()], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })
            .optional()?;
        raw.map(decode).transpose()
    }

    /// All device-local rows.
    pub fn list_device_local(&self) -> Result<Vec<DeviceLocal>> {
        let mut stmt = self
            .conn
            .prepare_cached(&format!("SELECT {COLS} FROM device_local ORDER BY item_id"))?;
        let raws = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<rusqlite::Result<Vec<RawLocal>>>()?;
        raws.into_iter().map(decode).collect()
    }
}

impl WriteTx<'_> {
    /// Records a connect at `at`: sets `last_connected_at` and bumps the
    /// frecency (see the module docs). Returns the new frecency.
    pub fn touch_connected(&self, item: ItemId, at: i64) -> Result<f64> {
        let prev = self.as_read().get_device_local(item)?;
        let frecency = bump_frecency(
            prev.as_ref()
                .and_then(|p| p.last_connected_at.map(|t| (p.frecency, t))),
            at,
        );
        self.conn.execute(
            "INSERT INTO device_local (item_id, last_connected_at, frecency) VALUES (?1, ?2, ?3)
             ON CONFLICT(item_id) DO UPDATE SET
                last_connected_at = excluded.last_connected_at,
                frecency = excluded.frecency",
            params![item.as_bytes(), at, frecency],
        )?;
        Ok(frecency)
    }

    /// Sets (or clears) the item's recording directory.
    pub fn set_recording_dir(&self, item: ItemId, dir: Option<&str>) -> Result<()> {
        self.conn.execute(
            "INSERT INTO device_local (item_id, recording_dir) VALUES (?1, ?2)
             ON CONFLICT(item_id) DO UPDATE SET recording_dir = excluded.recording_dir",
            params![item.as_bytes(), dir],
        )?;
        Ok(())
    }

    // M4-08
    /// Moves the device-local row of `from` to `to` (an item re-created under a
    /// new id, e.g. imported into the account vault at login), replacing any row
    /// of `to`. A no-op when `from` has no row.
    pub fn move_device_local(&self, from: ItemId, to: ItemId) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO device_local (item_id, last_connected_at, frecency, recording_dir)
             SELECT ?2, last_connected_at, frecency, recording_dir FROM device_local WHERE item_id = ?1",
            params![from.as_bytes(), to.as_bytes()],
        )?;
        self.conn.execute(
            "DELETE FROM device_local WHERE item_id = ?1",
            params![from.as_bytes()],
        )?;
        Ok(())
    }
}

impl Store {
    /// See [`WriteTx::touch_connected`].
    pub async fn touch_connected(&self, item: ItemId, at: i64) -> Result<f64> {
        self.write(move |w| w.touch_connected(item, at)).await
    }

    /// See [`ReadTx::get_device_local`].
    pub async fn get_device_local(&self, item: ItemId) -> Result<Option<DeviceLocal>> {
        self.read(move |r| r.get_device_local(item)).await
    }

    /// See [`ReadTx::list_device_local`].
    pub async fn list_device_local(&self) -> Result<Vec<DeviceLocal>> {
        self.read(|r| r.list_device_local()).await
    }

    /// See [`WriteTx::set_recording_dir`].
    pub async fn set_recording_dir(&self, item: ItemId, dir: Option<String>) -> Result<()> {
        self.write(move |w| w.set_recording_dir(item, dir.as_deref()))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400_000;

    // T-10: two connects 14 days apart → 0.5·1 + 1 = 1.5; recent use ranks higher.
    #[test]
    fn t10_frecency_half_life() {
        let first = bump_frecency(None, 0);
        assert!((first - 1.0).abs() < 1e-12);
        let second = bump_frecency(Some((first, 0)), 14 * DAY);
        assert!((second - 1.5).abs() < 1e-12, "{second}");

        // A: used 3 times long ago. B: used once yesterday. At day 100 B ranks higher.
        let mut a = None;
        for t in [0, DAY, 2 * DAY] {
            let f = bump_frecency(a, t);
            a = Some((f, t));
        }
        let b = (bump_frecency(None, 99 * DAY), 99 * DAY);
        let (fa, ta) = a.unwrap_or_default();
        let now = 100 * DAY;
        assert!(decay(b.0, b.1, now) > decay(fa, ta, now));
        // …but at day 3, A's three recent connects beat a single one.
        let c = (bump_frecency(None, 3 * DAY), 3 * DAY);
        assert!(decay(fa, ta, 3 * DAY) > decay(c.0, c.1, 3 * DAY));

        // Clock going backwards does not inflate the score.
        assert!((decay(2.0, 10 * DAY, 5 * DAY) - 2.0).abs() < 1e-12);
    }
}
