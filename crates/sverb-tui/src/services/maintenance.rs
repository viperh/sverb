//! Daily maintenance (SPEC §9.12 retention). Run by the ConnLog service on
//! `LogsEffect::Maintain`, which the reducer sends on unlock and every 24 h while
//! unlocked (`TimerKind::LogsMaintenance`).
//!
//! - Connection logs whose `started_at` is older than `logs.retention_days` (default 90;
//!   0 keeps them forever) are tombstoned (queued for sync only with `logs.sync`).
//! - Recordings older than `recording.retention_days` (spec addition; default 0 keeps
//!   them until deleted) are deleted, judged by the file's modification time (the end
//!   of the recording), and their `device_local.recording_dir` is cleared. Recordings
//!   of expired log entries are kept: the two retentions are independent.

use std::{path::Path, sync::Arc, time::UNIX_EPOCH};

use sverb_core::model::{HlcClock, ItemId};
use sverb_store::Store;
use tracing::{debug, warn};

use super::{
    connlog::{load_logs, remove_file, tombstone},
    vault::UnlockedVault,
};

/// Milliseconds per day.
const DAY_MS: i64 = 86_400_000;

/// The retention settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Retention {
    /// `logs.retention_days` (0 = forever).
    pub logs_days: u32,
    /// `recording.retention_days` (0 = until deleted).
    pub recording_days: u32,
}

/// What a run did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Tombstoned log entries.
    pub tombstoned: Vec<ItemId>,
    /// Entries whose recording was deleted.
    pub recordings_deleted: Vec<ItemId>,
}

/// The cutoff for `days` before `now_ms`; `None` for 0 (keep forever).
fn cutoff(now_ms: i64, days: u32) -> Option<i64> {
    (days > 0).then(|| now_ms.saturating_sub(i64::from(days).saturating_mul(DAY_MS)))
}

/// Apply `retention` at `now_ms` (the store's clock).
///
/// # Errors
/// Reading the logs failed (single entries that fail are logged and skipped).
pub async fn run(
    store: &Store,
    vault: &Arc<UnlockedVault>,
    clock: &mut HlcClock,
    sync: bool,
    retention: Retention,
    now_ms: i64,
) -> Result<Report, String> {
    let mut report = Report::default();
    if let Some(cutoff) = cutoff(now_ms, retention.logs_days) {
        for (id, log) in load_logs(store, vault).await? {
            if log.started_at.0 >= cutoff {
                continue;
            }
            match tombstone(store, vault, clock, sync, id).await {
                Ok(()) => report.tombstoned.push(id),
                Err(err) => warn!(item = %id.short(), %err, "cannot expire a connection log"),
            }
        }
    }
    if let Some(cutoff) = cutoff(now_ms, retention.recording_days) {
        let rows = store.list_device_local().await.map_err(|e| e.to_string())?;
        for row in rows {
            let Some(dir) = row.recording_dir else {
                continue;
            };
            let path = Path::new(&dir);
            let Some(mtime) = modified_ms(path) else {
                // Gone already: forget the path.
                if !path.exists() {
                    let _ = store.set_recording_dir(row.item_id, None).await;
                }
                continue;
            };
            if mtime >= cutoff {
                continue;
            }
            if let Err(err) = remove_file(path) {
                warn!(%err, "cannot delete an expired recording");
                continue;
            }
            debug!(item = %row.item_id.short(), "expired recording deleted");
            if let Err(err) = store.set_recording_dir(row.item_id, None).await {
                warn!(%err, "cannot clear the recording path");
            }
            report.recordings_deleted.push(row.item_id);
        }
    }
    Ok(report)
}

/// A file's modification time in Unix milliseconds.
fn modified_ms(path: &Path) -> Option<i64> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    let d = modified.duration_since(UNIX_EPOCH).ok()?;
    i64::try_from(d.as_millis()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_days_keeps_forever() {
        assert_eq!(cutoff(1_000 * DAY_MS, 0), None);
        assert_eq!(cutoff(100 * DAY_MS, 90), Some(10 * DAY_MS));
    }
}
