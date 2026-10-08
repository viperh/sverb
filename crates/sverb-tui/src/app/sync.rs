//! M4-07: `UiEvent::Sync` in the reducer.
//!
//! Engine toasts become toasts. The status (top bar / status bar: `⟳ synced`,
//! `offline (3 pending)`, …) and the read-only actions ("Revert to server
//! version", "Copy to personal vault") are rendered by M4-09; applied remote
//! changes reach the views through `UiEvent::IndexUpdated` (the sync service
//! updates the index).

use sverb_sync::{SyncEvent, ToastLevel as SyncToast};

use super::{App, Effect, ToastLevel};

impl App {
    pub(crate) fn on_sync(&mut self, ev: SyncEvent, effects: &mut Vec<Effect>) {
        match ev {
            SyncEvent::Toast { level, message } => {
                let level = match level {
                    SyncToast::Info => ToastLevel::Info,
                    SyncToast::Warn => ToastLevel::Warning,
                    SyncToast::Error => ToastLevel::Error,
                };
                self.push_toast(level, message, effects);
            }
            SyncEvent::Status(status) => tracing::debug!(%status, "sync status"),
            SyncEvent::Applied { .. } | SyncEvent::ReadOnly { .. } => {}
        }
    }
}
