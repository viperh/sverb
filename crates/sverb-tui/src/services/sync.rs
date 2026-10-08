//! M4-07: the sync service (feature `sync`).
//!
//! Runs one [`SyncEngine`] while the vault is unlocked (§12, §2.1):
//! [`SyncService::start`] after unlock, [`SyncService::stop`] on lock (the WS
//! disconnects and the engine's keys are dropped), [`SyncService::local_change`]
//! after every local item write (push debounce).
//!
//! Engine events are forwarded as `UiEvent::Sync`. Remote changes the engine
//! applied are folded into the search index here (decrypt, `index_upsert` /
//! `index_remove`), so the reducer gets the usual `UiEvent::IndexUpdated`.
//!
//! The calls from the unlock / lock / item-write paths (`services::vault`) and the
//! status bar rendering are wired by M4-09.

use std::sync::{Arc, Mutex, PoisonError};

use sverb_core::config::Config;
use sverb_sync::{
    EngineConfig, NoKeySource, SyncEngine, SyncError, SyncEvent, SyncHandle, SyncStatus,
    VaultKeySource, shared_hlc,
};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use super::EventSender;
use super::vault::VaultService;
use crate::app::UiEvent;

/// Owns the running engine (if any). Cheap to clone.
#[derive(Debug, Clone, Default)]
pub struct SyncService {
    handle: Arc<Mutex<Option<SyncHandle>>>,
}

impl SyncService {
    fn slot(&self) -> std::sync::MutexGuard<'_, Option<SyncHandle>> {
        self.handle.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Starts the engine for the unlocked `vault`. A device without sync set up
    /// reports [`SyncStatus::Disabled`]; one whose tokens were rejected reports
    /// [`SyncStatus::NeedsLogin`].
    pub fn start(
        &self,
        vault: &VaultService,
        config: &Config,
        key_source: Option<Arc<dyn VaultKeySource>>,
        tx: &EventSender,
    ) {
        let Some(unlocked) = vault.unlocked() else {
            return;
        };
        self.stop_now();
        let store = vault.store().clone();
        let lmk = unlocked.lmk().clone();
        let hlc = shared_hlc(unlocked.hlc());
        drop(unlocked);
        let engine_config = EngineConfig::from_config(config);
        let key_source = key_source.unwrap_or_else(|| Arc::new(NoKeySource));
        let this = self.clone();
        let vault = vault.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let (ev_tx, ev_rx) = mpsc::unbounded_channel();
            match SyncEngine::new(store, lmk, hlc, key_source, engine_config, Some(ev_tx)).await {
                Ok(engine) => {
                    let handle = engine.spawn();
                    // A lock may have happened while the engine was being built.
                    if vault.unlocked().is_none() {
                        handle.shutdown().await;
                        return;
                    }
                    *this.slot() = Some(handle);
                    forward(ev_rx, vault, tx).await;
                }
                Err(e) => {
                    let status = match e {
                        SyncError::NotConfigured(_) => SyncStatus::Disabled,
                        SyncError::NeedsLogin => SyncStatus::NeedsLogin,
                        other => {
                            warn!(error = %other, "sync engine did not start");
                            SyncStatus::Error {
                                message: other.to_string(),
                            }
                        }
                    };
                    let _ = tx.send(UiEvent::Sync(SyncEvent::Status(status))).await;
                }
            }
        });
    }

    /// A local item was written.
    pub fn local_change(&self) {
        if let Some(h) = self.slot().as_ref() {
            h.local_change();
        }
    }

    /// `sync_now` from the UI (palette, `sverb sync --now` on a running TUI).
    pub fn request_sync(&self) {
        if let Some(h) = self.slot().as_ref() {
            h.request_sync();
        }
    }

    /// The current status (`Disabled` when no engine runs).
    pub fn status(&self) -> SyncStatus {
        self.slot()
            .as_ref()
            .map_or(SyncStatus::Disabled, SyncHandle::status)
    }

    fn stop_now(&self) -> Option<SyncHandle> {
        self.slot().take()
    }

    /// Stops the engine (vault locked, quit). Dropping the handle cancels the
    /// engine at once; the task finishes in the background.
    pub fn stop(&self) {
        if let Some(h) = self.stop_now() {
            debug!("sync engine stopping");
            tokio::spawn(h.shutdown());
        }
    }
}

/// Forwards engine events; folds applied remote changes into the index.
async fn forward(mut rx: mpsc::UnboundedReceiver<SyncEvent>, vault: VaultService, tx: EventSender) {
    while let Some(ev) = rx.recv().await {
        if let SyncEvent::Applied { items, .. } = &ev {
            reindex(&vault, items, &tx).await;
        }
        if tx.send(UiEvent::Sync(ev)).await.is_err() {
            return;
        }
    }
}

async fn reindex(vault: &VaultService, items: &[sverb_core::model::ItemId], tx: &EventSender) {
    let Some(unlocked) = vault.unlocked() else {
        return;
    };
    for id in items {
        match vault.store().get_item(*id).await {
            Ok(Some(row)) => match unlocked.open(&row) {
                Ok(body) => vault.index_upsert(row.id, row.vault_id, &body, tx),
                Err(e) => debug!(item = %id, error = %e, "applied item not indexed"),
            },
            Ok(None) => vault.index_remove(*id, tx),
            Err(e) => warn!(item = %id, error = %e, "reading an applied item failed"),
        }
    }
}
