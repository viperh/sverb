//! M1-04: the vault service: executes `Effect::Vault` and owns the keys.
//!
//! - [`VaultEngine`] (`vault/engine.rs`) does the work: Argon2 and keyring calls in
//!   `spawn_blocking`, store transactions, key wrapping. It never contacts a server.
//! - [`VaultService`] runs engine calls as tasks, keeps the [`UnlockedVault`] (the
//!   LMK and vault keys, never in `App`) and reports results as `UiEvent::Vault`.
//! - `Effect::Vault(Lock)` drops the keys **synchronously** (zeroized on drop). A
//!   generation counter makes an unlock that finishes after a lock discard its keys.
//! - After an unlock it reads the persistent flags and sends `UiEvent::Meta` (the
//!   one-time leader notice), and it persists `Effect::SetMetaFlag`.
//!
//! - M1-05: it owns the in-memory search index ([`ItemIndex`]): built in the
//!   unlock decrypt pass, updated per item write / remote apply
//!   ([`VaultService::index_upsert`], [`VaultService::index_remove`]), published to
//!   the reducer as `UiEvent::IndexUpdated(Arc<IndexSnapshot>)`, and dropped (so
//!   zeroized) with the keys on lock.
//!
//! Suspend detection (logind `PrepareForSleep` over D-Bus, feature
//! `suspend-detect`) is not implemented yet; a detector would send
//! `VaultEvent::LockRequested`.

pub mod engine;
// M1-07: item writes and reads (save, delete, duplicate, pin, the Hosts catalog).
pub mod items;
pub mod os_keyring;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use sverb_core::model::{ItemBody, ItemId, VaultId};
use sverb_core::paths::Paths;
// M1-05
use sverb_core::search::{IndexSnapshot, ItemIndex};
use sverb_core::vault::{Argon2Cost, KeyringStore, VaultError};
use sverb_store::Store;
use tracing::{debug, warn};

pub use self::engine::{
    Initialized, UnlockMethod, UnlockedVault, VaultEngine, VaultStatus, vault_display_name,
};
pub use self::os_keyring::{KEYRING_ENV, OsKeyring, keyring_from_env};
use super::EventSender;
use crate::app::{
    MetaFlag, MetaFlags, UiEvent, UnlockFailure, UnlockRequest, VaultEffect, VaultEvent,
    VaultStatusInfo,
};

/// The vault service. Cheap to clone; clones share the keys.
#[derive(Debug, Clone)]
pub struct VaultService {
    engine: VaultEngine,
    unlocked: Arc<Mutex<Option<Arc<UnlockedVault>>>>,
    generation: Arc<AtomicU64>,
    // M1-05
    /// The decrypted search index (`None` while locked).
    index: Arc<Mutex<Option<ItemIndex>>>,
    // M1-07
    /// The HLC clock of item writes in this unlocked session (`None` while locked).
    items_clock: Arc<Mutex<Option<items::SharedClock>>>,
}

impl VaultService {
    /// A service over `engine`.
    pub fn new(engine: VaultEngine) -> Self {
        Self {
            engine,
            unlocked: Arc::new(Mutex::new(None)),
            generation: Arc::new(AtomicU64::new(0)),
            index: Arc::new(Mutex::new(None)),
            // M1-07
            items_clock: Arc::new(Mutex::new(None)),
        }
    }

    // M2-08
    /// A service over `engine` holding `vault`, already unlocked (headless commands
    /// such as `sverb forward`, which unlock before building their services).
    pub fn from_unlocked(engine: VaultEngine, vault: UnlockedVault) -> Self {
        let service = Self::new(engine);
        let generation = service.generation.load(Ordering::SeqCst);
        service.install(vault, generation);
        service
    }

    /// Open the store at [`Paths::db_file`] (in `spawn_blocking`) with the production
    /// Argon2 cost.
    ///
    /// # Errors
    /// [`VaultError::Storage`] if the database cannot be opened.
    pub async fn open(paths: &Paths, keyring: Arc<dyn KeyringStore>) -> Result<Self, VaultError> {
        let paths = paths.clone();
        let store = tokio::task::spawn_blocking(move || Store::open(&paths))
            .await
            .map_err(|e| VaultError::Storage(e.to_string()))?
            .map_err(|e| VaultError::Storage(e.to_string()))?;
        Ok(Self::new(VaultEngine::new(
            store,
            keyring,
            Argon2Cost::PRODUCTION,
        )))
    }

    /// The engine.
    pub fn engine(&self) -> &VaultEngine {
        &self.engine
    }

    /// The store.
    pub fn store(&self) -> &Store {
        self.engine.store()
    }

    fn slot(&self) -> std::sync::MutexGuard<'_, Option<Arc<UnlockedVault>>> {
        self.unlocked.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether keys are loaded.
    pub fn is_unlocked(&self) -> bool {
        self.slot().is_some()
    }

    /// The unlocked vault, for services that read or write items (M1-05, M1-07).
    /// `None` while locked. Do not keep it across a lock.
    pub fn unlocked(&self) -> Option<Arc<UnlockedVault>> {
        self.slot().clone()
    }

    /// Keys currently alive (test hook, T-13).
    pub fn live_keys(&self) -> usize {
        self.engine.live_keys()
    }

    /// Drop (and so zeroize) the keys now. M1-05: the search index (and the
    /// service's snapshot of it) is dropped too.
    pub fn lock(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        let keys = self.slot().take();
        drop(keys);
        let index = self.index_slot().take();
        drop(index);
        // M1-07
        self.items_clock
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        debug!("vault locked");
    }

    /// Install keys from an operation started at generation `gen`; discards them if a
    /// lock happened since. Returns whether they were installed.
    fn install(&self, mut vault: UnlockedVault, generation: u64) -> bool {
        let mut slot = self.slot();
        if self.generation.load(Ordering::SeqCst) != generation {
            drop(vault);
            return false;
        }
        // M1-05: the service owns the index from here on.
        let index = vault.take_index();
        // M1-07: item writes resume the HLC from `meta.hlc_last`.
        *self
            .items_clock
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(items::SharedClock::new(&vault));
        *slot = Some(Arc::new(vault));
        *self.index_slot() = index;
        true
    }

    // M1-05 ------------------------------------------------------------ search index

    fn index_slot(&self) -> std::sync::MutexGuard<'_, Option<ItemIndex>> {
        self.index.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The current index snapshot; `None` while locked.
    pub fn index_snapshot(&self) -> Option<Arc<IndexSnapshot>> {
        self.index_slot().as_mut().map(ItemIndex::snapshot)
    }

    /// Mutate the index (no-op while locked) and return the new snapshot.
    pub fn update_index(&self, f: impl FnOnce(&mut ItemIndex)) -> Option<Arc<IndexSnapshot>> {
        let mut slot = self.index_slot();
        let index = slot.as_mut()?;
        f(index);
        Some(index.snapshot())
    }

    /// After an item write or a remote apply: replace (or, for a deleted body,
    /// remove) the item's entry, recompute dependents, and publish the snapshot.
    pub fn index_upsert(&self, item: ItemId, vault: VaultId, body: &ItemBody, tx: &EventSender) {
        if let Some(snapshot) = self.update_index(|ix| ix.upsert(item, vault, body)) {
            publish(snapshot, tx);
        }
    }

    /// After an item was purged: drop its entry and publish the snapshot.
    pub fn index_remove(&self, item: ItemId, tx: &EventSender) {
        if let Some(snapshot) = self.update_index(|ix| {
            ix.remove(item);
        }) {
            publish(snapshot, tx);
        }
    }

    // M1-07
    /// Item operations for the unlocked vault; `None` while locked.
    pub fn item_ops(&self) -> Option<items::ItemOps> {
        let vault = self.unlocked()?;
        let clock = self
            .items_clock
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()?;
        Some(items::ItemOps::with_clock(
            self.engine.clone(),
            vault,
            clock,
        ))
    }

    /// Send the startup status (probes the keyring only before first run).
    pub fn report_status(&self, tx: &EventSender) {
        let engine = self.engine.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let info = match engine.status().await {
                Ok(status) => {
                    let keyring_available = if status.initialized {
                        false
                    } else {
                        engine.keyring_available().await
                    };
                    VaultStatusInfo {
                        initialized: status.initialized,
                        keyring_enabled: status.keyring_enabled,
                        keyring_available,
                        failures: status.backoff.failures,
                        retry_after: status.retry_after,
                    }
                }
                Err(e) => {
                    warn!(error = %e, "cannot read the vault status");
                    // The prompt reports the error on the first attempt.
                    VaultStatusInfo {
                        initialized: true,
                        ..VaultStatusInfo::default()
                    }
                }
            };
            let _ = tx.send(UiEvent::Vault(VaultEvent::Status(info))).await;
        });
    }

    /// Persist a one-time flag (`Effect::SetMetaFlag`).
    pub fn set_meta_flag(&self, flag: MetaFlag) {
        let store = self.store().clone();
        tokio::spawn(async move {
            if let Err(e) = store.set_meta(flag.key(), vec![1]).await {
                warn!(flag = flag.key(), error = %e, "cannot persist meta flag");
            }
        });
    }

    /// Execute a vault effect. Must be called inside a tokio runtime.
    pub fn execute(&self, effect: VaultEffect, tx: &EventSender) {
        let generation = self.generation.load(Ordering::SeqCst);
        let this = self.clone();
        let tx = tx.clone();
        match effect {
            VaultEffect::Lock => self.lock(),
            // M1-07
            VaultEffect::Items(op) => items::execute(self, op, &tx),
            VaultEffect::Initialize { password, keyring } => {
                tokio::spawn(async move {
                    let ev = match this.engine.initialize(password.expose(), keyring).await {
                        Ok(Initialized {
                            vault,
                            keyring_error,
                        }) => {
                            this.install(vault, generation);
                            let note = keyring_error
                                .map(|e| format!("Keyring unlock could not be enabled: {e}"));
                            VaultEvent::Unlocked {
                                via_keyring: false,
                                note,
                            }
                        }
                        Err(e) => VaultEvent::UnlockFailed(UnlockFailure::Other(e.to_string())),
                    };
                    this.finish(ev, &tx).await;
                });
            }
            VaultEffect::Unlock(request) => {
                tokio::spawn(async move {
                    let via_keyring = request == UnlockRequest::Keyring;
                    let result = match &request {
                        UnlockRequest::Password(pw) => {
                            this.engine.unlock_with_password(pw.expose()).await
                        }
                        UnlockRequest::Keyring => this.engine.unlock_with_keyring().await,
                    };
                    drop(request);
                    let ev = match result {
                        Ok(vault) => {
                            this.install(vault, generation);
                            VaultEvent::Unlocked {
                                via_keyring,
                                note: None,
                            }
                        }
                        Err(e) => VaultEvent::UnlockFailed(failure(e, via_keyring)),
                    };
                    this.finish(ev, &tx).await;
                });
            }
            VaultEffect::ChangePassword { current, new } => {
                tokio::spawn(async move {
                    let ev = match this.unlocked() {
                        None => VaultEvent::PasswordChangeFailed("The vault is locked".into()),
                        Some(vault) => {
                            let current = current.as_ref().map(|c| c.expose());
                            match this
                                .engine
                                .change_password(&vault, current, new.expose())
                                .await
                            {
                                Ok(()) => VaultEvent::PasswordChanged,
                                Err(e) => VaultEvent::PasswordChangeFailed(e.to_string()),
                            }
                        }
                    };
                    let _ = tx.send(UiEvent::Vault(ev)).await;
                });
            }
        }
    }

    /// Report an unlock result; after a success, also the persistent flags.
    async fn finish(&self, ev: VaultEvent, tx: &EventSender) {
        let unlocked = matches!(ev, VaultEvent::Unlocked { .. });
        if unlocked && !self.is_unlocked() {
            // Locked again while the unlock ran: the keys were discarded.
            let ev = VaultEvent::UnlockFailed(UnlockFailure::Other(
                "The vault was locked while unlocking; try again".into(),
            ));
            let _ = tx.send(UiEvent::Vault(ev)).await;
            return;
        }
        let _ = tx.send(UiEvent::Vault(ev)).await;
        if unlocked {
            let seen = self
                .store()
                .get_meta(MetaFlag::SeenLeaderNotice.key())
                .await
                .ok()
                .flatten()
                .is_some_and(|v| v.iter().any(|b| *b != 0));
            let flags = MetaFlags {
                seen_leader_notice: seen,
            };
            let _ = tx.send(UiEvent::Meta(flags)).await;
            // M1-05: the index built during unlock.
            if let Some(snapshot) = self.index_snapshot() {
                let _ = tx.send(UiEvent::IndexUpdated(snapshot)).await;
            }
        }
    }
}

// M1-05
/// Send `UiEvent::IndexUpdated` without blocking the caller.
fn publish(snapshot: Arc<IndexSnapshot>, tx: &EventSender) {
    match tx.try_send(UiEvent::IndexUpdated(snapshot)) {
        Ok(()) => {}
        Err(tokio::sync::mpsc::error::TrySendError::Full(ev)) => {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                let tx = tx.clone();
                handle.spawn(async move {
                    let _ = tx.send(ev).await;
                });
            }
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
    }
}

/// Map an engine error to what the prompt shows. Keyring failures always fall back
/// to the password prompt.
fn failure(err: VaultError, via_keyring: bool) -> UnlockFailure {
    match err {
        VaultError::WrongPassword {
            failures,
            retry_after,
        } => UnlockFailure::WrongPassword {
            failures,
            retry_after,
        },
        VaultError::Backoff { retry_after } => UnlockFailure::Backoff { retry_after },
        other if via_keyring => UnlockFailure::Keyring(match other {
            VaultError::Keyring(msg) => msg,
            other => other.to_string(),
        }),
        other => UnlockFailure::Other(other.to_string()),
    }
}
