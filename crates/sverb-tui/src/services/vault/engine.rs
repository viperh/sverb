//! The vault engine: first run, password and keyring unlock, persisted
//! backoff, password change and keyring enrolment (SPEC §5.3, §11.2, §11.2.1).
//!
//! UI-free (the TUI service and the CLI's `require_unlocked` both use it). Argon2
//! and keyring calls run in `spawn_blocking`; SQLite goes through the store's own
//! blocking pool. **Nothing here contacts a server**: unlock is purely local.
//!
//! Keys live only in [`UnlockedVault`] (`Key32`, zeroized on drop). Every key it
//! holds is counted in a per-engine live-key counter, so tests can prove that
//! locking dropped all of them.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use sverb_core::model::{
    DeviceId, Hlc, HlcClock, ItemBody, ItemId, VaultId, migrate::is_read_only,
};
// The in-memory search index built during the unlock decrypt pass.
use sverb_core::hardening::Locked;
use sverb_core::search::ItemIndex;
use sverb_core::vault::{
    Argon2Cost, BackoffState, KdfParams, KeyringStore, VaultError, check_strength, keyring_account,
};
use sverb_crypto::envelope::{open_item, seal_item};
use sverb_crypto::kdf::argon2id;
use sverb_crypto::random::{os_rng, random_key32, random_salt16};
use sverb_crypto::wrap::{WrapPurpose, unwrap_key32, wrap_key};
use sverb_crypto::{CryptoError, Key32};
use sverb_store::meta::keys;
use sverb_store::{ItemRow, Store, StoreError, VaultKind};
use zeroize::Zeroizing;

/// How a vault was unlocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockMethod {
    /// Master password (Argon2id KEK).
    Password,
    /// OS keyring KEK.
    Keyring,
    /// First run created the vault.
    Created,
}

/// What a locked database looks like (no secrets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultStatus {
    /// `meta.kdf` exists.
    pub initialized: bool,
    /// `meta.lmk_wrapped_keyring` exists.
    pub keyring_enabled: bool,
    /// The persisted backoff.
    pub backoff: BackoffState,
    /// `Err(remaining)` while the next attempt must wait.
    pub retry_after: Option<std::time::Duration>,
}

/// A key counted in the engine's live-key counter.
///
/// The key lives in `mlock`ed pages where the OS allows it (best effort,
/// SPEC §17 "Memory scraping"); it is zeroized before they are unlocked.
struct TrackedKey {
    key: Locked<Key32>,
    live: Arc<AtomicUsize>,
}

impl TrackedKey {
    fn new(key: Key32, live: &Arc<AtomicUsize>) -> Self {
        live.fetch_add(1, Ordering::SeqCst);
        Self {
            key: Locked::new(key),
            live: Arc::clone(live),
        }
    }
}

impl Drop for TrackedKey {
    fn drop(&mut self) {
        // `Locked<Key32>` zeroizes the key when it is dropped right after this.
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

struct VaultKeyEntry {
    kind: VaultKind,
    key_version: u32,
    key: TrackedKey,
}

/// The unlocked key material: the LMK and every vault key. Owned by the vault
/// service (never by `App`); dropping it zeroizes the keys.
pub struct UnlockedVault {
    lmk: TrackedKey,
    // Behind a lock so a shared vault granted while unlocked can be added
    // ([`UnlockedVault::add_vault`]).
    vaults: std::sync::RwLock<BTreeMap<VaultId, VaultKeyEntry>>,
    device_id: DeviceId,
    hlc_last: Hlc,
    method: UnlockMethod,
    items: usize,
    undecryptable: usize,
    /// The search index built at unlock; the vault service takes it
    /// ([`UnlockedVault::take_index`]) and owns it from then on.
    index: Option<ItemIndex>,
}

impl fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlockedVault")
            .field("vaults", &self.map().keys().collect::<Vec<_>>())
            .field("device_id", &self.device_id)
            .field("method", &self.method)
            .field("items", &self.items)
            .finish_non_exhaustive()
    }
}

impl UnlockedVault {
    fn map(&self) -> std::sync::RwLockReadGuard<'_, BTreeMap<VaultId, VaultKeyEntry>> {
        self.vaults
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Loads the key of a vault added to the store while unlocked (a shared vault
    /// the sync engine adopted after verifying its grant; its key is wrapped under
    /// the LMK). `Ok(false)` when it was loaded already.
    ///
    /// # Errors
    /// The key does not unwrap with the LMK.
    pub fn add_vault(&self, row: &sverb_store::VaultRow) -> Result<bool, VaultError> {
        if self.map().contains_key(&row.id) {
            return Ok(false);
        }
        let vk = unwrap_key32(
            &self.lmk.key,
            &WrapPurpose::VaultKey(*row.id.as_bytes()),
            &row.wrapped_key,
        )
        .map_err(|e| VaultError::from_crypto(e, "vault key"))?;
        let entry = VaultKeyEntry {
            kind: row.kind,
            key_version: row.key_version,
            key: TrackedKey::new(vk, &self.lmk.live),
        };
        self.vaults
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(row.id, entry);
        Ok(true)
    }

    /// Replaces the key of a loaded vault whose stored key version moved on (a
    /// key rotation the sync engine applied; the local items were re-sealed
    /// under it). `Ok(false)` when nothing changed or the vault is not loaded.
    ///
    /// # Errors
    /// The key does not unwrap with the LMK.
    pub fn update_vault_key(&self, row: &sverb_store::VaultRow) -> Result<bool, VaultError> {
        if self
            .map()
            .get(&row.id)
            .is_none_or(|e| e.key_version >= row.key_version)
        {
            return Ok(false);
        }
        let vk = unwrap_key32(
            &self.lmk.key,
            &WrapPurpose::VaultKey(*row.id.as_bytes()),
            &row.wrapped_key,
        )
        .map_err(|e| VaultError::from_crypto(e, "vault key"))?;
        let entry = VaultKeyEntry {
            kind: row.kind,
            key_version: row.key_version,
            key: TrackedKey::new(vk, &self.lmk.live),
        };
        self.vaults
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(row.id, entry);
        Ok(true)
    }

    /// Opens a vault name sealed under the vault's key (`name_enc`: sealed like an
    /// item envelope with the vault id as item id, §4.13). `None` when the vault is
    /// not loaded or the name does not open.
    pub fn open_vault_name(&self, vault: VaultId, name_enc: &[u8]) -> Option<String> {
        let map = self.map();
        let entry = map.get(&vault)?;
        let plain = open_item(
            |_| Some(&entry.key.key),
            vault.as_bytes(),
            vault.as_bytes(),
            name_enc,
        )
        .ok()?;
        String::from_utf8(plain.to_vec()).ok()
    }

    /// The kind of a loaded vault.
    pub fn vault_kind(&self, vault: VaultId) -> Option<VaultKind> {
        self.map().get(&vault).map(|e| e.kind)
    }

    /// How it was unlocked.
    pub fn method(&self) -> UnlockMethod {
        self.method
    }

    /// This device's id (`meta.device_id`).
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// An HLC resumed from `meta.hlc_last`.
    pub fn hlc(&self) -> HlcClock {
        HlcClock::default().with_last(self.hlc_last)
    }

    /// The vaults whose keys are loaded.
    pub fn vault_ids(&self) -> Vec<VaultId> {
        self.map().keys().copied().collect()
    }

    /// The personal vault.
    pub fn personal_vault(&self) -> Option<VaultId> {
        self.map()
            .iter()
            .find(|(_, v)| v.kind == VaultKind::Personal)
            .map(|(id, _)| *id)
    }

    /// Items decrypted at unlock.
    pub fn item_count(&self) -> usize {
        self.items
    }

    /// Items that failed to decrypt at unlock (logged, skipped).
    pub fn undecryptable_count(&self) -> usize {
        self.undecryptable
    }

    /// The search index built from the unlock decrypt pass (once; `None` after).
    pub fn take_index(&mut self) -> Option<ItemIndex> {
        self.index.take()
    }

    /// The LMK (wraps sync tokens and the recording key input). Keep borrows short.
    pub fn lmk(&self) -> &Key32 {
        &self.lmk.key
    }

    /// Seal `body` for `item` in `vault` under its current vault key. Returns the key
    /// version and the envelope for `WriteTx::put_item`.
    ///
    /// # Errors
    /// [`VaultError::Locked`] for an unknown vault, or a corrupt-body error.
    pub fn seal(
        &self,
        vault: VaultId,
        item: ItemId,
        body: &ItemBody,
    ) -> Result<(u32, Vec<u8>), VaultError> {
        let map = self.map();
        let entry = map.get(&vault).ok_or(VaultError::Locked)?;
        let cbor = body
            .to_cbor()
            .map_err(|e| VaultError::Corrupt(format!("item body: {e}")))?;
        let env = seal_item(
            &entry.key.key,
            vault.as_bytes(),
            item.as_bytes(),
            entry.key_version,
            &cbor,
            &mut os_rng(),
        )
        .map_err(|e| VaultError::from_crypto(e, "item"))?;
        Ok((entry.key_version, env))
    }

    /// Decrypt a stored item.
    ///
    /// # Errors
    /// [`VaultError::Locked`] for an unknown vault, [`VaultError::Corrupt`] if the
    /// envelope does not open or the body does not decode.
    pub fn open(&self, row: &ItemRow) -> Result<ItemBody, VaultError> {
        let map = self.map();
        let entry = map.get(&row.vault_id).ok_or(VaultError::Locked)?;
        let lookup = |v: u32| (v == entry.key_version).then_some(&*entry.key.key);
        let plain = open_item(
            lookup,
            row.vault_id.as_bytes(),
            row.id.as_bytes(),
            &row.envelope,
        )
        .map_err(|e| VaultError::from_crypto(e, "item"))?;
        ItemBody::from_cbor(&plain).map_err(|e| VaultError::Corrupt(format!("item body: {e}")))
    }
}

/// The display name of a vault for `@vault` filters. Vault names are not stored
/// locally yet (§4.13; they arrive with sync): `Personal`, or `Shared <short id>`.
pub fn vault_display_name(id: VaultId, kind: VaultKind) -> String {
    match kind {
        VaultKind::Personal => "Personal".to_owned(),
        VaultKind::Shared => format!("Shared {}", id.short()),
    }
}

/// Build the search index from decrypted bodies, with vault names and frecency
/// (decayed to `now`). The bodies are consumed and dropped here.
fn new_index(
    vaults: impl IntoIterator<Item = (VaultId, VaultKind)>,
    bodies: Vec<(ItemId, VaultId, ItemBody)>,
    locals: &[sverb_store::DeviceLocal],
    now: i64,
) -> ItemIndex {
    let mut index = ItemIndex::build(bodies.iter().map(|(id, v, b)| (*id, *v, b)));
    drop(bodies);
    for (id, kind) in vaults {
        index.set_vault_name(id, vault_display_name(id, kind));
    }
    index.set_frecency(
        locals
            .iter()
            .map(|l| (l.item_id, l.score_at(now)))
            .collect(),
    );
    index
}

/// What first run produced.
#[derive(Debug)]
pub struct Initialized {
    /// The unlocked vault.
    pub vault: UnlockedVault,
    /// Keyring unlock was requested but could not be enabled (the vault was created
    /// without it).
    pub keyring_error: Option<String>,
}

/// The engine: a store, a keyring and the Argon2 cost for new wraps. Cheap to clone.
#[derive(Clone)]
pub struct VaultEngine {
    store: Store,
    keyring: Arc<dyn KeyringStore>,
    cost: Argon2Cost,
    kdf_runs: Arc<AtomicUsize>,
    live_keys: Arc<AtomicUsize>,
}

impl fmt::Debug for VaultEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultEngine")
            .field("store", &self.store)
            .field("keyring", &self.keyring)
            .field("cost", &self.cost)
            .finish_non_exhaustive()
    }
}

fn storage(e: StoreError) -> VaultError {
    VaultError::Storage(e.to_string())
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, VaultError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| VaultError::Storage(format!("background task failed: {e}")))
}

/// Raw meta values read in one snapshot.
#[derive(Default)]
struct Meta {
    kdf: Option<Vec<u8>>,
    lmk_pw: Option<Vec<u8>>,
    lmk_keyring: Option<Vec<u8>>,
    failures: Option<Vec<u8>>,
    next_allowed: Option<Vec<u8>>,
    db_id: Option<Vec<u8>>,
}

impl VaultEngine {
    /// An engine over `store`, using `keyring` for keyring unlock and `cost` for new
    /// password wraps (first run, password change).
    pub fn new(store: Store, keyring: Arc<dyn KeyringStore>, cost: Argon2Cost) -> Self {
        Self {
            store,
            keyring,
            cost,
            kdf_runs: Arc::new(AtomicUsize::new(0)),
            live_keys: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// The store.
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// How many times Argon2 ran (test hook).
    pub fn kdf_runs(&self) -> usize {
        self.kdf_runs.load(Ordering::SeqCst)
    }

    /// Keys currently held by [`UnlockedVault`]s from this engine (test hook).
    pub fn live_keys(&self) -> usize {
        self.live_keys.load(Ordering::SeqCst)
    }

    async fn meta(&self) -> Result<Meta, VaultError> {
        self.store
            .read(|r| {
                Ok(Meta {
                    kdf: r.get_meta(keys::KDF)?,
                    lmk_pw: r.get_meta(keys::LMK_WRAPPED_PW)?,
                    lmk_keyring: r.get_meta(keys::LMK_WRAPPED_KEYRING)?,
                    failures: r.get_meta(keys::UNLOCK_FAILURES)?,
                    next_allowed: r.get_meta(keys::UNLOCK_NEXT_ALLOWED_AT)?,
                    db_id: r.get_meta(keys::DB_ID)?,
                })
            })
            .await
            .map_err(storage)
    }

    /// The locked database's state.
    ///
    /// # Errors
    /// [`VaultError::Storage`].
    pub async fn status(&self) -> Result<VaultStatus, VaultError> {
        let m = self.meta().await?;
        let backoff = BackoffState::decode(m.failures.as_deref(), m.next_allowed.as_deref());
        Ok(VaultStatus {
            initialized: m.kdf.is_some(),
            keyring_enabled: m.lmk_keyring.is_some(),
            backoff,
            retry_after: backoff.check(self.store.now()).err(),
        })
    }

    /// Whether the OS keyring works (writes and deletes a test entry). Blocking
    /// keyring calls run on the blocking pool.
    pub async fn keyring_available(&self) -> bool {
        let keyring = Arc::clone(&self.keyring);
        blocking(move || keyring.probe()).await.unwrap_or(false)
    }

    async fn derive(&self, password: &str, params: KdfParams) -> Result<Key32, VaultError> {
        let pw = Zeroizing::new(password.as_bytes().to_vec());
        self.kdf_runs.fetch_add(1, Ordering::SeqCst);
        blocking(move || argon2id(&pw, &params.argon2()))
            .await?
            .map_err(|e| VaultError::Corrupt(format!("meta.kdf: {e}")))
    }

    fn track(&self, key: Key32) -> TrackedKey {
        TrackedKey::new(key, &self.live_keys)
    }

    /// First run (§2.2): LMK, salt, KEK, Personal vault, device id and HLC, written
    /// in one transaction. `enable_keyring` also stores a keyring KEK.
    ///
    /// # Errors
    /// [`VaultError::WeakPassword`], [`VaultError::AlreadyInitialized`],
    /// [`VaultError::Storage`].
    pub async fn initialize(
        &self,
        password: &str,
        enable_keyring: bool,
    ) -> Result<Initialized, VaultError> {
        check_strength(password, &["sverb"])?;
        if self.meta().await?.kdf.is_some() {
            return Err(VaultError::AlreadyInitialized);
        }
        let mut rng = os_rng();
        let lmk = random_key32(&mut rng);
        let params = self.cost.with_salt(random_salt16(&mut rng));
        let kek = self.derive(password, params).await?;
        let lmk_pw = wrap_key(&kek, &WrapPurpose::Lmk, lmk.expose_secret(), &mut rng)
            .map_err(|e| VaultError::from_crypto(e, "lmk"))?;
        drop(kek);

        let vault_id = VaultId::new();
        let vk = random_key32(&mut rng);
        let wrapped_vk = wrap_key(
            &lmk,
            &WrapPurpose::VaultKey(*vault_id.as_bytes()),
            vk.expose_secret(),
            &mut rng,
        )
        .map_err(|e| VaultError::from_crypto(e, "vault key"))?;
        let device_id = DeviceId::new();
        let hlc_last = HlcClock::default().now();
        let db_id = DeviceId::new().to_string();

        // Optional keyring KEK (stored before the transaction, removed if it fails).
        let mut keyring_error = None;
        let mut lmk_keyring = None;
        if enable_keyring {
            let kr_kek = random_key32(&mut rng);
            let account = keyring_account(&db_id);
            let keyring = Arc::clone(&self.keyring);
            let secret = Zeroizing::new(kr_kek.expose_secret().to_vec());
            let acct = account.clone();
            match blocking(move || keyring.set(&acct, &secret)).await? {
                Ok(()) => {
                    lmk_keyring = Some(
                        wrap_key(&kr_kek, &WrapPurpose::Lmk, lmk.expose_secret(), &mut rng)
                            .map_err(|e| VaultError::from_crypto(e, "lmk"))?,
                    );
                }
                Err(e) => keyring_error = Some(e.0),
            }
        }

        let kdf = params.to_cbor();
        let device_bytes = *device_id.as_bytes();
        let wrote = self
            .store
            .write(move |w| {
                if w.as_read().get_meta(keys::KDF)?.is_some() {
                    return Ok(false);
                }
                w.set_meta(keys::KDF, &kdf)?;
                w.set_meta(keys::LMK_WRAPPED_PW, &lmk_pw)?;
                if let Some(kr) = &lmk_keyring {
                    w.set_meta(keys::LMK_WRAPPED_KEYRING, kr)?;
                }
                w.set_meta(keys::DB_ID, db_id.as_bytes())?;
                w.set_meta(keys::DEVICE_ID, &device_bytes)?;
                w.set_meta(keys::HLC_LAST, &hlc_last.as_u64().to_be_bytes())?;
                w.delete_meta(keys::UNLOCK_FAILURES)?;
                w.delete_meta(keys::UNLOCK_NEXT_ALLOWED_AT)?;
                w.create_vault(vault_id, VaultKind::Personal, None, 1, &wrapped_vk)?;
                Ok(true)
            })
            .await
            .map_err(storage)?;
        if !wrote {
            return Err(VaultError::AlreadyInitialized);
        }
        let mut vaults = BTreeMap::new();
        vaults.insert(
            vault_id,
            VaultKeyEntry {
                kind: VaultKind::Personal,
                key_version: 1,
                key: self.track(vk),
            },
        );
        Ok(Initialized {
            vault: UnlockedVault {
                lmk: self.track(lmk),
                vaults: std::sync::RwLock::new(vaults),
                device_id,
                hlc_last,
                method: UnlockMethod::Created,
                items: 0,
                undecryptable: 0,
                // A new database has no items.
                index: Some(new_index(
                    [(vault_id, VaultKind::Personal)],
                    Vec::new(),
                    &[],
                    0,
                )),
            },
            keyring_error,
        })
    }

    /// Check `password` against `meta.lmk_wrapped_pw` with the persisted backoff.
    /// Returns the LMK on success (and resets the counter).
    async fn try_password(&self, password: &str) -> Result<Key32, VaultError> {
        let m = self.meta().await?;
        let (Some(kdf), Some(wrapped)) = (m.kdf, m.lmk_pw) else {
            return Err(VaultError::NotInitialized);
        };
        let params = KdfParams::from_cbor(&kdf)?;
        let backoff = BackoffState::decode(m.failures.as_deref(), m.next_allowed.as_deref());
        if let Err(retry_after) = backoff.check(self.store.now()) {
            // Refused without running Argon2.
            return Err(VaultError::Backoff { retry_after });
        }
        let kek = self.derive(password, params).await?;
        match unwrap_key32(&kek, &WrapPurpose::Lmk, &wrapped) {
            Ok(lmk) => {
                if backoff.failures > 0 {
                    self.store
                        .write(|w| {
                            w.delete_meta(keys::UNLOCK_FAILURES)?;
                            w.delete_meta(keys::UNLOCK_NEXT_ALLOWED_AT)
                        })
                        .await
                        .map_err(storage)?;
                }
                Ok(lmk)
            }
            Err(CryptoError::Auth | CryptoError::Malformed(_)) => {
                // Read-modify-write in one transaction so concurrent processes count
                // every failure.
                let next = self
                    .store
                    .write(|w| {
                        let r = w.as_read();
                        let cur = BackoffState::decode(
                            r.get_meta(keys::UNLOCK_FAILURES)?.as_deref(),
                            r.get_meta(keys::UNLOCK_NEXT_ALLOWED_AT)?.as_deref(),
                        );
                        let next = cur.after_failure(w.now());
                        w.set_meta(keys::UNLOCK_FAILURES, &next.failures_bytes())?;
                        w.set_meta(keys::UNLOCK_NEXT_ALLOWED_AT, &next.next_allowed_at_bytes())?;
                        Ok(next)
                    })
                    .await
                    .map_err(storage)?;
                Err(VaultError::WrongPassword {
                    failures: next.failures,
                    retry_after: next.current_delay(),
                })
            }
            Err(other) => Err(VaultError::from_crypto(other, "meta.lmk_wrapped_pw")),
        }
    }

    /// Validate `password` only (`sverb unlock`): counts toward the backoff like a
    /// real unlock, loads no vault keys.
    ///
    /// # Errors
    /// As [`VaultEngine::unlock_with_password`].
    pub async fn verify_password(&self, password: &str) -> Result<(), VaultError> {
        self.try_password(password).await.map(drop)
    }

    /// Unlock with the master password (§2.3).
    ///
    /// # Errors
    /// [`VaultError::NotInitialized`], [`VaultError::Backoff`] (Argon2 did not run),
    /// [`VaultError::WrongPassword`] (counter persisted), [`VaultError::Corrupt`],
    /// [`VaultError::Storage`].
    pub async fn unlock_with_password(&self, password: &str) -> Result<UnlockedVault, VaultError> {
        let lmk = self.try_password(password).await?;
        self.open_vaults(lmk, UnlockMethod::Password).await
    }

    async fn keyring_kek(&self, db_id: Option<Vec<u8>>) -> Result<Key32, VaultError> {
        let db_id = db_id
            .and_then(|b| String::from_utf8(b).ok())
            .ok_or_else(|| VaultError::Corrupt("meta.db_id is missing".into()))?;
        let account = keyring_account(&db_id);
        let keyring = Arc::clone(&self.keyring);
        let secret = blocking(move || keyring.get(&account))
            .await?
            .map_err(|e| VaultError::Keyring(e.0))?
            .ok_or_else(|| VaultError::Keyring("the keyring entry is missing".into()))?;
        Key32::from_slice(&secret)
            .map_err(|_| VaultError::Keyring("the keyring entry is malformed".into()))
    }

    /// Unlock with the OS keyring (§2.3). No backoff (the OS gates the keyring).
    ///
    /// # Errors
    /// [`VaultError::KeyringNotEnabled`], [`VaultError::Keyring`] (entry missing,
    /// prompt cancelled, wrong entry), [`VaultError::NotInitialized`].
    pub async fn unlock_with_keyring(&self) -> Result<UnlockedVault, VaultError> {
        let m = self.meta().await?;
        if m.kdf.is_none() {
            return Err(VaultError::NotInitialized);
        }
        let wrapped = m.lmk_keyring.ok_or(VaultError::KeyringNotEnabled)?;
        let kek = self.keyring_kek(m.db_id).await?;
        let lmk = unwrap_key32(&kek, &WrapPurpose::Lmk, &wrapped).map_err(|_| {
            VaultError::Keyring("the keyring entry does not match this database".into())
        })?;
        self.open_vaults(lmk, UnlockMethod::Keyring).await
    }

    /// Unwrap every vault key, decrypt every item (read-only marks, §4.1), and load
    /// the device id and HLC.
    async fn open_vaults(
        &self,
        lmk: Key32,
        method: UnlockMethod,
    ) -> Result<UnlockedVault, VaultError> {
        let lmk = self.track(lmk);
        let (rows, items, device, hlc, locals) = self
            .store
            .read(|r| {
                Ok((
                    r.list_vaults()?,
                    r.list_all_items()?,
                    r.get_meta(keys::DEVICE_ID)?,
                    r.get_meta(keys::HLC_LAST)?,
                    // Frecency for the index ordering.
                    r.list_device_local()?,
                ))
            })
            .await
            .map_err(storage)?;
        let mut vaults = BTreeMap::new();
        for row in rows {
            let purpose = WrapPurpose::VaultKey(*row.id.as_bytes());
            match unwrap_key32(&lmk.key, &purpose, &row.wrapped_key) {
                Ok(vk) => {
                    vaults.insert(
                        row.id,
                        VaultKeyEntry {
                            kind: row.kind,
                            key_version: row.key_version,
                            key: self.track(vk),
                        },
                    );
                }
                // Not wrapped under the LMK (e.g. a shared vault awaiting a grant).
                Err(e) => {
                    tracing::warn!(vault = %row.id.short(), error = %e, "vault key does not unwrap")
                }
            }
        }
        let device_id = device
            .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
            .map(DeviceId::from_bytes)
            .ok_or_else(|| VaultError::Corrupt("meta.device_id is missing".into()))?;
        let hlc_last = hlc
            .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
            .map_or(Hlc::ZERO, |b| Hlc::from_u64(u64::from_be_bytes(b)));
        let mut unlocked = UnlockedVault {
            lmk,
            vaults: std::sync::RwLock::new(vaults),
            device_id,
            hlc_last,
            method,
            items: 0,
            undecryptable: 0,
            index: None,
        };
        // Decrypt every item: refresh the read-only marks on every unlock.
        // The in-memory search index is built from the same pass.
        let mut bodies = Vec::with_capacity(items.len());
        for row in &items {
            match unlocked.open(row) {
                Ok(body) => {
                    self.store.set_read_only(row.id, is_read_only(&body));
                    unlocked.items += 1;
                    if !row.deleted {
                        bodies.push((row.id, row.vault_id, body));
                    }
                }
                Err(e) => {
                    unlocked.undecryptable += 1;
                    tracing::warn!(item = %row.id.short(), error = %e, "item does not decrypt");
                }
            }
        }
        let kinds: Vec<(VaultId, VaultKind)> =
            unlocked.map().iter().map(|(id, v)| (*id, v.kind)).collect();
        unlocked.index = Some(new_index(kinds, bodies, &locals, self.store.now()));
        Ok(unlocked)
    }

    /// Change the master password (§2.5, local-only). `current` is verified by
    /// unwrapping (with the backoff). `None` is the keyring recovery path (§2.6) and
    /// requires a keyring-unlocked vault. The LMK is re-wrapped under a KEK with a
    /// **new salt** and the engine's (current default) Argon2 cost; the keyring wrap is
    /// unchanged.
    ///
    /// # Errors
    /// [`VaultError::WeakPassword`], [`VaultError::WrongPassword`],
    /// [`VaultError::Backoff`], [`VaultError::KeyringNotEnabled`] (recovery without a
    /// keyring unlock), [`VaultError::Storage`].
    pub async fn change_password(
        &self,
        unlocked: &UnlockedVault,
        current: Option<&str>,
        new_password: &str,
    ) -> Result<(), VaultError> {
        check_strength(new_password, &["sverb"])?;
        match current {
            Some(pw) => {
                let lmk = self.try_password(pw).await?;
                if lmk != *unlocked.lmk.key {
                    return Err(VaultError::Corrupt(
                        "the password unlocks a different LMK".into(),
                    ));
                }
            }
            None if unlocked.method == UnlockMethod::Keyring => {}
            None => return Err(VaultError::KeyringNotEnabled),
        }
        let mut rng = os_rng();
        let params = self.cost.with_salt(random_salt16(&mut rng));
        let kek = self.derive(new_password, params).await?;
        let lmk_pw = wrap_key(
            &kek,
            &WrapPurpose::Lmk,
            unlocked.lmk.key.expose_secret(),
            &mut rng,
        )
        .map_err(|e| VaultError::from_crypto(e, "lmk"))?;
        let kdf = params.to_cbor();
        self.store
            .write(move |w| {
                w.set_meta(keys::KDF, &kdf)?;
                w.set_meta(keys::LMK_WRAPPED_PW, &lmk_pw)?;
                w.delete_meta(keys::UNLOCK_FAILURES)?;
                w.delete_meta(keys::UNLOCK_NEXT_ALLOWED_AT)
            })
            .await
            .map_err(storage)
    }

    /// Turn keyring unlock on (new keyring KEK, `meta.lmk_wrapped_keyring`) or off
    /// (entry and wrap deleted).
    ///
    /// # Errors
    /// [`VaultError::Keyring`], [`VaultError::Storage`].
    pub async fn set_keyring_unlock(
        &self,
        unlocked: &UnlockedVault,
        enable: bool,
    ) -> Result<(), VaultError> {
        let db_id = self
            .meta()
            .await?
            .db_id
            .and_then(|b| String::from_utf8(b).ok())
            .ok_or_else(|| VaultError::Corrupt("meta.db_id is missing".into()))?;
        let account = keyring_account(&db_id);
        let keyring = Arc::clone(&self.keyring);
        if enable {
            let mut rng = os_rng();
            let kek = random_key32(&mut rng);
            let wrapped = wrap_key(
                &kek,
                &WrapPurpose::Lmk,
                unlocked.lmk.key.expose_secret(),
                &mut rng,
            )
            .map_err(|e| VaultError::from_crypto(e, "lmk"))?;
            let secret = Zeroizing::new(kek.expose_secret().to_vec());
            blocking(move || keyring.set(&account, &secret))
                .await?
                .map_err(|e| VaultError::Keyring(e.0))?;
            self.store
                .write(move |w| w.set_meta(keys::LMK_WRAPPED_KEYRING, &wrapped))
                .await
                .map_err(storage)
        } else {
            self.store
                .write(|w| w.delete_meta(keys::LMK_WRAPPED_KEYRING))
                .await
                .map_err(storage)?;
            blocking(move || keyring.delete(&account))
                .await?
                .map_err(|e| VaultError::Keyring(e.0))
        }
    }

    /// The keyring account this database uses (`None` before first run).
    ///
    /// # Errors
    /// [`VaultError::Storage`].
    pub async fn keyring_account(&self) -> Result<Option<String>, VaultError> {
        Ok(self
            .meta()
            .await?
            .db_id
            .and_then(|b| String::from_utf8(b).ok())
            .map(|id| keyring_account(&id)))
    }
}
