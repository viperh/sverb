//! Vault keys held by the engine while the vault is unlocked.
//!
//! The engine unwraps every `vaults.wrapped_key` with the LMK (purpose
//! `VaultKey(vault_id)`, §5.3) when it starts. After a key rotation (§13.2)
//! it keeps the previous versions in memory, so items still sealed under an
//! old version (pulled, or pending) can be opened and re-sealed under the
//! new one. Keys are zeroized when the engine is dropped (lock).

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use sverb_core::model::{ItemBody, ItemId, VaultId};
use sverb_crypto::Key32;
use sverb_crypto::envelope::{open_item, seal_item};
use sverb_crypto::random::os_rng;
use sverb_crypto::wrap::{WrapPurpose, unwrap_key32, wrap_key};
use sverb_proto::sync::VaultView;
use sverb_store::{VaultKind, VaultRow};

use crate::error::SyncError;

struct Entry {
    kind: VaultKind,
    current: u32,
    keys: BTreeMap<u32, Key32>,
}

/// Every loaded vault key, by vault and key version.
#[derive(Default)]
pub struct VaultKeys {
    vaults: HashMap<VaultId, Entry>,
}

impl fmt::Debug for VaultKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultKeys")
            .field("vaults", &self.vaults.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl VaultKeys {
    /// Unwraps the keys of `rows` with `lmk`. Vaults whose key does not unwrap
    /// are skipped and returned as `(vault, reason)`.
    #[must_use]
    pub fn load(rows: &[VaultRow], lmk: &Key32) -> (Self, Vec<(VaultId, String)>) {
        let mut keys = Self::default();
        let mut failed = Vec::new();
        for row in rows {
            let purpose = WrapPurpose::VaultKey(*row.id.as_bytes());
            match unwrap_key32(lmk, &purpose, &row.wrapped_key) {
                Ok(k) => keys.insert(row.id, row.kind, row.key_version, k),
                Err(e) => failed.push((row.id, e.to_string())),
            }
        }
        (keys, failed)
    }

    /// Adds key `version` of `vault`; it becomes current when it is the
    /// highest version known.
    pub fn insert(&mut self, vault: VaultId, kind: VaultKind, version: u32, key: Key32) {
        let e = self.vaults.entry(vault).or_insert_with(|| Entry {
            kind,
            current: version,
            keys: BTreeMap::new(),
        });
        e.keys.insert(version, key);
        e.current = e.current.max(version);
    }

    /// The vaults with keys, in id order.
    #[must_use]
    pub fn vault_ids(&self) -> Vec<VaultId> {
        let mut v: Vec<_> = self.vaults.keys().copied().collect();
        v.sort();
        v
    }

    /// The vault's kind.
    #[must_use]
    pub fn kind(&self, vault: VaultId) -> Option<VaultKind> {
        self.vaults.get(&vault).map(|e| e.kind)
    }

    /// The current key version of `vault`.
    #[must_use]
    pub fn current_version(&self, vault: VaultId) -> Option<u32> {
        self.vaults.get(&vault).map(|e| e.current)
    }

    /// Whether key `version` of `vault` is loaded.
    #[must_use]
    pub fn has(&self, vault: VaultId, version: u32) -> bool {
        self.vaults
            .get(&vault)
            .is_some_and(|e| e.keys.contains_key(&version))
    }

    /// Decrypts an envelope of `item` in `vault` (any loaded key version).
    ///
    /// # Errors
    /// A description when the vault is unknown, the key version is missing,
    /// the envelope does not authenticate, or the body does not decode.
    pub fn open(&self, vault: VaultId, item: ItemId, envelope: &[u8]) -> Result<ItemBody, String> {
        let e = self.vaults.get(&vault).ok_or("no key for this vault")?;
        let plain = open_item(
            |v| e.keys.get(&v),
            vault.as_bytes(),
            item.as_bytes(),
            envelope,
        )
        .map_err(|e| e.to_string())?;
        ItemBody::from_cbor(&plain).map_err(|e| e.to_string())
    }

    /// Seals `body` for `item` under the current key of `vault`. Returns the
    /// key version and the envelope.
    ///
    /// # Errors
    /// A description when the vault is unknown or encoding fails.
    pub fn seal(
        &self,
        vault: VaultId,
        item: ItemId,
        body: &ItemBody,
    ) -> Result<(u32, Vec<u8>), String> {
        let e = self.vaults.get(&vault).ok_or("no key for this vault")?;
        let key = e.keys.get(&e.current).ok_or("current key missing")?;
        let cbor = body.to_cbor().map_err(|e| e.to_string())?;
        let env = seal_item(
            key,
            vault.as_bytes(),
            item.as_bytes(),
            e.current,
            &cbor,
            &mut os_rng(),
        )
        .map_err(|e| e.to_string())?;
        Ok((e.current, env))
    }

    /// The current key of `vault` wrapped under `lmk` for
    /// `vaults.wrapped_key`.
    ///
    /// # Errors
    /// [`SyncError::Crypto`].
    pub fn wrap_current(&self, vault: VaultId, lmk: &Key32) -> Result<(u32, Vec<u8>), SyncError> {
        let e = self
            .vaults
            .get(&vault)
            .ok_or(SyncError::Crypto("no key for this vault".into()))?;
        let key = e
            .keys
            .get(&e.current)
            .ok_or(SyncError::Crypto("current key missing".into()))?;
        let wrapped = wrap_key(
            lmk,
            &WrapPurpose::VaultKey(*vault.as_bytes()),
            key.expose_secret(),
            &mut os_rng(),
        )
        .map_err(|e| SyncError::Crypto(e.to_string()))?;
        Ok((e.current, wrapped))
    }
}

/// Opens new vault keys from the server's grants (`GET /v1/vaults`), after a
/// key rotation (§13.2) or a new membership.
///
/// Opening a grant needs the account's X25519 private key, which only the
/// account layer holds; the engine asks through this trait.
pub trait VaultKeySource: Send + Sync + fmt::Debug {
    /// The key `version` of `vault`, from the caller's grant in `view`, or
    /// `None` when it can't be opened (no account keys loaded, bad
    /// signature).
    fn open_grant(&self, view: &VaultView, version: u32) -> Option<Key32>;

    // Adopting shared vaults (`engine.rs`). Defaults suit sources that
    // can't check memberships (they open nothing new anyway).
    /// The account whose grants this source opens.
    fn account(&self) -> Option<uuid::Uuid> {
        None
    }

    /// The device's pins changed (a granter was pinned on first sight).
    fn update_pins(&self, _pins: crate::trust::PinSet) {}

    /// The server's (untrusted) membership list of a shared vault, for the
    /// "granter has `manage`" check (§13.3).
    fn observe_vault_members(&self, _members: &sverb_proto::vaults::VaultMembersView) {}

    /// [`Self::open_grant`] with the reason it was refused.
    ///
    /// # Errors
    /// Why the grant can't be used.
    fn check_grant(&self, view: &VaultView, version: u32) -> Result<Key32, String> {
        self.open_grant(view, version)
            .ok_or_else(|| "the vault key grant could not be opened".to_owned())
    }
}

/// A [`VaultKeySource`] that can't open anything: rotations then surface as
/// an error status until the account keys are available.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoKeySource;

impl VaultKeySource for NoKeySource {
    fn open_grant(&self, _view: &VaultView, _version: u32) -> Option<Key32> {
        None
    }
}
