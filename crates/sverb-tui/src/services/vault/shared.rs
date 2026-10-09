//! Shared vaults in the vault service (SPEC §13.1, §13.4, §4.13).
//!
//! UI-free helpers the item service, the SSH resolver and the sync service use:
//! * [`VaultService::adopt_new_vaults`]: the sync engine verified a new grant
//!   and stored the vault key under the LMK; load it into the unlocked vault so
//!   the vault's items decrypt (before its pulled items are indexed);
//! * [`vault_info`]: display names (sealed under each vault key in `meta`), which
//!   vaults are shared and which are read-only for this account (the permission
//!   the sync engine records in `meta`);
//! * [`override_for`]: this user's [`CredentialOverride`] for a shared host, from
//!   the personal vault only (§13.4).
//!
//! The `meta` keys are written by `sverb_sync::account::vaults` (sync builds);
//! their spelling is repeated here so local-only builds read them without the
//! sync crate (they simply never exist there).

use std::collections::{BTreeMap, BTreeSet};

use sverb_core::model::{CredentialOverride, ItemId, ItemKind, VaultId};
use sverb_core::resolve::overrides::{OverrideLayer, pick_override};
use sverb_store::{Store, VaultKind};
use tracing::{debug, warn};

use super::items::Loaded;
use super::{UnlockedVault, VaultService, vault_display_name};

/// `meta` key prefix of a vault's sealed name (`sverb_sync::account::vaults`).
pub const META_VAULT_NAME_PREFIX: &str = "vault_name_enc/";
/// `meta` key prefix of this account's permission on a shared vault.
pub const META_VAULT_PERMISSION_PREFIX: &str = "vault_permission/";

/// What the UI needs to know about the local vaults.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VaultInfo {
    /// Display names (`Personal`, the shared vault's name, or `Shared <id>`).
    pub names: BTreeMap<VaultId, String>,
    /// The shared vaults.
    pub shared: BTreeSet<VaultId>,
    /// Shared vaults this account may only read (§13.2).
    pub read_only: BTreeSet<VaultId>,
}

/// Names, kinds and read-only flags of the vaults whose keys `unlocked` holds.
pub async fn vault_info(store: &Store, unlocked: &UnlockedVault) -> VaultInfo {
    let mut info = VaultInfo::default();
    let rows = match store.list_vaults().await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "listing vaults failed");
            return info;
        }
    };
    for row in rows {
        let mut name = vault_display_name(row.id, row.kind);
        if row.kind == VaultKind::Shared {
            info.shared.insert(row.id);
            let key = format!("{META_VAULT_NAME_PREFIX}{}", row.id.uuid());
            if let Ok(Some(enc)) = store.get_meta(&key).await
                && let Some(n) = unlocked.open_vault_name(row.id, &enc)
            {
                name = n;
            }
            let key = format!("{META_VAULT_PERMISSION_PREFIX}{}", row.id.uuid());
            if let Ok(Some(p)) = store.get_meta(&key).await
                && p == b"read"
            {
                info.read_only.insert(row.id);
            }
        }
        info.names.insert(row.id, name);
    }
    info
}

/// This user's credential overrides (personal vault only), as resolution layers.
pub fn overrides(items: &[Loaded], personal: Option<VaultId>) -> Vec<OverrideLayer> {
    items
        .iter()
        .filter(|i| i.body.kind == ItemKind::CredentialOverride && Some(i.vault) == personal)
        .filter(|i| !i.body.is_deleted())
        .filter_map(|i| match CredentialOverride::try_from(&i.body) {
            Ok(o) => Some(OverrideLayer::new(i.id, &o)),
            Err(e) => {
                debug!(item = %i.id.short(), error = %e, "credential override skipped");
                None
            }
        })
        .collect()
}

/// The override for `host` among `items` (see [`overrides`]).
pub fn override_for(
    host: ItemId,
    items: &[Loaded],
    personal: Option<VaultId>,
) -> Option<OverrideLayer> {
    let all = overrides(items, personal);
    pick_override(host, &all).cloned()
}

impl VaultService {
    /// The vault selector changed: new hosts go to `vault` (`None`: Personal).
    pub fn set_new_item_vault(&self, vault: Option<VaultId>) {
        *self
            .new_item_vault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = vault;
    }

    /// Puts the vaults' display names into the search index (`@vault` filters,
    /// badges).
    pub async fn refresh_vault_names(&self) {
        let Some(unlocked) = self.unlocked() else {
            return;
        };
        let info = vault_info(self.store(), &unlocked).await;
        self.update_index(|ix| {
            for (v, n) in &info.names {
                ix.set_vault_name(*v, n.clone());
            }
        });
    }

    /// Loads the keys of vaults the sync engine added since unlock (§13.2:
    /// verified grants, keys wrapped under the LMK). Returns the new vaults.
    pub async fn adopt_new_vaults(&self) -> Vec<VaultId> {
        let Some(unlocked) = self.unlocked() else {
            return Vec::new();
        };
        let rows = match self.store().list_vaults().await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "listing vaults failed");
                return Vec::new();
            }
        };
        let mut added = Vec::new();
        for row in rows {
            match unlocked.add_vault(&row) {
                Ok(true) => added.push(row.id),
                Ok(false) => {}
                Err(e) => warn!(vault = %row.id.short(), error = %e, "vault key does not unwrap"),
            }
        }
        if !added.is_empty() {
            let info = vault_info(self.store(), &unlocked).await;
            self.update_index(|ix| {
                for v in &added {
                    if let Some(n) = info.names.get(v) {
                        ix.set_vault_name(*v, n.clone());
                    }
                }
            });
        }
        added
    }

    /// Switches loaded vaults to the key now stored for them (after a key
    /// rotation). Returns the vaults whose key changed.
    pub async fn refresh_vault_keys(&self) -> Vec<VaultId> {
        let Some(unlocked) = self.unlocked() else {
            return Vec::new();
        };
        let rows = match self.store().list_vaults().await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "listing vaults failed");
                return Vec::new();
            }
        };
        let mut changed = Vec::new();
        for row in rows {
            match unlocked.update_vault_key(&row) {
                Ok(true) => changed.push(row.id),
                Ok(false) => {}
                Err(e) => {
                    warn!(vault = %row.id.short(), error = %e, "rotated vault key does not unwrap")
                }
            }
        }
        changed
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use sverb_core::model::{DeviceId, HlcClock, ItemBody};

    use super::*;

    #[test]
    fn overrides_come_from_the_personal_vault_only() {
        let personal = VaultId::new();
        let shared = VaultId::new();
        let host = ItemId::new();
        let mut o = CredentialOverride::new(host);
        o.username = Some("bob".into());
        let body = o.to_body(&mut HlcClock::default(), DeviceId::new());
        let mine = Loaded {
            id: ItemId::new(),
            vault: personal,
            body: body.clone(),
        };
        let planted = Loaded {
            id: ItemId::from_bytes([0; 16]),
            vault: shared,
            body,
        };
        let other = Loaded {
            id: ItemId::new(),
            vault: personal,
            body: ItemBody::new(ItemKind::Host, 1),
        };
        let items = [planted, mine, other];
        let got = override_for(host, &items, Some(personal)).unwrap();
        assert_eq!(got.item, items[1].id);
        assert_eq!(got.username.as_deref(), Some("bob"));
        assert!(override_for(ItemId::new(), &items, Some(personal)).is_none());
        assert!(override_for(host, &items, None).is_none());
    }
}
