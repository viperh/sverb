//! Shared vaults on the client (SPEC §13.1, §13.2, §13.3, §11.3).
//!
//! * **Create** ([`VaultAdmin::create`]): a fresh vault key (VK), the name
//!   sealed under it, the creator's `manage` self-grant; the VK is kept locally
//!   wrapped under the LMK (§5.3). The server never sees the VK.
//! * **Grant** ([`VaultAdmin::grant`]): the member's public keys are fetched and
//!   on first sight, **refused** while a key change is pending), the VK is
//!   HPKE-wrapped to the member and the wrap signed with our Ed25519 key.
//! * **Receive**: the sync engine adopts vaults it sees for the first time
//!   (`engine.rs`, on `vault_access granted` or a vault list refresh): it pins the
//!   granter on first sight, verifies the grant signature against the **pinned**
//!   granter key and checks that the granter has `manage` according to the
//!   membership list ([`crate::trust::verify_grant`]), and only then wraps the VK
//!   under the LMK into the local `vaults` table and pulls.
//! * **Implicit `manage`** (§13.1): org owners and admins manage every org vault,
//!   but the server can't hand them a key. [`VaultAdmin::reconcile_admins`] (run
//!   by any `manage` member's client) grants `manage` to admins that hold no key.
//! * **Move / copy** ([`apply_transfer`]): the plan of
//!   [`sverb_core::model::vault_refs::plan_transfer`] sealed under the target VK,
//!   written in one local transaction (the engine pushes it).
//!
//! Vault names are sealed under the VK (`name_enc`, like the personal vault's,
//! §4.13). This device keeps the sealed name in `meta` (`vault_name_enc/<id>`)
//! and opens it with the VK, so the name never sits in plaintext at rest.

use std::collections::BTreeMap;
use std::sync::Arc;

use sverb_core::model::vault_refs::TransferPlan;
use sverb_core::model::{ItemBody, OrgId, VaultId};
use sverb_crypto::Key32;
use sverb_crypto::account::AccountKeys;
use sverb_crypto::envelope::open_item;
use sverb_crypto::grant::{grant_vault_key, self_grant};
use sverb_crypto::random::{os_rng, random_key32};
use sverb_crypto::wrap::{WrapPurpose, unwrap_key32, wrap_key};
use sverb_proto::auth::GrantUpload;
use sverb_proto::orgs::Role;
use sverb_proto::sync::Permission;
use sverb_proto::vaults::{CreateVaultRequest, GrantRequest, OrgVaultView, VaultMembersView};
use sverb_store::{Store, VaultKind};
use uuid::Uuid;

use super::devices::{call, session};
use super::register::seal_vault_name;
use super::{AccountConfig, AccountError};
use crate::keys::VaultKeys;
use crate::tokens::TokenManager;
use crate::trust::{TokenDirectory, Trust, TrustError};

/// `meta` key prefix of a vault's sealed name (`vault_name_enc/<uuid>`).
pub const META_VAULT_NAME_PREFIX: &str = "vault_name_enc/";

/// `meta` key prefix of this account's permission on a shared vault
/// (`vault_permission/<uuid>` = `read` / `write` / `manage`), kept from the
/// vault list so the UI can show "Read-only vault" offline.
pub const META_VAULT_PERMISSION_PREFIX: &str = "vault_permission/";

/// Longest vault name.
pub const MAX_VAULT_NAME: usize = 100;

/// Why a shared-vault operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VaultAdminError {
    /// The member's (or granter's) key is not trusted: a pending key change
    /// (compare safety numbers first) or no pin.
    #[error(transparent)]
    Trust(#[from] TrustError),
    /// A server or local error.
    #[error(transparent)]
    Account(#[from] AccountError),
    /// This device holds no key for the vault.
    #[error("this device has no key for vault {0}")]
    NoKey(VaultId),
    /// Bad input (empty name, …).
    #[error("{0}")]
    Invalid(String),
}

impl From<crate::error::SyncError> for VaultAdminError {
    fn from(e: crate::error::SyncError) -> Self {
        Self::Account(e.into())
    }
}

impl From<sverb_store::StoreError> for VaultAdminError {
    fn from(e: sverb_store::StoreError) -> Self {
        Self::Account(e.into())
    }
}

impl From<sverb_crypto::CryptoError> for VaultAdminError {
    fn from(e: sverb_crypto::CryptoError) -> Self {
        Self::Account(e.into())
    }
}

type Res<T> = Result<T, VaultAdminError>;

/// What [`VaultAdmin::reconcile_admins`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// `(vault, user)` granted `manage`.
    pub granted: Vec<(VaultId, Uuid)>,
    /// `(vault, user, reason)` not granted (untrusted key, server error).
    pub skipped: Vec<(VaultId, Uuid, String)>,
}

/// An org vault as listed for the vault management page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgVaultEntry {
    /// The server's row.
    pub view: OrgVaultView,
    /// The name, when this device holds the key.
    pub name: Option<String>,
}

impl OrgVaultEntry {
    /// "needs key": an org admin without a grant yet (§13.1).
    #[must_use]
    pub fn needs_key(&self) -> bool {
        !self.view.has_key
    }
}

/// Opens a sealed vault name with the vault key.
///
/// # Errors
/// [`AccountError::Crypto`] when it does not open or is not UTF-8.
pub fn open_vault_name(
    vk: &Key32,
    vault: VaultId,
    name_enc: &[u8],
) -> Result<String, AccountError> {
    let plain = open_item(|_| Some(vk), vault.as_bytes(), vault.as_bytes(), name_enc)?;
    String::from_utf8(plain.to_vec())
        .map_err(|_| AccountError::Crypto("vault name is not UTF-8".into()))
}

fn name_key(vault: VaultId) -> String {
    format!("{META_VAULT_NAME_PREFIX}{}", vault.uuid())
}

/// Keeps a vault's sealed name on this device.
///
/// # Errors
/// [`AccountError::Local`].
pub async fn save_vault_name(
    store: &Store,
    vault: VaultId,
    name_enc: Vec<u8>,
) -> Result<(), AccountError> {
    Ok(store.set_meta(&name_key(vault), name_enc).await?)
}

/// Records this account's permission on `vault` (only written when it changed).
pub async fn note_permission(store: &Store, vault: VaultId, permission: Permission) {
    let key = format!("{META_VAULT_PERMISSION_PREFIX}{}", vault.uuid());
    let value = permission.as_str().as_bytes();
    match store.get_meta(&key).await {
        Ok(Some(cur)) if cur == value => {}
        Ok(_) => {
            if let Err(e) = store.set_meta(&key, value.to_vec()).await {
                tracing::warn!(%vault, error = %e, "vault permission not saved");
            }
        }
        Err(e) => tracing::warn!(%vault, error = %e, "vault permission not read"),
    }
}

/// The permission recorded by [`note_permission`].
///
/// # Errors
/// [`AccountError::Local`].
pub async fn local_permission(
    store: &Store,
    vault: VaultId,
) -> Result<Option<Permission>, AccountError> {
    let key = format!("{META_VAULT_PERMISSION_PREFIX}{}", vault.uuid());
    Ok(store
        .get_meta(&key)
        .await?
        .and_then(|b| String::from_utf8(b).ok())
        .and_then(|s| Permission::parse(&s)))
}

/// The names of the local shared vaults this device can open (sealed names in
/// `meta`, opened with `keys`).
///
/// # Errors
/// [`AccountError::Local`].
pub async fn vault_names(
    store: &Store,
    keys: impl Fn(VaultId) -> Option<Key32>,
) -> Result<BTreeMap<VaultId, String>, AccountError> {
    let mut out = BTreeMap::new();
    for row in store.list_vaults().await? {
        if row.kind != VaultKind::Shared {
            continue;
        }
        let Some(enc) = store.get_meta(&name_key(row.id)).await? else {
            continue;
        };
        if let Some(vk) = keys(row.id)
            && let Ok(name) = open_vault_name(&vk, row.id, &enc)
        {
            out.insert(row.id, name);
        }
    }
    Ok(out)
}

/// The local key of `vault` (unwrapped with the LMK) and its version.
///
/// # Errors
/// [`VaultAdminError::NoKey`].
pub async fn local_vault_key(store: &Store, lmk: &Key32, vault: VaultId) -> Res<(Key32, u32)> {
    let row = store
        .get_vault(vault)
        .await?
        .ok_or(VaultAdminError::NoKey(vault))?;
    let vk = unwrap_key32(
        lmk,
        &WrapPurpose::VaultKey(*vault.as_bytes()),
        &row.wrapped_key,
    )
    .map_err(|_| VaultAdminError::NoKey(vault))?;
    Ok((vk, row.key_version))
}

/// Seals and writes a transfer plan ([`sverb_core::model::vault_refs::plan_transfer`])
/// in one local transaction: the new items into `target`, the tombstones into
/// their source vaults; everything is queued for push. `keys` must hold the
/// target's and the sources' keys.
///
/// # Errors
/// [`VaultAdminError::NoKey`], a crypto or store error.
pub async fn apply_transfer(
    store: &Store,
    keys: &VaultKeys,
    target: VaultId,
    plan: &TransferPlan,
) -> Res<()> {
    let mut rows: Vec<(VaultId, sverb_core::model::ItemId, u32, Vec<u8>, bool)> = Vec::new();
    let seal = |vault: VaultId, id, body: &ItemBody| {
        keys.seal(vault, id, body)
            .map_err(|_| VaultAdminError::NoKey(vault))
    };
    for (id, body) in &plan.writes {
        let (kv, env) = seal(target, *id, body)?;
        rows.push((target, *id, kv, env, false));
    }
    for (id, vault, body) in &plan.tombstones {
        let (kv, env) = seal(*vault, *id, body)?;
        rows.push((*vault, *id, kv, env, true));
    }
    store
        .write(move |w| {
            for (vault, id, kv, env, deleted) in &rows {
                w.put_item(*vault, *id, *kv, env, *deleted, true)?;
            }
            Ok(())
        })
        .await?;
    Ok(())
}

/// Shared-vault management for the signed-in account on this device.
#[derive(Clone)]
pub struct VaultAdmin {
    // `pub(crate)` for the rotation orchestrator (`crate::rotation`).
    pub(crate) store: Store,
    pub(crate) lmk: Key32,
    pub(crate) tokens: Arc<TokenManager>,
    pub(crate) keys: Arc<AccountKeys>,
    pub(crate) trust: Trust,
}

impl std::fmt::Debug for VaultAdmin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultAdmin")
            .field("me", &self.trust.me())
            .finish_non_exhaustive()
    }
}

impl VaultAdmin {
    /// Management as account `me` (holding `keys`) through `tokens`.
    #[must_use]
    pub fn new(
        store: Store,
        lmk: Key32,
        tokens: Arc<TokenManager>,
        me: Uuid,
        keys: Arc<AccountKeys>,
    ) -> Self {
        let trust = Trust::new(store.clone(), me);
        Self {
            store,
            lmk,
            tokens,
            keys,
            trust,
        }
    }

    /// For the account signed in on this unlocked device.
    ///
    /// # Errors
    /// [`AccountError::NotSignedIn`] (no account keys), [`AccountError`].
    pub async fn load(store: &Store, lmk: &Key32, cfg: &AccountConfig) -> Res<Self> {
        let (acct, keys) = super::load_account_keys(store, lmk)
            .await?
            .ok_or(AccountError::NotSignedIn)?;
        let tokens = Arc::new(session(store, lmk, cfg).await?);
        Ok(Self::new(
            store.clone(),
            lmk.clone(),
            tokens,
            acct.user_id,
            Arc::new(keys),
        ))
    }

    /// This account.
    #[must_use]
    pub fn me(&self) -> Uuid {
        self.trust.me()
    }

    /// The trust store of this account.
    #[must_use]
    pub const fn trust(&self) -> &Trust {
        &self.trust
    }

    /// Creates a shared vault of `org` named `name` (org admin+). Returns its id;
    /// the vault is ready locally (key under the LMK, name in `meta`).
    ///
    /// # Errors
    /// [`VaultAdminError::Invalid`] (name), the server's `403` / `404`.
    pub async fn create(&self, org: Uuid, name: &str) -> Res<VaultId> {
        let name = name.trim();
        if name.is_empty()
            || name.chars().count() > MAX_VAULT_NAME
            || name.chars().any(char::is_control)
        {
            return Err(VaultAdminError::Invalid(format!(
                "a vault name has 1 to {MAX_VAULT_NAME} characters"
            )));
        }
        let mut rng = os_rng();
        let vault = VaultId::new();
        let kv = 1;
        let vk = random_key32(&mut rng);
        let me = self.me();
        let name_enc = seal_vault_name(&vk, vault, kv, name)?;
        let grant = self_grant(
            &vk,
            vault.as_bytes(),
            kv,
            me.as_bytes(),
            &self.keys,
            &mut rng,
        )?;
        let req = CreateVaultRequest {
            id: vault.uuid(),
            org_id: org,
            name_enc: name_enc.clone(),
            self_grant: GrantUpload {
                wrapped_vault_key: grant.wrapped,
                signature: grant.signature.to_vec(),
                key_version: kv,
            },
        };
        call(&self.tokens, |api, t| {
            let req = req.clone();
            async move { api.create_vault(&t, &req).await }
        })
        .await?;
        let wrapped = wrap_key(
            &self.lmk,
            &WrapPurpose::VaultKey(*vault.as_bytes()),
            vk.expose_secret(),
            &mut rng,
        )?;
        self.store
            .create_vault(
                vault,
                VaultKind::Shared,
                Some(OrgId::from_uuid(org)),
                kv,
                wrapped,
            )
            .await?;
        save_vault_name(&self.store, vault, name_enc).await?;
        tracing::info!(%vault, %org, "shared vault created");
        Ok(vault)
    }

    /// The org's members with their permission on `vault`.
    ///
    /// # Errors
    /// [`AccountError`] (`404` when invisible).
    pub async fn members(&self, vault: VaultId) -> Res<VaultMembersView> {
        let id = vault.uuid();
        Ok(call(&self.tokens, |api, t| async move {
            api.vault_members(&t, id).await
        })
        .await?)
    }

    /// Grants `user` access to `vault` with `permission` (§13.2): their keys are
    /// fetched and checked against the pins first (pinned on first sight;
    /// **refused** while a key change is pending: compare safety numbers and
    /// accept the new key in Settings → Team).
    ///
    /// # Errors
    /// [`VaultAdminError::Trust`] (key changed), [`VaultAdminError::NoKey`],
    /// the server's `403` / `400`.
    pub async fn grant(&self, vault: VaultId, user: Uuid, permission: Permission) -> Res<()> {
        let (vk, kv) = local_vault_key(&self.store, &self.lmk, vault).await?;
        let keys = match self
            .trust
            .keys_for_grant(&TokenDirectory(self.tokens.clone()), user)
            .await
        {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!(%vault, %user, error = %e, "REFUSING to grant: the member's key is not trusted");
                return Err(e.into());
            }
        };
        let g = grant_vault_key(
            &vk,
            vault.as_bytes(),
            kv,
            user.as_bytes(),
            &keys.x25519,
            self.keys.ed25519_signing_key(),
            &mut os_rng(),
        )?;
        let req = GrantRequest {
            permission,
            key_version: kv,
            wrapped_vault_key: g.wrapped,
            signature: g.signature.to_vec(),
        };
        let id = vault.uuid();
        call(&self.tokens, |api, t| {
            let req = req.clone();
            async move { api.grant_vault_member(&t, id, user, &req).await }
        })
        .await?;
        tracing::info!(%vault, %user, permission = permission.as_str(), "vault access granted");
        Ok(())
    }

    /// Revokes `user`'s access (or leaves, for our own id). The key rotation that
    /// `crate::rotation`).
    ///
    /// # Errors
    /// The server's `403` / `404`.
    pub async fn revoke(&self, vault: VaultId, user: Uuid) -> Res<()> {
        let id = vault.uuid();
        call(&self.tokens, |api, t| async move {
            api.revoke_vault_member(&t, id, user).await
        })
        .await?;
        Ok(())
    }

    /// The org's vaults visible to this account, with their names where this
    /// device holds the key ("needs key" otherwise, §13.1).
    ///
    /// # Errors
    /// [`AccountError`].
    pub async fn org_vaults(&self, org: Uuid) -> Res<Vec<OrgVaultEntry>> {
        let views = call(&self.tokens, |api, t| async move {
            api.org_vaults(&t, org).await
        })
        .await?;
        let mut out = Vec::with_capacity(views.len());
        for view in views {
            let vault = VaultId::from_uuid(view.id);
            let name = match local_vault_key(&self.store, &self.lmk, vault).await {
                Ok((vk, _)) => open_vault_name(&vk, vault, &view.name_enc).ok(),
                Err(_) => None,
            };
            out.push(OrgVaultEntry { view, name });
        }
        Ok(out)
    }

    /// The background reconcile of §13.1: for every local shared vault this
    /// account manages, org owners and admins that hold no key for the current
    /// version are granted `manage`. Members whose key is not trusted are
    /// skipped (reported), never granted.
    ///
    /// # Errors
    /// Listing the local vaults failed; per-vault errors are in the report.
    pub async fn reconcile_admins(&self) -> Res<ReconcileReport> {
        let mut report = ReconcileReport::default();
        let me = self.me();
        for row in self.store.list_vaults().await? {
            if row.kind != VaultKind::Shared {
                continue;
            }
            let members = match self.members(row.id).await {
                Ok(m) => m,
                Err(e) => {
                    tracing::debug!(vault = %row.id, error = %e, "reconcile: no member list");
                    continue;
                }
            };
            if row.key_version != members.key_version {
                continue; // a rotation is pending
            }
            let i_manage = members
                .members
                .iter()
                .find(|m| m.user_id == me)
                .and_then(sverb_proto::vaults::VaultMemberView::effective)
                == Some(Permission::Manage);
            if !i_manage {
                continue;
            }
            for m in &members.members {
                if m.user_id == me || m.has_key || m.org_role < Role::Admin {
                    continue;
                }
                match self.grant(row.id, m.user_id, Permission::Manage).await {
                    Ok(()) => report.granted.push((row.id, m.user_id)),
                    Err(e) => report.skipped.push((row.id, m.user_id, e.to_string())),
                }
            }
        }
        Ok(report)
    }
}

// ------------------------------------------------------------- engine adoption

impl crate::engine::Ctx {
    /// Adopts the shared vaults in `views` that this device does not have yet
    /// (§13.2 "receiving side"): membership list → TOFU pin of the granter →
    /// [`crate::keys::VaultKeySource::check_grant`] (signature against the
    /// **pinned** granter key, granter has `manage`) → VK wrapped under the LMK
    /// into the local `vaults` table. A refused grant is reported once (toast and
    /// status) and the key is never used.
    pub(crate) async fn adopt_new_vaults(
        &mut self,
        views: &[sverb_proto::sync::VaultView],
    ) -> Result<(), crate::error::SyncError> {
        use crate::status::{SyncEvent, ToastLevel};
        let known: std::collections::HashSet<VaultId> =
            self.keys.read().vault_ids().into_iter().collect();
        let stored: std::collections::HashMap<VaultId, sverb_store::VaultRow> = self
            .store
            .list_vaults()
            .await?
            .into_iter()
            .map(|r| (r.id, r))
            .collect();
        for view in views {
            let vault = VaultId::from_uuid(view.id);
            if view.kind != sverb_proto::sync::VaultKind::Shared || known.contains(&vault) {
                continue;
            }
            // Created on this device after the engine started: the key is in the
            // store already (under the LMK).
            if let Some(row) = stored.get(&vault) {
                match unwrap_key32(
                    &self.lmk,
                    &WrapPurpose::VaultKey(*vault.as_bytes()),
                    &row.wrapped_key,
                ) {
                    Ok(vk) => {
                        self.keys
                            .write()
                            .insert(vault, row.kind, row.key_version, vk);
                        self.unknown_vaults.remove(&vault);
                    }
                    Err(e) => tracing::warn!(%vault, error = %e, "vault key does not unwrap"),
                }
                continue;
            }
            if view.rotation.is_some()
                || !view
                    .grants
                    .iter()
                    .any(|g| g.key_version == view.key_version)
            {
                continue;
            }
            let id = view.id;
            match self
                .call(|api, t| async move { api.vault_members(&t, id).await })
                .await
            {
                Ok(m) => self.key_source.observe_vault_members(&m),
                Err(e) => {
                    tracing::warn!(%vault, error = %e, "no member list for a new shared vault; retrying later");
                    continue;
                }
            }
            if let Some(me) = self.key_source.account() {
                let trust = Trust::new(self.store.clone(), me);
                if let Err(e) = trust
                    .pin_granters(
                        &TokenDirectory(self.tokens.clone()),
                        std::slice::from_ref(view),
                    )
                    .await
                {
                    tracing::warn!(%vault, error = %e, "could not pin the granter");
                }
                match trust.pins().await {
                    Ok(p) => self.key_source.update_pins(p),
                    Err(e) => tracing::warn!(error = %e, "cannot read the key pins"),
                }
            }
            match self.key_source.check_grant(view, view.key_version) {
                Ok(vk) => {
                    let wrapped = wrap_key(
                        &self.lmk,
                        &WrapPurpose::VaultKey(*vault.as_bytes()),
                        vk.expose_secret(),
                        &mut os_rng(),
                    )
                    .map_err(|e| crate::error::SyncError::Crypto(e.to_string()))?;
                    self.store
                        .create_vault(
                            vault,
                            VaultKind::Shared,
                            view.org_id.map(OrgId::from_uuid),
                            view.key_version,
                            wrapped,
                        )
                        .await?;
                    if let Err(e) = save_vault_name(&self.store, vault, view.name_enc.clone()).await
                    {
                        tracing::warn!(%vault, error = %e, "vault name not saved");
                    }
                    let name = open_vault_name(&vk, vault, &view.name_enc).ok();
                    note_permission(&self.store, vault, view.permission).await;
                    self.keys
                        .write()
                        .insert(vault, VaultKind::Shared, view.key_version, vk);
                    self.rejected_grants.remove(&vault);
                    self.unknown_vaults.remove(&vault);
                    tracing::info!(%vault, permission = view.permission.as_str(), "shared vault adopted");
                    self.toast(
                        ToastLevel::Info,
                        match &name {
                            Some(n) => format!("You now have access to the shared vault “{n}”"),
                            None => "You now have access to a shared vault".to_owned(),
                        },
                    );
                    self.emit(SyncEvent::VaultAdded { vault, name });
                }
                Err(reason) => {
                    if self.rejected_grants.insert(vault, reason.clone()).is_none() {
                        self.toast(
                            ToastLevel::Error,
                            format!(
                                "A vault was shared with you, but its key could not be verified \
                                 and is not used: {reason}"
                            ),
                        );
                    }
                }
            }
        }
        Ok(())
    }
}
