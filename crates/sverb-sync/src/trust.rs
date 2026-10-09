//! M5-03: public-key trust (SPEC §13.3, §11.3, §17 "server compromise").
//!
//! A malicious server could substitute public keys. The client therefore:
//!
//! - **pins** every user's keys on first sight (TOFU), device-locally
//!   ([`sverb_store::pins`]), whenever it sees them: fetching keys to grant,
//!   listing members, verifying grants ([`Trust::fetch`], [`Trust::observe`]);
//! - treats a **changed** key as an attack until proven otherwise: the pin is not
//!   replaced, the member shows "⚠ key changed", grants **to** that user are blocked
//!   ([`Trust::keys_for_grant`]) and grants **from** that user are not trusted
//!   ([`verify_grant`]) until the user compares safety numbers and accepts the new
//!   key ([`Trust::accept_new_key`]);
//! - shows **safety numbers** ([`Trust::safety_number`]: 60 digits in 12 groups,
//!   symmetric, from `sverb_crypto::fingerprint`) and records out-of-band
//!   verification (✓, [`Trust::mark_verified`]);
//! - uses a wrapped vault key only after [`verify_grant`]: the Ed25519 signature
//!   over the canonical grant encoding must verify with the **pinned** key of
//!   `wrapped_by`, and the granter must have `manage` on the vault (or be an org
//!   owner/admin, or the vault's creator) according to the server's membership list.
//!   [`TrustedKeySource`] is the engine's [`VaultKeySource`] that enforces this.
//!
//! Client-side rules on top of the (untrusted) membership list:
//! - a personal vault key is only accepted as a **self-grant** signed with this
//!   account's own key;
//! - a self-grant claimed for **another** user (`wrapped_by == member != me`) is
//!   rejected, except the shared vault creator's own self-grant (TOFU on the
//!   creator, whose key must be pinned like any granter);
//! - every granter must be pinned and unchanged, so every accepted grant chain
//!   leads to a pinned key.
//!
//! The residual risk (a server lying about membership or the creator, or serving
//! substituted keys before the first pin) is documented in `docs/threat-model.md`.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use parking_lot::RwLock;
use sverb_crypto::Key32;
use sverb_crypto::account::{AccountKeys, AccountPublicKeys};
use sverb_crypto::fingerprint::{key_fingerprint, safety_number};
use sverb_crypto::grant::{Grant, open_grant, verify_grant as verify_signature};
use sverb_crypto::sign::SIGNATURE_LEN;
use sverb_proto::sync::{Permission, VaultGrant, VaultKind, VaultView};
use sverb_proto::users::UserPublicKeys;
use sverb_store::{PinObservation, PinState, PinnedKey, SetVerified, Store};
use uuid::Uuid;

use crate::error::SyncError;
use crate::http::ApiClient;
use crate::keys::VaultKeySource;
use crate::tokens::TokenManager;

/// Why a key or a grant is not trusted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrustError {
    /// No pinned key for this user (never seen, or unknown).
    #[error("no pinned key for user {0}")]
    NotPinned(Uuid),
    /// The server presented a different key than the pinned one.
    #[error(
        "the key of user {0} changed: compare safety numbers and accept the new key before trusting it"
    )]
    KeyChanged(Uuid),
    /// The grant's signature does not verify with the granter's pinned key
    /// (a forged or tampered grant).
    #[error("the grant's signature does not verify with the granter's pinned key")]
    BadSignature,
    /// The grant verified but its vault key does not open with our key.
    #[error("the vault key could not be opened")]
    Open,
    /// The granter has no `manage` on the vault per the membership list.
    #[error("user {0} is not allowed to grant access to this vault")]
    GranterLacksManage(Uuid),
    /// A personal vault key that is not a self-grant.
    #[error("a personal vault key must be a self-grant")]
    PersonalNotSelfGrant,
    /// `wrapped_by == member` for another user than us (and not the creator).
    #[error("a self-grant claimed for another user ({0}) is not trusted")]
    SelfGrantForOther(Uuid),
    /// A shared vault without a membership list to check the granter against.
    #[error("no membership list for this shared vault")]
    NoMembership,
    /// No grant for this key version.
    #[error("no grant for key version {0}")]
    NoGrant(u32),
    /// Wrong lengths in server-supplied key material.
    #[error("malformed key material: {0}")]
    Malformed(&'static str),
    /// The server answered with the keys of another user.
    #[error("the server returned the keys of another user")]
    WrongUser,
    /// No user matches the name (or several do).
    #[error("{0}")]
    Lookup(String),
    /// Fetching keys failed.
    #[error(transparent)]
    Sync(#[from] SyncError),
}

impl From<sverb_store::StoreError> for TrustError {
    fn from(e: sverb_store::StoreError) -> Self {
        Self::Sync(SyncError::Store(e.to_string()))
    }
}

// ------------------------------------------------------------------- membership

/// An org role (§13.1). Owners and admins implicitly `manage` every org vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OrgRole {
    /// Org owner.
    Owner,
    /// Org admin.
    Admin,
    /// Plain member.
    Member,
}

/// The server's membership list for one shared vault. **Untrusted**: it can only
/// narrow trust (a granter not listed with `manage` is rejected), never widen it
/// (signatures are still checked against pinned keys).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VaultMembership {
    /// Org role of each org member.
    pub org_roles: HashMap<Uuid, OrgRole>,
    /// Vault permission of each vault member.
    pub permissions: HashMap<Uuid, Permission>,
    /// The user who created the vault (its first self-grant is TOFU-trusted).
    pub creator: Option<Uuid>,
}

impl VaultMembership {
    /// Whether `user` may grant access: `manage` on the vault, or org owner/admin.
    #[must_use]
    pub fn can_manage(&self, user: Uuid) -> bool {
        matches!(self.permissions.get(&user), Some(Permission::Manage))
            || matches!(
                self.org_roles.get(&user),
                Some(OrgRole::Owner | OrgRole::Admin)
            )
    }
}

// ------------------------------------------------------------------------- pins

/// An in-memory snapshot of the pins, for the synchronous checks.
#[derive(Debug, Clone, Default)]
pub struct PinSet {
    pins: HashMap<Uuid, PinnedKey>,
    me: Option<(Uuid, AccountPublicKeys)>,
}

impl PinSet {
    /// A snapshot of `pins`.
    #[must_use]
    pub fn from_pins(pins: Vec<PinnedKey>) -> Self {
        Self {
            pins: pins
                .into_iter()
                .map(|p| (Uuid::from_bytes(p.user_id), p))
                .collect(),
            me: None,
        }
    }

    /// This account's own public keys (derived from the private keys we hold,
    /// so authoritative): used for self-grants instead of the self pin.
    #[must_use]
    pub fn with_self(mut self, me: Uuid, keys: AccountPublicKeys) -> Self {
        self.me = Some((me, keys));
        self
    }

    /// The pin of `user`.
    #[must_use]
    pub fn get(&self, user: Uuid) -> Option<&PinnedKey> {
        self.pins.get(&user)
    }

    /// Adds or replaces a pin in the snapshot.
    pub fn insert(&mut self, pin: PinnedKey) {
        self.pins.insert(Uuid::from_bytes(pin.user_id), pin);
    }

    /// The keys of `user` that may be trusted: this account's own keys, or a pin
    /// with no pending change.
    ///
    /// # Errors
    /// [`TrustError::NotPinned`], [`TrustError::KeyChanged`].
    pub fn trusted(&self, user: Uuid) -> Result<AccountPublicKeys, TrustError> {
        if let Some((me, keys)) = self.me
            && me == user
        {
            return Ok(keys);
        }
        let pin = self.pins.get(&user).ok_or(TrustError::NotPinned(user))?;
        if pin.state() == PinState::KeyChanged {
            return Err(TrustError::KeyChanged(user));
        }
        Ok(AccountPublicKeys {
            x25519: pin.x25519_pub,
            ed25519: pin.ed25519_pub,
        })
    }
}

// ---------------------------------------------------------------------- grants

/// A grant to check: `grant` wraps key `grant.key_version` of `vault_id` for
/// `member`.
#[derive(Debug, Clone, Copy)]
pub struct GrantToVerify<'a> {
    /// The vault.
    pub vault_id: Uuid,
    /// Personal or shared.
    pub vault_kind: VaultKind,
    /// The member the key is wrapped for.
    pub member: Uuid,
    /// The grant as the server returned it.
    pub grant: &'a VaultGrant,
}

/// Verifies a grant before its vault key is used (§11.3, §13.3). `me` is this
/// account; `membership` the server's list for shared vaults.
///
/// # Errors
/// The [`TrustError`] naming the first rule the grant breaks.
pub fn verify_grant(
    pins: &PinSet,
    me: Uuid,
    g: &GrantToVerify<'_>,
    membership: Option<&VaultMembership>,
) -> Result<(), TrustError> {
    let granter = g.grant.wrapped_by;
    let creator = membership.and_then(|m| m.creator);
    match g.vault_kind {
        VaultKind::Personal => {
            if granter != me || g.member != me {
                return Err(TrustError::PersonalNotSelfGrant);
            }
        }
        VaultKind::Shared => {
            if granter == g.member && g.member != me && creator != Some(granter) {
                return Err(TrustError::SelfGrantForOther(granter));
            }
        }
    }
    let keys = pins.trusted(granter)?;
    let signature: [u8; SIGNATURE_LEN] = g
        .grant
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| TrustError::Malformed("grant signature length"))?;
    let grant = Grant {
        wrapped: g.grant.wrapped_vault_key.clone(),
        signature,
    };
    verify_signature(
        &grant,
        g.vault_id.as_bytes(),
        g.member.as_bytes(),
        g.grant.key_version,
        &keys.ed25519,
    )
    .map_err(|_| TrustError::BadSignature)?;
    if g.vault_kind == VaultKind::Shared && granter != me {
        let m = membership.ok_or(TrustError::NoMembership)?;
        if !m.can_manage(granter) && m.creator != Some(granter) {
            return Err(TrustError::GranterLacksManage(granter));
        }
    }
    Ok(())
}

/// Verifies our grant for key `version` in `view` ([`verify_grant`]) and opens it
/// with our X25519 key.
///
/// # Errors
/// [`TrustError::NoGrant`], any [`verify_grant`] error, [`TrustError::Open`].
pub fn open_verified_grant(
    pins: &PinSet,
    me: Uuid,
    my_keys: &AccountKeys,
    view: &VaultView,
    version: u32,
    membership: Option<&VaultMembership>,
) -> Result<Key32, TrustError> {
    let grant = view
        .grants
        .iter()
        .find(|g| g.key_version == version)
        .ok_or(TrustError::NoGrant(version))?;
    verify_grant(
        pins,
        me,
        &GrantToVerify {
            vault_id: view.id,
            vault_kind: view.kind,
            member: me,
            grant,
        },
        membership,
    )?;
    let wrapped = Grant {
        wrapped: grant.wrapped_vault_key.clone(),
        signature: [0; SIGNATURE_LEN],
    };
    open_grant(
        &wrapped,
        view.id.as_bytes(),
        version,
        my_keys.x25519_secret_bytes(),
    )
    .map_err(|_| TrustError::Open)
}

/// The engine's [`VaultKeySource`] (§11.3): opens a new grant only after
/// [`verify_grant`] against the pins and the vault's membership list.
pub struct TrustedKeySource {
    me: Uuid,
    keys: Arc<AccountKeys>,
    pins: RwLock<PinSet>,
    memberships: RwLock<HashMap<Uuid, VaultMembership>>,
}

impl fmt::Debug for TrustedKeySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustedKeySource")
            .field("me", &self.me)
            .finish_non_exhaustive()
    }
}

impl TrustedKeySource {
    /// A source for account `me` holding `keys`, checking against `pins`.
    #[must_use]
    pub fn new(me: Uuid, keys: Arc<AccountKeys>, pins: PinSet) -> Self {
        let pins = pins.with_self(me, keys.public());
        Self {
            me,
            keys,
            pins: RwLock::new(pins),
            memberships: RwLock::new(HashMap::new()),
        }
    }

    /// Replaces the pin snapshot (after pins changed).
    pub fn set_pins(&self, pins: PinSet) {
        *self.pins.write() = pins.with_self(self.me, self.keys.public());
    }

    /// Sets the server's membership list of a shared vault.
    pub fn set_membership(&self, vault: Uuid, membership: VaultMembership) {
        self.memberships.write().insert(vault, membership);
    }

    /// [`open_verified_grant`] with the current snapshot.
    ///
    /// # Errors
    /// See [`open_verified_grant`].
    pub fn open_checked(&self, view: &VaultView, version: u32) -> Result<Key32, TrustError> {
        let memberships = self.memberships.read();
        open_verified_grant(
            &self.pins.read(),
            self.me,
            &self.keys,
            view,
            version,
            memberships.get(&view.id),
        )
    }
}

impl VaultKeySource for TrustedKeySource {
    fn open_grant(&self, view: &VaultView, version: u32) -> Option<Key32> {
        match self.open_checked(view, version) {
            Ok(k) => Some(k),
            Err(e) => {
                tracing::warn!(vault = %view.id, version, error = %e, "vault key grant rejected");
                None
            }
        }
    }

    // M5-02: shared-vault adoption by the engine.
    fn account(&self) -> Option<Uuid> {
        Some(self.me)
    }

    fn update_pins(&self, pins: PinSet) {
        self.set_pins(pins);
    }

    fn observe_vault_members(&self, members: &sverb_proto::vaults::VaultMembersView) {
        self.set_membership(members.vault_id, membership_from_view(members));
    }

    fn check_grant(&self, view: &VaultView, version: u32) -> Result<Key32, String> {
        self.open_checked(view, version).map_err(|e| {
            tracing::warn!(vault = %view.id, version, error = %e, "vault key grant rejected");
            e.to_string()
        })
    }
}

// M5-02
/// The [`VaultMembership`] of a `GET /v1/vaults/{id}/members` answer.
#[must_use]
pub fn membership_from_view(v: &sverb_proto::vaults::VaultMembersView) -> VaultMembership {
    use sverb_proto::orgs::Role;
    VaultMembership {
        org_roles: v
            .members
            .iter()
            .map(|m| {
                let role = match m.org_role {
                    Role::Owner => OrgRole::Owner,
                    Role::Admin => OrgRole::Admin,
                    Role::Member => OrgRole::Member,
                };
                (m.user_id, role)
            })
            .collect(),
        permissions: v
            .members
            .iter()
            .filter_map(|m| m.permission.map(|p| (m.user_id, p)))
            .collect(),
        creator: v.created_by,
    }
}

// ------------------------------------------------------------------- directory

/// Where public keys come from (`GET /v1/users/{id}/public-keys`).
pub trait KeyDirectory: Send + Sync {
    /// The keys the server has for `user`.
    fn public_keys(
        &self,
        user: Uuid,
    ) -> impl Future<Output = Result<UserPublicKeys, SyncError>> + Send;
}

/// [`KeyDirectory`] over the API with a fixed access token.
#[derive(Clone)]
pub struct ApiDirectory {
    /// The client.
    pub api: ApiClient,
    /// An access token.
    pub token: String,
}

// M7-05: the access token never reaches `Debug` output.
impl std::fmt::Debug for ApiDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiDirectory")
            .field("api", &self.api)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

impl KeyDirectory for ApiDirectory {
    async fn public_keys(&self, user: Uuid) -> Result<UserPublicKeys, SyncError> {
        self.api.user_public_keys(&self.token, user).await
    }
}

/// [`KeyDirectory`] over the engine's token manager (refreshes on 401 once).
#[derive(Debug, Clone)]
pub struct TokenDirectory(pub Arc<TokenManager>);

impl KeyDirectory for TokenDirectory {
    async fn public_keys(&self, user: Uuid) -> Result<UserPublicKeys, SyncError> {
        let token = self.0.access().await?;
        match self.0.api().user_public_keys(&token, user).await {
            Err(e) if e.is_status(401) => {
                self.0.refresh_after_401(&token).await?;
                let token = self.0.access().await?;
                self.0.api().user_public_keys(&token, user).await
            }
            r => r,
        }
    }
}

fn key_material(dto: &UserPublicKeys) -> Result<AccountPublicKeys, TrustError> {
    Ok(AccountPublicKeys {
        x25519: dto
            .x25519_pub
            .as_slice()
            .try_into()
            .map_err(|_| TrustError::Malformed("x25519 public key length"))?,
        ed25519: dto
            .ed25519_pub
            .as_slice()
            .try_into()
            .map_err(|_| TrustError::Malformed("ed25519 public key length"))?,
    })
}

// ----------------------------------------------------------------------- trust

/// The store-backed trust operations of account `me` on this device.
#[derive(Debug, Clone)]
pub struct Trust {
    store: Store,
    me: Uuid,
}

impl Trust {
    /// Trust decisions of account `me`, stored in `store`.
    #[must_use]
    pub const fn new(store: Store, me: Uuid) -> Self {
        Self { store, me }
    }

    /// This account.
    #[must_use]
    pub const fn me(&self) -> Uuid {
        self.me
    }

    /// Pins this account's own keys (at login/registration, M4-08). Safety
    /// numbers need them.
    ///
    /// # Errors
    /// [`TrustError::Sync`] (store).
    pub async fn pin_self(
        &self,
        keys: &AccountPublicKeys,
        label: Option<String>,
    ) -> Result<PinObservation, TrustError> {
        Ok(self
            .store
            .observe_pin(*self.me.as_bytes(), label, keys.x25519, keys.ed25519, true)
            .await?)
    }

    /// Records that `keys` were presented for `user` (pin on first sight; a
    /// different key is parked as a change, see [`sverb_store::pins`]).
    ///
    /// # Errors
    /// [`TrustError::Sync`] (store).
    pub async fn observe(
        &self,
        user: Uuid,
        label: Option<String>,
        keys: &AccountPublicKeys,
    ) -> Result<PinObservation, TrustError> {
        let obs = self
            .store
            .observe_pin(
                *user.as_bytes(),
                label,
                keys.x25519,
                keys.ed25519,
                user == self.me,
            )
            .await?;
        if let PinObservation::Changed { pinned, seen } = obs {
            tracing::warn!(
                %user,
                pinned = %hex(&pinned[..8]),
                seen = %hex(&seen[..8]),
                "public key CHANGED for a pinned user; grants to and from this user are blocked"
            );
        }
        Ok(obs)
    }

    /// Fetches the keys of `user` from `dir` and observes them.
    ///
    /// # Errors
    /// [`TrustError::Sync`], [`TrustError::Malformed`], [`TrustError::WrongUser`].
    pub async fn fetch<D: KeyDirectory>(
        &self,
        dir: &D,
        user: Uuid,
    ) -> Result<(AccountPublicKeys, PinObservation), TrustError> {
        let dto = dir.public_keys(user).await?;
        if dto.user_id != user {
            return Err(TrustError::WrongUser);
        }
        let keys = key_material(&dto)?;
        let obs = self.observe(user, dto.email, &keys).await?;
        Ok((keys, obs))
    }

    /// The keys to wrap a vault key for `user` (§13.2 "grant"): fetched, pinned
    /// on first sight, and refused while a key change is pending. Returns the
    /// **pinned** keys.
    ///
    /// # Errors
    /// [`TrustError::KeyChanged`], or a fetch error.
    pub async fn keys_for_grant<D: KeyDirectory>(
        &self,
        dir: &D,
        user: Uuid,
    ) -> Result<AccountPublicKeys, TrustError> {
        self.fetch(dir, user).await?;
        self.pins().await?.trusted(user)
    }

    /// Pins the granters of `views` not seen yet (first sight), so that
    /// [`verify_grant`] can check them. Granters already pinned are not fetched.
    ///
    /// # Errors
    /// A fetch or store error.
    pub async fn pin_granters<D: KeyDirectory>(
        &self,
        dir: &D,
        views: &[VaultView],
    ) -> Result<(), TrustError> {
        let pins = self.pins().await?;
        let mut seen = std::collections::HashSet::new();
        for g in views.iter().flat_map(|v| &v.grants) {
            let u = g.wrapped_by;
            if u != self.me && pins.get(u).is_none() && seen.insert(u) {
                self.fetch(dir, u).await?;
            }
        }
        Ok(())
    }

    /// A snapshot of every pin.
    ///
    /// # Errors
    /// [`TrustError::Sync`] (store).
    pub async fn pins(&self) -> Result<PinSet, TrustError> {
        Ok(PinSet::from_pins(self.store.list_pins().await?))
    }

    /// Every pin (this account first).
    ///
    /// # Errors
    /// [`TrustError::Sync`] (store).
    pub async fn members(&self) -> Result<Vec<PinnedKey>, TrustError> {
        Ok(self.store.list_pins().await?)
    }

    /// The pinned user named `query`: a user id, an exact label (email,
    /// case-insensitive) or a unique email local part (`bob` for
    /// `bob@example.com`).
    ///
    /// # Errors
    /// [`TrustError::Lookup`] when nothing or several match.
    pub async fn find(&self, query: &str) -> Result<PinnedKey, TrustError> {
        find_pin(&self.members().await?, query)
    }

    /// This account's own pin.
    ///
    /// # Errors
    /// [`TrustError::NotPinned`] before [`Trust::pin_self`].
    pub async fn own_pin(&self) -> Result<PinnedKey, TrustError> {
        self.store
            .get_pin(*self.me.as_bytes())
            .await?
            .ok_or(TrustError::NotPinned(self.me))
    }

    /// The safety number between this account and `user` (60 digits in 12
    /// groups, symmetric). While a key change is pending it is computed from
    /// the **new** key, which is what the user must compare before accepting it.
    ///
    /// # Errors
    /// [`TrustError::NotPinned`] for us or them.
    pub async fn safety_number(&self, user: Uuid) -> Result<String, TrustError> {
        let mine = self.own_pin().await?;
        let theirs = self
            .store
            .get_pin(*user.as_bytes())
            .await?
            .ok_or(TrustError::NotPinned(user))?;
        Ok(pin_safety_number(&mine, &theirs))
    }

    /// Marks `user` verified (✓) after comparing safety numbers.
    ///
    /// # Errors
    /// [`TrustError::NotPinned`], [`TrustError::KeyChanged`] (accept the new key
    /// instead).
    pub async fn mark_verified(&self, user: Uuid) -> Result<(), TrustError> {
        match self.store.set_pin_verified(*user.as_bytes(), true).await? {
            SetVerified::Set => Ok(()),
            SetVerified::NoPin => Err(TrustError::NotPinned(user)),
            SetVerified::KeyChangePending => Err(TrustError::KeyChanged(user)),
        }
    }

    /// "Accept new key": the pending changed key becomes the pin (`verified`
    /// when the user confirmed the new safety number). Returns whether a change
    /// was pending.
    ///
    /// # Errors
    /// [`TrustError::Sync`] (store).
    pub async fn accept_new_key(&self, user: Uuid, verified: bool) -> Result<bool, TrustError> {
        Ok(self
            .store
            .accept_new_key(*user.as_bytes(), verified)
            .await?)
    }
}

/// The safety number of two pins (see [`Trust::safety_number`]).
#[must_use]
pub fn pin_safety_number(mine: &PinnedKey, theirs: &PinnedKey) -> String {
    mine.safety_number_with(theirs)
}

/// The safety number of two key sets.
#[must_use]
pub fn keys_safety_number(a: &AccountPublicKeys, b: &AccountPublicKeys) -> String {
    safety_number(
        &key_fingerprint(&a.x25519, &a.ed25519),
        &key_fingerprint(&b.x25519, &b.ed25519),
    )
}

/// See [`Trust::find`] ([`sverb_store::pins::find_pin`]).
///
/// # Errors
/// [`TrustError::Lookup`].
pub fn find_pin(pins: &[PinnedKey], query: &str) -> Result<PinnedKey, TrustError> {
    sverb_store::pins::find_pin(pins, query)
        .cloned()
        .map_err(TrustError::Lookup)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use sverb_crypto::account::generate_account_keys;
    use sverb_crypto::grant::{grant_vault_key, self_grant};
    use sverb_crypto::random::{os_rng, random_key32};

    use super::*;

    struct User {
        id: Uuid,
        keys: AccountKeys,
    }

    fn user() -> User {
        User {
            id: Uuid::now_v7(),
            keys: generate_account_keys(&mut os_rng()),
        }
    }

    fn pin_of(u: &User) -> PinnedKey {
        let p = u.keys.public();
        PinnedKey {
            user_id: *u.id.as_bytes(),
            label: None,
            fingerprint: p.fingerprint(),
            x25519_pub: p.x25519,
            ed25519_pub: p.ed25519,
            first_seen_at: 0,
            verified: false,
            verified_at: None,
            is_self: false,
            changed: None,
        }
    }

    /// `granter` grants key v1 of `vault` to `member`.
    fn grant(granter: &User, member: &User, vault: Uuid, vk: &Key32) -> VaultGrant {
        let g = grant_vault_key(
            vk,
            vault.as_bytes(),
            1,
            member.id.as_bytes(),
            &member.keys.public().x25519,
            granter.keys.ed25519_signing_key(),
            &mut os_rng(),
        )
        .unwrap();
        VaultGrant {
            key_version: 1,
            wrapped_vault_key: g.wrapped,
            wrapped_by: granter.id,
            signature: g.signature.to_vec(),
        }
    }

    fn view(vault: Uuid, kind: VaultKind, grants: Vec<VaultGrant>) -> VaultView {
        VaultView {
            id: vault,
            kind,
            org_id: None,
            name_enc: Vec::new(),
            key_version: 1,
            head_revision: 0,
            permission: Permission::Write,
            grants,
            rotation: None,
        }
    }

    fn membership(manager: Uuid, plain: Uuid) -> VaultMembership {
        VaultMembership {
            org_roles: HashMap::from([(manager, OrgRole::Member), (plain, OrgRole::Member)]),
            permissions: HashMap::from([(manager, Permission::Manage), (plain, Permission::Write)]),
            creator: None,
        }
    }

    // T-03: the safety number Alice sees for Bob equals the one Bob sees for Alice.
    #[test]
    fn t03_safety_number_symmetric() {
        let (alice, bob) = (user(), user());
        let mut a_self = pin_of(&alice);
        a_self.is_self = true;
        let mut b_self = pin_of(&bob);
        b_self.is_self = true;
        let on_alice = pin_safety_number(&a_self, &pin_of(&bob));
        let on_bob = pin_safety_number(&b_self, &pin_of(&alice));
        assert_eq!(on_alice, on_bob);
        let groups: Vec<&str> = on_alice.split(' ').collect();
        assert_eq!(groups.len(), 12);
        assert!(
            groups
                .iter()
                .all(|g| g.len() == 5 && g.bytes().all(|b| b.is_ascii_digit()))
        );
        assert_eq!(
            keys_safety_number(&alice.keys.public(), &bob.keys.public()),
            on_alice
        );
        // A different key for Bob changes it.
        let carol = user();
        assert_ne!(pin_safety_number(&a_self, &pin_of(&carol)), on_alice);
    }

    // T-05: grant verification.
    #[test]
    fn t05_grant_verification() {
        let (me, bob, mallory) = (user(), user(), user());
        let vault = Uuid::now_v7();
        let vk = random_key32(&mut os_rng());
        let mut pins = PinSet::from_pins(vec![pin_of(&bob)]).with_self(me.id, me.keys.public());
        let members = membership(bob.id, mallory.id);
        let check = |pins: &PinSet, g: &VaultGrant, m: Option<&VaultMembership>| {
            verify_grant(
                pins,
                me.id,
                &GrantToVerify {
                    vault_id: vault,
                    vault_kind: VaultKind::Shared,
                    member: me.id,
                    grant: g,
                },
                m,
            )
        };

        // Valid: Bob (pinned, manage) → ok, and the key opens.
        let good = grant(&bob, &me, vault, &vk);
        check(&pins, &good, Some(&members)).unwrap();
        let v = view(vault, VaultKind::Shared, vec![good.clone()]);
        let k = open_verified_grant(&pins, me.id, &me.keys, &v, 1, Some(&members)).unwrap();
        assert_eq!(k.expose_secret(), vk.expose_secret());

        // Wrong signer: Mallory (unpinned) → reject.
        let by_mallory = grant(&mallory, &me, vault, &vk);
        assert_eq!(
            check(&pins, &by_mallory, Some(&members)),
            Err(TrustError::NotPinned(mallory.id))
        );
        // The server claims Bob signed Mallory's grant → bad signature.
        let mut forged = by_mallory.clone();
        forged.wrapped_by = bob.id;
        assert_eq!(
            check(&pins, &forged, Some(&members)),
            Err(TrustError::BadSignature)
        );
        // Unknown user id → reject.
        let mut unknown = good.clone();
        unknown.wrapped_by = Uuid::now_v7();
        assert!(matches!(
            check(&pins, &unknown, Some(&members)),
            Err(TrustError::NotPinned(_))
        ));

        // A signer without manage per the membership list → reject.
        pins.insert(pin_of(&mallory));
        assert_eq!(
            check(&pins, &by_mallory, Some(&members)),
            Err(TrustError::GranterLacksManage(mallory.id))
        );
        // ... unless an org admin.
        let mut admin = members.clone();
        admin.org_roles.insert(mallory.id, OrgRole::Admin);
        check(&pins, &by_mallory, Some(&admin)).unwrap();
        // No membership list for a shared vault → reject.
        assert_eq!(check(&pins, &good, None), Err(TrustError::NoMembership));

        // A tampered wrapped key → reject.
        let mut tampered = good.clone();
        let last = tampered.wrapped_vault_key.len() - 1;
        tampered.wrapped_vault_key[last] ^= 1;
        assert_eq!(
            check(&pins, &tampered, Some(&members)),
            Err(TrustError::BadSignature)
        );
        // A tampered key version → reject.
        let mut bumped = good.clone();
        bumped.key_version = 2;
        assert_eq!(
            check(&pins, &bumped, Some(&members)),
            Err(TrustError::BadSignature)
        );
        // A truncated signature → reject.
        let mut short = good.clone();
        short.signature.pop();
        assert!(matches!(
            check(&pins, &short, Some(&members)),
            Err(TrustError::Malformed(_))
        ));

        // Bob's key changed → his grants are not trusted.
        let mut changed = pin_of(&bob);
        changed.changed = Some(sverb_store::KeyChange {
            fingerprint: [1; 32],
            x25519_pub: [1; 32],
            ed25519_pub: [1; 32],
            seen_at: 1,
        });
        let mut pins2 = pins.clone();
        pins2.insert(changed);
        assert_eq!(
            check(&pins2, &good, Some(&members)),
            Err(TrustError::KeyChanged(bob.id))
        );
    }

    #[test]
    fn self_grant_rules() {
        let (me, bob) = (user(), user());
        let vault = Uuid::now_v7();
        let vk = random_key32(&mut os_rng());
        let pins = PinSet::from_pins(vec![pin_of(&bob)]).with_self(me.id, me.keys.public());

        // Personal vault: my own self-grant opens.
        let g = self_grant(
            &vk,
            vault.as_bytes(),
            1,
            me.id.as_bytes(),
            &me.keys,
            &mut os_rng(),
        )
        .unwrap();
        let mine = VaultGrant {
            key_version: 1,
            wrapped_vault_key: g.wrapped,
            wrapped_by: me.id,
            signature: g.signature.to_vec(),
        };
        let v = view(vault, VaultKind::Personal, vec![mine]);
        open_verified_grant(&pins, me.id, &me.keys, &v, 1, None).unwrap();
        assert_eq!(
            open_verified_grant(&pins, me.id, &me.keys, &v, 2, None).unwrap_err(),
            TrustError::NoGrant(2)
        );

        // Personal vault granted by someone else → reject.
        let by_bob = grant(&bob, &me, vault, &vk);
        let v = view(vault, VaultKind::Personal, vec![by_bob]);
        assert_eq!(
            open_verified_grant(&pins, me.id, &me.keys, &v, 1, None).unwrap_err(),
            TrustError::PersonalNotSelfGrant
        );

        // A self-grant claimed for another user (Bob → Bob) → reject, unless
        // Bob created the vault.
        let bob_self = grant(&bob, &bob, vault, &vk);
        let target = GrantToVerify {
            vault_id: vault,
            vault_kind: VaultKind::Shared,
            member: bob.id,
            grant: &bob_self,
        };
        let mut m = membership(Uuid::now_v7(), bob.id);
        assert_eq!(
            verify_grant(&pins, me.id, &target, Some(&m)),
            Err(TrustError::SelfGrantForOther(bob.id))
        );
        m.creator = Some(bob.id);
        verify_grant(&pins, me.id, &target, Some(&m)).unwrap();
    }

    #[test]
    fn trusted_key_source_rejects_unpinned() {
        let (me, bob) = (user(), user());
        let vault = Uuid::now_v7();
        let vk = random_key32(&mut os_rng());
        let keys = Arc::new(me.keys.clone());
        let src = TrustedKeySource::new(me.id, keys, PinSet::default());
        let v = view(vault, VaultKind::Shared, vec![grant(&bob, &me, vault, &vk)]);
        src.set_membership(vault, membership(bob.id, me.id));
        assert!(src.open_grant(&v, 1).is_none());
        src.set_pins(PinSet::from_pins(vec![pin_of(&bob)]));
        assert!(src.open_grant(&v, 1).is_some());
    }

    #[test]
    fn find_by_id_label_local_part() {
        let mk = |b: u8, l: &str| PinnedKey {
            label: Some(l.into()),
            user_id: [b; 16],
            ..pin_of(&user())
        };
        let pins = vec![
            mk(1, "bob@example.com"),
            mk(2, "bobby@example.com"),
            mk(3, "bob@other.test"),
        ];
        assert_eq!(
            find_pin(&pins, "BOBBY@example.com").unwrap().user_id,
            [2; 16]
        );
        assert_eq!(find_pin(&pins, "bobby").unwrap().user_id, [2; 16]);
        assert!(matches!(find_pin(&pins, "bob"), Err(TrustError::Lookup(_))));
        assert!(matches!(find_pin(&pins, "zed"), Err(TrustError::Lookup(_))));
        let id = Uuid::from_bytes([3; 16]).to_string();
        assert_eq!(find_pin(&pins, &id).unwrap().user_id, [3; 16]);
    }
}
