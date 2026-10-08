//! In-memory backend of [`super::AuthStore`].
//!
//! A faithful model of the PostgreSQL backend for tests that run without a
//! database: same tables (as maps), same checks, same outcomes. Each
//! operation validates first and mutates last under one lock, so it is
//! atomic like the SQL transactions. The registration policy mirrors
//! [`crate::registration::authorize`] (mode, setup token, invites); the
//! Postgres tests exercise the real one.
//!
//! [`MemData::fail_vault_insert`] injects a failure at the personal-vault
//! step of registration (task M4-02 T-03).

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::{
    AccessCtx, AccountKeysRow, DeviceChoice, DeviceRow, LoginStateRow, LoginUser, NewAccount,
    NewCredentials, NewDevice, RECOVERY_CODE_MAX_ATTEMPTS, RecoveryInfo, RefreshOutcome, TotpState,
};
use crate::auth::tokens::{IssuedTokens, LAST_SEEN_THROTTLE, TokenHash, TokenKind};
use crate::error::ApiError;
use crate::registration::{
    RegistrationCredential, RegistrationGrant, RegistrationMode, hash_token,
};

type Res<T> = Result<T, ApiError>;

/// A `users` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemUser {
    /// Email as registered.
    pub email: String,
    /// Created.
    pub created_at: DateTime<Utc>,
    /// Instance admin.
    pub is_instance_admin: bool,
    /// OPAQUE record.
    pub opaque_record: Vec<u8>,
    /// Sealed TOTP secret.
    pub totp_secret_enc: Option<Vec<u8>>,
    /// Sealed pending TOTP secret.
    pub totp_pending_enc: Option<Vec<u8>>,
    /// Last accepted TOTP step.
    pub totp_last_step: Option<i64>,
    /// Disabled.
    pub disabled: bool,
}

/// A `devices` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemDevice {
    /// Owner.
    pub user_id: Uuid,
    /// Name.
    pub name: String,
    /// Platform.
    pub platform: String,
    /// Created.
    pub created_at: DateTime<Utc>,
    /// Last seen.
    pub last_seen_at: Option<DateTime<Utc>>,
    /// Revoked.
    pub revoked_at: Option<DateTime<Utc>>,
}

/// An `auth_tokens` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemToken {
    /// Device.
    pub device_id: Uuid,
    /// Kind.
    pub kind: TokenKind,
    /// Expiry.
    pub expires_at: DateTime<Utc>,
    /// Rotation family.
    pub family: Uuid,
    /// Set when rotated.
    pub used_at: Option<DateTime<Utc>>,
}

/// A `vaults` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemVault {
    /// `personal` or `shared`.
    pub personal: bool,
    /// Owner of a personal vault.
    pub owner_user_id: Option<Uuid>,
    /// Encrypted name.
    pub name_enc: Vec<u8>,
    /// Key version.
    pub key_version: i32,
    // M4-04: the sync columns.
    /// Owning org (shared vaults).
    pub org_id: Option<Uuid>,
    /// Highest assigned revision.
    pub head_revision: i64,
    /// Tombstones at or below this revision were purged.
    pub gc_floor_revision: i64,
    /// Non-`None` while a key rotation is in progress (§13.2).
    pub rotation: Option<serde_json::Value>,
}

// M4-04
impl MemVault {
    /// A fresh personal vault (head 0, no rotation).
    #[must_use]
    pub const fn personal(owner: Uuid, name_enc: Vec<u8>, key_version: i32) -> Self {
        Self {
            personal: true,
            owner_user_id: Some(owner),
            name_enc,
            key_version,
            org_id: None,
            head_revision: 0,
            gc_floor_revision: 0,
            rotation: None,
        }
    }

    /// A fresh shared vault (head 0, no rotation).
    #[must_use]
    pub const fn shared(org_id: Option<Uuid>, name_enc: Vec<u8>, key_version: i32) -> Self {
        Self {
            personal: false,
            owner_user_id: None,
            name_enc,
            key_version,
            org_id,
            head_revision: 0,
            gc_floor_revision: 0,
            rotation: None,
        }
    }
}

/// M4-04: an `items` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemItem {
    /// Revision of this version.
    pub revision: i64,
    /// Key version of the envelope.
    pub key_version: i32,
    /// Sealed item.
    pub envelope: Vec<u8>,
    /// Tombstone.
    pub deleted: bool,
    /// Last write.
    pub updated_at: DateTime<Utc>,
    /// Writing device.
    pub updated_by_device: Option<Uuid>,
}

/// A `vault_members` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemMember {
    /// Vault.
    pub vault_id: Uuid,
    /// Member.
    pub user_id: Uuid,
    /// Permission.
    pub permission: String,
    /// Key version.
    pub key_version: i32,
    /// Wrapped key.
    pub wrapped_vault_key: Vec<u8>,
    /// Granter.
    pub wrapped_by: Uuid,
    /// Signature.
    pub signature: Vec<u8>,
}

/// An `invites` row (instance or org invite).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemInvite {
    /// Token hash.
    pub token_hash: [u8; 32],
    /// Bound email.
    pub email: Option<String>,
    /// Org invite (accepted later by M5-01) rather than an instance invite.
    pub org: bool,
    /// Accepted.
    pub accepted: bool,
}

/// A `recovery_codes` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemRecoveryCode {
    /// Hash.
    pub code_hash: TokenHash,
    /// Expiry.
    pub expires_at: DateTime<Utc>,
    /// Failed attempts.
    pub attempts: i32,
}

/// An `audit_events` row.
#[derive(Debug, Clone, PartialEq)]
pub struct MemAudit {
    /// Actor.
    pub actor: Option<Uuid>,
    /// Kind.
    pub kind: String,
    /// Target.
    pub target: Option<Uuid>,
    /// Metadata.
    pub meta: serde_json::Value,
}

/// All tables.
#[derive(Debug)]
pub struct MemData {
    /// `users`.
    pub users: BTreeMap<Uuid, MemUser>,
    /// `account_keys`.
    pub account_keys: BTreeMap<Uuid, AccountKeysRow>,
    /// `devices`.
    pub devices: BTreeMap<Uuid, MemDevice>,
    /// `auth_tokens` by hash.
    pub tokens: BTreeMap<TokenHash, MemToken>,
    /// `vaults`.
    pub vaults: BTreeMap<Uuid, MemVault>,
    /// `vault_members`.
    pub vault_members: Vec<MemMember>,
    /// `items` by `(vault_id, item_id)` (M4-04: full rows).
    pub items: BTreeMap<(Uuid, Uuid), MemItem>,
    /// `login_states`.
    pub login_states: BTreeMap<Uuid, LoginStateRow>,
    /// `reauth_tokens`: hash → (user, expiry).
    pub reauth: BTreeMap<TokenHash, (Uuid, DateTime<Utc>)>,
    /// `recovery_codes`.
    pub recovery_codes: BTreeMap<Uuid, MemRecoveryCode>,
    /// `server_secrets` (sealed values).
    pub secrets: BTreeMap<String, Vec<u8>>,
    /// `audit_events`.
    pub audit: Vec<MemAudit>,
    /// `settings.registration_mode`.
    pub registration_mode: RegistrationMode,
    /// `settings.setup_token_hash`.
    pub setup_token_hash: Option<[u8; 32]>,
    /// `invites`.
    pub invites: Vec<MemInvite>,
    /// Failure injection: the personal-vault insert of the next
    /// registrations fails.
    pub fail_vault_insert: bool,
}

impl Default for MemData {
    fn default() -> Self {
        Self {
            users: BTreeMap::new(),
            account_keys: BTreeMap::new(),
            devices: BTreeMap::new(),
            tokens: BTreeMap::new(),
            vaults: BTreeMap::new(),
            vault_members: Vec::new(),
            items: BTreeMap::new(),
            login_states: BTreeMap::new(),
            reauth: BTreeMap::new(),
            recovery_codes: BTreeMap::new(),
            secrets: BTreeMap::new(),
            audit: Vec::new(),
            registration_mode: RegistrationMode::InviteOnly,
            setup_token_hash: None,
            invites: Vec::new(),
            fail_vault_insert: false,
        }
    }
}

impl MemData {
    /// Sets the setup token (what bootstrap does on first start).
    pub fn set_setup_token(&mut self, token: &str) {
        self.setup_token_hash = Some(hash_token(token));
    }

    /// Adds an email-bound instance invite.
    pub fn add_invite(&mut self, token: &str, email: Option<&str>) {
        self.invites.push(MemInvite {
            token_hash: hash_token(token),
            email: email.map(str::to_lowercase),
            org: false,
            accepted: false,
        });
    }

    fn user_id_by_email(&self, email: &str) -> Option<Uuid> {
        let key = email.trim().to_lowercase();
        self.users
            .iter()
            .find(|(_, u)| u.email.to_lowercase() == key)
            .map(|(id, _)| *id)
    }

    fn login_user(&self, id: Uuid) -> Option<LoginUser> {
        self.users.get(&id).map(|u| LoginUser {
            id,
            email: u.email.clone(),
            opaque_record: u.opaque_record.clone(),
            disabled: u.disabled,
            is_instance_admin: u.is_instance_admin,
            totp_secret_enc: u.totp_secret_enc.clone(),
        })
    }

    /// The policy of [`crate::registration::authorize`]; returns the grant
    /// and the invite index to mark accepted.
    fn authorize(
        &self,
        email: &str,
        cred: RegistrationCredential<'_>,
    ) -> Res<(RegistrationGrant, Option<usize>, bool)> {
        if self.registration_mode == RegistrationMode::Closed {
            return Err(ApiError::Forbidden(
                "registration is closed on this server".into(),
            ));
        }
        match cred {
            RegistrationCredential::SetupToken(t) => {
                if self.setup_token_hash != Some(hash_token(t)) {
                    return Err(ApiError::Forbidden(
                        "invalid or already used setup token".into(),
                    ));
                }
                Ok((
                    RegistrationGrant {
                        is_instance_admin: true,
                        ..RegistrationGrant::default()
                    },
                    None,
                    true,
                ))
            }
            RegistrationCredential::InviteToken(t) => {
                let hash = hash_token(t);
                let email = email.to_lowercase();
                let found = self.invites.iter().position(|i| {
                    i.token_hash == hash
                        && !i.accepted
                        && i.email.as_deref().is_none_or(|e| e == email)
                });
                match found {
                    Some(i) if !self.invites[i].org => {
                        Ok((RegistrationGrant::default(), Some(i), false))
                    }
                    Some(_) => Ok((RegistrationGrant::default(), None, false)),
                    None => Err(ApiError::Forbidden(
                        "invalid, expired or already used invite".into(),
                    )),
                }
            }
            RegistrationCredential::None => match self.registration_mode {
                RegistrationMode::Open => Ok((RegistrationGrant::default(), None, false)),
                _ => Err(ApiError::Forbidden(
                    "registration on this server requires an invite".into(),
                )),
            },
        }
    }

    fn insert_device(&mut self, user_id: Uuid, d: &NewDevice, now: DateTime<Utc>) {
        self.devices.insert(
            d.id,
            MemDevice {
                user_id,
                name: d.name.clone(),
                platform: d.platform.clone(),
                created_at: now,
                last_seen_at: Some(now),
                revoked_at: None,
            },
        );
    }

    fn insert_tokens(&mut self, device_id: Uuid, tokens: &IssuedTokens, family: Uuid) {
        for rec in tokens.records() {
            self.tokens.insert(
                rec.hash,
                MemToken {
                    device_id,
                    kind: rec.kind,
                    expires_at: rec.expires_at,
                    family,
                    used_at: None,
                },
            );
        }
    }

    fn delete_device_tokens(&mut self, pred: impl Fn(Uuid) -> bool) {
        self.tokens.retain(|_, t| !pred(t.device_id));
    }

    fn user_devices(&self, user_id: Uuid) -> Vec<Uuid> {
        self.devices
            .iter()
            .filter(|(_, d)| d.user_id == user_id)
            .map(|(id, _)| *id)
            .collect()
    }

    fn check_reauth(&self, user_id: Uuid, hash: &TokenHash, now: DateTime<Utc>) -> Res<()> {
        match self.reauth.get(hash) {
            Some((u, exp)) if *u == user_id && *exp > now => Ok(()),
            _ => Err(ApiError::AuthRequired(
                "a fresh login is required (reauth token missing, used or expired)".into(),
            )),
        }
    }

    fn check_version(&self, user_id: Uuid, new: &NewCredentials) -> Res<()> {
        let current = self
            .account_keys
            .get(&user_id)
            .map(|k| k.version)
            .ok_or_else(|| ApiError::NotFound("account not found".into()))?;
        if current.checked_add(1) != Some(new.version) {
            return Err(ApiError::Conflict(format!(
                "account key version must be {} (current version + 1)",
                current.saturating_add(1)
            )));
        }
        Ok(())
    }

    fn replace_credentials(&mut self, user_id: Uuid, new: &NewCredentials) {
        if let Some(u) = self.users.get_mut(&user_id) {
            u.opaque_record.clone_from(&new.opaque_record);
        }
        if let Some(k) = self.account_keys.get_mut(&user_id) {
            k.private_bundle_enc.clone_from(&new.private_bundle_enc);
            k.version = new.version;
        }
    }

    fn push_audit(
        &mut self,
        actor: Option<Uuid>,
        kind: &str,
        target: Option<Uuid>,
        meta: serde_json::Value,
    ) {
        self.audit.push(MemAudit {
            actor,
            kind: kind.to_owned(),
            target,
            meta,
        });
    }
}

/// The in-memory store.
#[derive(Debug, Default)]
pub struct MemStore(Mutex<MemData>);

impl MemStore {
    /// An empty store (registration mode `invite-only`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, MemData> {
        // A panic while holding the lock can only come from a failing test.
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Runs `f` on the tables (test setup and inspection).
    pub fn with_data<R>(&self, f: impl FnOnce(&mut MemData) -> R) -> R {
        f(&mut self.lock())
    }

    pub(super) fn check_registration(
        &self,
        email: &str,
        cred: RegistrationCredential<'_>,
    ) -> Res<()> {
        self.lock().authorize(email, cred).map(|_| ())
    }

    pub(super) fn register(
        &self,
        a: &NewAccount,
        cred: RegistrationCredential<'_>,
        tokens: &IssuedTokens,
        family: Uuid,
        now: DateTime<Utc>,
    ) -> Res<RegistrationGrant> {
        let mut d = self.lock();
        let (grant, invite, setup_used) = d.authorize(&a.email, cred)?;
        if d.users.contains_key(&a.user_id) || d.user_id_by_email(&a.email).is_some() {
            return Err(ApiError::Conflict(
                "an account with this email or id already exists".into(),
            ));
        }
        if d.fail_vault_insert {
            return Err(ApiError::internal(std::io::Error::other(
                "injected failure: personal vault insert",
            )));
        }
        if d.vaults.contains_key(&a.vault_id) {
            return Err(ApiError::Conflict(
                "a vault with this id already exists".into(),
            ));
        }
        // Every check passed: apply all changes.
        if setup_used {
            d.setup_token_hash = None;
        }
        if let Some(i) = invite {
            d.invites[i].accepted = true;
        }
        d.users.insert(
            a.user_id,
            MemUser {
                email: a.email.clone(),
                created_at: now,
                is_instance_admin: grant.is_instance_admin,
                opaque_record: a.opaque_record.clone(),
                totp_secret_enc: None,
                totp_pending_enc: None,
                totp_last_step: None,
                disabled: false,
            },
        );
        d.account_keys.insert(a.user_id, a.keys.clone());
        d.vaults.insert(
            a.vault_id,
            MemVault::personal(a.user_id, a.vault_name_enc.clone(), a.grant_key_version),
        );
        d.vault_members.push(MemMember {
            vault_id: a.vault_id,
            user_id: a.user_id,
            permission: "manage".into(),
            key_version: a.grant_key_version,
            wrapped_vault_key: a.grant_wrapped.clone(),
            wrapped_by: a.user_id,
            signature: a.grant_signature.clone(),
        });
        d.insert_device(a.user_id, &a.device, now);
        d.insert_tokens(a.device.id, tokens, family);
        Ok(grant)
    }

    pub(super) fn user_by_email(&self, email: &str) -> Res<Option<LoginUser>> {
        let d = self.lock();
        Ok(d.user_id_by_email(email).and_then(|id| d.login_user(id)))
    }

    pub(super) fn user_by_id(&self, id: Uuid) -> Res<Option<LoginUser>> {
        Ok(self.lock().login_user(id))
    }

    pub(super) fn put_login_state(&self, row: &LoginStateRow, now: DateTime<Utc>) -> Res<()> {
        let mut d = self.lock();
        d.login_states.retain(|_, s| s.expires_at > now);
        d.login_states.insert(row.id, row.clone());
        Ok(())
    }

    pub(super) fn take_login_state(
        &self,
        id: Uuid,
        now: DateTime<Utc>,
    ) -> Res<Option<LoginStateRow>> {
        Ok(self
            .lock()
            .login_states
            .remove(&id)
            .filter(|s| s.expires_at > now))
    }

    pub(super) fn start_session(
        &self,
        user_id: Uuid,
        device: &DeviceChoice,
        tokens: &IssuedTokens,
        family: Uuid,
        now: DateTime<Utc>,
    ) -> Res<Uuid> {
        let mut d = self.lock();
        let device_id = match device {
            DeviceChoice::Existing(id, fallback) => {
                let resumable = d
                    .devices
                    .get(id)
                    .is_some_and(|dev| dev.user_id == user_id && dev.revoked_at.is_none());
                if resumable {
                    let id = *id;
                    if let Some(dev) = d.devices.get_mut(&id) {
                        dev.last_seen_at = Some(now);
                    }
                    d.delete_device_tokens(|dev| dev == id);
                    id
                } else {
                    d.insert_device(user_id, fallback, now);
                    fallback.id
                }
            }
            DeviceChoice::New(nd) => {
                d.insert_device(user_id, nd, now);
                nd.id
            }
        };
        d.insert_tokens(device_id, tokens, family);
        Ok(device_id)
    }

    pub(super) fn account_keys(&self, user_id: Uuid) -> Res<Option<AccountKeysRow>> {
        Ok(self.lock().account_keys.get(&user_id).cloned())
    }

    pub(super) fn lookup_access(
        &self,
        hash: &TokenHash,
        now: DateTime<Utc>,
    ) -> Res<Option<AccessCtx>> {
        let mut d = self.lock();
        let Some(t) = d.tokens.get(hash) else {
            return Ok(None);
        };
        if t.kind != TokenKind::Access || t.expires_at <= now {
            return Ok(None);
        }
        let device_id = t.device_id;
        let Some(dev) = d.devices.get(&device_id) else {
            return Ok(None);
        };
        let user_id = dev.user_id;
        if dev.revoked_at.is_some() || d.users.get(&user_id).is_none_or(|u| u.disabled) {
            return Ok(None);
        }
        if let Some(dev) = d.devices.get_mut(&device_id)
            && dev
                .last_seen_at
                .is_none_or(|t| t + LAST_SEEN_THROTTLE <= now)
        {
            dev.last_seen_at = Some(now);
        }
        Ok(Some(AccessCtx { user_id, device_id }))
    }

    // M4-05
    pub(super) fn access_expires_at(
        &self,
        hash: &TokenHash,
        now: DateTime<Utc>,
    ) -> Res<Option<DateTime<Utc>>> {
        let d = self.lock();
        let Some(t) = d.tokens.get(hash) else {
            return Ok(None);
        };
        if t.kind != TokenKind::Access || t.expires_at <= now {
            return Ok(None);
        }
        let Some(dev) = d.devices.get(&t.device_id) else {
            return Ok(None);
        };
        if dev.revoked_at.is_some() || d.users.get(&dev.user_id).is_none_or(|u| u.disabled) {
            return Ok(None);
        }
        Ok(Some(t.expires_at))
    }

    pub(super) fn refresh(
        &self,
        hash: &TokenHash,
        new: &IssuedTokens,
        now: DateTime<Utc>,
    ) -> Res<RefreshOutcome> {
        let mut d = self.lock();
        let Some(t) = d
            .tokens
            .get(hash)
            .filter(|t| t.kind == TokenKind::Refresh)
            .cloned()
        else {
            return Ok(RefreshOutcome::Invalid);
        };
        if t.used_at.is_some() {
            d.tokens.retain(|_, x| x.family != t.family);
            let user_id = d.devices.get(&t.device_id).map(|dev| dev.user_id);
            return Ok(RefreshOutcome::Reused {
                device_id: t.device_id,
                user_id,
                family: t.family,
            });
        }
        if t.expires_at <= now {
            return Ok(RefreshOutcome::Invalid);
        }
        let user_id = match d.devices.get(&t.device_id) {
            Some(dev)
                if dev.revoked_at.is_none()
                    && d.users.get(&dev.user_id).is_some_and(|u| !u.disabled) =>
            {
                dev.user_id
            }
            _ => return Ok(RefreshOutcome::Invalid),
        };
        if let Some(old) = d.tokens.get_mut(hash) {
            old.used_at = Some(now);
        }
        d.insert_tokens(t.device_id, new, t.family);
        if let Some(dev) = d.devices.get_mut(&t.device_id) {
            dev.last_seen_at = Some(now);
        }
        Ok(RefreshOutcome::Rotated(AccessCtx {
            user_id,
            device_id: t.device_id,
        }))
    }

    pub(super) fn logout(&self, device_id: Uuid) -> Res<()> {
        self.lock().delete_device_tokens(|d| d == device_id);
        Ok(())
    }

    pub(super) fn list_devices(&self, user_id: Uuid) -> Res<Vec<DeviceRow>> {
        let d = self.lock();
        let mut rows: Vec<DeviceRow> = d
            .devices
            .iter()
            .filter(|(_, dev)| dev.user_id == user_id)
            .map(|(id, dev)| DeviceRow {
                id: *id,
                name: Some(dev.name.clone()),
                platform: Some(dev.platform.clone()),
                created_at: Some(dev.created_at),
                last_seen_at: dev.last_seen_at,
                revoked_at: dev.revoked_at,
            })
            .collect();
        rows.sort_by_key(|r| (r.created_at, r.id));
        Ok(rows)
    }

    pub(super) fn revoke_device(
        &self,
        user_id: Uuid,
        device_id: Uuid,
        now: DateTime<Utc>,
    ) -> Res<bool> {
        let mut d = self.lock();
        match d.devices.get_mut(&device_id) {
            Some(dev) if dev.user_id == user_id => {
                dev.revoked_at.get_or_insert(now);
            }
            _ => return Ok(false),
        }
        d.delete_device_tokens(|x| x == device_id);
        Ok(true)
    }

    pub(super) fn totp_state(&self, user_id: Uuid) -> Res<TotpState> {
        Ok(self
            .lock()
            .users
            .get(&user_id)
            .map(|u| TotpState {
                secret_enc: u.totp_secret_enc.clone(),
                pending_enc: u.totp_pending_enc.clone(),
            })
            .unwrap_or_default())
    }

    pub(super) fn set_totp_pending(&self, user_id: Uuid, pending_enc: Option<&[u8]>) -> Res<()> {
        if let Some(u) = self.lock().users.get_mut(&user_id) {
            u.totp_pending_enc = pending_enc.map(<[u8]>::to_vec);
        }
        Ok(())
    }

    pub(super) fn enable_totp(&self, user_id: Uuid, secret_enc: &[u8], step: i64) -> Res<()> {
        if let Some(u) = self.lock().users.get_mut(&user_id) {
            u.totp_secret_enc = Some(secret_enc.to_vec());
            u.totp_pending_enc = None;
            u.totp_last_step = Some(step);
        }
        Ok(())
    }

    pub(super) fn disable_totp(&self, user_id: Uuid) -> Res<()> {
        if let Some(u) = self.lock().users.get_mut(&user_id) {
            u.totp_secret_enc = None;
            u.totp_pending_enc = None;
            u.totp_last_step = None;
        }
        Ok(())
    }

    pub(super) fn consume_totp_step(&self, user_id: Uuid, step: i64) -> Res<bool> {
        let mut d = self.lock();
        let Some(u) = d.users.get_mut(&user_id) else {
            return Ok(false);
        };
        if u.totp_last_step.is_some_and(|last| last >= step) {
            return Ok(false);
        }
        u.totp_last_step = Some(step);
        Ok(true)
    }

    pub(super) fn insert_reauth(
        &self,
        hash: &TokenHash,
        user_id: Uuid,
        expires_at: DateTime<Utc>,
    ) -> Res<()> {
        self.lock().reauth.insert(*hash, (user_id, expires_at));
        Ok(())
    }

    pub(super) fn change_password(
        &self,
        ctx: AccessCtx,
        reauth: &TokenHash,
        new: &NewCredentials,
        now: DateTime<Utc>,
    ) -> Res<()> {
        let mut d = self.lock();
        // Like the SQL transaction: a failed version check rolls the reauth
        // consumption back, so check everything first.
        d.check_reauth(ctx.user_id, reauth, now)?;
        d.check_version(ctx.user_id, new)?;
        d.reauth.retain(|_, (u, _)| *u != ctx.user_id);
        d.replace_credentials(ctx.user_id, new);
        let others: Vec<Uuid> = d
            .user_devices(ctx.user_id)
            .into_iter()
            .filter(|id| *id != ctx.device_id)
            .collect();
        d.delete_device_tokens(|dev| others.contains(&dev));
        d.push_audit(
            Some(ctx.user_id),
            "password_changed",
            Some(ctx.user_id),
            serde_json::json!({ "version": new.version, "device_id": ctx.device_id }),
        );
        Ok(())
    }

    pub(super) fn issue_recovery_code(
        &self,
        email: &str,
        code_hash: &TokenHash,
        expires_at: DateTime<Utc>,
    ) -> Res<Option<Uuid>> {
        let mut d = self.lock();
        let Some(user_id) = d.user_id_by_email(email) else {
            return Ok(None);
        };
        d.recovery_codes.insert(
            user_id,
            MemRecoveryCode {
                code_hash: *code_hash,
                expires_at,
                attempts: 0,
            },
        );
        Ok(Some(user_id))
    }

    pub(super) fn check_recovery_code(
        &self,
        email: &str,
        code_hash: &TokenHash,
        now: DateTime<Utc>,
    ) -> Res<Option<RecoveryInfo>> {
        let mut d = self.lock();
        let Some(user_id) = d.user_id_by_email(email) else {
            return Ok(None);
        };
        let (Some(user), Some(keys)) = (d.users.get(&user_id), d.account_keys.get(&user_id)) else {
            return Ok(None);
        };
        let info = RecoveryInfo {
            user_id,
            email: user.email.clone(),
            recovery_bundle_enc: keys.recovery_bundle_enc.clone(),
            version: keys.version,
            ed25519_pub: keys.ed25519_pub.clone(),
        };
        let disabled = user.disabled;
        let Some(code) = d.recovery_codes.get_mut(&user_id) else {
            return Ok(None);
        };
        if code.code_hash == *code_hash && code.expires_at > now && !disabled {
            return Ok(Some(info));
        }
        code.attempts += 1;
        if code.attempts >= RECOVERY_CODE_MAX_ATTEMPTS || code.expires_at <= now {
            d.recovery_codes.remove(&user_id);
        }
        Ok(None)
    }

    pub(super) fn finish_recovery(
        &self,
        user_id: Uuid,
        code_hash: &TokenHash,
        new: &NewCredentials,
        now: DateTime<Utc>,
    ) -> Res<()> {
        let mut d = self.lock();
        let valid = d
            .recovery_codes
            .get(&user_id)
            .is_some_and(|c| c.code_hash == *code_hash && c.expires_at > now);
        if !valid {
            return Err(ApiError::AuthRequired(
                "invalid or expired recovery code".into(),
            ));
        }
        d.check_version(user_id, new)?;
        d.recovery_codes.remove(&user_id);
        d.replace_credentials(user_id, new);
        let devices = d.user_devices(user_id);
        d.delete_device_tokens(|dev| devices.contains(&dev));
        d.reauth.retain(|_, (u, _)| *u != user_id);
        d.push_audit(
            Some(user_id),
            "account_recovered",
            Some(user_id),
            serde_json::json!({ "version": new.version }),
        );
        Ok(())
    }

    pub(super) fn delete_account(
        &self,
        user_id: Uuid,
        reauth: &TokenHash,
        now: DateTime<Utc>,
    ) -> Res<()> {
        let mut d = self.lock();
        d.check_reauth(user_id, reauth, now)?;
        d.reauth.retain(|_, (u, _)| *u != user_id);
        let personal: Vec<Uuid> = d
            .vaults
            .iter()
            .filter(|(_, v)| v.personal && v.owner_user_id == Some(user_id))
            .map(|(id, _)| *id)
            .collect();
        d.items.retain(|(v, _), _| !personal.contains(v));
        d.vault_members
            .retain(|m| !personal.contains(&m.vault_id) && m.user_id != user_id);
        d.vaults.retain(|id, _| !personal.contains(id));
        let devices = d.user_devices(user_id);
        d.delete_device_tokens(|dev| devices.contains(&dev));
        d.login_states.retain(|_, s| s.user_id != Some(user_id));
        d.devices.retain(|_, dev| dev.user_id != user_id);
        d.recovery_codes.remove(&user_id);
        d.account_keys.remove(&user_id);
        d.users.remove(&user_id);
        d.push_audit(
            Some(user_id),
            "account_deleted",
            Some(user_id),
            serde_json::json!({}),
        );
        Ok(())
    }

    pub(super) fn get_secret(&self, name: &str) -> Res<Option<Vec<u8>>> {
        Ok(self.lock().secrets.get(name).cloned())
    }

    pub(super) fn insert_secret_if_absent(&self, name: &str, value: &[u8]) -> Res<()> {
        self.lock()
            .secrets
            .entry(name.to_owned())
            .or_insert_with(|| value.to_vec());
        Ok(())
    }

    pub(super) fn audit(
        &self,
        actor: Option<Uuid>,
        kind: &str,
        target: Option<Uuid>,
        meta: serde_json::Value,
        _now: DateTime<Utc>,
    ) -> Res<()> {
        self.lock().push_audit(actor, kind, target, meta);
        Ok(())
    }
}
