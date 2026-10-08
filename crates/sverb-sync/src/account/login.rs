//! Logging in (M4-08 §2.2, §2.3, §2.5).
//!
//! [`start_login`] runs OPAQUE, opens the account keys and the vault grants,
//! checks whether the account password differs from the local master
//! password, and — when the local personal vault is not the account's —
//! downloads the account's items (in memory) to build the dry-run duplicate
//! preview. Nothing local changes until [`LoginSession::commit`], which does
//! everything in **one** SQLite transaction:
//!
//! * re-wrap the LMK under the account password (new salt) if it differs
//!   (the UI shows [`super::PASSWORD_ADOPT_WARNING`] first);
//! * add the account's vaults (keys wrapped under the LMK) and the
//!   downloaded items;
//! * import the local items under new ids with remapped references
//!   ([`super::merge_local`]), move their device-local rows (frecency), and
//!   delete the old local vault;
//! * store `meta.account`.
//!
//! A crash before the commit leaves the local vault exactly as it was; the
//! tokens are saved right after it. The push of the imported items is then
//! ordinary sync.
//!
//! The same entry point covers the other login cases:
//! * a device whose local personal vault **is** the account's (re-login
//!   after a password change elsewhere, §2.5; after `logout --keep-local`;
//!   after a registration that crashed before its local commit): nothing is
//!   imported, the tokens and (if needed) the LMK wrap are renewed;
//! * a new device (§2.3): the caller first initializes the local vault with
//!   the account password (one password), whose empty personal vault is then
//!   replaced by the account's.

use std::fmt;

use serde::de::DeserializeOwned;
use sverb_core::model::{DeviceId, ItemBody, ItemId, VaultId};
use sverb_crypto::Key32;
use sverb_crypto::account::{AccountKeys, EXPORT_KEY_LEN, derive_akek, open_private_bundle};
use sverb_crypto::opaque::client_login_start;
use sverb_crypto::random::os_rng;
use sverb_proto::auth::{
    LoginDevice, LoginFinishRequest, LoginPurpose, LoginStartRequest, LoginStartResponse,
    SessionResponse,
};
use sverb_proto::sync::{VaultKind as ProtoVaultKind, VaultView};
use sverb_store::meta::keys as meta_keys;
use sverb_store::{RemoteItem, Store, VaultKind, VaultRow};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::grants::GrantKeySource;
use super::local::{self, LocalAccount};
use super::merge_local::{ImportPlan, ImportPreview, build_preview, plan_import};
use super::{AccountConfig, AccountError, login_error, probe_server};
use crate::http::ApiClient;
use crate::keys::VaultKeys;
use crate::tokens::TokenManager;

/// What the user typed.
#[derive(Clone)]
pub struct LoginRequest {
    /// Server base URL.
    pub server_url: String,
    /// Account email.
    pub email: String,
    /// Account password.
    pub password: Zeroizing<String>,
    /// TOTP code, when the account requires one.
    pub totp: Option<String>,
}

impl fmt::Debug for LoginRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginRequest")
            .field("server_url", &self.server_url)
            .field("email", &self.email)
            .finish_non_exhaustive()
    }
}

/// OPAQUE login (start + finish). Returns the export key and the finish
/// response (`SessionResponse` for a login, `ReauthResponse` for a reauth).
pub(crate) async fn opaque_login<T: DeserializeOwned>(
    api: &ApiClient,
    email: &str,
    password: &str,
    cfg: &AccountConfig,
    purpose: LoginPurpose,
    device: LoginDevice,
    totp: Option<String>,
) -> Result<(Zeroizing<[u8; EXPORT_KEY_LEN]>, T), AccountError> {
    let (state, ke1) = client_login_start(&mut os_rng(), password.as_bytes())?;
    let start: LoginStartResponse = api
        .post_v1(
            "/auth/login/start",
            &LoginStartRequest {
                email: email.to_owned(),
                credential_request: ke1,
            },
            None,
        )
        .await
        .map_err(login_error)?;
    let ksf = cfg.ksf.clone();
    let pw = Zeroizing::new(password.to_owned());
    let ke2 = start.credential_response;
    let fin =
        tokio::task::spawn_blocking(move || state.finish(&mut os_rng(), pw.as_bytes(), &ke2, &ksf))
            .await
            .map_err(|e| AccountError::Local(e.to_string()))?
            // A wrong password (or unknown account) fails here, client side.
            .map_err(|_| AccountError::LoginFailed)?;
    let resp: T = api
        .post_v1(
            "/auth/login/finish",
            &LoginFinishRequest {
                login_state_id: start.login_state_id,
                credential_finalization: fin.finalization.clone(),
                totp,
                device,
                purpose,
            },
            None,
        )
        .await
        .map_err(login_error)?;
    Ok((fin.export_key, resp))
}

/// A vault of the account with its opened keys.
struct AccountVault {
    view: VaultView,
    keys: Vec<(u32, Key32)>,
}

impl AccountVault {
    fn id(&self) -> VaultId {
        VaultId::from_uuid(self.view.id)
    }

    fn kind(&self) -> VaultKind {
        match self.view.kind {
            ProtoVaultKind::Personal => VaultKind::Personal,
            _ => VaultKind::Shared,
        }
    }

    fn current(&self) -> Option<&Key32> {
        self.keys
            .iter()
            .find(|(v, _)| *v == self.view.key_version)
            .map(|(_, k)| k)
    }
}

/// The local vault to import.
struct LocalSide {
    row: VaultRow,
    items: Vec<(ItemId, ItemBody)>,
}

/// A login in progress: OPAQUE done, nothing stored yet.
pub struct LoginSession {
    api: ApiClient,
    email: String,
    password: Zeroizing<String>,
    lmk: Key32,
    session: SessionResponse,
    keys: AccountKeys,
    password_differs: bool,
    personal: AccountVault,
    shared: Vec<AccountVault>,
    /// `None`: the local personal vault is the account's (nothing to import).
    local: Option<LocalSide>,
    remote: Vec<RemoteItem>,
    account_items: Vec<(ItemId, ItemBody)>,
    head: u64,
    preview: ImportPreview,
    kdf_cost: sverb_core::vault::Argon2Cost,
    crash_after: Option<usize>,
}

impl fmt::Debug for LoginSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginSession")
            .field("server", &self.api.base_url())
            .field("user_id", &self.session.user_id)
            .field("password_differs", &self.password_differs)
            .field("import", &self.local.is_some())
            .finish_non_exhaustive()
    }
}

/// The result of [`LoginSession::commit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggedIn {
    /// The account.
    pub user_id: Uuid,
    /// This device, as the server knows it.
    pub device_id: Uuid,
    /// The account's personal vault (now the local personal vault).
    pub vault: VaultId,
    /// Local items imported under new ids.
    pub imported: usize,
    /// Whether the LMK was re-wrapped under the account password.
    pub password_changed: bool,
    /// The local vault that was replaced (deleted), if any.
    pub replaced_vault: Option<VaultId>,
}

/// Starts a login on an unlocked device (`lmk`).
///
/// # Errors
/// [`AccountError::LoginFailed`], [`AccountError::TotpRequired`],
/// [`AccountError::Unreachable`], [`AccountError::Crypto`] (bundle or grant
/// does not open), [`AccountError::Local`].
pub async fn start_login(
    store: &Store,
    lmk: &Key32,
    req: &LoginRequest,
    cfg: &AccountConfig,
) -> Result<LoginSession, AccountError> {
    let api = probe_server(&req.server_url, cfg).await?;
    let email = req.email.trim().to_owned();
    let previous_device = store.get_sync_state().await?.and_then(|s| s.device_id);
    let device = LoginDevice {
        id: previous_device.map(|d| d.uuid()),
        name: Some(cfg.device.name.clone()),
        platform: Some(cfg.device.platform.clone()),
    };
    let (export_key, session): (_, SessionResponse) = opaque_login(
        &api,
        &email,
        &req.password,
        cfg,
        LoginPurpose::Login,
        device,
        req.totp.clone(),
    )
    .await?;
    let akek = derive_akek(&export_key);
    let keys = open_private_bundle(
        &akek,
        session.user_id.as_bytes(),
        session.account_keys.version,
        &session.account_keys.private_bundle_enc,
    )
    .map_err(|e| AccountError::Crypto(format!("private bundle: {e}")))?;
    let token = session.tokens.access_token.clone();
    let views = api.list_vaults(&token).await?;

    let source = GrantKeySource::new(session.user_id, keys.clone());
    let mut personal = None;
    let mut shared = Vec::new();
    for view in views {
        let mut opened = Vec::new();
        for g in &view.grants {
            match source.open(&view, g.key_version) {
                Ok(k) => opened.push((g.key_version, k)),
                Err(e) => {
                    tracing::warn!(vault = %view.id, version = g.key_version, error = %e, "grant not opened")
                }
            }
        }
        let v = AccountVault { view, keys: opened };
        if v.current().is_none() {
            if v.view.kind == ProtoVaultKind::Personal {
                return Err(AccountError::Crypto(
                    "the personal vault's self-grant does not verify".into(),
                ));
            }
            // M5-03: grants from users this device does not trust yet.
            continue;
        }
        if v.view.kind == ProtoVaultKind::Personal && personal.is_none() {
            personal = Some(v);
        } else {
            shared.push(v);
        }
    }
    let personal =
        personal.ok_or_else(|| AccountError::Crypto("the account has no personal vault".into()))?;

    let password_differs = local::try_local_password(store, &req.password)
        .await?
        .is_none();

    let local_side = match local::personal_vault(store, lmk).await {
        Ok((row, _)) if row.id == personal.id() => None,
        Ok((row, vk)) => {
            let items = decrypt_local(store, &row, &vk).await?;
            Some(LocalSide { row, items })
        }
        Err(e) => {
            tracing::info!(error = %e, "no local personal vault to import");
            None
        }
    };

    let mut s = LoginSession {
        api,
        email,
        password: req.password.clone(),
        lmk: lmk.clone(),
        session,
        keys,
        password_differs,
        personal,
        shared,
        local: local_side,
        remote: Vec::new(),
        account_items: Vec::new(),
        head: 0,
        preview: ImportPreview::default(),
        kdf_cost: cfg.kdf_cost,
        crash_after: None,
    };
    if s.local.is_some() {
        s.download().await?;
        if let Some(l) = &s.local {
            s.preview = build_preview(&l.items, &s.account_items);
        }
    }
    Ok(s)
}

async fn decrypt_local(
    store: &Store,
    row: &VaultRow,
    vk: &Key32,
) -> Result<Vec<(ItemId, ItemBody)>, AccountError> {
    let mut keys = VaultKeys::default();
    keys.insert(row.id, row.kind, row.key_version, vk.clone());
    let mut out = Vec::new();
    for r in store.list_items(row.id).await? {
        match keys.open(row.id, r.id, &r.envelope) {
            Ok(b) => out.push((r.id, b)),
            Err(e) => {
                return Err(AccountError::Local(format!(
                    "local item {} does not decrypt ({e}); nothing was imported",
                    r.id.short()
                )));
            }
        }
    }
    Ok(out)
}

impl LoginSession {
    /// Whether the account password differs from the local master password:
    /// show [`super::PASSWORD_ADOPT_WARNING`] before [`Self::commit`].
    #[must_use]
    pub const fn password_differs(&self) -> bool {
        self.password_differs
    }

    /// Whether local items will be imported (the local personal vault is
    /// not the account's).
    #[must_use]
    pub const fn will_import(&self) -> bool {
        self.local.is_some()
    }

    /// The dry-run preview (empty when nothing is imported).
    #[must_use]
    pub const fn preview(&self) -> &ImportPreview {
        &self.preview
    }

    /// The preview, to set the duplicate choices.
    pub fn preview_mut(&mut self) -> &mut ImportPreview {
        &mut self.preview
    }

    /// The account.
    #[must_use]
    pub const fn user_id(&self) -> Uuid {
        self.session.user_id
    }

    /// The account's personal vault.
    #[must_use]
    pub fn account_vault(&self) -> VaultId {
        self.personal.id()
    }

    /// The opened account keys (for a [`GrantKeySource`]).
    #[must_use]
    pub fn grant_source(&self) -> GrantKeySource {
        GrantKeySource::new(self.session.user_id, self.keys.clone())
    }

    /// Test hook (T-06): panic inside the import transaction after writing
    /// this many items.
    #[doc(hidden)]
    pub fn set_crash_after(&mut self, n: Option<usize>) {
        self.crash_after = n;
    }

    /// Downloads every item of the account's personal vault (in memory).
    async fn download(&mut self) -> Result<(), AccountError> {
        let vault = self.personal.id();
        let mut keys = VaultKeys::default();
        for (v, k) in &self.personal.keys {
            keys.insert(vault, VaultKind::Personal, *v, k.clone());
        }
        let token = self.session.tokens.access_token.clone();
        let mut since = 0;
        loop {
            let page = self
                .api
                .pull(
                    &token,
                    vault.uuid(),
                    since,
                    sverb_proto::sync::MAX_PULL_LIMIT,
                )
                .await?;
            for it in &page.items {
                let id = ItemId::from_uuid(it.id);
                match keys.open(vault, id, &it.envelope) {
                    Ok(b) => self.account_items.push((id, b)),
                    Err(e) => {
                        tracing::warn!(item = %id.short(), error = %e, "account item does not decrypt")
                    }
                }
                self.remote.push(RemoteItem {
                    id,
                    revision: i64::try_from(it.revision).unwrap_or(i64::MAX),
                    key_version: it.key_version,
                    envelope: it.envelope.clone(),
                    deleted: it.deleted,
                    local_pending: false,
                });
            }
            self.head = page.head_revision;
            since = page
                .items
                .iter()
                .map(|i| i.revision)
                .max()
                .unwrap_or(since)
                .max(since);
            if !page.more || page.items.is_empty() {
                break;
            }
        }
        Ok(())
    }

    /// Commits the login (see the module docs). Can be retried after a
    /// failure: nothing local changed.
    ///
    /// # Errors
    /// [`AccountError::Local`] / [`AccountError::Crypto`].
    pub async fn commit(&self, store: &Store) -> Result<LoggedIn, AccountError> {
        let lmk = self.lmk.clone();
        let wrap = if self.password_differs {
            Some(local::wrap_lmk(&lmk, &self.password, self.kdf_cost).await?)
        } else {
            None
        };
        let user_id = self.session.user_id;
        let acct = LocalAccount {
            user_id,
            email: self.email.clone(),
            key_version: self.session.account_keys.version,
        };
        let keys_enc = local::seal_local_keys(&lmk, &acct, &self.keys)?;

        // Vault rows to create (personal + opened shared).
        let mut vaults = Vec::new();
        for v in std::iter::once(&self.personal).chain(&self.shared) {
            let Some(k) = v.current() else { continue };
            let wrapped = local::wrap_vault_key(&lmk, v.id(), k)?;
            vaults.push((v.id(), v.kind(), v.view.key_version, wrapped));
        }

        // The import: plan and seal outside the transaction.
        let vault = self.personal.id();
        let mut sealed = Vec::new();
        let mut moves = Vec::new();
        let mut replaced = None;
        let mut hlc_last = None;
        if let Some(l) = &self.local {
            let (device, mut clock) = local::device_clock(store).await?;
            let plan: ImportPlan = plan_import(
                &l.items,
                &self.account_items,
                &self.preview,
                &mut clock,
                device,
            );
            let mut keys = VaultKeys::default();
            keys.insert(
                vault,
                VaultKind::Personal,
                self.personal.view.key_version,
                self.personal
                    .current()
                    .cloned()
                    .ok_or_else(|| AccountError::Crypto("no current vault key".into()))?,
            );
            for w in &plan.writes {
                let (kv, env) = keys
                    .seal(vault, w.to, &w.body)
                    .map_err(AccountError::Crypto)?;
                sealed.push((w.to, kv, env));
            }
            moves = plan.id_map.into_iter().collect::<Vec<_>>();
            replaced = Some(l.row.id);
            hlc_last = Some(clock.last().as_u64());
        }
        let remote = if self.local.is_some() {
            self.remote.clone()
        } else {
            Vec::new()
        };
        let head = i64::try_from(self.head).unwrap_or(i64::MAX);
        let crash_after = self.crash_after;
        let imported = sealed.len();

        store
            .write(move |w| {
                if let Some(wrap) = &wrap {
                    local::write_lmk_wrap(w, wrap)?;
                }
                for (id, kind, kv, wrapped) in &vaults {
                    match w.as_read().get_vault(*id)? {
                        None => w.create_vault(*id, *kind, None, *kv, wrapped)?,
                        Some(row) if row.key_version < *kv => {
                            w.update_wrapped_key(*id, *kv, wrapped)?
                        }
                        Some(_) => {}
                    }
                }
                if replaced.is_some() {
                    w.apply_remote(vault, &remote, head)?;
                }
                for (n, (id, kv, env)) in sealed.iter().enumerate() {
                    if crash_after.is_some_and(|c| n >= c) {
                        panic!("M4-08 test hook: crash during the import transaction");
                    }
                    w.put_item(vault, *id, *kv, env, false, true)?;
                }
                for (from, to) in &moves {
                    w.move_device_local(*from, *to)?;
                }
                if let Some(old) = replaced {
                    w.delete_vault(old)?;
                }
                if let Some(h) = hlc_last {
                    w.set_meta(meta_keys::HLC_LAST, &h.to_be_bytes())?;
                }
                local::write_account(w, &acct, &keys_enc)
            })
            .await?;

        TokenManager::save_login(
            store,
            &lmk,
            self.api.base_url(),
            Some(DeviceId::from_uuid(self.session.device_id)),
            &self.session.tokens,
        )
        .await?;
        tracing::info!(%user_id, imported, password_changed = self.password_differs, "logged in");
        Ok(LoggedIn {
            user_id,
            device_id: self.session.device_id,
            vault,
            imported,
            password_changed: self.password_differs,
            replaced_vault: replaced,
        })
    }
}
