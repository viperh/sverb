//! M1-07: the item service: save, delete, duplicate, pin and read items (SPEC §4,
//! §5.2), shared by the TUI (`Effect::Vault(VaultEffect::Items)`) and the CLI
//! (`sverb hosts add | rm | list`).
//!
//! Every write: load the current body (or start an empty one), apply the typed
//! change through `ItemBody::set` (HLC-stamped, unchanged values create no stamp),
//! validate, seal with the vault key, `put_item`, persist `meta.hlc_last`, then update
//! the search index. A delete stamps the tombstone the same way; the row stays in
//! the database with `deleted = 1` for sync.
//!
//! **Outbox rule:** every local write is marked dirty (and queued in the outbox),
//! also in local-only mode, so enabling sync later pushes everything (§11.2.1).
//! Nothing is pushed here.
//!
//! The functions on [`ItemOps`] are UI-free; [`execute`] runs an [`ItemEffect`] for
//! the TUI and reports through the event channel.

use std::sync::{Arc, Mutex, PoisonError};

use sverb_core::error_report::ErrorReport;
use sverb_core::model::{
    Group, HlcClock, Host, Identity, ItemBody, ItemId, ItemKind, Key, Snippet, Tag,
    ValidationError, VaultId, current_schema, migrate::is_read_only, validate::validate_host,
};
// M2-01
use sverb_core::model::{
    group::{DeleteGroupMode, DeletePlan, plan_delete},
    tag::{tag_key, validate_tag},
    validate::validate_group_parent,
};
// M2-02
use sverb_core::model::identity::{check_identity_vault, inline_conversion, validate_identity};
use sverb_core::resolve::GlobalDefaults;
use sverb_core::secret::SecretString;
use sverb_core::vault::VaultError;
use sverb_store::meta::keys;
use sverb_store::{DeviceLocal, StoreError};
use tracing::{debug, warn};

use super::{UnlockedVault, VaultEngine, VaultService, vault_display_name};
use crate::app::hosts::ItemEffect;
use crate::app::{EffectOutput, UiEvent, VaultEvent};
use crate::services::EventSender;
use crate::views::hosts::catalog::{HostCatalog, HostRecord, HostSummary, IdentityInfo, TagInfo};
use crate::views::hosts::form::{apply_changes, apply_group_changes};
use crate::widgets::form::{FieldChanges, SecretValue};
// M2-02
use crate::views::keychain::identity_form::{IdentityRecord, apply_identity_changes};

/// Why an item operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemError {
    /// The vault is locked.
    Locked,
    /// No such (live) item.
    NotFound,
    /// The item has a newer schema (§4.1).
    ReadOnly,
    /// The item is not of the expected kind.
    WrongKind(ItemKind),
    /// Validation failed.
    Invalid(Vec<ValidationError>),
    /// Storage or crypto failure.
    Storage(String),
    // M5-02
    /// The vault grants this account only `read` (§13.2).
    ReadOnlyVault,
    /// A move / copy would leave references outside the shared target (§13.4).
    Blocked(Vec<String>),
}

impl std::fmt::Display for ItemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Locked => f.write_str("the vault is locked"),
            Self::NotFound => f.write_str("the item no longer exists"),
            Self::ReadOnly => {
                f.write_str("this item was written by a newer sverb; update to edit it")
            }
            Self::WrongKind(k) => write!(f, "expected a {k} item"),
            Self::Invalid(errors) => {
                let all: Vec<String> = errors.iter().map(ToString::to_string).collect();
                f.write_str(&all.join("; "))
            }
            Self::Storage(msg) => f.write_str(msg),
            // M5-02
            Self::ReadOnlyVault => f.write_str("this shared vault is read-only for you"),
            Self::Blocked(refs) => write!(
                f,
                "items in a shared vault can only reference items of that vault: {}",
                refs.join(", ")
            ),
        }
    }
}

impl std::error::Error for ItemError {}

impl From<VaultError> for ItemError {
    fn from(e: VaultError) -> Self {
        match e {
            VaultError::Locked => Self::Locked,
            other => Self::Storage(other.to_string()),
        }
    }
}

impl From<StoreError> for ItemError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::ReadOnlyItem(_) => Self::ReadOnly,
            other => Self::Storage(other.to_string()),
        }
    }
}

impl ItemError {
    /// The user-facing report.
    pub fn report(&self) -> ErrorReport {
        ErrorReport::msg(self.to_string())
    }
}

/// A completed write.
#[derive(Debug, Clone)]
pub struct Written {
    /// The item.
    pub id: ItemId,
    /// Its vault.
    pub vault: VaultId,
    /// The body as stored.
    pub body: ItemBody,
}

/// A decrypted live item.
#[derive(Debug, Clone)]
pub struct Loaded {
    /// The item.
    pub id: ItemId,
    /// Its vault.
    pub vault: VaultId,
    /// The body.
    pub body: ItemBody,
}

/// The HLC clock shared by every write of one unlocked session.
#[derive(Debug, Clone)]
pub struct SharedClock(Arc<Mutex<HlcClock>>);

impl SharedClock {
    /// A clock resumed from the vault's `meta.hlc_last`.
    pub fn new(vault: &UnlockedVault) -> Self {
        Self(Arc::new(Mutex::new(vault.hlc())))
    }

    fn with<R>(&self, f: impl FnOnce(&mut HlcClock) -> R) -> R {
        f(&mut self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

/// Item operations over an engine and an unlocked vault.
#[derive(Debug, Clone)]
pub struct ItemOps {
    engine: VaultEngine,
    vault: Arc<UnlockedVault>,
    clock: SharedClock,
    // M5-02
    /// Where new hosts go (the vault selector; `None`: Personal).
    new_vault: Option<VaultId>,
}

/// Validate a body of `kind` (the self-contained rules of its typed view).
fn validate(body: &ItemBody) -> Result<(), ItemError> {
    match body.kind {
        ItemKind::Host => {
            let host = Host::try_from(body).map_err(|e| ItemError::Storage(e.to_string()))?;
            validate_host(&host).map_err(ItemError::Invalid)
        }
        _ => Ok(()),
    }
}

impl ItemOps {
    /// Operations with a fresh clock (the CLI: one command, one clock).
    pub fn new(engine: VaultEngine, vault: Arc<UnlockedVault>) -> Self {
        let clock = SharedClock::new(&vault);
        Self {
            engine,
            vault,
            clock,
            new_vault: None,
        }
    }

    /// Operations sharing `clock` (the TUI service).
    pub fn with_clock(engine: VaultEngine, vault: Arc<UnlockedVault>, clock: SharedClock) -> Self {
        Self {
            engine,
            vault,
            clock,
            new_vault: None,
        }
    }

    /// The unlocked vault.
    pub fn vault(&self) -> &Arc<UnlockedVault> {
        &self.vault
    }

    /// Load one live item (`None` if missing, deleted or undecryptable).
    ///
    /// # Errors
    /// Storage failures.
    pub async fn load(&self, id: ItemId) -> Result<Option<Loaded>, ItemError> {
        let row = self.engine.store().get_item(id).await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let body = self.vault.open(&row)?;
        if body.is_deleted() {
            return Ok(None);
        }
        Ok(Some(Loaded {
            id,
            vault: row.vault_id,
            body,
        }))
    }

    /// Every live item of the given kinds (all kinds when empty). Items that do not
    /// decrypt are skipped (and logged).
    ///
    /// # Errors
    /// Storage failures.
    pub async fn list(&self, kinds: &[ItemKind]) -> Result<Vec<Loaded>, ItemError> {
        let rows = self.engine.store().list_all_items().await?;
        let mut out = Vec::new();
        for row in rows.into_iter().filter(|r| !r.deleted) {
            match self.vault.open(&row) {
                Ok(body)
                    if !body.is_deleted() && (kinds.is_empty() || kinds.contains(&body.kind)) =>
                {
                    out.push(Loaded {
                        id: row.id,
                        vault: row.vault_id,
                        body,
                    });
                }
                Ok(_) => {}
                Err(e) => debug!(item = %row.id.short(), error = %e, "item skipped"),
            }
        }
        Ok(out)
    }

    /// Seal and store `body`, marking it dirty (outbox rule), and persist the HLC.
    async fn store(
        &self,
        id: ItemId,
        vault: VaultId,
        body: ItemBody,
    ) -> Result<Written, ItemError> {
        let (key_version, envelope) = self.vault.seal(vault, id, &body)?;
        let hlc = self.clock.with(|c| c.last());
        let deleted = body.is_deleted();
        self.engine
            .store()
            .write(move |w| {
                w.put_item(vault, id, key_version, &envelope, deleted, true)?;
                w.set_meta(keys::HLC_LAST, &hlc.as_u64().to_be_bytes())
            })
            .await?;
        Ok(Written { id, vault, body })
    }

    /// Create (`id: None`) or update an item of `kind`: `edit` changes the body
    /// through the stamped setters; then it is validated, sealed and stored.
    /// New items go to `vault`, else the Personal vault.
    ///
    /// # Errors
    /// [`ItemError::Invalid`] (nothing is written), [`ItemError::NotFound`],
    /// [`ItemError::ReadOnly`], storage failures.
    pub async fn save(
        &self,
        kind: ItemKind,
        id: Option<ItemId>,
        vault: Option<VaultId>,
        edit: impl FnOnce(
            &mut ItemBody,
            &mut HlcClock,
            sverb_core::model::DeviceId,
        ) -> Result<(), Vec<ValidationError>>,
    ) -> Result<Written, ItemError> {
        let device = self.vault.device_id();
        // M2-10
        let existed = id.is_some();
        let (id, vault, mut body) = match id {
            Some(id) => {
                let loaded = self.load(id).await?.ok_or(ItemError::NotFound)?;
                if loaded.body.kind != kind {
                    return Err(ItemError::WrongKind(kind));
                }
                (id, loaded.vault, loaded.body)
            }
            None => {
                let vault = vault
                    .or_else(|| self.vault.personal_vault())
                    .ok_or(ItemError::Locked)?;
                (
                    ItemId::new(),
                    vault,
                    ItemBody::new(kind, current_schema(kind)),
                )
            }
        };
        if is_read_only(&body) {
            return Err(ItemError::ReadOnly);
        }
        // M2-10: what the locally-acting values were before this save.
        let before = existed.then(|| body.clone());
        self.clock
            .with(|clock| edit(&mut body, clock, device))
            .map_err(ItemError::Invalid)?;
        validate(&body)?;
        // M5-02: read-only vaults and the §13.4 reference rule of shared vaults.
        self.check_shared_vault(vault, &body).await?;
        let written = self.store(id, vault, body).await?;
        self.approve_typed(id, before.as_ref(), &written.body).await;
        Ok(written)
    }

    // M5-02
    /// New hosts go to `vault` (the vault selector; `None`: Personal).
    #[must_use]
    pub fn with_new_vault(mut self, vault: Option<VaultId>) -> Self {
        self.new_vault = vault.filter(|v| self.vault.vault_kind(*v).is_some());
        self
    }

    // M5-02
    /// "Move to vault…" / "Copy to vault…" (§13.1): new ids in `target`, sealed
    /// under its key; a move tombstones the sources. References that would leave a
    /// shared target follow `refs` ([`ItemError::Blocked`] lists them for
    /// `RefPolicy::Block`). Returns every write.
    ///
    /// # Errors
    /// [`ItemError::Blocked`], [`ItemError::ReadOnlyVault`], [`ItemError::NotFound`],
    /// storage failures.
    pub async fn transfer(
        &self,
        items: &[ItemId],
        target: VaultId,
        copy: bool,
        refs: sverb_core::model::vault_refs::RefPolicy,
    ) -> Result<Vec<Written>, ItemError> {
        use sverb_core::model::vault_refs::{
            TransferError, TransferMode, VaultScope, plan_transfer,
        };
        let all = self.list(&[]).await?;
        let by_id: std::collections::BTreeMap<ItemId, (VaultId, &ItemBody)> =
            all.iter().map(|l| (l.id, (l.vault, &l.body))).collect();
        let scope = match self.vault.vault_kind(target) {
            Some(sverb_store::VaultKind::Shared) => VaultScope::Shared,
            Some(sverb_store::VaultKind::Personal) => VaultScope::Personal,
            None => return Err(ItemError::Locked),
        };
        let mode = if copy {
            TransferMode::Copy
        } else {
            TransferMode::Move
        };
        let device = self.vault.device_id();
        let plan = self
            .clock
            .with(|clock| {
                plan_transfer(
                    items,
                    target,
                    scope,
                    mode,
                    refs,
                    |id| by_id.get(&id).copied(),
                    ItemId::new,
                    clock,
                    device,
                )
            })
            .map_err(|e| match e {
                TransferError::Blocked(bad) => ItemError::Blocked(
                    bad.iter()
                        .map(|b| {
                            let label = by_id
                                .get(&b.target)
                                .and_then(|(_, body)| {
                                    body.get("label").or_else(|| body.get("name"))
                                })
                                .and_then(|v| v.as_text())
                                .map_or_else(|| b.target.short(), ToOwned::to_owned);
                            let kind = by_id
                                .get(&b.target)
                                .map_or("item", |(_, body)| body.kind.as_str());
                            format!("{kind} “{label}”")
                        })
                        .collect(),
                ),
                TransferError::Unknown(_) => ItemError::NotFound,
                TransferError::SameVault => {
                    ItemError::Invalid(vec![ValidationError::new("vault", "already in that vault")])
                }
            })?;
        for (_, body) in &plan.writes {
            self.check_shared_vault(target, body).await?;
        }
        for (_, vault, _) in &plan.tombstones {
            if self.vault.vault_kind(*vault) == Some(sverb_store::VaultKind::Shared) {
                let key = format!(
                    "{}{}",
                    super::shared::META_VAULT_PERMISSION_PREFIX,
                    vault.uuid()
                );
                if self.engine.store().get_meta(&key).await?.as_deref() == Some(b"read".as_slice())
                {
                    return Err(ItemError::ReadOnlyVault);
                }
            }
        }
        let mut out = Vec::new();
        for (id, body) in plan.writes {
            out.push(self.store(id, target, body).await?);
        }
        for (id, vault, body) in plan.tombstones {
            out.push(self.store(id, vault, body).await?);
        }
        Ok(out)
    }

    // M5-02
    /// "Use my own credentials…" (§13.4): the personal-vault override of
    /// `host` uses `identity`; `None` removes the override.
    ///
    /// # Errors
    /// [`ItemError::Locked`], storage failures.
    pub async fn set_override(
        &self,
        host: ItemId,
        identity: Option<ItemId>,
    ) -> Result<Vec<Written>, ItemError> {
        use sverb_core::model::CredentialOverride;
        let personal = self.vault.personal_vault().ok_or(ItemError::Locked)?;
        let existing: Vec<ItemId> = self
            .list(&[ItemKind::CredentialOverride])
            .await?
            .into_iter()
            .filter(|l| l.vault == personal)
            .filter(|l| {
                CredentialOverride::try_from(&l.body).is_ok_and(|o| o.shared_host_id == host)
            })
            .map(|l| l.id)
            .collect();
        let mut out = Vec::new();
        let Some(identity) = identity else {
            for id in existing {
                out.push(self.delete(id).await?);
            }
            return Ok(out);
        };
        let (keep, extra) = match existing.split_first() {
            Some((k, rest)) => (Some(*k), rest.to_vec()),
            None => (None, Vec::new()),
        };
        out.push(
            self.save(
                ItemKind::CredentialOverride,
                keep,
                Some(personal),
                move |body, clock, device| {
                    let mut o = CredentialOverride::try_from(&*body)
                        .unwrap_or_else(|_| CredentialOverride::new(host));
                    o.shared_host_id = host;
                    o.identity_id = Some(identity);
                    o.apply_to(body, clock, device);
                    Ok(())
                },
            )
            .await?,
        );
        for id in extra {
            out.push(self.delete(id).await?);
        }
        Ok(out)
    }

    // M5-02
    /// A shared vault: refused when this account may only read it (§13.2), and
    /// every reference must stay inside the vault (§13.4).
    ///
    /// # Errors
    /// [`ItemError::ReadOnly`], [`ItemError::Invalid`].
    async fn check_shared_vault(&self, vault: VaultId, body: &ItemBody) -> Result<(), ItemError> {
        use sverb_core::model::vault_refs::{VaultScope, item_refs, validate_vault_refs};
        if self.vault.vault_kind(vault) != Some(sverb_store::VaultKind::Shared) {
            return Ok(());
        }
        let key = format!(
            "{}{}",
            super::shared::META_VAULT_PERMISSION_PREFIX,
            vault.uuid()
        );
        if self.engine.store().get_meta(&key).await?.as_deref() == Some(b"read".as_slice()) {
            return Err(ItemError::ReadOnlyVault);
        }
        let mut vaults = std::collections::BTreeMap::new();
        for (_, r) in item_refs(body) {
            if let Some(row) = self.engine.store().get_item(r).await?
                && !row.deleted
            {
                vaults.insert(r, row.vault_id);
            }
        }
        validate_vault_refs(vault, VaultScope::Shared, body, |id| {
            vaults.get(&id).copied()
        })
        .map_err(ItemError::Invalid)
    }

    // M2-10
    /// Values typed in this save on this device are pre-approved (§17.1): the
    /// locally-acting values that changed get their `local_approvals` row. Unchanged
    /// values (possibly synced) are not. A non-loopback listen address is left to
    /// the §9.6 first-start confirmation. A failure is logged: the value is then
    /// asked for at connect, which is safe.
    async fn approve_typed(&self, id: ItemId, before: Option<&ItemBody>, after: &ItemBody) {
        use sverb_core::resolve::approval::{ActionKind, typed_actions};
        let typed: Vec<_> = typed_actions(id, before, after)
            .into_iter()
            .filter(|a| a.kind != ActionKind::ForwardBind)
            .collect();
        if typed.is_empty() {
            return;
        }
        if let Err(e) = self.engine.store().approve_all_local(&typed).await {
            warn!(item = %id.short(), error = %e, "typed values not pre-approved");
        }
    }

    // ------------------------------------------------------------------ M2-10

    /// The host's label and every value of it that acts on this machine (§17.1):
    /// resolved through its groups and the vault defaults (keyed by the item that
    /// defines each value), plus its forwarding rules (`port_forwards` and the rules
    /// whose `host_id` is the host).
    ///
    /// # Errors
    /// [`ItemError::NotFound`], storage failures.
    pub async fn host_local_actions(
        &self,
        host_id: ItemId,
    ) -> Result<(String, Vec<sverb_core::resolve::approval::LocalAction>), ItemError> {
        use sverb_core::model::PortForward;
        use sverb_core::resolve::approval::{HostItems, local_actions};
        use sverb_core::resolve::{LookupTable, Settings, Target, resolve_settings};
        let items = self
            .list(&[
                ItemKind::Host,
                ItemKind::Group,
                ItemKind::Identity,
                ItemKind::PortForward,
            ])
            .await?;
        let host_item = items
            .iter()
            .find(|i| i.id == host_id && i.body.kind == ItemKind::Host)
            .ok_or(ItemError::NotFound)?;
        let host = Host::try_from(&host_item.body).map_err(|_| ItemError::NotFound)?;
        let mut lookup = LookupTable::default();
        let mut vault_defaults = None;
        let mut forwards = Vec::new();
        for item in &items {
            lookup.mark_live(item.id);
            match item.body.kind {
                ItemKind::Group => {
                    if let Ok(g) = Group::try_from(&item.body) {
                        if g.is_vault_defaults && item.vault == host_item.vault {
                            vault_defaults = Some(item.id);
                        }
                        lookup.insert_group(item.id, item.vault, &g);
                    }
                }
                ItemKind::Identity => {
                    if let Ok(i) = Identity::try_from(&item.body) {
                        lookup.insert_identity(item.id, &i);
                    }
                }
                ItemKind::PortForward => {
                    if let Ok(pf) = PortForward::try_from(&item.body)
                        && (pf.host_id == host_id || host.port_forwards.contains(&item.id))
                    {
                        forwards.push((item.id, pf));
                    }
                }
                _ => {}
            }
        }
        let resolved = resolve_settings(
            &Target::of(&host),
            &Settings::from_host(&host),
            &lookup,
            lookup.defaults_of(host_item.vault),
            &GlobalDefaults::default(),
        );
        let actions = local_actions(
            &resolved,
            &HostItems {
                host_id: Some(host_id),
                vault_defaults,
                forwards: &forwards,
            },
        );
        Ok((host.display_label().to_owned(), actions))
    }

    // ------------------------------------------------------------------ M2-02

    /// The vault of every live identity (cross-vault checks, §13.4).
    ///
    /// # Errors
    /// Storage failures.
    pub async fn identity_vaults(
        &self,
    ) -> Result<std::collections::BTreeMap<ItemId, VaultId>, ItemError> {
        Ok(self
            .list(&[ItemKind::Identity])
            .await?
            .into_iter()
            .map(|l| (l.id, l.vault))
            .collect())
    }

    /// The vault an item is (or a new one will be) stored in.
    async fn vault_of(&self, id: Option<ItemId>) -> Result<VaultId, ItemError> {
        match id {
            Some(id) => Ok(self.load(id).await?.ok_or(ItemError::NotFound)?.vault),
            None => self.vault.personal_vault().ok_or(ItemError::Locked),
        }
    }

    /// One live identity with its vault.
    ///
    /// # Errors
    /// [`ItemError::NotFound`], [`ItemError::WrongKind`], storage failures.
    pub async fn load_identity(&self, id: ItemId) -> Result<(VaultId, Identity), ItemError> {
        let loaded = self.load(id).await?.ok_or(ItemError::NotFound)?;
        let identity = Identity::try_from(&loaded.body)
            .map_err(|_| ItemError::WrongKind(ItemKind::Identity))?;
        Ok((loaded.vault, identity))
    }

    /// Create (`id: None`, in `vault` or the Personal vault) or update an identity
    /// through its typed view; `edit` changes it. Hosts that reference it follow
    /// through resolution, so nothing else is written.
    ///
    /// # Errors
    /// As [`ItemOps::save`]; [`ItemError::Invalid`] for an empty label.
    pub async fn save_identity(
        &self,
        id: Option<ItemId>,
        vault: Option<VaultId>,
        edit: impl FnOnce(&mut Identity) -> Result<(), Vec<ValidationError>> + Send,
    ) -> Result<Written, ItemError> {
        self.save(ItemKind::Identity, id, vault, move |body, clock, device| {
            let mut identity = Identity::try_from(&*body)
                .map_err(|e| vec![ValidationError::new("item", e.to_string())])?;
            edit(&mut identity)?;
            validate_identity(&identity)?;
            identity.apply_to(body, clock, device);
            Ok(())
        })
        .await
    }

    /// Delete (tombstone) an identity (§9.3). Hosts that reference it resolve their
    /// credentials from the next level (§12.4). With `convert`, every host using it
    /// (directly or through a group) first gets, as inline fields, exactly the
    /// credentials it took from the identity. Returns every write (the tombstone
    /// last).
    ///
    /// # Errors
    /// [`ItemError::NotFound`], [`ItemError::WrongKind`]; the first failing write.
    pub async fn delete_identity(
        &self,
        id: ItemId,
        convert: bool,
    ) -> Result<Vec<Written>, ItemError> {
        let (_, identity) = self.load_identity(id).await?;
        let mut out = Vec::new();
        if convert {
            let with = self.catalog().await?;
            let mut without = with.clone();
            without.lookup.identities.remove(&id);
            let globals = GlobalDefaults::default();
            let plans: Vec<_> = with
                .hosts
                .values()
                .filter_map(|h| {
                    let before = with.resolve(h, &globals);
                    if before.identity_id != Some(id) {
                        return None;
                    }
                    let after = without.resolve(h, &globals);
                    let conv = inline_conversion(id, h.identity_id, &before, &after);
                    (!conv.is_empty()).then_some((h.id, conv))
                })
                .collect();
            for (host, conv) in plans {
                let source = Identity {
                    password: identity
                        .password
                        .as_ref()
                        .map(|p| SecretString::from(p.expose())),
                    ..Identity::default()
                };
                out.push(
                    self.edit_host(host, move |h| conv.apply(h, &source))
                        .await?,
                );
            }
        }
        out.push(self.delete(id).await?);
        Ok(out)
    }

    /// Save a host from form changes (only changed fields are stamped).
    ///
    /// # Errors
    /// As [`ItemOps::save`].
    pub async fn save_host(
        &self,
        id: Option<ItemId>,
        changes: FieldChanges,
    ) -> Result<Written, ItemError> {
        // M2-02: identities are referenced only within their vault (§13.4).
        let identity_vaults = self.identity_vaults().await?;
        // M5-02: a new host goes to the selected vault (§4.13).
        let new_vault = if id.is_none() { self.new_vault } else { None };
        let host_vault = match new_vault {
            Some(v) => v,
            None => self.vault_of(id).await?,
        };
        self.save(ItemKind::Host, id, new_vault, move |body, clock, device| {
            let mut host = Host::try_from(&*body)
                .map_err(|e| vec![ValidationError::new("item", e.to_string())])?;
            apply_changes(&mut host, &changes)?;
            check_identity_vault("identity_id", host_vault, host.identity_id, |i| {
                identity_vaults.get(&i).copied()
            })
            .map_err(|e| vec![e])?;
            host.apply_to(body, clock, device);
            Ok(())
        })
        .await
    }

    // ------------------------------------------------------------------ M2-01

    /// Save a group (or the vault defaults) from form changes. A new parent must
    /// not create a cycle (§4.3).
    ///
    /// # Errors
    /// As [`ItemOps::save`]; [`ItemError::Invalid`] for a cycle or an empty name.
    pub async fn save_group(
        &self,
        id: Option<ItemId>,
        changes: FieldChanges,
    ) -> Result<Written, ItemError> {
        let parents: std::collections::BTreeMap<ItemId, Option<ItemId>> = self
            .list(&[ItemKind::Group])
            .await?
            .iter()
            .filter_map(|l| Group::try_from(&l.body).ok().map(|g| (l.id, g.parent_id)))
            .collect();
        // M2-02: identities are referenced only within their vault (§13.4).
        let identity_vaults = self.identity_vaults().await?;
        let group_vault = self.vault_of(id).await?;
        self.save(ItemKind::Group, id, None, move |body, clock, device| {
            let mut group = Group::try_from(&*body)
                .map_err(|e| vec![ValidationError::new("item", e.to_string())])?;
            apply_group_changes(&mut group, &changes)?;
            check_identity_vault(
                "identity_id",
                group_vault,
                group.defaults.identity_id,
                |i| identity_vaults.get(&i).copied(),
            )
            .map_err(|e| vec![e])?;
            if !group.is_vault_defaults && group.name.trim().is_empty() {
                return Err(vec![ValidationError::new("name", "a group needs a name")]);
            }
            if let Some(id) = id {
                validate_group_parent(id, group.parent_id, |g| parents.get(&g).copied().flatten())
                    .map_err(|e| vec![e])?;
            }
            if group.parent_id.is_some_and(|p| !parents.contains_key(&p)) {
                return Err(vec![ValidationError::new(
                    "parent_id",
                    "the parent group no longer exists",
                )]);
            }
            group.apply_to(body, clock, device);
            Ok(())
        })
        .await
    }

    /// Create (`id: None`, in the Personal vault) or rename / recolor a tag. Names
    /// are unique per vault, case-insensitively (§4.11).
    ///
    /// # Errors
    /// [`ItemError::Invalid`] for a duplicate or empty name or an unknown color.
    pub async fn save_tag(
        &self,
        id: Option<ItemId>,
        name: String,
        color: Option<String>,
    ) -> Result<Written, ItemError> {
        let tags = self.list(&[ItemKind::Tag]).await?;
        let vault = match id {
            Some(id) => tags.iter().find(|t| t.id == id).map(|t| t.vault),
            None => self.vault.personal_vault(),
        }
        .ok_or(ItemError::NotFound)?;
        let others: Vec<(ItemId, String)> = tags
            .iter()
            .filter(|t| t.vault == vault)
            .filter_map(|t| Tag::try_from(&t.body).ok().map(|v| (t.id, v.name)))
            .collect();
        validate_tag(
            id,
            &name,
            color.as_deref(),
            others.iter().map(|(i, n)| (*i, n.as_str())),
        )
        .map_err(ItemError::Invalid)?;
        self.save(
            ItemKind::Tag,
            id,
            Some(vault),
            move |body, clock, device| {
                let mut tag = Tag::try_from(&*body)
                    .map_err(|e| vec![ValidationError::new("item", e.to_string())])?;
                tag.name = name.trim().to_owned();
                tag.color = color;
                tag.apply_to(body, clock, device);
                Ok(())
            },
        )
        .await
    }

    /// Edit one host through its typed view (only what `f` changes is stamped).
    async fn edit_host(
        &self,
        id: ItemId,
        f: impl FnOnce(&mut Host) + Send,
    ) -> Result<Written, ItemError> {
        self.save(
            ItemKind::Host,
            Some(id),
            None,
            move |body, clock, device| {
                let mut host = Host::try_from(&*body)
                    .map_err(|e| vec![ValidationError::new("item", e.to_string())])?;
                f(&mut host);
                host.apply_to(body, clock, device);
                Ok(())
            },
        )
        .await
    }

    /// Move hosts to `group` (`None`: the top level).
    ///
    /// # Errors
    /// [`ItemError::NotFound`] if the group is gone; the first failing host.
    pub async fn move_to_group(
        &self,
        hosts: &[ItemId],
        group: Option<ItemId>,
    ) -> Result<Vec<Written>, ItemError> {
        if let Some(g) = group {
            let loaded = self.load(g).await?.ok_or(ItemError::NotFound)?;
            if loaded.body.kind != ItemKind::Group {
                return Err(ItemError::WrongKind(ItemKind::Group));
            }
        }
        let mut out = Vec::new();
        for id in hosts {
            out.push(self.edit_host(*id, move |h| h.group_id = group).await?);
        }
        Ok(out)
    }

    /// Add and remove tags on hosts; only `tags` changes. `create` makes (or reuses,
    /// case-insensitively) a tag of that name first and adds it. Returns the writes
    /// (the new tag first).
    ///
    /// # Errors
    /// An invalid new tag name; the first failing host.
    pub async fn set_tags(
        &self,
        hosts: &[ItemId],
        add: &[ItemId],
        remove: &[ItemId],
        create: Option<String>,
    ) -> Result<Vec<Written>, ItemError> {
        let mut out = Vec::new();
        let mut add = add.to_vec();
        if let Some(name) = create {
            let existing = self
                .list(&[ItemKind::Tag])
                .await?
                .into_iter()
                .filter(|t| Some(t.vault) == self.vault.personal_vault())
                .find(|t| Tag::try_from(&t.body).is_ok_and(|v| tag_key(&v.name) == tag_key(&name)))
                .map(|t| t.id);
            let id = match existing {
                Some(id) => id,
                None => {
                    let w = self.save_tag(None, name, None).await?;
                    let id = w.id;
                    out.push(w);
                    id
                }
            };
            add.push(id);
        }
        for id in hosts {
            let add = add.clone();
            let remove = remove.to_vec();
            out.push(
                self.edit_host(*id, move |h| {
                    h.tags.retain(|t| !remove.contains(t));
                    for t in add {
                        if !h.tags.contains(&t) {
                            h.tags.push(t);
                        }
                    }
                })
                .await?,
            );
        }
        Ok(out)
    }

    /// What deleting `group` would do (§9.2).
    ///
    /// # Errors
    /// [`ItemError::NotFound`]; storage failures.
    pub async fn plan_group_delete(
        &self,
        group: ItemId,
        mode: DeleteGroupMode,
    ) -> Result<DeletePlan, ItemError> {
        let items = self.list(&[ItemKind::Host, ItemKind::Group]).await?;
        let mut hosts = Vec::new();
        let mut groups = Vec::new();
        let mut parent = None;
        let mut found = false;
        for l in &items {
            match l.body.kind {
                ItemKind::Host => {
                    if let Ok(h) = Host::try_from(&l.body) {
                        hosts.push((l.id, h.group_id));
                    }
                }
                _ => {
                    if let Ok(g) = Group::try_from(&l.body) {
                        if l.id == group {
                            found = true;
                            parent = g.parent_id;
                        }
                        groups.push((l.id, g.parent_id));
                    }
                }
            }
        }
        if !found {
            return Err(ItemError::NotFound);
        }
        Ok(plan_delete(group, parent, &hosts, &groups, mode))
    }

    /// Delete `group`: move its hosts and subgroups to the parent group, or delete
    /// everything below it (§9.2). Returns every write.
    ///
    /// # Errors
    /// As [`ItemOps::plan_group_delete`]; the first failing write.
    pub async fn delete_group(
        &self,
        group: ItemId,
        mode: DeleteGroupMode,
    ) -> Result<Vec<Written>, ItemError> {
        let plan = self.plan_group_delete(group, mode).await?;
        let mut out = Vec::new();
        let to = plan.new_parent;
        for h in &plan.move_hosts {
            out.push(self.edit_host(*h, move |host| host.group_id = to).await?);
        }
        for g in &plan.move_groups {
            out.push(
                self.save(
                    ItemKind::Group,
                    Some(*g),
                    None,
                    move |body, clock, device| {
                        let mut group = Group::try_from(&*body)
                            .map_err(|e| vec![ValidationError::new("item", e.to_string())])?;
                        group.parent_id = to;
                        group.apply_to(body, clock, device);
                        Ok(())
                    },
                )
                .await?,
            );
        }
        for h in &plan.delete_hosts {
            out.push(self.delete(*h).await?);
        }
        for g in &plan.delete_groups {
            out.push(self.delete(*g).await?);
        }
        Ok(out)
    }

    /// Stamp the tombstone (the row stays, `deleted = 1`).
    ///
    /// # Errors
    /// [`ItemError::NotFound`], [`ItemError::ReadOnly`], storage failures.
    pub async fn delete(&self, id: ItemId) -> Result<Written, ItemError> {
        let loaded = self.load(id).await?.ok_or(ItemError::NotFound)?;
        if is_read_only(&loaded.body) {
            return Err(ItemError::ReadOnly);
        }
        let mut body = loaded.body;
        let device = self.vault.device_id();
        self.clock.with(|c| body.delete(c, device));
        self.store(id, loaded.vault, body).await
    }

    /// Copy every field to a new item with fresh stamps; the label becomes
    /// `"<label> (copy)"`.
    ///
    /// # Errors
    /// [`ItemError::NotFound`], storage failures.
    pub async fn duplicate(&self, id: ItemId) -> Result<Written, ItemError> {
        let loaded = self.load(id).await?.ok_or(ItemError::NotFound)?;
        let src = loaded.body;
        let device = self.vault.device_id();
        let label_key = match src.kind {
            ItemKind::Host
            | ItemKind::Identity
            | ItemKind::Key
            | ItemKind::Certificate
            | ItemKind::PortForward => "label",
            _ => "name",
        };
        let mut body = ItemBody::new(src.kind, src.schema_version);
        self.clock.with(|clock| {
            for (key, value) in &src.fields {
                if key != label_key && !value.value.is_null() {
                    body.set(key, value.value.clone(), clock, device);
                }
            }
            let base = src
                .get(label_key)
                .and_then(|v| v.as_text())
                .filter(|s| !s.is_empty())
                .or_else(|| src.get("address").and_then(|v| v.as_text()))
                .unwrap_or("item")
                .to_owned();
            body.set(label_key, format!("{base} (copy)"), clock, device);
        });
        self.store(ItemId::new(), loaded.vault, body).await
    }

    /// Set `pinned` on a host.
    ///
    /// # Errors
    /// As [`ItemOps::save`].
    pub async fn set_pinned(&self, id: ItemId, pinned: bool) -> Result<Written, ItemError> {
        self.save(
            ItemKind::Host,
            Some(id),
            None,
            move |body, clock, device| {
                if pinned {
                    body.set("pinned", true, clock, device);
                } else if body.get("pinned").is_some() {
                    body.set("pinned", false, clock, device);
                }
                Ok(())
            },
        )
        .await
    }

    /// A host with its password, for the edit form.
    ///
    /// # Errors
    /// [`ItemError::NotFound`], storage failures.
    pub async fn host_record(&self, id: ItemId) -> Result<HostRecord, ItemError> {
        let loaded = self.load(id).await?.ok_or(ItemError::NotFound)?;
        let host =
            Host::try_from(&loaded.body).map_err(|_| ItemError::WrongKind(ItemKind::Host))?;
        let last = self
            .engine
            .store()
            .get_device_local(id)
            .await?
            .and_then(|l| l.last_connected_at);
        Ok(HostRecord {
            summary: HostSummary::from_host(id, loaded.vault, &host, last),
            password: host
                .password
                .as_ref()
                .map(|p| SecretValue::from(p.expose())),
        })
    }

    /// Build the Hosts view catalog: hosts, tags, groups, identities, key and
    /// snippet names, device-local last-connected times.
    ///
    /// # Errors
    /// Storage failures.
    pub async fn catalog(&self) -> Result<HostCatalog, ItemError> {
        // M2-01: every live item (ids for missing-reference checks, §12.4).
        let items = self.list(&[]).await?;
        let locals: Vec<DeviceLocal> = self.engine.store().list_device_local().await?;
        let last = |id: ItemId| {
            locals
                .iter()
                .find(|l| l.item_id == id)
                .and_then(|l| l.last_connected_at)
        };
        let mut cat = HostCatalog {
            loaded_at: self.engine.store().now(),
            personal_vault: self.vault.personal_vault(),
            ..HostCatalog::default()
        };
        let vaults = self.engine.store().read(|r| r.list_vaults()).await?;
        for v in vaults {
            cat.vault_names
                .insert(v.id, vault_display_name(v.id, v.kind));
        }
        // M5-02: shared vault names, read-only vaults, this user's overrides.
        let info = super::shared::vault_info(self.engine.store(), &self.vault).await;
        cat.vault_names.extend(info.names);
        cat.shared_vaults = info.shared;
        cat.read_only_vaults = info.read_only;
        for layer in super::shared::overrides(&items, cat.personal_vault) {
            let keep = cat
                .overrides
                .get(&layer.host)
                .is_none_or(|cur| layer.item < cur.item);
            if keep {
                cat.overrides.insert(layer.host, layer);
            }
        }
        for item in &items {
            let b = &item.body;
            cat.lookup.mark_live(item.id);
            match b.kind {
                ItemKind::Host => match Host::try_from(b) {
                    Ok(h) => {
                        cat.hosts.insert(
                            item.id,
                            HostSummary::from_host(item.id, item.vault, &h, last(item.id)),
                        );
                    }
                    Err(e) => warn!(item = %item.id.short(), error = %e, "host skipped"),
                },
                ItemKind::Tag => {
                    if let Ok(t) = Tag::try_from(b) {
                        cat.tag_vaults.insert(item.id, item.vault);
                        cat.tags.insert(
                            item.id,
                            TagInfo {
                                name: t.name,
                                color: t.color,
                            },
                        );
                    }
                }
                ItemKind::Group => {
                    if let Ok(g) = Group::try_from(b) {
                        // M2-01: groups with their defaults; the vault-defaults item.
                        cat.lookup.insert_group(item.id, item.vault, &g);
                        if !g.is_vault_defaults {
                            cat.group_vaults.insert(item.id, item.vault);
                            cat.groups.insert(item.id, g.name);
                        }
                    }
                }
                ItemKind::Identity => {
                    if let Ok(i) = Identity::try_from(b) {
                        // M5-02
                        cat.identity_vaults.insert(item.id, item.vault);
                        cat.lookup.insert_identity(item.id, &i);
                        cat.identities.insert(
                            item.id,
                            IdentityInfo {
                                label: i.label,
                                username: i.username,
                                key_id: i.key_id,
                            },
                        );
                    }
                }
                ItemKind::Key => {
                    if let Ok(k) = Key::try_from(b) {
                        // M2-03: public data for the Keychain.
                        cat.key_details.insert(
                            item.id,
                            crate::views::keychain::keys::KeyInfo::from_key(item.vault, &k),
                        );
                        cat.keys.insert(item.id, k.label);
                    }
                }
                // M2-03: certificates with their derived fields (§4.6).
                ItemKind::Certificate => {
                    if let Ok(c) = sverb_core::model::Certificate::try_from(b) {
                        cat.certs.insert(
                            item.id,
                            crate::views::keychain::keys::CertSummary {
                                vault: item.vault,
                                info: sverb_core::keychain::cert::parse_cert(&c.cert).ok(),
                                label: c.label,
                                key_id: c.key_id,
                                cert: c.cert,
                            },
                        );
                    }
                }
                ItemKind::Snippet => {
                    if let Ok(s) = Snippet::try_from(b) {
                        cat.snippets.insert(item.id, s.name);
                    }
                }
                _ => {}
            }
        }
        Ok(cat)
    }

    /// Record a successful connect (device-local `last_connected_at`, frecency).
    /// Returns the new frecency.
    ///
    /// # Errors
    /// Storage failures.
    pub async fn touch_connected(&self, id: ItemId) -> Result<f64, ItemError> {
        let store = self.engine.store();
        Ok(store.touch_connected(id, store.now()).await?)
    }
}

// M2-03: keychain writes and the keychain effect executor.
pub mod keychain;
// M2-04: install key on host (exec runs over dedicated connections).
pub mod install;

// ---------------------------------------------------------------------- TUI service

fn done(tx: &EventSender, id: crate::app::EffectId, result: Result<EffectOutput, ErrorReport>) {
    let tx = tx.clone();
    tokio::spawn(async move {
        let _ = tx.send(UiEvent::EffectDone { id, result }).await;
    });
}

async fn report_error(tx: &EventSender, what: &str, err: &ItemError) {
    let report = ErrorReport::msg(format!("{what}: {err}"));
    let _ = tx
        .send(UiEvent::Vault(VaultEvent::ItemFailed(report)))
        .await;
}

/// Run an item effect for the TUI. Results come back as `EffectDone` (for effects
/// with an id) or `VaultEvent::ItemFailed`; every write updates the index.
pub fn execute(service: &VaultService, op: ItemEffect, tx: &EventSender) {
    // M2-04: install runs report progress over time; they resolve hosts themselves.
    let op = match op {
        ItemEffect::Keychain(crate::app::keychain::keys::KeychainEffect::Install(op)) => {
            install::execute(service, op, tx);
            return;
        }
        // M5-02: the vault selector.
        ItemEffect::SetNewItemVault(v) => {
            service.set_new_item_vault(v);
            return;
        }
        op => op,
    };
    let Some(ops) = service.item_ops() else {
        match op {
            ItemEffect::Save { id, .. }
            | ItemEffect::LoadHosts { id }
            | ItemEffect::LoadHost { id, .. }
            // M2-02
            | ItemEffect::SaveIdentity { id, .. }
            | ItemEffect::LoadIdentity { id, .. } => {
                done(tx, id, Err(ItemError::Locked.report()));
            }
            _ => debug!("item effect ignored: the vault is locked"),
        }
        return;
    };
    let service = service.clone();
    let tx = tx.clone();
    tokio::spawn(async move {
        let index = |w: &Written| service.index_upsert(w.id, w.vault, &w.body, &tx);
        match op {
            ItemEffect::Save {
                id,
                item,
                kind,
                changes,
            } => {
                // M2-01: groups (and the vault defaults) save through the same effect.
                let result = match kind {
                    ItemKind::Group => ops.save_group(item, changes).await,
                    // M1-14: a passphrase typed into an auth prompt ("save to vault").
                    ItemKind::Key => {
                        crate::services::ssh::save_key_changes(&ops, item, changes).await
                    }
                    _ => {
                        // M1-14: the host form's key-file import (task §2.6) creates the
                        // Key item first and points `key_id` at it.
                        let mut changes = changes;
                        match crate::services::ssh::import_key_file_change(&ops, &mut changes).await
                        {
                            Ok(imported) => {
                                if let Some(w) = &imported {
                                    index(w);
                                }
                                ops.save_host(item, changes).await
                            }
                            Err(e) => Err(e),
                        }
                    }
                };
                if let Ok(w) = &result {
                    index(w);
                }
                let result = result
                    .map(|w| EffectOutput::Item(w.id))
                    .map_err(|e| e.report());
                let _ = tx.send(UiEvent::EffectDone { id, result }).await;
            }
            ItemEffect::Delete(item) => match ops.delete(item).await {
                Ok(w) => index(&w),
                Err(e) => report_error(&tx, "Delete failed", &e).await,
            },
            ItemEffect::Duplicate(item) => match ops.duplicate(item).await {
                Ok(w) => index(&w),
                Err(e) => report_error(&tx, "Duplicate failed", &e).await,
            },
            ItemEffect::SetPinned { item, pinned } => match ops.set_pinned(item, pinned).await {
                Ok(w) => index(&w),
                Err(e) => report_error(&tx, "Pin failed", &e).await,
            },
            ItemEffect::LoadHosts { id } => {
                let result = ops
                    .catalog()
                    .await
                    .map(|c| EffectOutput::Hosts(Arc::new(c)))
                    .map_err(|e| e.report());
                let _ = tx.send(UiEvent::EffectDone { id, result }).await;
            }
            ItemEffect::LoadHost { id, item } => {
                let result = ops
                    .host_record(item)
                    .await
                    .map(|r| EffectOutput::Host(Box::new(r)))
                    .map_err(|e| e.report());
                let _ = tx.send(UiEvent::EffectDone { id, result }).await;
            }
            ItemEffect::TouchConnected(item) => match ops.touch_connected(item).await {
                Ok(frecency) => {
                    if let Some(snapshot) =
                        service.update_index(|ix| ix.set_item_frecency(item, frecency))
                    {
                        let _ = tx.send(UiEvent::IndexUpdated(snapshot)).await;
                    }
                }
                Err(e) => debug!(error = %e, "cannot record the connection time"),
            },
            // M2-01
            ItemEffect::MoveToGroup { items, group } => {
                match ops.move_to_group(&items, group).await {
                    Ok(ws) => ws.iter().for_each(index),
                    Err(e) => report_error(&tx, "Move failed", &e).await,
                }
            }
            ItemEffect::SetTags {
                items,
                add,
                remove,
                create,
            } => match ops.set_tags(&items, &add, &remove, create).await {
                Ok(ws) => ws.iter().for_each(index),
                Err(e) => report_error(&tx, "Tagging failed", &e).await,
            },
            ItemEffect::DeleteGroup { group, mode } => match ops.delete_group(group, mode).await {
                Ok(ws) => ws.iter().for_each(index),
                Err(e) => report_error(&tx, "Delete failed", &e).await,
            },
            ItemEffect::SaveTag { item, name, color } => {
                match ops.save_tag(item, name, color).await {
                    Ok(w) => index(&w),
                    Err(e) => report_error(&tx, "Tag not saved", &e).await,
                }
            }
            // M2-02
            ItemEffect::SaveIdentity {
                id,
                item,
                vault,
                changes,
            } => {
                let result = ops
                    .save_identity(item, vault, move |i| apply_identity_changes(i, &changes))
                    .await;
                if let Ok(w) = &result {
                    index(w);
                }
                let result = result
                    .map(|w| EffectOutput::Item(w.id))
                    .map_err(|e| e.report());
                let _ = tx.send(UiEvent::EffectDone { id, result }).await;
            }
            ItemEffect::LoadIdentity { id, item } => {
                let result = ops
                    .load_identity(item)
                    .await
                    .map(|(vault, i)| {
                        EffectOutput::Identity(Box::new(IdentityRecord::from_identity(
                            item, vault, &i,
                        )))
                    })
                    .map_err(|e| e.report());
                let _ = tx.send(UiEvent::EffectDone { id, result }).await;
            }
            ItemEffect::DeleteIdentity { item, convert } => {
                match ops.delete_identity(item, convert).await {
                    Ok(ws) => ws.iter().for_each(index),
                    Err(e) => report_error(&tx, "Delete failed", &e).await,
                }
            }
            // M2-03
            ItemEffect::Keychain(op) => {
                let ev = keychain::run(&ops, op, index).await;
                let _ = tx.send(UiEvent::Vault(VaultEvent::Keychain(ev))).await;
            }
            // M5-02
            ItemEffect::SetNewItemVault(_) => {}
            ItemEffect::Transfer {
                items,
                target,
                copy,
                refs,
            } => {
                use crate::app::hosts::SharedVaultEvent;
                let ev = match ops.transfer(&items, target, copy, refs).await {
                    Ok(ws) => {
                        ws.iter().for_each(index);
                        let n = items.len();
                        let what = if n == 1 {
                            "1 host".to_owned()
                        } else {
                            format!("{n} hosts")
                        };
                        SharedVaultEvent::Done(if copy {
                            format!("Copied {what}")
                        } else {
                            format!("Moved {what}")
                        })
                    }
                    Err(ItemError::Blocked(refs)) => SharedVaultEvent::TransferBlocked {
                        items,
                        target,
                        copy,
                        refs,
                    },
                    Err(e) => {
                        let what = if copy { "Copy failed" } else { "Move failed" };
                        return report_error(&tx, what, &e).await;
                    }
                };
                let _ = tx.send(UiEvent::Vault(VaultEvent::Shared(ev))).await;
            }
            ItemEffect::SetOverride { host, identity } => {
                match ops.set_override(host, identity).await {
                    Ok(ws) => {
                        ws.iter().for_each(index);
                        let msg = if identity.is_some() {
                            "Your own credentials are used for this host"
                        } else {
                            "Override removed: the shared credentials are used"
                        };
                        let ev = crate::app::hosts::SharedVaultEvent::Done(msg.to_owned());
                        let _ = tx.send(UiEvent::Vault(VaultEvent::Shared(ev))).await;
                    }
                    Err(e) => report_error(&tx, "Saving the override failed", &e).await,
                }
            }
        }
    });
}
