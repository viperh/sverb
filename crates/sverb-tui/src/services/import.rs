//! M2-11: the import / export service (SPEC §9.13), shared by the import wizard
//! (`Effect::Import`) and the CLI (`sverb import …`, `sverb export …`).
//!
//! Imports are a dry run first ([`ImportService::preview`]: parse, then classify against
//! the vault). [`ImportService::apply`] re-classifies against the current vault,
//! imports the confirmed IdentityFiles as Key items (deduplicated by public key), builds
//! the stamped bodies and stores **everything in one transaction** (any failure rolls
//! back the whole import). Locally-acting values the user saw in the preview
//! (ProxyCommand, non-loopback forwards) count as approved at confirmation (M2-10
//! §2.2): [`ApplyReport::approvals`] become `local_approvals` rows (M2-10) after the
//! items are written, and are handed to the forward approval store when one is given.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sverb_conn::forward::{ApprovalStore, RiskyValue};
// M2-10
use sverb_core::resolve::approval::{ActionKind, LocalAction};
use sverb_core::error_report::ErrorReport;
use sverb_core::exporters::{self, csv::CsvRow, ssh_config::SshConfigExport, write_file};
use sverb_core::importers::{
    self, ApplyOptions, ApprovalNote, ConflictPolicy, Existing, ImportPlan,
    backup::{BackupItem, BackupPayload, BackupVault},
    preview::{ExistingItem, classify, materialize},
    ssh_config::SshConfigOptions,
};
use sverb_core::keychain::{
    self,
    import::{ImportOptions, import_text, needs_passphrase},
};
use sverb_core::model::{
    Group, Host, ItemBody, ItemId, ItemKind, PortForward, Tag, UnixMillis, VaultId, current_schema,
};
use sverb_core::secret::SecretString;
use sverb_store::VaultKind;
use sverb_store::meta::keys;

use super::vault::{UnlockedVault, VaultEngine, vault_display_name};

/// An import or export failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportFailure(pub String);

impl std::fmt::Display for ImportFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ImportFailure {}

impl ImportFailure {
    /// The user-facing report.
    pub fn report(&self) -> ErrorReport {
        ErrorReport::msg(self.0.clone())
    }
}

fn fail(e: impl std::fmt::Display) -> ImportFailure {
    ImportFailure(e.to_string())
}

/// What to import from.
#[derive(Debug)]
pub enum SourceSpec {
    /// `~/.ssh/config` (default) or a file.
    SshConfig(Option<PathBuf>),
    /// `~/.ssh/known_hosts` (default) or a file.
    KnownHosts(Option<PathBuf>),
    /// A CSV file.
    Csv(PathBuf),
    /// A `.sverb-backup` and its export password.
    Backup {
        /// The file.
        path: PathBuf,
        /// The export password.
        password: SecretString,
    },
    // M7-03
    /// PuTTY sessions: a sessions directory, or `None` for the user's own
    /// (`~/.putty/sessions`; the registry on Windows).
    Putty(Option<PathBuf>),
}

/// `~` → the home directory.
pub fn expand_home(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    match s.strip_prefix("~/") {
        Some(rest) => home_dir().map_or_else(|| path.to_path_buf(), |h| h.join(rest)),
        None if s == "~" => home_dir().unwrap_or_else(|| path.to_path_buf()),
        None => path.to_path_buf(),
    }
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

impl SourceSpec {
    /// The resolved file.
    pub fn path(&self) -> PathBuf {
        match self {
            Self::SshConfig(p) => p.as_deref().map_or_else(
                || SshConfigOptions::user().ssh_dir.join("config"),
                expand_home,
            ),
            Self::KnownHosts(p) => p.as_deref().map_or_else(
                || SshConfigOptions::user().ssh_dir.join("known_hosts"),
                expand_home,
            ),
            Self::Csv(p) | Self::Backup { path: p, .. } => expand_home(p),
            // M7-03
            Self::Putty(p) => p.as_deref().map_or_else(
                || importers::putty_sessions::default_dir().unwrap_or_default(),
                expand_home,
            ),
        }
    }
}

/// Which IdentityFiles to import as keys (the separate confirmation, §9.13).
#[derive(Debug, Default)]
pub struct KeyChoice {
    /// Import them (off: hosts are imported without keys).
    pub import: bool,
    /// Passphrases for encrypted non-OpenSSH files, by path as written. Encrypted
    /// OpenSSH keys are imported as they are (auth asks for the passphrase); other
    /// encrypted files without a passphrase are skipped.
    pub passphrases: BTreeMap<String, SecretString>,
}

/// The state of one IdentityFile (for the confirmation list).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityFileState {
    /// Importable without a passphrase.
    Ready,
    /// An encrypted key that needs its passphrase to be imported.
    NeedsPassphrase,
    /// Cannot be imported.
    Unreadable(String),
}

/// An IdentityFile of the plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityFileInfo {
    /// As written in the config.
    pub path: String,
    /// The file read.
    pub resolved: PathBuf,
    /// Ready, needs a passphrase, unreadable.
    pub state: IdentityFileState,
}

/// The outcome of a confirmed import.
#[derive(Debug, Clone, Default)]
pub struct ApplyReport {
    /// Items created.
    pub created: usize,
    /// Items overwritten.
    pub updated: usize,
    /// Duplicates (nothing written).
    pub duplicates: usize,
    /// Conflicts kept as they were.
    pub conflicts_skipped: usize,
    /// Keys imported from IdentityFiles.
    pub keys_imported: usize,
    /// IdentityFiles not imported, with reasons.
    pub keys_skipped: Vec<(String, String)>,
    /// Locally-acting values approved at confirmation.
    pub approvals: Vec<ApprovalNote>,
    /// Everything written (`(id, vault, body)`, for the search index).
    pub written: Vec<(ItemId, VaultId, ItemBody)>,
}

impl ApplyReport {
    /// One line for a toast or the CLI.
    pub fn summary(&self) -> String {
        let mut s = format!(
            "Imported {} new, {} updated, {} duplicate, {} conflicts skipped",
            self.created, self.updated, self.duplicates, self.conflicts_skipped
        );
        if self.keys_imported > 0 {
            s.push_str(&format!(", {} keys", self.keys_imported));
        }
        if !self.keys_skipped.is_empty() {
            s.push_str(&format!(
                ", {} identity files skipped",
                self.keys_skipped.len()
            ));
        }
        s
    }
}

/// Backup export options.
#[derive(Debug, Clone, Copy)]
pub struct BackupKdf {
    /// Argon2id memory (KiB).
    pub m_kib: u32,
    /// Passes.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

impl Default for BackupKdf {
    fn default() -> Self {
        Self {
            m_kib: sverb_crypto::kdf::Argon2Params::DEFAULT_M_KIB,
            t: sverb_crypto::kdf::Argon2Params::DEFAULT_T,
            p: sverb_crypto::kdf::Argon2Params::DEFAULT_P,
        }
    }
}

/// Import and export over an unlocked vault.
#[derive(Debug, Clone)]
pub struct ImportService {
    engine: VaultEngine,
    vault: Arc<UnlockedVault>,
}

impl ImportService {
    /// The service.
    pub fn new(engine: VaultEngine, vault: Arc<UnlockedVault>) -> Self {
        Self { engine, vault }
    }

    /// The vault new items go to when none is chosen (Personal).
    pub fn default_vault(&self) -> Option<VaultId> {
        self.vault.personal_vault()
    }

    /// Every vault with its display name.
    ///
    /// # Errors
    /// Storage failures.
    pub async fn vaults(&self) -> Result<Vec<(VaultId, String, VaultKind)>, ImportFailure> {
        let rows = self.engine.store().list_vaults().await.map_err(fail)?;
        let loaded = self.vault.vault_ids();
        Ok(rows
            .into_iter()
            .filter(|r| loaded.contains(&r.id))
            .map(|r| (r.id, vault_display_name(r.id, r.kind), r.kind))
            .collect())
    }

    /// Every live item (all vaults).
    async fn items(&self) -> Result<Vec<ExistingItem>, ImportFailure> {
        let rows = self.engine.store().list_all_items().await.map_err(fail)?;
        let mut out = Vec::new();
        for row in rows.into_iter().filter(|r| !r.deleted) {
            match self.vault.open(&row) {
                Ok(body) if !body.is_deleted() => out.push(ExistingItem {
                    id: row.id,
                    vault: row.vault_id,
                    body,
                }),
                Ok(_) => {}
                Err(e) => tracing::debug!(item = %row.id.short(), error = %e, "item skipped"),
            }
        }
        Ok(out)
    }

    /// The vault snapshot to classify against.
    ///
    /// # Errors
    /// Storage failures; no vault.
    pub async fn existing(&self, vault: Option<VaultId>) -> Result<Existing, ImportFailure> {
        let vault = vault
            .or_else(|| self.default_vault())
            .ok_or_else(|| ImportFailure("no vault to import into".to_owned()))?;
        Ok(Existing::new(self.items().await?, vault))
    }

    /// Groups of `vault` as `(id, path)` (for the target picker), sorted by path.
    ///
    /// # Errors
    /// Storage failures.
    pub async fn group_paths(
        &self,
        vault: VaultId,
    ) -> Result<Vec<(ItemId, String)>, ImportFailure> {
        let groups: BTreeMap<ItemId, Group> = self
            .items()
            .await?
            .into_iter()
            .filter(|i| i.vault == vault && i.body.kind == ItemKind::Group)
            .filter_map(|i| Group::try_from(&i.body).ok().map(|g| (i.id, g)))
            .filter(|(_, g)| !g.is_vault_defaults)
            .collect();
        let mut out: Vec<(ItemId, String)> = groups
            .keys()
            .map(|id| (*id, group_path(*id, &groups)))
            .collect();
        out.sort_by_key(|a| a.1.to_lowercase());
        Ok(out)
    }

    /// Parses the source (nothing is classified yet).
    ///
    /// # Errors
    /// Unreadable or malformed sources; a wrong backup password.
    pub async fn parse(&self, source: &SourceSpec) -> Result<ImportPlan, ImportFailure> {
        parse_source(source).await
    }

    /// Parse and classify against `vault` (default Personal) with `group` as the target.
    ///
    /// # Errors
    /// As [`ImportService::parse`]; storage failures.
    pub async fn preview(
        &self,
        source: &SourceSpec,
        vault: Option<VaultId>,
        group: Option<ItemId>,
    ) -> Result<ImportPlan, ImportFailure> {
        let mut plan = self.parse(source).await?;
        let existing = self.existing(vault).await?;
        classify(&mut plan, &existing, group);
        Ok(plan)
    }

    /// The IdentityFiles of `plan` with their state (read from disk).
    pub fn identity_files(&self, plan: &ImportPlan) -> Vec<IdentityFileInfo> {
        identity_files(plan)
    }

    /// Writes the confirmed import in one transaction.
    ///
    /// # Errors
    /// Storage failures (nothing is written), an inconsistent plan.
    pub async fn apply(
        &self,
        plan: ImportPlan,
        vault: Option<VaultId>,
        group: Option<ItemId>,
        policy: ConflictPolicy,
        keys: KeyChoice,
        forward_approvals: Option<&dyn ApprovalStore>,
    ) -> Result<ApplyReport, ImportFailure> {
        let mut plan = plan;
        let existing = self.existing(vault).await?;
        let vault = existing.vault;
        if let Some(g) = group {
            let ok = existing
                .get(g)
                .is_some_and(|e| e.vault == vault && e.body.kind == ItemKind::Group);
            if !ok {
                return Err(ImportFailure(
                    "the target group is not a group of the target vault".to_owned(),
                ));
            }
        }
        classify(&mut plan, &existing, group);
        let device = self.vault.device_id();
        let mut clock = self.vault.hlc();
        let mut report = ApplyReport::default();

        // Identity files → Key items (dedup by public key).
        let mut identity_keys = BTreeMap::new();
        let mut writes: Vec<(ItemId, VaultId, ItemBody)> = Vec::new();
        if keys.import {
            let mut publics = existing.key_publics();
            for info in identity_files(&plan) {
                let text = match std::fs::read_to_string(&info.resolved) {
                    Ok(t) => t,
                    Err(e) => {
                        report.keys_skipped.push((info.path.clone(), e.to_string()));
                        continue;
                    }
                };
                let pass = keys
                    .passphrases
                    .get(&info.path)
                    .map(|p| p.expose().to_owned());
                let imported = match import_text(&text, pass.as_deref(), ImportOptions::default()) {
                    Ok(k) => k,
                    Err(e) => {
                        report.keys_skipped.push((info.path.clone(), e.to_string()));
                        continue;
                    }
                };
                if let Some(id) = keychain::import::find_duplicate(
                    &imported.public_key,
                    publics.iter().map(|(i, p)| (*i, p.as_str())),
                ) {
                    identity_keys.insert(info.path.clone(), id);
                    continue;
                }
                let stem = keychain::import::file_stem(&info.path);
                let label = imported.suggested_label(stem.as_deref());
                let public = imported.public_key.clone();
                let key = imported.into_key(label);
                let id = ItemId::new();
                let mut body = ItemBody::new(ItemKind::Key, current_schema(ItemKind::Key));
                key.apply_to(&mut body, &mut clock, device);
                writes.push((id, vault, body));
                publics.push((id, public));
                identity_keys.insert(info.path.clone(), id);
                report.keys_imported += 1;
            }
        }

        let opts = ApplyOptions {
            vault: Some(vault),
            group,
            policy,
            identity_keys,
        };
        let set = materialize(
            &plan,
            &existing,
            &opts,
            &mut clock,
            device,
            &mut ItemId::new,
        )
        .map_err(fail)?;
        report.created = set.created();
        report.updated = set.updated();
        report.duplicates = set.duplicates;
        report.conflicts_skipped = set.conflicts_skipped;
        report.approvals = set.approvals;
        writes.extend(set.writes.into_iter().map(|w| (w.id, w.vault, w.body)));

        // Seal everything, then one transaction.
        let mut sealed = Vec::with_capacity(writes.len());
        for (id, v, body) in &writes {
            let (key_version, envelope) = self.vault.seal(*v, *id, body).map_err(fail)?;
            sealed.push((*id, *v, key_version, envelope, body.is_deleted()));
        }
        let hlc = clock.last();
        self.engine
            .store()
            .write(move |w| {
                for (id, v, key_version, envelope, deleted) in &sealed {
                    w.put_item(*v, *id, *key_version, envelope, *deleted, true)?;
                }
                w.set_meta(keys::HLC_LAST, &hlc.as_u64().to_be_bytes())
            })
            .await
            .map_err(|e| ImportFailure(format!("import rolled back: {e}")))?;

        // M2-10: the values the user saw in the preview are approved on this device
        // (`local_approvals`, never synced). `forward_approvals` (the forward
        // manager's store) is the same device view in sverb; it is kept for callers
        // that pass another store.
        let notes: Vec<LocalAction> = report
            .approvals
            .iter()
            .filter_map(|n| {
                ActionKind::from_field(&n.field)
                    .map(|kind| LocalAction::new(n.item_id, kind, n.value.clone()))
            })
            .collect();
        self.engine
            .store()
            .approve_all_local(&notes)
            .await
            .map_err(|e| ImportFailure(format!("approvals not stored: {e}")))?;
        if let Some(store) = forward_approvals {
            for note in &report.approvals {
                let field: &'static str = match note.field.as_str() {
                    "bind_addr" => "bind_addr",
                    "dest_host" => "dest_host",
                    _ => continue,
                };
                store.approve(&RiskyValue {
                    rule: note.item_id,
                    field,
                    value: note.value.clone(),
                    synced: false,
                });
            }
        }
        report.written = writes;
        Ok(report)
    }

    // ------------------------------------------------------------------ exports

    /// Writes an encrypted backup of the Personal vault (and the shared vaults when
    /// `include_shared`). Returns the item count.
    ///
    /// # Errors
    /// A weak password, an existing file without `overwrite`, I/O or crypto errors.
    pub async fn export_backup(
        &self,
        path: &Path,
        password: SecretString,
        include_shared: bool,
        overwrite: bool,
        kdf: BackupKdf,
    ) -> Result<usize, ImportFailure> {
        exporters::backup::check_password(password.expose()).map_err(fail)?;
        check_target(path, overwrite)?;
        let vaults: Vec<(VaultId, String, VaultKind)> = self
            .vaults()
            .await?
            .into_iter()
            .filter(|(_, _, k)| include_shared || *k == VaultKind::Personal)
            .collect();
        let items = self.items().await?;
        let mut payload = BackupPayload::default();
        for (id, name, kind) in &vaults {
            let defaults = items.iter().find_map(|i| {
                (i.vault == *id
                    && i.body.kind == ItemKind::Group
                    && Group::try_from(&i.body).is_ok_and(|g| g.is_vault_defaults))
                .then_some(i.id)
            });
            payload.vaults.push(BackupVault {
                id: *id,
                name: name.clone(),
                kind: match kind {
                    VaultKind::Personal => "personal",
                    VaultKind::Shared => "shared",
                }
                .to_owned(),
                defaults,
            });
        }
        for item in items {
            if vaults.iter().any(|(v, _, _)| *v == item.vault) {
                payload.items.push(BackupItem {
                    id: item.id,
                    vault: item.vault,
                    body: item.body,
                });
            }
        }
        let count = payload.items.len();
        let path = path.to_path_buf();
        tokio::task::spawn_blocking(move || {
            let text = exporters::backup::encrypt(
                &payload,
                password.expose(),
                kdf.m_kib,
                kdf.t,
                kdf.p,
                UnixMillis::now(),
            )
            .map_err(fail)?;
            write_file(&path, text.as_bytes(), overwrite).map_err(|e| write_error(&path, &e))
        })
        .await
        .map_err(fail)??;
        Ok(count)
    }

    /// Writes the hosts as an `ssh_config` (lossy, no secrets). Returns the host count.
    ///
    /// # Errors
    /// An existing file without `overwrite`, I/O errors.
    pub async fn export_ssh_config(
        &self,
        path: &Path,
        overwrite: bool,
    ) -> Result<usize, ImportFailure> {
        check_target(path, overwrite)?;
        let items = self.items().await?;
        let mut data = SshConfigExport::default();
        for i in &items {
            match i.body.kind {
                ItemKind::Host => {
                    if let Ok(h) = Host::try_from(&i.body) {
                        data.hosts.push((i.id, h));
                    }
                }
                ItemKind::Group => {
                    if let Ok(g) = Group::try_from(&i.body) {
                        data.groups.insert(i.id, g);
                    }
                }
                ItemKind::PortForward => {
                    if let Ok(f) = PortForward::try_from(&i.body) {
                        data.forwards.push(f);
                    }
                }
                _ => {}
            }
        }
        data.hosts
            .sort_by_key(|a| a.1.display_label().to_lowercase());
        let count = data.hosts.len();
        let text = exporters::ssh_config::export(&data);
        write_file(path, text.as_bytes(), overwrite).map_err(|e| write_error(path, &e))?;
        Ok(count)
    }

    /// Writes the hosts as CSV. Returns the host count.
    ///
    /// # Errors
    /// An existing file without `overwrite`, I/O errors.
    pub async fn export_csv(&self, path: &Path, overwrite: bool) -> Result<usize, ImportFailure> {
        check_target(path, overwrite)?;
        let items = self.items().await?;
        let groups: BTreeMap<ItemId, Group> = items
            .iter()
            .filter(|i| i.body.kind == ItemKind::Group)
            .filter_map(|i| Group::try_from(&i.body).ok().map(|g| (i.id, g)))
            .collect();
        let tags: BTreeMap<ItemId, String> = items
            .iter()
            .filter(|i| i.body.kind == ItemKind::Tag)
            .filter_map(|i| Tag::try_from(&i.body).ok().map(|t| (i.id, t.name)))
            .collect();
        let mut rows: Vec<CsvRow> = items
            .iter()
            .filter(|i| i.body.kind == ItemKind::Host)
            .filter_map(|i| Host::try_from(&i.body).ok())
            .map(|h| CsvRow {
                label: h.label.clone(),
                address: h.address.clone(),
                port: h.port,
                username: h.username.clone(),
                group: h
                    .group_id
                    .filter(|g| groups.contains_key(g))
                    .map(|g| group_path(g, &groups)),
                tags: h.tags.iter().filter_map(|t| tags.get(t).cloned()).collect(),
            })
            .collect();
        rows.sort_by_key(|a| a.label.to_lowercase());
        let text = exporters::csv::export(&rows).map_err(ImportFailure)?;
        write_file(path, text.as_bytes(), overwrite).map_err(|e| write_error(path, &e))?;
        Ok(rows.len())
    }
}

fn check_target(path: &Path, overwrite: bool) -> Result<(), ImportFailure> {
    if !overwrite && path.exists() {
        return Err(ImportFailure(format!(
            "{} already exists; not overwritten (pass --force to replace it)",
            path.display()
        )));
    }
    Ok(())
}

fn write_error(path: &Path, e: &std::io::Error) -> ImportFailure {
    if e.kind() == std::io::ErrorKind::AlreadyExists {
        ImportFailure(format!(
            "{} already exists; not overwritten (pass --force to replace it)",
            path.display()
        ))
    } else {
        ImportFailure(format!("cannot write {}: {e}", path.display()))
    }
}

/// `a/b/c` of a group.
fn group_path(id: ItemId, groups: &BTreeMap<ItemId, Group>) -> String {
    let mut parts = Vec::new();
    let mut cur = Some(id);
    while let Some(g) = cur.and_then(|c| groups.get(&c)) {
        parts.push(g.name.clone());
        if parts.len() > 64 {
            break;
        }
        cur = g.parent_id;
    }
    parts.reverse();
    parts.join("/")
}

/// Reads and parses a source (backups are decrypted off the runtime).
async fn parse_source(source: &SourceSpec) -> Result<ImportPlan, ImportFailure> {
    let path = source.path();
    let read = |p: &Path| {
        std::fs::read_to_string(p)
            .map_err(|e| ImportFailure(format!("cannot read {}: {e}", p.display())))
    };
    match source {
        SourceSpec::SshConfig(_) => {
            let opts = SshConfigOptions::user();
            importers::ssh_config::parse_file(&path, &opts).map_err(fail)
        }
        SourceSpec::KnownHosts(_) => Ok(importers::known_hosts::parse(&read(&path)?)),
        SourceSpec::Csv(_) => importers::csv::parse(&read(&path)?).map_err(fail),
        // M7-03
        SourceSpec::Putty(Some(_)) => importers::putty_sessions::parse_dir(&path).map_err(fail),
        SourceSpec::Putty(None) => importers::putty_sessions::parse_user().map_err(fail),
        SourceSpec::Backup { password, .. } => {
            let text = read(&path)?;
            let password = SecretString::from(password.expose());
            tokio::task::spawn_blocking(move || {
                importers::backup::decrypt(&text, password.expose())
                    .map(|p| importers::backup::plan(&p))
                    .map_err(fail)
            })
            .await
            .map_err(fail)?
        }
    }
}

/// `~`, `%d` (home) and relative paths (to the home directory) of an IdentityFile.
fn resolve_identity(path: &str) -> PathBuf {
    let home = home_dir();
    let p = match &home {
        Some(h) => path.replace("%d", &h.to_string_lossy()),
        None => path.to_owned(),
    };
    let pb = expand_home(Path::new(&p));
    if pb.is_relative()
        && let Some(h) = home
    {
        return h.join(pb);
    }
    pb
}

fn identity_files(plan: &ImportPlan) -> Vec<IdentityFileInfo> {
    plan.identity_files()
        .into_iter()
        .map(|path| {
            let resolved = resolve_identity(&path);
            let state = match std::fs::read_to_string(&resolved) {
                Err(e) => IdentityFileState::Unreadable(e.to_string()),
                Ok(text) => {
                    let openssh = text.contains("BEGIN OPENSSH PRIVATE KEY");
                    if needs_passphrase(&text) && !openssh {
                        IdentityFileState::NeedsPassphrase
                    } else {
                        IdentityFileState::Ready
                    }
                }
            };
            IdentityFileInfo {
                path,
                resolved,
                state,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------- the TUI

use crate::app::UiEvent;
use crate::services::EventSender;
use crate::services::vault::VaultService;
use crate::views::import_wizard::{
    ExportFormat, ImportEffect, ImportEvent, ImportRequest, Policy, PreviewData, PreviewRow,
    WizardSource,
};

fn spec_of(r: &ImportRequest) -> SourceSpec {
    let path = PathBuf::from(&r.path);
    match r.source {
        WizardSource::SshConfig => SourceSpec::SshConfig(Some(path)),
        WizardSource::KnownHosts => SourceSpec::KnownHosts(Some(path)),
        WizardSource::Csv => SourceSpec::Csv(path),
        // M7-03
        WizardSource::Putty if r.path.trim().is_empty() => SourceSpec::Putty(None),
        WizardSource::Putty => SourceSpec::Putty(Some(path)),
        WizardSource::Backup => SourceSpec::Backup {
            path,
            password: SecretString::from(r.password.as_ref().map_or("", |p| p.expose())),
        },
    }
}

fn policy_of(p: Policy) -> ConflictPolicy {
    match p {
        Policy::Skip => ConflictPolicy::Skip,
        Policy::Overwrite => ConflictPolicy::Overwrite,
        Policy::KeepBoth => ConflictPolicy::KeepBoth,
    }
}

/// The wizard's view of a classified plan (no secrets: backup rows show only labels,
/// ids and redacted diffs).
pub fn preview_data(plan: &ImportPlan, files: &[IdentityFileInfo]) -> PreviewData {
    let c = plan.counts();
    PreviewData {
        new: c.new,
        duplicate: c.duplicate,
        conflict: c.conflict,
        rows: plan
            .items
            .iter()
            .map(|i| PreviewRow {
                status: i.status.as_str().to_owned(),
                kind: i.kind.as_str().to_owned(),
                label: i.label.clone(),
                details: i
                    .fields
                    .iter()
                    .filter(|(k, _)| k.as_str() != "label" && k.as_str() != "name")
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(" "),
                diffs: match &i.status {
                    importers::PlanStatus::Conflict(_, d) => d
                        .iter()
                        .map(|d| format!("{}: {} -> {}", d.field, d.existing, d.imported))
                        .collect(),
                    _ => Vec::new(),
                },
            })
            .collect(),
        skipped: plan
            .skipped
            .iter()
            .map(|s| match &s.source_line {
                Some(l) => format!("{l}: {}", s.reason),
                None => s.reason.clone(),
            })
            .collect(),
        warnings: plan.warnings.clone(),
        notes: plan.notes.clone(),
        identity_files: files
            .iter()
            .map(|f| match &f.state {
                IdentityFileState::Ready => f.path.clone(),
                IdentityFileState::NeedsPassphrase => {
                    format!(
                        "{} (encrypted: skipped, import it from the Keychain)",
                        f.path
                    )
                }
                IdentityFileState::Unreadable(e) => format!("{} (cannot read: {e})", f.path),
            })
            .collect(),
        ..PreviewData::default()
    }
}

/// Run an import wizard effect. Results come back as `UiEvent::Import`; written items
/// update the search index.
pub fn execute(vault: Option<&VaultService>, op: ImportEffect, tx: &EventSender) {
    let dialog = match &op {
        ImportEffect::Preview { dialog, .. }
        | ImportEffect::Apply { dialog, .. }
        | ImportEffect::Export { dialog, .. } => *dialog,
    };
    let tx = tx.clone();
    let vault = vault.cloned();
    tokio::spawn(async move {
        let failed = |message: String| UiEvent::Import(ImportEvent::Failed { dialog, message });
        let Some((vs, unlocked)) = vault.and_then(|v| v.unlocked().map(|u| (v, u))) else {
            let _ = tx.send(failed("The vault is locked".to_owned())).await;
            return;
        };
        let svc = ImportService::new(vs.engine().clone(), unlocked);
        let ev = match op {
            ImportEffect::Preview { request, .. } => {
                let spec = spec_of(&request);
                match svc.preview(&spec, request.vault, request.group).await {
                    Ok(plan) => {
                        let files = svc.identity_files(&plan);
                        let mut data = preview_data(&plan, &files);
                        let target = request.vault.or_else(|| svc.default_vault());
                        data.vault = target;
                        data.vaults = svc
                            .vaults()
                            .await
                            .unwrap_or_default()
                            .into_iter()
                            .map(|(id, name, _)| (id, name))
                            .collect();
                        if let Some(v) = target {
                            data.groups = svc.group_paths(v).await.unwrap_or_default();
                        }
                        UiEvent::Import(ImportEvent::Previewed {
                            dialog,
                            preview: Box::new(data),
                        })
                    }
                    Err(e) => failed(e.0),
                }
            }
            ImportEffect::Apply {
                request,
                policy,
                import_keys,
                ..
            } => {
                let spec = spec_of(&request);
                let result = match svc.parse(&spec).await {
                    Ok(plan) => {
                        svc.apply(
                            plan,
                            request.vault,
                            request.group,
                            policy_of(policy),
                            KeyChoice {
                                import: import_keys,
                                ..KeyChoice::default()
                            },
                            None,
                        )
                        .await
                    }
                    Err(e) => Err(e),
                };
                match result {
                    Ok(report) => {
                        for (id, v, body) in &report.written {
                            vs.index_upsert(*id, *v, body, &tx);
                        }
                        UiEvent::Import(ImportEvent::Applied {
                            dialog,
                            summary: report.summary(),
                        })
                    }
                    Err(e) => failed(e.0),
                }
            }
            ImportEffect::Export {
                format,
                path,
                password,
                include_shared,
                overwrite,
                ..
            } => {
                let file = expand_home(Path::new(&path));
                let result = match format {
                    ExportFormat::Backup => svc
                        .export_backup(
                            &file,
                            SecretString::from(password.as_ref().map_or("", |p| p.expose())),
                            include_shared,
                            overwrite,
                            BackupKdf::default(),
                        )
                        .await
                        .map(|n| format!("Backed up {n} items to {}", file.display())),
                    ExportFormat::SshConfig => svc
                        .export_ssh_config(&file, overwrite)
                        .await
                        .map(|n| format!("Exported {n} hosts to {}", file.display())),
                    ExportFormat::Csv => svc
                        .export_csv(&file, overwrite)
                        .await
                        .map(|n| format!("Exported {n} hosts to {}", file.display())),
                };
                match result {
                    Ok(summary) => UiEvent::Import(ImportEvent::Exported { dialog, summary }),
                    Err(e) => failed(e.0),
                }
            }
        };
        let _ = tx.send(ev).await;
    });
}

#[cfg(test)]
#[path = "import_tests.rs"]
mod tests;
