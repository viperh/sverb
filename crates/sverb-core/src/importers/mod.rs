//! Imports (SPEC §9.13): `~/.ssh/config`, `known_hosts`, CSV and sverb backups.
//!
//! Every import is a **dry run first**. An importer turns its source into an
//! [`ImportPlan`]: the planned items (hosts, groups, tags, forwards, known hosts, backup
//! bodies), what was skipped (with the source line and a reason) and warnings. Nothing
//! here touches the store:
//!
//! 1. parse: [`ssh_config::parse_file`], [`known_hosts::parse`], [`csv::parse`],
//!    [`backup::decrypt`] + [`backup::plan`];
//! 2. classify against the existing items ([`preview::classify`] with an
//!    [`preview::Existing`] snapshot): every item is `New`, `Duplicate(existing)` or
//!    `Conflict(existing, diffs)`;
//! 3. show the preview ([`ImportPlan::counts`], [`ImportPlan::render_table`]), let the
//!    user pick the target vault and group and the [`ConflictPolicy`];
//! 4. [`preview::materialize`] builds the stamped bodies to write (one transaction, in
//!    the caller), plus the locally-acting values the confirmation approves.
//!
//! Duplicate detection: hosts by `(address, port, user)`, keys by public key, known
//! hosts by `(pattern, key)`, tags by name, groups by name and parent, backup items by
//! id.
//!
//! The PuTTY importer is [`putty_sessions`], producing the same
//! [`ImportPlan`] of [`HostDraft`]s ([`ImportSource::Putty`]).

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};

use crate::model::{ForwardKind, ItemBody, ItemId, ItemKind, KnownHost};

pub mod backup;
pub mod csv;
pub mod known_hosts;
pub mod preview;
pub mod ssh_config;
// PuTTY sessions → HostDrafts, same pipeline.
pub mod putty_sessions;

pub use preview::{ApplyOptions, ApprovalNote, ConflictPolicy, Existing, WriteSet};

/// Where an import comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImportSource {
    /// `~/.ssh/config` (OpenSSH client configuration).
    SshConfig,
    /// `~/.ssh/known_hosts`.
    KnownHosts,
    /// `label,address,port,username,group,tags`.
    Csv,
    /// An encrypted `.sverb-backup`.
    Backup,
    /// PuTTY sessions.
    Putty,
}

impl ImportSource {
    /// The CLI name (`ssh-config`, `known-hosts`, …).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SshConfig => "ssh-config",
            Self::KnownHosts => "known-hosts",
            Self::Csv => "csv",
            Self::Backup => "backup",
            Self::Putty => "putty",
        }
    }
}

impl fmt::Display for ImportSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A reference from one planned item to another: an index into [`ImportPlan::items`].
pub type PlanRef = usize;

/// A host to import. `None` / empty fields are not set (they inherit).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostDraft {
    /// `label`
    pub label: String,
    /// `address`
    pub address: String,
    /// `port`
    pub port: Option<u16>,
    /// `username`
    pub username: Option<String>,
    /// The planned group (`None`: the target group).
    pub group: Option<PlanRef>,
    /// Planned tags.
    pub tags: Vec<PlanRef>,
    /// IdentityFile paths as written (`~` not expanded); imported after confirmation.
    pub identity_files: Vec<String>,
    /// Planned jump hosts, in order.
    pub jump_chain: Vec<PlanRef>,
    /// `ProxyJump none` overriding a group's chain: stored as an explicit empty chain.
    pub no_jump: bool,
    /// `ProxyCommand`.
    pub proxy_command: Option<String>,
    /// A SOCKS5 / HTTP proxy (PuTTY `ProxyMethod`).
    pub proxy: Option<ProxyDraft>,
    /// `ForwardAgent`.
    pub agent_forwarding: Option<bool>,
    /// `SetEnv`.
    pub env: Vec<(String, String)>,
    /// `ServerAliveInterval`.
    pub keepalive_secs: Option<u32>,
    /// Planned forwards of this host.
    pub forwards: Vec<PlanRef>,
}

/// The kind of a [`ProxyDraft`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyDraftKind {
    /// `proxy.kind = "socks5"`
    Socks5,
    /// `proxy.kind = "http"` (HTTP CONNECT)
    Http,
}

/// A network proxy to import. A password is never imported (it is asked for later).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyDraft {
    /// SOCKS5 or HTTP.
    pub kind: ProxyDraftKind,
    /// `host:port` (`[v6]:port`).
    pub addr: String,
    /// `proxy.auth.user`
    pub user: Option<String>,
}

impl fmt::Display for ProxyDraft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scheme = match self.kind {
            ProxyDraftKind::Socks5 => "socks5",
            ProxyDraftKind::Http => "http",
        };
        match &self.user {
            Some(u) => write!(f, "{scheme}://{u}@{}", self.addr),
            None => write!(f, "{scheme}://{}", self.addr),
        }
    }
}

/// Inheritable settings of a planned group (§4.3 `defaults.*`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DefaultsDraft {
    /// `port`
    pub port: Option<u16>,
    /// `username`
    pub username: Option<String>,
    /// IdentityFile paths (the first becomes `defaults.key_id`).
    pub identity_files: Vec<String>,
    /// Planned jump hosts.
    pub jump_chain: Vec<PlanRef>,
    /// `ProxyCommand`.
    pub proxy_command: Option<String>,
    /// `ForwardAgent`.
    pub agent_forwarding: Option<bool>,
    /// `SetEnv`.
    pub env: Vec<(String, String)>,
    /// `ServerAliveInterval`.
    pub keepalive_secs: Option<u32>,
}

impl DefaultsDraft {
    /// Nothing is set.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// A group to import.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupDraft {
    /// `name`
    pub name: String,
    /// The planned parent (`None`: the target group).
    pub parent: Option<PlanRef>,
    /// `defaults.*`
    pub defaults: DefaultsDraft,
}

/// A port forward to import (always `auto_start`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardDraft {
    /// `label`
    pub label: String,
    /// `kind`
    pub kind: ForwardKind,
    /// The planned host carrying it.
    pub host: PlanRef,
    /// `bind_addr`
    pub bind_addr: String,
    /// `bind_port`
    pub bind_port: u16,
    /// `dest_host` (`None` for dynamic).
    pub dest_host: Option<String>,
    /// `dest_port`
    pub dest_port: Option<u16>,
}

/// What a planned item is.
#[derive(Debug, Clone, PartialEq)]
pub enum Draft {
    /// A host.
    Host(Box<HostDraft>),
    /// A group (wildcard `Host` blocks, CSV group paths).
    Group(GroupDraft),
    /// A tag (by name).
    Tag(String),
    /// A port forward.
    Forward(ForwardDraft),
    /// A known_hosts entry.
    KnownHost(KnownHost),
    /// An item of a backup: its id and full stamped body.
    Backup {
        /// The id it had (kept when absent locally).
        id: ItemId,
        /// The body with its stamps.
        body: Box<ItemBody>,
    },
}

/// A difference between an imported item and the existing one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDiff {
    /// The field.
    pub field: String,
    /// The existing value (`-`: unset).
    pub existing: String,
    /// The imported value (`-`: unset).
    pub imported: String,
}

/// How a planned item relates to what is already in the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanStatus {
    /// Not there yet: it will be created.
    New,
    /// Already there, identical: nothing is written (references link to it).
    Duplicate(ItemId),
    /// The same item (by its identity) with different fields: the conflict policy
    /// decides.
    Conflict(ItemId, Vec<FieldDiff>),
}

impl PlanStatus {
    /// `new`, `duplicate` or `conflict`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Duplicate(_) => "duplicate",
            Self::Conflict(..) => "conflict",
        }
    }
}

/// One item of an [`ImportPlan`].
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedItem {
    /// The item kind.
    pub kind: ItemKind,
    /// What to show in the preview (host label, group name, …).
    pub label: String,
    /// Displayed fields (also what conflicts are diffed on).
    pub fields: BTreeMap<String, String>,
    /// The content.
    pub draft: Draft,
    /// New / duplicate / conflict.
    pub status: PlanStatus,
    /// `file:line` it came from, when known.
    pub source_line: Option<String>,
}

impl PlannedItem {
    /// A new item.
    pub fn new(kind: ItemKind, label: impl Into<String>, draft: Draft) -> Self {
        Self {
            kind,
            label: label.into(),
            fields: BTreeMap::new(),
            draft,
            status: PlanStatus::New,
            source_line: None,
        }
    }
}

/// A part of the source that is not imported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// `file:line` (or `line N`), when known.
    pub source_line: Option<String>,
    /// Why.
    pub reason: String,
}

impl Skipped {
    /// A skipped entry.
    pub fn new(source_line: Option<String>, reason: impl Into<String>) -> Self {
        Self {
            source_line,
            reason: reason.into(),
        }
    }
}

/// The dry-run result of an importer.
#[derive(Debug, Clone, PartialEq)]
pub struct ImportPlan {
    /// The source.
    pub source: ImportSource,
    /// Planned items. [`PlanRef`]s index this list.
    pub items: Vec<PlannedItem>,
    /// What is not imported, with reasons.
    pub skipped: Vec<Skipped>,
    /// Non-fatal notes (include cycles, unsupported keywords summary, …).
    pub warnings: Vec<String>,
    /// Preview notes ("group a/b will be created").
    pub notes: Vec<String>,
}

/// Counts for the preview header.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PlanCounts {
    /// New items.
    pub new: usize,
    /// Duplicates.
    pub duplicate: usize,
    /// Conflicts.
    pub conflict: usize,
    /// Skipped entries.
    pub skipped: usize,
}

impl ImportPlan {
    /// An empty plan.
    pub fn new(source: ImportSource) -> Self {
        Self {
            source,
            items: Vec::new(),
            skipped: Vec::new(),
            warnings: Vec::new(),
            notes: Vec::new(),
        }
    }

    /// Adds an item and returns its reference.
    pub fn push(&mut self, item: PlannedItem) -> PlanRef {
        self.items.push(item);
        self.items.len() - 1
    }

    /// The label of a planned item (`?` for a dangling reference).
    pub fn label_of(&self, r: PlanRef) -> &str {
        self.items.get(r).map_or("?", |i| i.label.as_str())
    }

    /// New / duplicate / conflict / skipped counts.
    pub fn counts(&self) -> PlanCounts {
        let mut c = PlanCounts {
            skipped: self.skipped.len(),
            ..PlanCounts::default()
        };
        for item in &self.items {
            match item.status {
                PlanStatus::New => c.new += 1,
                PlanStatus::Duplicate(_) => c.duplicate += 1,
                PlanStatus::Conflict(..) => c.conflict += 1,
            }
        }
        c
    }

    /// Every distinct IdentityFile of the plan (the separate confirmation, §9.13).
    pub fn identity_files(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for item in &self.items {
            let files = match &item.draft {
                Draft::Host(h) => &h.identity_files,
                Draft::Group(g) => &g.defaults.identity_files,
                _ => continue,
            };
            for f in files {
                if !out.contains(f) {
                    out.push(f.clone());
                }
            }
        }
        out
    }

    /// The preview as text: counts, one row per item (status, kind, label, fields,
    /// diffs), then skipped entries and warnings. The CLI prints it; snapshots use it.
    pub fn render_table(&self) -> String {
        let c = self.counts();
        let mut out = String::new();
        let _ = writeln!(
            out,
            "Import preview ({}): {} new, {} duplicate, {} conflict, {} skipped",
            self.source, c.new, c.duplicate, c.conflict, c.skipped
        );
        if !self.items.is_empty() {
            let kw = self
                .items
                .iter()
                .map(|i| i.kind.as_str().len())
                .max()
                .unwrap_or(4)
                .max(4);
            let lw = self
                .items
                .iter()
                .map(|i| i.label.chars().count())
                .max()
                .unwrap_or(5)
                .clamp(5, 32);
            let _ = writeln!(
                out,
                "{:<9}  {:<kw$}  {:<lw$}  DETAILS",
                "STATUS", "KIND", "LABEL"
            );
            for item in &self.items {
                let details: Vec<String> = item
                    .fields
                    .iter()
                    .filter(|(k, _)| k.as_str() != "label")
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect();
                let _ = writeln!(
                    out,
                    "{:<9}  {:<kw$}  {:<lw$}  {}",
                    item.status.as_str(),
                    item.kind.as_str(),
                    item.label,
                    details.join(" ")
                );
                if let PlanStatus::Conflict(_, diffs) = &item.status {
                    for d in diffs {
                        let _ = writeln!(
                            out,
                            "           ~ {}: {} -> {}",
                            d.field, d.existing, d.imported
                        );
                    }
                }
            }
        }
        if !self.notes.is_empty() {
            out.push_str("Notes:\n");
            for n in &self.notes {
                let _ = writeln!(out, "  {n}");
            }
        }
        if !self.skipped.is_empty() {
            out.push_str("Skipped:\n");
            for s in &self.skipped {
                match &s.source_line {
                    Some(l) => {
                        let _ = writeln!(out, "  {l}: {}", s.reason);
                    }
                    None => {
                        let _ = writeln!(out, "  {}", s.reason);
                    }
                }
            }
        }
        if !self.warnings.is_empty() {
            out.push_str("Warnings:\n");
            for w in &self.warnings {
                let _ = writeln!(out, "  {w}");
            }
        }
        out
    }
}

/// Why an import cannot proceed at all (single entries are [`Skipped`] instead).
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    /// The source could not be read.
    #[error("cannot read {path}: {message}")]
    Read {
        /// The file.
        path: String,
        /// The OS error.
        message: String,
    },
    /// The source is not in the expected format.
    #[error("{0}")]
    Format(String),
    /// A backup error.
    #[error(transparent)]
    Backup(#[from] backup::BackupError),
    /// A plan reference or an existing item is missing (a bug or a concurrent change).
    #[error("import plan is inconsistent: {0}")]
    Inconsistent(String),
}

/// Display helper: `-` for an unset value.
pub(crate) fn show_opt<T: fmt::Display>(v: Option<&T>) -> String {
    v.map_or_else(|| "-".to_owned(), ToString::to_string)
}

/// Display helper for env lists: `A=1;B=2`.
pub(crate) fn show_env(env: &[(String, String)]) -> String {
    env.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(";")
}

#[cfg(test)]
mod tests;
