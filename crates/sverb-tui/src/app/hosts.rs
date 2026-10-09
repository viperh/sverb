//! M1-07: hosts in the reducer (SPEC §9.1).
//!
//! - Keeps the Hosts view fed: every new index snapshot goes to the view and asks the
//!   vault service for a fresh [`crate::views::hosts::catalog::HostCatalog`]
//!   (`ItemEffect::LoadHosts`; one load in flight, a newer snapshot re-loads after it).
//! - Carries out the view's requests: connect, add / edit (the host form), duplicate,
//!   delete (confirm "Delete N hosts?"), pin, copy the `ssh` command.
//! - Quick connect (`leader o`) and `sverb connect <target>`: a saved host (resolved
//!   through the index, `resolve_host_arg`) or an unsaved target parsed by
//!   `sverb_core::quick_connect`. An unsaved target that connects gets the
//!   "Save as host?" offer; `s` opens the form prefilled.
//! - Connecting emits `Effect::OpenSession` with `SessionSpec::Ssh` (until M1-13 lands
//!   the SSH connector the session ends with "Ssh sessions are not available yet"),
//!   applies the host's recording setting (`resolve_record_sessions`), and records the
//!   connection time (`ItemEffect::TouchConnected`) once the session is connected.
//! - M2-01: connecting and "copy as command" use the resolved settings (group chain,
//!   vault defaults, config; `sverb_core::resolve`). Each connection resolves anew,
//!   so changing a group's defaults affects the next connection only. Groups and tags
//!   are organized through `views/hosts/organize.rs` dialogs.

use std::collections::BTreeMap;
use std::sync::Arc;

// M5-02: the vault selector, move / copy to vault, credential overrides.
mod shared_vaults;
pub use shared_vaults::SharedVaultEvent;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use sverb_conn::{SessionSpec, SessionState, SshSpec};
use sverb_core::host_arg::HostArgError;
use sverb_core::model::{
    DEFAULT_SSH_PORT, ItemId, ItemKind,
    group::{DeleteGroupMode, DeletePlan, plan_delete},
};
// M2-01
use sverb_core::quick_connect::{self, QuickTarget};
use sverb_core::resolve::{GlobalDefaults, Source};
use sverb_core::search::resolve_host_arg;
use sverb_core::ssh_command;

use super::{
    App, Effect, EffectId, EffectOutput, EffectResult, PendingKind, SessionId, ToastLevel,
    VaultEffect,
};
use crate::views::{
    DialogKind,
    dialogs::ModalDialog,
    hosts::{
        HostsRequest,
        // M2-01
        catalog::HostCatalog,
        form::{
            GroupFormInit, HOST_FORM_FEATURES, HostFormDialog, HostFormInit, InheritCx, group_form,
            host_form,
        },
        organize::{
            DeleteGroupDialog, GroupFormDialog, GroupPicker, OrganizeDialog, TagManager, TagPicker,
        },
        quick::{QuickConnect, QuickPick, SaveHostOffer},
    },
};
use crate::widgets::confirm;
use crate::widgets::form::FieldChanges;

/// Pane size used before the terminal size is known.
const FALLBACK_SIZE: (u16, u16) = (80, 24);

/// Item writes and reads for the vault service (`Effect::Vault(VaultEffect::Items)`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ItemEffect {
    /// Create (`item: None`) or update an item from form changes. Answered with
    /// `EffectDone(Ok(EffectOutput::Item(id)))`.
    Save {
        /// Correlation id.
        id: EffectId,
        /// The item (`None`: new, in the Personal vault).
        item: Option<ItemId>,
        /// Its kind (M1-07: hosts).
        kind: ItemKind,
        /// The changed fields.
        changes: FieldChanges,
    },
    /// Tombstone an item. Failures come back as `VaultEvent::ItemFailed`.
    Delete(ItemId),
    /// Copy an item (`"<label> (copy)"`).
    Duplicate(ItemId),
    /// Pin or unpin a host.
    SetPinned {
        /// The host.
        item: ItemId,
        /// Pinned or not.
        pinned: bool,
    },
    /// Build the Hosts catalog. Answered with `EffectOutput::Hosts`.
    LoadHosts {
        /// Correlation id.
        id: EffectId,
    },
    /// Load a host with its password for the edit form (`EffectOutput::Host`).
    LoadHost {
        /// Correlation id.
        id: EffectId,
        /// The host.
        item: ItemId,
    },
    /// Record a successful connection (device-local, frecency).
    TouchConnected(ItemId),
    // M2-01
    /// Set `group_id` on hosts (`None`: the top level). Failures: `ItemFailed`.
    MoveToGroup {
        /// The hosts.
        items: Vec<ItemId>,
        /// The new group.
        group: Option<ItemId>,
    },
    /// Add and remove tags on hosts (only `tags` changes on each); `create` makes a
    /// new tag first and adds it too.
    SetTags {
        /// The hosts.
        items: Vec<ItemId>,
        /// Tags to add.
        add: Vec<ItemId>,
        /// Tags to remove.
        remove: Vec<ItemId>,
        /// A new tag's name.
        create: Option<String>,
    },
    /// Delete a group: move its hosts and subgroups to the parent, or delete them.
    DeleteGroup {
        /// The group.
        group: ItemId,
        /// What happens to its contents.
        mode: DeleteGroupMode,
    },
    /// Create (`item: None`) or rename / recolor a tag (names unique per vault).
    SaveTag {
        /// The tag.
        item: Option<ItemId>,
        /// `name`
        name: String,
        /// `color`
        color: Option<String>,
    },
    // M2-02
    /// Create (`item: None`, in `vault` or the Personal vault) or update an identity
    /// from form changes. Answered with `EffectDone(Ok(EffectOutput::Item(id)))`.
    SaveIdentity {
        /// Correlation id.
        id: EffectId,
        /// The identity (`None`: new).
        item: Option<ItemId>,
        /// Where a new identity goes (`None`: the Personal vault).
        vault: Option<sverb_core::model::VaultId>,
        /// The changed fields.
        changes: FieldChanges,
    },
    /// Load an identity with its password for the edit form
    /// (`EffectOutput::Identity`).
    LoadIdentity {
        /// Correlation id.
        id: EffectId,
        /// The identity.
        item: ItemId,
    },
    /// Delete an identity; with `convert`, the hosts using it first get its
    /// credentials as inline fields. Failures: `ItemFailed`.
    DeleteIdentity {
        /// The identity.
        item: ItemId,
        /// "Convert to inline credentials on those hosts".
        convert: bool,
    },
    // M2-03
    /// Keychain work (generate, import, export, passphrase, certificates, flags).
    /// Results come back as `VaultEvent::Keychain`.
    Keychain(crate::app::keychain::keys::KeychainEffect),
    // M5-02
    /// New items go to this vault (`None`: the Personal vault): the vault
    /// selector (§4.13).
    SetNewItemVault(Option<sverb_core::model::VaultId>),
    /// Move or copy items to `target` (§13.1: new ids, the sources of a move
    /// tombstoned). A reference that would leave a shared target is handled by
    /// `refs`; when blocked, `VaultEvent::Shared(TransferBlocked)` asks.
    Transfer {
        /// The items.
        items: Vec<ItemId>,
        /// The target vault.
        target: sverb_core::model::VaultId,
        /// Copy (else move).
        copy: bool,
        /// Referenced items outside the target.
        refs: sverb_core::model::vault_refs::RefPolicy,
    },
    /// "Use my own credentials…" (§13.4): the personal-vault override of a shared
    /// host uses `identity` (`None`: remove the override).
    SetOverride {
        /// The shared host.
        host: ItemId,
        /// A personal identity.
        identity: Option<ItemId>,
    },
}

/// Where a session came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionOrigin {
    /// A saved host.
    Saved(ItemId),
    /// An unsaved quick-connect target.
    Ephemeral(QuickTarget),
}

/// Hosts state of the reducer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostsUi {
    /// The catalog load in flight.
    loading: Option<EffectId>,
    /// A newer index arrived while loading.
    reload: bool,
    /// Sessions opened from hosts or quick connect, until they first connect.
    sessions: BTreeMap<SessionId, SessionOrigin>,
    /// `sverb connect <target>` waiting for the first catalog.
    pending_connect: Option<String>,
    // M5-02
    /// `general.default_vault` was applied to the vault selector since unlock.
    default_vault_applied: bool,
}

impl App {
    // ------------------------------------------------------------------ data

    /// A new index snapshot reached the reducer: refresh the view, reload the catalog.
    pub(crate) fn hosts_on_index(&mut self, effects: &mut Vec<Effect>) {
        let Some(index) = self.index().cloned() else {
            return;
        };
        if self
            .views
            .hosts
            .index()
            .is_some_and(|cur| Arc::ptr_eq(cur, &index))
        {
            return;
        }
        // M2-02: the Keychain's Identities sub-tab follows the index too.
        self.views.keychain.set_index(Arc::clone(&index));
        self.views.hosts.set_index(index);
        self.needs_redraw = true;
        self.load_hosts(effects);
    }

    fn load_hosts(&mut self, effects: &mut Vec<Effect>) {
        if self.hosts.loading.is_some() {
            self.hosts.reload = true;
            return;
        }
        let id = self.ids.effect();
        self.pending.insert(id, PendingKind::HostsLoad);
        self.hosts.loading = Some(id);
        effects.push(Effect::Vault(VaultEffect::Items(ItemEffect::LoadHosts {
            id,
        })));
    }

    /// The vault locked: decrypted host data goes.
    pub(crate) fn hosts_on_lock(&mut self) {
        self.views.hosts.clear();
        // M2-02
        self.views.keychain.clear();
        if let Some(id) = self.hosts.loading.take() {
            self.pending.remove(&id);
        }
        self.hosts.reload = false;
        // M5-02
        self.hosts.default_vault_applied = false;
        self.needs_redraw = true;
    }

    /// Results of item effects (catalog loads, saves, the edit form).
    pub(crate) fn hosts_on_effect_done(
        &mut self,
        kind: &PendingKind,
        result: EffectResult,
        effects: &mut Vec<Effect>,
    ) {
        match kind {
            PendingKind::HostsLoad => {
                self.hosts.loading = None;
                match result {
                    Ok(EffectOutput::Hosts(catalog)) if self.index().is_some() => {
                        // M5-02: the vault selected at unlock (§4.13).
                        if !self.hosts.default_vault_applied {
                            self.hosts.default_vault_applied = true;
                            let v = shared_vaults::default_vault(
                                &catalog,
                                &self.config.general.default_vault,
                            );
                            if v.is_some() {
                                self.views.hosts.set_vault(v);
                                effects.push(Effect::Vault(VaultEffect::Items(
                                    ItemEffect::SetNewItemVault(v),
                                )));
                            }
                        }
                        // M2-02: identities, their usage counts and key names.
                        self.views.keychain.set_catalog(Arc::clone(&catalog));
                        self.views.hosts.set_catalog(catalog);
                        self.needs_redraw = true;
                        if let Some(target) = self.hosts.pending_connect.take() {
                            self.connect_target(&target, effects);
                        }
                    }
                    Ok(_) => {}
                    Err(report) => self.push_error(&report, effects),
                }
                if std::mem::take(&mut self.hosts.reload) {
                    self.load_hosts(effects);
                }
            }
            PendingKind::SaveItem { dialog } => {
                let pos = self.dialogs.iter().position(|d| d.id == *dialog);
                match result {
                    Ok(out) => {
                        // M2-01: the group / vault-defaults editor saves the same way.
                        let what = match pos.map(|p| &self.dialogs[p].kind) {
                            Some(DialogKind::Organize(OrganizeDialog::GroupForm(g))) => {
                                if g.vault_defaults {
                                    "Vault defaults saved"
                                } else {
                                    "Group saved"
                                }
                            }
                            _ => "Host saved",
                        };
                        if let Some(pos) = pos {
                            self.dialogs.remove(pos);
                        }
                        if let EffectOutput::Item(id) = out
                            && !self.views.hosts.select(id)
                        {
                            self.views
                                .hosts
                                .list
                                .select_key(&crate::views::hosts::HostRowKey::Group(id));
                        }
                        self.push_toast(ToastLevel::Success, what.to_owned(), effects);
                    }
                    Err(report) => {
                        match pos.map(|p| &mut self.dialogs[p].kind) {
                            Some(DialogKind::HostForm(f)) => {
                                f.form.save_failed(report.short.clone());
                            }
                            // M2-01
                            Some(DialogKind::Organize(OrganizeDialog::GroupForm(g))) => {
                                g.form.save_failed(report.short.clone());
                            }
                            _ => {}
                        }
                        self.push_error(&report, effects);
                    }
                }
                self.needs_redraw = true;
            }
            PendingKind::EditHost => match result {
                Ok(EffectOutput::Host(record)) => self.open_host_form(HostFormInit::edit(*record)),
                Ok(_) => {}
                Err(report) => self.push_error(&report, effects),
            },
            // M2-02
            PendingKind::SaveIdentity { .. } | PendingKind::EditIdentity => {
                self.keychain_on_effect_done(kind, result, effects);
            }
        }
    }

    // ------------------------------------------------------------------ view requests

    /// After a dispatch: the Hosts view's request and a quick-connect answer.
    pub(crate) fn take_hosts_requests(&mut self, effects: &mut Vec<Effect>) {
        if let Some(req) = self.views.hosts.take_request() {
            self.on_hosts_request(req, effects);
        }
        let answer = match self.dialogs.last_mut().map(|d| &mut d.kind) {
            Some(DialogKind::QuickConnect(q)) => q.take_answer(),
            _ => None,
        };
        if let Some(pick) = answer {
            self.dialogs.pop();
            self.needs_redraw = true;
            match pick {
                QuickPick::Host(id) => self.connect_host(id, effects),
                QuickPick::Target(t) => self.connect_ephemeral(t, effects),
            }
        }
    }

    fn on_hosts_request(&mut self, req: HostsRequest, effects: &mut Vec<Effect>) {
        self.needs_redraw = true;
        match req {
            HostsRequest::Connect(ids) => {
                for id in ids {
                    self.connect_host(id, effects);
                }
                self.views.hosts.clear_marks();
            }
            // M1-17: each host in a split of the current tab.
            HostsRequest::ConnectSplit(ids) => {
                self.connect_split(ids, effects);
                self.views.hosts.clear_marks();
            }
            HostsRequest::Add => self.open_host_form(HostFormInit::default()),
            HostsRequest::Edit(item) => {
                let id = self.ids.effect();
                self.pending.insert(id, PendingKind::EditHost);
                effects.push(Effect::Vault(VaultEffect::Items(ItemEffect::LoadHost {
                    id,
                    item,
                })));
            }
            HostsRequest::Duplicate(ids) => {
                for id in ids {
                    effects.push(Effect::Vault(VaultEffect::Items(ItemEffect::Duplicate(id))));
                }
                self.views.hosts.clear_marks();
            }
            HostsRequest::Delete(ids) => self.confirm_delete(&ids, effects),
            HostsRequest::Pin(ids, pinned) => {
                for item in ids {
                    effects.push(Effect::Vault(VaultEffect::Items(ItemEffect::SetPinned {
                        item,
                        pinned,
                    })));
                }
                self.views.hosts.clear_marks();
            }
            HostsRequest::CopyCommand(id) => self.copy_ssh_command(id, effects),
            // M7-01: "Clear history" (asks first).
            // M5-02
            HostsRequest::VaultSelected(v) => {
                effects.push(Effect::Vault(VaultEffect::Items(
                    ItemEffect::SetNewItemVault(v),
                )));
            }
            HostsRequest::MoveToVault(ids) => self.pick_target_vault(ids, false, effects),
            HostsRequest::CopyToVault(ids) => self.pick_target_vault(ids, true, effects),
            HostsRequest::Override(host) => self.pick_override(host, effects),
            HostsRequest::ClearHistory(id) => {
                let label = self
                    .views
                    .hosts
                    .catalog()
                    .and_then(|c| c.hosts.get(&id).map(|h| h.display_label().to_owned()))
                    .unwrap_or_else(|| "this host".to_owned());
                self.confirm_clear_history(Some(id), &label, effects);
            }
            // M2-01
            HostsRequest::MoveToGroup(ids) => {
                if let Some(c) = self.organize_catalog(effects) {
                    self.push_dialog(DialogKind::Organize(OrganizeDialog::GroupPicker(
                        GroupPicker::new(ids, &c),
                    )));
                }
            }
            HostsRequest::Tag(ids) => {
                if let Some(c) = self.organize_catalog(effects) {
                    self.push_dialog(DialogKind::Organize(OrganizeDialog::TagPicker(
                        TagPicker::new(ids, &c),
                    )));
                }
            }
            HostsRequest::NewGroup(parent) => {
                if let Some(c) = self.organize_catalog(effects) {
                    let init = GroupFormInit {
                        parent_id: parent,
                        ..GroupFormInit::default()
                    };
                    self.open_group_form(&init, &c);
                }
            }
            HostsRequest::EditGroup(group) => {
                if let Some(c) = self.organize_catalog(effects)
                    && let Some(init) = GroupFormInit::edit(&c, group)
                {
                    self.open_group_form(&init, &c);
                }
            }
            HostsRequest::VaultDefaults => {
                if let Some(c) = self.organize_catalog(effects) {
                    match c.personal_vault {
                        Some(v) => {
                            let init = GroupFormInit::vault_defaults(&c, v);
                            self.open_group_form(&init, &c);
                        }
                        None => {
                            self.push_toast(
                                ToastLevel::Info,
                                "Unlock the vault to edit its defaults".to_owned(),
                                effects,
                            );
                        }
                    }
                }
            }
            HostsRequest::DeleteGroup(group) => {
                if let Some(c) = self.organize_catalog(effects) {
                    self.open_delete_group(group, &c);
                }
            }
            HostsRequest::AddInGroup(group) => {
                let mut init = HostFormInit::default();
                init.summary.group_id = Some(group);
                self.open_host_form(init);
            }
            HostsRequest::ManageTags => {
                if let Some(c) = self.organize_catalog(effects) {
                    self.push_dialog(DialogKind::Organize(OrganizeDialog::Tags(TagManager::new(
                        &c,
                    ))));
                }
            }
            // M2-11
            HostsRequest::Import => {
                self.push_dialog(DialogKind::ImportWizard(Box::new(
                    crate::views::import_wizard::ImportWizard::import(
                        crate::views::import_wizard::WizardSource::SshConfig,
                    ),
                )));
            }
            HostsRequest::Export => {
                self.push_dialog(DialogKind::ImportWizard(Box::new(
                    crate::views::import_wizard::ImportWizard::export(),
                )));
            }
        }
    }

    // ------------------------------------------------------------------ M2-01

    /// The catalog for an organizing dialog, or a "still loading" hint.
    fn organize_catalog(&mut self, effects: &mut Vec<Effect>) -> Option<Arc<HostCatalog>> {
        let c = self.views.hosts.catalog().cloned();
        if c.is_none() {
            self.push_toast(
                ToastLevel::Info,
                "The hosts are still loading; try again".to_owned(),
                effects,
            );
        }
        c
    }

    fn inherit_cx(
        &self,
        catalog: &Arc<HostCatalog>,
        vault: Option<sverb_core::model::VaultId>,
    ) -> InheritCx {
        InheritCx {
            catalog: Arc::clone(catalog),
            globals: GlobalDefaults::from_config(&self.config),
            vault,
        }
    }

    fn open_group_form(&mut self, init: &GroupFormInit, catalog: &Arc<HostCatalog>) {
        let schemes = self.schemes.names();
        let form = group_form(
            init,
            Some(catalog),
            self.index().cloned(),
            &schemes,
            HOST_FORM_FEATURES,
        );
        let mut excluded = std::collections::BTreeSet::new();
        if let Some(id) = init.item {
            excluded.insert(id);
            excluded.extend(sverb_core::model::group::descendants(
                id,
                catalog.lookup.groups.iter().map(|(g, n)| (*g, n.parent_id)),
            ));
        }
        let vault = init
            .item
            .and_then(|i| catalog.group_vaults.get(&i).copied());
        let mut dialog = GroupFormDialog {
            item: init.item,
            vault_defaults: init.vault_defaults,
            excluded_parents: excluded,
            form,
            inherit: Some(self.inherit_cx(catalog, vault)),
        };
        dialog.sync_inherited();
        self.push_dialog(DialogKind::Organize(OrganizeDialog::GroupForm(Box::new(
            dialog,
        ))));
    }

    /// The delete-group dialog with its counts (§9.2).
    fn open_delete_group(&mut self, group: ItemId, catalog: &HostCatalog) {
        let plan = group_delete_plan(catalog, group, DeleteGroupMode::DeleteAll);
        let (hosts, subgroups) = catalog.group_contents(group);
        self.push_dialog(DialogKind::Organize(OrganizeDialog::DeleteGroup(
            DeleteGroupDialog {
                group,
                name: catalog.group_name(group).unwrap_or_default().to_owned(),
                hosts,
                subgroups,
                delete_count: plan.deleted_contents(),
                choice: 0,
                typing: None,
                error: None,
            },
        )));
    }

    /// The "Delete N hosts?" confirmation; one delete effect per host.
    pub(crate) fn confirm_delete(&mut self, ids: &[ItemId], effects: &mut Vec<Effect>) {
        let mut modal = confirm::delete(ids.len(), "host");
        let names: Vec<String> = ids
            .iter()
            .take(5)
            .map(|id| {
                self.views
                    .hosts
                    .host(*id)
                    .map_or_else(|| id.short(), |h| h.display_label().to_owned())
            })
            .collect();
        let more = ids.len() - names.len();
        modal.body = if more > 0 {
            format!("{} and {more} more. {}", names.join(", "), modal.body)
        } else {
            format!("{}. {}", names.join(", "), modal.body)
        };
        let deletes = ids
            .iter()
            .map(|id| Effect::Vault(VaultEffect::Items(ItemEffect::Delete(*id))))
            .collect();
        let route = format!("button:{}", confirm::YES);
        self.push_modal(ModalDialog::new(modal).on(&route, deletes), effects);
    }

    fn copy_ssh_command(&mut self, id: ItemId, effects: &mut Vec<Effect>) {
        let line = self.views.hosts.catalog().and_then(|c| {
            c.hosts
                .get(&id)
                .map(|h| ssh_command::render(&c.ssh_target(h)))
        });
        match line {
            Some(line) => {
                effects.push(Effect::CopyToClipboard(line.clone()));
                self.push_toast(ToastLevel::Success, format!("Copied: {line}"), effects);
            }
            None => {
                self.push_toast(
                    ToastLevel::Info,
                    "The host is still loading; try again".to_owned(),
                    effects,
                );
            }
        }
    }

    fn open_host_form(&mut self, init: HostFormInit) {
        let schemes = self.schemes.names();
        let catalog = self.views.hosts.catalog().cloned();
        let form = host_form(
            &init,
            catalog.as_deref(),
            self.index().cloned(),
            &schemes,
            self.config.ssh.keepalive_secs,
            HOST_FORM_FEATURES,
        );
        // M2-01: placeholders resolve the draft against the catalog.
        let vault = init.item.map(|_| init.summary.vault);
        let mut dialog = HostFormDialog {
            item: init.item,
            form,
            inherit: catalog.map(|c| Box::new(self.inherit_cx(&c, vault))),
        };
        dialog.sync_inherited();
        self.push_dialog(DialogKind::HostForm(dialog));
    }

    // ------------------------------------------------------------------ quick connect

    /// `leader o`.
    pub(crate) fn open_quick_connect(&mut self) {
        let index = self.index().cloned();
        self.push_dialog(DialogKind::QuickConnect(QuickConnect::new(index)));
    }

    /// Keys for the "Save as host?" offer: `s` opens the form; any other key
    /// dismisses it and (except `Esc`) goes on to where it was going.
    pub(crate) fn on_hosts_dialog_key(&mut self, key: KeyEvent, effects: &mut Vec<Effect>) -> bool {
        let Some(DialogKind::SaveHostOffer(offer)) = self.dialogs.last().map(|d| &d.kind) else {
            return false;
        };
        let target = offer.target.clone();
        self.dialogs.pop();
        self.needs_redraw = true;
        let plain = !key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT);
        match key.code {
            KeyCode::Char('s' | 'S') if plain => {
                let port = target.port.filter(|p| *p != DEFAULT_SSH_PORT);
                self.open_host_form(HostFormInit::new_host(
                    &target.host,
                    target.user.as_deref(),
                    port,
                ));
            }
            KeyCode::Esc => {}
            _ => self.on_key(key, effects),
        }
        true
    }

    // ------------------------------------------------------------------ connecting

    fn new_session_id(&mut self) -> SessionId {
        loop {
            let id = self.ids.session();
            if !self.tabs.sessions.contains(&id) {
                break id;
            }
        }
    }

    fn pane_size(&self) -> (u16, u16) {
        let main = self.shell_rects().main;
        if main.width > 2 && main.height > 2 {
            (main.width - 2, main.height - 2)
        } else {
            FALLBACK_SIZE
        }
    }

    fn open_ssh(&mut self, spec: SshSpec, label: String, effects: &mut Vec<Effect>) -> SessionId {
        let id = self.new_session_id();
        let (cols, rows) = self.pane_size();
        effects.push(Effect::OpenSession {
            id,
            spec: SessionSpec::Ssh(spec),
            cols,
            rows,
        });
        self.focus_session(id);
        self.set_pane_label(id, label);
        id
    }

    /// Connect to a saved host (`Enter`, quick connect, `sverb connect`).
    pub fn connect_host(&mut self, item: ItemId, effects: &mut Vec<Effect>) {
        let catalog = self.views.hosts.catalog().cloned();
        let summary = catalog.as_ref().and_then(|c| c.hosts.get(&item));
        let entry = self.views.hosts.index().and_then(|i| i.get(item)).cloned();
        let (spec, label, scheme, record) = match (summary, &entry) {
            (Some(h), _) => {
                // M2-01: resolved now, so this connection uses the current group
                // defaults; open sessions keep the settings they started with.
                let r = catalog
                    .as_ref()
                    .map(|c| c.resolve(h, &GlobalDefaults::from_config(&self.config)));
                let r = r.unwrap_or_else(|| {
                    sverb_core::resolve::resolve_settings(
                        &h.resolve_target(),
                        &h.settings(),
                        &sverb_core::resolve::LookupTable::default(),
                        None,
                        &GlobalDefaults::from_config(&self.config),
                    )
                });
                // The configured scheme is the pane default; only an explicit one
                // (host, group or vault defaults) overrides it.
                let scheme = (!matches!(
                    r.source(sverb_core::resolve::SettingKey::ColorScheme),
                    Source::GlobalConfig | Source::BuiltinDefault
                ))
                .then(|| r.color_scheme.clone());
                (
                    SshSpec {
                        host: r.address.clone(),
                        port: r.port,
                        user: r.username.clone(),
                        host_id: Some(item),
                        label: Some(h.display_label().to_owned()),
                        backspace: (!matches!(
                            r.source(sverb_core::resolve::SettingKey::Backspace),
                            Source::BuiltinDefault
                        ))
                        .then_some(r.backspace),
                    },
                    h.display_label().to_owned(),
                    scheme,
                    r.record_sessions,
                )
            }
            (None, Some(e)) => (
                SshSpec {
                    host: e.address.to_string(),
                    port: DEFAULT_SSH_PORT,
                    user: (!e.user.is_empty()).then(|| e.user.to_string()),
                    host_id: Some(item),
                    label: Some(e.display_label().to_owned()),
                    ..SshSpec::default()
                },
                e.display_label().to_owned(),
                None,
                self.config.recording.enabled,
            ),
            (None, None) => {
                self.push_toast(
                    ToastLevel::Error,
                    "That host no longer exists".to_owned(),
                    effects,
                );
                return;
            }
        };
        let id = self.open_ssh(spec, label, effects);
        self.set_pane_host(id, Some(item.to_string()));
        if scheme.is_some() {
            self.set_session_scheme(id, scheme);
        }
        self.hosts.sessions.insert(id, SessionOrigin::Saved(item));
        // M3-05: per-host recording (M2-01: resolved through the group chain).
        self.auto_record(id, record, effects);
    }

    /// Connect to an unsaved target.
    pub fn connect_ephemeral(&mut self, target: QuickTarget, effects: &mut Vec<Effect>) {
        let spec = SshSpec {
            host: target.host.clone(),
            port: target.port.unwrap_or(DEFAULT_SSH_PORT),
            user: target.user.clone(),
            ..SshSpec::default()
        };
        let id = self.open_ssh(spec, target.display(), effects);
        self.hosts
            .sessions
            .insert(id, SessionOrigin::Ephemeral(target));
        self.auto_record(id, self.config.recording.enabled, effects);
    }

    /// `sverb connect <target>`: a saved host first (label, address, unique fuzzy
    /// match), else `[user@]host[:port]` / `ssh://…`.
    pub(crate) fn connect_target(&mut self, target: &str, effects: &mut Vec<Effect>) {
        let resolved = self
            .views
            .hosts
            .index()
            .map(|i| resolve_host_arg(i, target));
        match resolved {
            Some(Ok(id)) => return self.connect_host(id, effects),
            Some(Err(e @ HostArgError::Ambiguous { .. }))
                if quick_connect::parse(target).is_err() =>
            {
                self.push_toast(ToastLevel::Error, e.to_string(), effects);
                return;
            }
            _ => {}
        }
        match quick_connect::parse(target) {
            Ok(t) => self.connect_ephemeral(t, effects),
            Err(e) => {
                self.push_toast(
                    ToastLevel::Error,
                    format!("Cannot connect to {target:?}: {e}"),
                    effects,
                );
            }
        }
    }

    /// The launch intent `Connect`: wait for the first catalog when a vault is attached.
    pub(crate) fn launch_connect(&mut self, target: String, effects: &mut Vec<Effect>) {
        if self.vault.active && self.views.hosts.catalog().is_none() {
            self.hosts.pending_connect = Some(target);
        } else {
            self.connect_target(&target, effects);
        }
    }

    /// Session state changes: record the connection of saved hosts, offer to save
    /// unsaved targets.
    pub(crate) fn hosts_on_session_state(
        &mut self,
        id: SessionId,
        state: &SessionState,
        effects: &mut Vec<Effect>,
    ) {
        match state {
            SessionState::Connected { .. } => match self.hosts.sessions.remove(&id) {
                Some(SessionOrigin::Saved(item)) => {
                    effects.push(Effect::Vault(VaultEffect::Items(
                        ItemEffect::TouchConnected(item),
                    )));
                }
                Some(SessionOrigin::Ephemeral(target)) => {
                    self.push_dialog(DialogKind::SaveHostOffer(SaveHostOffer { target }));
                }
                None => {}
            },
            SessionState::Closed => {
                self.hosts.sessions.remove(&id);
            }
            _ => {}
        }
    }
}

// M2-01
/// What deleting `group` does, from the catalog's hosts and groups.
pub fn group_delete_plan(
    catalog: &HostCatalog,
    group: ItemId,
    mode: DeleteGroupMode,
) -> DeletePlan {
    let hosts: Vec<(ItemId, Option<ItemId>)> =
        catalog.hosts.values().map(|h| (h.id, h.group_id)).collect();
    let groups: Vec<(ItemId, Option<ItemId>)> = catalog
        .lookup
        .groups
        .iter()
        .map(|(id, g)| (*id, g.parent_id))
        .collect();
    let parent = catalog.lookup.groups.get(&group).and_then(|g| g.parent_id);
    plan_delete(group, parent, &hosts, &groups, mode)
}

#[cfg(test)]
impl App {
    /// Put sample hosts in the Hosts view (tests): `(label, address)`.
    pub(crate) fn seed_hosts(&mut self, hosts: &[(&str, &str)]) -> Vec<ItemId> {
        let (index, ids) = crate::views::hosts::sample_index(hosts);
        self.views.hosts.set_index(index);
        ids
    }

    /// Three sample hosts (tests that move the list).
    pub(crate) fn seed_three_hosts(&mut self) -> Vec<ItemId> {
        self.seed_hosts(&[
            ("alpha", "10.0.0.1"),
            ("bravo", "10.0.0.2"),
            ("charlie", "10.0.0.3"),
        ])
    }
}
