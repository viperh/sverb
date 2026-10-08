//! M3-03: workspaces in the reducer (SPEC §9.9, §4.10, §16 `sverb --workspace`).
//!
//! - **Save** (`save_workspace`, from the palette): captures every tab's layout tree,
//!   host references, ratios, focused pane, title and broadcast set
//!   (`sverb_core::model::workspace`). Quick-connect panes (and anything else without a
//!   saved host or a local shell) are left out, with a warning naming them. The name is
//!   asked for (an existing name in the same vault asks to overwrite); the workspace
//!   goes to the personal vault, or, when every referenced host lives in one shared
//!   vault, the user may pick that vault. The service stores it as a synced item.
//! - **Open** (`open_workspace` picker, `workspaces` list, `sverb --workspace <name>`):
//!   the tabs are appended after the existing ones (or replace the only tab when it is
//!   a single dead pane). Every pane gets its session id at once; the
//!   `Effect::OpenSession`s (with their recording effects) go into a queue that is
//!   released [`OPEN_CONCURRENCY`] at a time: a session holds its slot while its pane
//!   is `Connecting` and frees it once connected, waiting for the user (auth prompts
//!   queue normally, M1-14), disconnected or closed ([`App::workspaces_pump`], run
//!   after every event). A deleted host opens as a "Host missing" placeholder pane
//!   (`leader x` closes it). Opening waits for the host catalog after an unlock.
//! - **Manage** (`workspaces`): rename, delete, duplicate, with an ASCII preview.
//!
//! **Deviation:** the concurrency bound is applied by the reducer (a queue of
//! `OpenSession` effects) rather than by a `Semaphore` inside the session service: the
//! reducer already sees every session's state, needs no new service plumbing, and the
//! bound only applies to workspace opens (not to every connection).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use sverb_conn::{LocalSpec, SessionSpec, SshSpec};
use sverb_core::{
    error_report::ErrorReport,
    model::{
        ItemId, VaultId,
        workspace::{Broadcast, LeafRef, OPEN_CONCURRENCY, WorkspaceSpec, WorkspaceTab},
    },
};

use super::{App, Effect, SessionId, ToastLevel};
use crate::keymap::action::ActionName;
use crate::views::{
    DialogId, DialogKind,
    sessions::{Pane, PaneKind, PaneLife, Tab, TabId, broadcast::BroadcastSet, pane_of},
    workspaces::{
        Purpose, Stage, WorkspaceRow, WorkspacesAnswer, WorkspacesDialog, name_prompt,
        overwrite_confirm,
    },
};
use crate::widgets::dialog::{Modal, ModalAnswer};
use crate::widgets::terminal_pane::PaneOverlay;

/// Preview size (cells) of one tab in the list's detail.
const PREVIEW: (u16, u16) = (36, 9);

/// A saved workspace as loaded from the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceEntry {
    /// Its item.
    pub id: ItemId,
    /// Its vault.
    pub vault: VaultId,
    /// Its name (also when the layout can't be read).
    pub name: String,
    /// The workspace, or why it can't be read (newer format, malformed).
    pub spec: Result<WorkspaceSpec, String>,
}

/// Requests for the workspace service (`services::workspaces`). Results come back as
/// `UiEvent::Workspaces`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WorkspacesEffect {
    /// List every workspace (answered with [`WorkspacesEvent::Loaded`]).
    Load,
    /// Save a workspace: overwrite item `id`, or create one in `vault` (`None`: the
    /// personal vault).
    Save {
        /// The item to overwrite.
        id: Option<ItemId>,
        /// The vault of a new item.
        vault: Option<VaultId>,
        /// The workspace.
        spec: WorkspaceSpec,
    },
    /// Rename a workspace.
    Rename {
        /// The item.
        id: ItemId,
        /// The new name.
        name: String,
    },
    /// Delete a workspace (a synced tombstone).
    Delete(ItemId),
    /// Copy a workspace (`<name> (copy)`).
    Duplicate(ItemId),
}

/// Results of the workspace service.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WorkspacesEvent {
    /// Every workspace.
    Loaded(Vec<WorkspaceEntry>),
    /// A write succeeded (a toast); the service sends a fresh `Loaded` after it.
    Done(String),
    /// Something failed.
    Failed(ErrorReport),
}

/// One queued session open: the session and the effects that open it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedOpen {
    /// The session (its pane already exists).
    pub session: SessionId,
    /// `OpenSession` and what goes with it (recording).
    pub effects: Vec<Effect>,
}

/// The save in progress (between the name prompt and the effect).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaveDraft {
    /// The captured workspace (named once the prompt is answered).
    pub spec: WorkspaceSpec,
    /// A shared vault to offer (all referenced hosts live there).
    pub shared_vault: Option<(VaultId, String)>,
    /// The chosen vault (`None`: personal).
    pub vault: Option<VaultId>,
}

/// Workspace state of the reducer (`Tabs::workspaces`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkspacesUi {
    /// The workspaces, once loaded (cleared on lock).
    pub list: Option<Vec<WorkspaceEntry>>,
    /// A `Load` is in flight.
    pub loading: bool,
    /// `sverb --workspace <name>`, waiting for the list.
    pub pending_launch: Option<String>,
    /// A workspace to open once the host catalog is there.
    pub pending_open: Option<WorkspaceSpec>,
    /// Session opens waiting for a slot.
    pub queue: VecDeque<QueuedOpen>,
    /// Sessions released from the queue that are still connecting.
    pub connecting: BTreeSet<SessionId>,
    /// Most connecting at once so far (tests, diagnostics).
    pub peak: usize,
    /// The open workspaces dialog.
    pub dialog: Option<DialogId>,
    /// The save in progress.
    pub save: Option<SaveDraft>,
    /// The name of the workspace opened or saved last (the save prompt's default).
    pub last_name: Option<String>,
}

impl App {
    // ------------------------------------------------------------------ actions

    /// `save_workspace`, `open_workspace`, `workspaces`. Returns `false` for other
    /// actions.
    pub(crate) fn apply_workspace_action(
        &mut self,
        action: ActionName,
        effects: &mut Vec<Effect>,
    ) -> bool {
        match action {
            ActionName::SaveWorkspace => self.start_save(effects),
            ActionName::OpenWorkspace => self.open_workspace_list("Open workspace", effects),
            ActionName::ManageWorkspaces => self.open_workspace_list("Workspaces", effects),
            _ => return false,
        }
        true
    }

    fn load_workspaces(&mut self, effects: &mut Vec<Effect>) {
        if !self.tabs.workspaces.loading {
            self.tabs.workspaces.loading = true;
            effects.push(Effect::Workspaces(WorkspacesEffect::Load));
        }
    }

    fn open_workspace_list(&mut self, title: &str, effects: &mut Vec<Effect>) {
        self.close_workspace_dialog();
        let loaded = self.tabs.workspaces.list.is_some();
        let dialog = WorkspacesDialog::list(title, self.workspace_rows(), loaded);
        let id = self.push_dialog(DialogKind::Workspaces(Box::new(dialog)));
        self.tabs.workspaces.dialog = Some(id);
        self.load_workspaces(effects);
    }

    fn close_workspace_dialog(&mut self) {
        if let Some(id) = self.tabs.workspaces.dialog.take() {
            self.dialogs.retain(|d| d.id != id);
            self.needs_redraw = true;
        }
        self.tabs.workspaces.save = None;
    }

    fn workspace_dialog_mut(&mut self) -> Option<&mut WorkspacesDialog> {
        let id = self.tabs.workspaces.dialog?;
        self.dialogs
            .iter_mut()
            .find(|d| d.id == id)
            .and_then(|d| match &mut d.kind {
                DialogKind::Workspaces(w) => Some(&mut **w),
                _ => None,
            })
    }

    // ------------------------------------------------------------------ labels

    /// A host's label (`None`: deleted or unknown).
    fn host_label(&self, id: ItemId) -> Option<String> {
        if let Some(h) = self.views.hosts.catalog().and_then(|c| c.hosts.get(&id)) {
            return Some(h.display_label().to_owned());
        }
        self.views
            .hosts
            .index()
            .and_then(|i| i.get(id))
            .map(|e| e.display_label().to_owned())
    }

    fn leaf_label(&self, leaf: &LeafRef) -> String {
        match leaf {
            LeafRef::Host(id) => self
                .host_label(*id)
                .unwrap_or_else(|| "missing host".to_owned()),
            LeafRef::Local { cwd: None } => "local".to_owned(),
            LeafRef::Local { cwd: Some(c) } => format!("local {c}"),
        }
    }

    fn workspace_rows(&self) -> Vec<WorkspaceRow> {
        let Some(list) = &self.tabs.workspaces.list else {
            return Vec::new();
        };
        let vault_name = |v: VaultId| {
            self.views
                .hosts
                .catalog()
                .filter(|c| c.personal_vault != Some(v))
                .and_then(|c| c.vault_names.get(&v).cloned())
        };
        let mut rows: Vec<WorkspaceRow> = list
            .iter()
            .map(|e| {
                let (detail, preview) = match &e.spec {
                    Ok(spec) => {
                        let mut preview = Vec::new();
                        for (i, t) in spec.tabs.iter().enumerate() {
                            preview.push(format!(
                                "Tab {}{}",
                                i + 1,
                                t.title_override
                                    .as_deref()
                                    .map(|t| format!(": {t}"))
                                    .unwrap_or_default()
                            ));
                            preview.extend(t.preview(PREVIEW.0, PREVIEW.1, |l| self.leaf_label(l)));
                        }
                        let tabs = spec.tabs.len();
                        let panes = spec.pane_count();
                        let mut detail = format!(
                            "{tabs} tab{} · {panes} pane{}",
                            if tabs == 1 { "" } else { "s" },
                            if panes == 1 { "" } else { "s" }
                        );
                        if let Some(v) = vault_name(e.vault) {
                            detail.push_str(&format!(" · {v}"));
                        }
                        (detail, preview)
                    }
                    Err(err) => (format!("can't open: {err}"), Vec::new()),
                };
                WorkspaceRow {
                    id: e.id,
                    name: e.name.clone(),
                    detail,
                    preview,
                }
            })
            .collect();
        rows.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
        rows
    }

    // ------------------------------------------------------------------ save

    /// What a pane saves as (`None`: not saveable).
    fn leaf_of(&self, pane: &Pane) -> Option<LeafRef> {
        match &pane.kind {
            PaneKind::Ssh(SshSpec {
                host_id: Some(id), ..
            }) => Some(LeafRef::Host(*id)),
            PaneKind::Local(spec) => Some(LeafRef::Local {
                cwd: spec.cwd.as_ref().map(|p| p.to_string_lossy().into_owned()),
            }),
            _ => None,
        }
    }

    /// Capture every tab. Returns the workspace (unnamed) and the labels of the panes
    /// left out.
    pub(crate) fn capture_workspace(&self) -> (WorkspaceSpec, Vec<String>) {
        let mut tabs = Vec::new();
        let mut omitted = Vec::new();
        let mut active = 0;
        for (i, tab) in self.tabs.list.iter().enumerate() {
            let broadcast = match &tab.broadcast {
                BroadcastSet::Off => Broadcast::Off,
                BroadcastSet::AllPanes => Broadcast::AllPanes,
                BroadcastSet::Custom(set) => Broadcast::Custom(set.clone()),
            };
            let captured = WorkspaceTab::capture(
                tab.title_override.clone(),
                &tab.layout,
                tab.focused,
                &broadcast,
                |p| tab.panes.get(&p).and_then(|pane| self.leaf_of(pane)),
            );
            for p in captured.omitted {
                let session = tab
                    .panes
                    .get(&p)
                    .map_or(super::SessionId(p.0), |x| x.session);
                omitted.push(self.pane(session).label);
            }
            if let Some(t) = captured.tab {
                if i == self.tabs.active {
                    active = u32::try_from(tabs.len()).unwrap_or(0);
                }
                tabs.push(t);
            }
        }
        (
            WorkspaceSpec {
                name: String::new(),
                tabs,
                active,
            },
            omitted,
        )
    }

    fn start_save(&mut self, effects: &mut Vec<Effect>) {
        let (spec, omitted) = self.capture_workspace();
        if spec.tabs.is_empty() {
            let msg = if omitted.is_empty() {
                "Nothing to save: no tabs are open".to_owned()
            } else {
                format!(
                    "Nothing to save: quick-connect and shared panes can't be saved ({})",
                    omitted.join(", ")
                )
            };
            self.push_toast(ToastLevel::Info, msg, effects);
            return;
        }
        if !omitted.is_empty() {
            self.push_toast(
                ToastLevel::Warning,
                format!(
                    "Not saved in the workspace (quick connect / shared): {}",
                    omitted.join(", ")
                ),
                effects,
            );
        }
        // A shared vault holding every referenced host is offered.
        let shared_vault = self.views.hosts.catalog().and_then(|c| {
            let vaults: BTreeSet<VaultId> = spec
                .host_ids()
                .iter()
                .filter_map(|h| c.hosts.get(h).map(|x| x.vault))
                .collect();
            let only = (vaults.len() == 1)
                .then(|| vaults.first().copied())
                .flatten()?;
            if c.personal_vault == Some(only) || spec.host_ids().len() > c.hosts.len() {
                return None;
            }
            let name = c
                .vault_names
                .get(&only)
                .cloned()
                .unwrap_or_else(|| "shared vault".to_owned());
            Some((only, name))
        });
        self.close_workspace_dialog();
        let default = self.tabs.workspaces.last_name.clone().unwrap_or_default();
        let modal = name_prompt("Save workspace", "Name for this workspace.", &default);
        let dialog = WorkspacesDialog::prompt("Save workspace", modal, Purpose::SaveName);
        let id = self.push_dialog(DialogKind::Workspaces(Box::new(dialog)));
        self.tabs.workspaces.dialog = Some(id);
        self.tabs.workspaces.save = Some(SaveDraft {
            spec,
            shared_vault,
            vault: None,
        });
        if self.tabs.workspaces.list.is_none() {
            self.load_workspaces(effects);
        }
    }

    /// The workspace named `name` in `vault` (`None`: the personal vault, or any vault
    /// when the personal vault is not known).
    fn find_named(&self, name: &str, vault: Option<VaultId>) -> Option<ItemId> {
        let personal = self.views.hosts.catalog().and_then(|c| c.personal_vault);
        let vault = vault.or(personal);
        self.tabs
            .workspaces
            .list
            .as_ref()?
            .iter()
            .find(|e| e.name == name && vault.is_none_or(|v| e.vault == v))
            .map(|e| e.id)
    }

    fn set_stage(&mut self, stage: Stage) {
        if let Some(d) = self.workspace_dialog_mut() {
            d.stage = stage;
        }
        self.needs_redraw = true;
    }

    /// Continue the save after the name (and maybe the vault) is known.
    fn continue_save(&mut self, effects: &mut Vec<Effect>, overwrite_ok: bool) {
        let Some(draft) = self.tabs.workspaces.save.clone() else {
            return self.close_workspace_dialog();
        };
        let existing = self.find_named(&draft.spec.name, draft.vault);
        if existing.is_some() && !overwrite_ok {
            self.set_stage(Stage::Modal {
                modal: overwrite_confirm(&draft.spec.name),
                purpose: Purpose::ConfirmOverwrite,
            });
            return;
        }
        self.tabs.workspaces.last_name = Some(draft.spec.name.clone());
        effects.push(Effect::Workspaces(WorkspacesEffect::Save {
            id: existing,
            vault: if existing.is_some() {
                None
            } else {
                draft.vault
            },
            spec: draft.spec,
        }));
        self.close_workspace_dialog();
    }

    // ------------------------------------------------------------------ dialog answers

    /// After a key in the dialog: carry out its answer (dispatch hook).
    pub(crate) fn take_workspaces_answer(&mut self, effects: &mut Vec<Effect>) {
        let Some(answer) = self.workspace_dialog_mut().and_then(|d| d.answer.take()) else {
            if let Some(id) = self.tabs.workspaces.dialog
                && !self.dialogs.iter().any(|d| d.id == id)
            {
                self.tabs.workspaces.dialog = None;
                self.tabs.workspaces.save = None;
            }
            return;
        };
        self.needs_redraw = true;
        match answer {
            WorkspacesAnswer::Close => self.close_workspace_dialog(),
            WorkspacesAnswer::Open(id) => {
                self.close_workspace_dialog();
                self.open_workspace_item(id, effects);
            }
            WorkspacesAnswer::Duplicate(id) => {
                effects.push(Effect::Workspaces(WorkspacesEffect::Duplicate(id)));
            }
            WorkspacesAnswer::Modal { purpose, answer } => {
                self.on_workspace_modal(purpose, answer, effects);
            }
        }
    }

    fn on_workspace_modal(
        &mut self,
        purpose: Purpose,
        answer: ModalAnswer,
        effects: &mut Vec<Effect>,
    ) {
        match (purpose, answer) {
            (Purpose::SaveName, ModalAnswer::Text(name)) => {
                let name = name.trim().to_owned();
                if name.is_empty() {
                    self.push_toast(ToastLevel::Info, "Enter a name".to_owned(), effects);
                    let modal = name_prompt("Save workspace", "Name for this workspace.", "");
                    return self.set_stage(Stage::Modal {
                        modal,
                        purpose: Purpose::SaveName,
                    });
                }
                let shared = self.tabs.workspaces.save.as_mut().and_then(|d| {
                    d.spec.name = name;
                    d.shared_vault.clone()
                });
                match shared {
                    Some((_, vault_name)) => self.set_stage(Stage::Modal {
                        modal: Modal::choice(
                            "Save workspace",
                            "Every host of this workspace is in a shared vault. Save it to:",
                            vec!["Personal vault".to_owned(), vault_name],
                        ),
                        purpose: Purpose::SaveVault,
                    }),
                    None => self.continue_save(effects, false),
                }
            }
            (Purpose::SaveVault, ModalAnswer::Choice(i)) => {
                if let Some(d) = self.tabs.workspaces.save.as_mut() {
                    d.vault = if i == 1 {
                        d.shared_vault.as_ref().map(|(v, _)| *v)
                    } else {
                        None
                    };
                }
                self.continue_save(effects, false);
            }
            (Purpose::ConfirmOverwrite, a) if a.is_button("overwrite") => {
                self.continue_save(effects, true);
            }
            (Purpose::Rename(id), ModalAnswer::Text(name)) => {
                let name = name.trim().to_owned();
                let vault = self.entry(id).map(|e| e.vault);
                if name.is_empty() {
                } else if self
                    .find_named(&name, vault)
                    .is_some_and(|other| other != id)
                {
                    self.push_toast(
                        ToastLevel::Error,
                        format!("A workspace named \"{name}\" already exists"),
                        effects,
                    );
                } else {
                    effects.push(Effect::Workspaces(WorkspacesEffect::Rename { id, name }));
                }
                self.set_stage(Stage::List);
            }
            (Purpose::ConfirmDelete(id), a) => {
                if a.is_button("delete") {
                    effects.push(Effect::Workspaces(WorkspacesEffect::Delete(id)));
                }
                self.set_stage(Stage::List);
            }
            (Purpose::Rename(_), _) => self.set_stage(Stage::List),
            // Cancelled save steps end the save.
            _ => self.close_workspace_dialog(),
        }
    }

    fn entry(&self, id: ItemId) -> Option<&WorkspaceEntry> {
        self.tabs
            .workspaces
            .list
            .as_ref()?
            .iter()
            .find(|e| e.id == id)
    }

    // ------------------------------------------------------------------ service results

    /// `UiEvent::Workspaces`.
    pub(crate) fn on_workspaces(&mut self, ev: WorkspacesEvent, effects: &mut Vec<Effect>) {
        match ev {
            WorkspacesEvent::Loaded(list) => {
                self.tabs.workspaces.loading = false;
                self.tabs.workspaces.list = Some(list);
                let rows = self.workspace_rows();
                if let Some(d) = self.workspace_dialog_mut() {
                    d.set_rows(rows);
                }
                if let Some(name) = self.tabs.workspaces.pending_launch.take() {
                    self.launch_named(&name, effects);
                }
            }
            WorkspacesEvent::Done(msg) => {
                self.push_toast(ToastLevel::Success, msg, effects);
            }
            WorkspacesEvent::Failed(report) => {
                self.tabs.workspaces.loading = false;
                if let Some(name) = self.tabs.workspaces.pending_launch.take() {
                    self.push_toast(
                        ToastLevel::Error,
                        format!("Can't open workspace \"{name}\": {}", report.short),
                        effects,
                    );
                } else {
                    self.push_toast(
                        ToastLevel::Error,
                        format!("Workspaces: {}", report.short),
                        effects,
                    );
                }
            }
        }
        self.needs_redraw = true;
    }

    // ------------------------------------------------------------------ open

    /// `sverb --workspace <name>` (delivered after unlock).
    pub(crate) fn launch_workspace(&mut self, name: String, effects: &mut Vec<Effect>) {
        self.tabs.workspaces.pending_launch = Some(name);
        // Always a fresh list: it may have changed since the last load.
        self.tabs.workspaces.loading = false;
        self.load_workspaces(effects);
    }

    fn launch_named(&mut self, name: &str, effects: &mut Vec<Effect>) {
        let list = self.tabs.workspaces.list.clone().unwrap_or_default();
        let found = list
            .iter()
            .find(|e| e.name == name)
            .or_else(|| list.iter().find(|e| e.name.eq_ignore_ascii_case(name)));
        match found {
            Some(e) => self.open_workspace_item(e.id, effects),
            None => {
                let mut names: Vec<&str> = list.iter().map(|e| e.name.as_str()).collect();
                names.sort_unstable();
                let available = if names.is_empty() {
                    "no workspaces are saved".to_owned()
                } else {
                    format!("available: {}", names.join(", "))
                };
                self.push_toast(
                    ToastLevel::Error,
                    format!("No workspace named \"{name}\" ({available})"),
                    effects,
                );
            }
        }
    }

    fn open_workspace_item(&mut self, id: ItemId, effects: &mut Vec<Effect>) {
        match self.entry(id).map(|e| e.spec.clone()) {
            Some(Ok(spec)) => self.open_workspace(spec, effects),
            Some(Err(e)) => {
                self.push_toast(
                    ToastLevel::Error,
                    format!("Can't open this workspace: {e}"),
                    effects,
                );
            }
            None => {
                self.push_toast(
                    ToastLevel::Error,
                    "That workspace no longer exists".to_owned(),
                    effects,
                );
            }
        }
    }

    /// Open `spec` now, or once the host catalog is loaded (right after an unlock).
    pub fn open_workspace(&mut self, spec: WorkspaceSpec, effects: &mut Vec<Effect>) {
        if self.workspace_waits_for_catalog(&spec) {
            self.tabs.workspaces.pending_open = Some(spec);
        } else {
            self.recreate_workspace(spec, effects);
        }
    }

    fn workspace_waits_for_catalog(&self, spec: &WorkspaceSpec) -> bool {
        self.vault.active && self.views.hosts.catalog().is_none() && !spec.host_ids().is_empty()
    }

    fn new_workspace_session(&mut self) -> SessionId {
        loop {
            let id = self.ids.session();
            if !self.tabs.sessions.contains(&id) {
                break id;
            }
        }
    }

    /// One pane for `leaf`: its session (focused, placed by us), its kind, and the
    /// effects that open it (queued).
    fn open_leaf(&mut self, leaf: &LeafRef, effects: &mut Vec<Effect>) -> Pane {
        let mut scratch = Vec::new();
        match leaf {
            LeafRef::Host(item) if self.host_known(*item) => {
                let before = self.tabs.sessions.len();
                self.connect_host(*item, &mut scratch);
                if self.tabs.sessions.len() > before
                    && let Some(id) = self.tabs.sessions.last().copied()
                {
                    return self.queue_pane(id, scratch, effects);
                }
                effects.extend(scratch);
                self.missing_pane(*item)
            }
            LeafRef::Host(item) => self.missing_pane(*item),
            LeafRef::Local { cwd } => {
                let id = self.new_workspace_session();
                let spec = LocalSpec {
                    cwd: cwd.as_ref().map(Into::into),
                    ..LocalSpec::default()
                };
                scratch.push(Effect::OpenSession {
                    id,
                    spec: SessionSpec::Local(spec),
                    cols: 80,
                    rows: 24,
                });
                self.focus_session(id);
                let label = cwd.as_deref().map_or_else(
                    || "local".to_owned(),
                    |c| {
                        let base = std::path::Path::new(c)
                            .file_name()
                            .map(|b| b.to_string_lossy().into_owned())
                            .unwrap_or_else(|| c.to_owned());
                        format!("local: {base}")
                    },
                );
                self.set_pane_label(id, label);
                self.auto_record(id, self.config.recording.enabled, &mut scratch);
                self.queue_pane(id, scratch, effects)
            }
        }
    }

    /// The pane of a queued session: its kind from the `OpenSession`, a "waiting"
    /// overlay until it opens.
    fn queue_pane(
        &mut self,
        id: SessionId,
        scratch: Vec<Effect>,
        effects: &mut Vec<Effect>,
    ) -> Pane {
        let mut pane = Pane::new(id);
        let mut opens = Vec::new();
        for e in scratch {
            match &e {
                Effect::OpenSession { spec, .. } => {
                    pane.kind = match spec {
                        SessionSpec::Ssh(s) => PaneKind::Ssh(s.clone()),
                        SessionSpec::Local(l) => PaneKind::Local(l.clone()),
                        _ => PaneKind::Unknown,
                    };
                    opens.push(e);
                }
                Effect::StartRecording { .. } => opens.push(e),
                _ => effects.push(e),
            }
        }
        self.set_pane_overlay(
            id,
            PaneOverlay::Connecting {
                frame: 0,
                detail: "waiting to connect".to_owned(),
            },
        );
        self.tabs.workspaces.queue.push_back(QueuedOpen {
            session: id,
            effects: opens,
        });
        pane
    }

    /// A "Host missing" placeholder (no session runs behind it).
    fn missing_pane(&mut self, item: ItemId) -> Pane {
        let id = self.new_workspace_session();
        self.focus_session(id);
        self.set_pane_label(id, "missing host");
        self.set_pane_overlay(
            id,
            PaneOverlay::Missing {
                what: "Host missing (deleted)".to_owned(),
            },
        );
        let mut pane = Pane::new(id);
        pane.kind = PaneKind::Ssh(SshSpec {
            host_id: Some(item),
            ..SshSpec::default()
        });
        pane.life = PaneLife::Down;
        pane
    }

    /// Whether the open tabs are just one dead pane (replaced by a workspace).
    fn only_tab_is_empty(&self) -> Option<SessionId> {
        let [tab] = self.tabs.list.as_slice() else {
            return None;
        };
        let [pane] = tab.panes.values().collect::<Vec<_>>()[..] else {
            return None;
        };
        let dead = pane.life == PaneLife::Down
            || !self.tabs.sessions.contains(&pane.session)
            || self.is_dead_pane(pane.session);
        dead.then_some(pane.session)
    }

    /// Recreate the tabs of `spec` and queue their sessions.
    fn recreate_workspace(&mut self, spec: WorkspaceSpec, effects: &mut Vec<Effect>) {
        if spec.tabs.is_empty() {
            self.push_toast(
                ToastLevel::Info,
                "The workspace is empty".to_owned(),
                effects,
            );
            return;
        }
        if let Some(old) = self.only_tab_is_empty() {
            effects.push(Effect::CloseSession(old));
            self.remove_session_pane(old);
        }
        let mut focus = None;
        let mut missing = 0;
        for (i, wtab) in spec.tabs.iter().enumerate() {
            let mut panes = Vec::new();
            for leaf in &wtab.leaves {
                let pane = self.open_leaf(leaf, effects);
                if matches!(leaf, LeafRef::Host(_)) && pane.life == PaneLife::Down {
                    missing += 1;
                }
                panes.push(pane);
            }
            let ids: Vec<_> = panes.iter().map(|p| p.id).collect();
            let Some((layout, focused, broadcast)) = wtab.instantiate(&ids) else {
                continue;
            };
            let id = TabId(self.tabs.next_tab);
            self.tabs.next_tab += 1;
            let mut recency: Vec<_> = layout
                .panes()
                .into_iter()
                .filter(|p| *p != focused)
                .collect();
            recency.push(focused);
            let tab = Tab {
                title_override: wtab.title_override.clone(),
                layout,
                focused,
                panes: panes
                    .into_iter()
                    .map(|p| (p.id, p))
                    .collect::<BTreeMap<_, _>>(),
                recency,
                broadcast: match broadcast {
                    Broadcast::Off => BroadcastSet::Off,
                    Broadcast::AllPanes => BroadcastSet::AllPanes,
                    Broadcast::Custom(set) => BroadcastSet::Custom(set),
                },
                ..Tab::new(id, Pane::new(SessionId(focused.0)))
            };
            let session = tab.focused_session();
            if i == spec.active as usize || focus.is_none() {
                focus = Some(session);
            }
            self.tabs.list.push(tab);
        }
        if let Some(s) = focus {
            self.focus_session(s);
            if let Some(i) = self.tabs.list.iter().position(|t| t.has_session(s)) {
                self.tabs.active = i;
            }
        }
        if !spec.name.is_empty() {
            self.tabs.workspaces.last_name = Some(spec.name.clone());
        }
        if missing > 0 {
            self.push_toast(
                ToastLevel::Warning,
                format!(
                    "{missing} host{} of the workspace no longer exist{}",
                    if missing == 1 { "" } else { "s" },
                    if missing == 1 { "s" } else { "" }
                ),
                effects,
            );
        }
        self.mode = self.derive_mode();
        self.needs_redraw = true;
        self.workspaces_pump(effects);
    }

    // ------------------------------------------------------------------ the queue

    /// After every event (`tabs_after_handle`): free the slots of sessions that are no
    /// longer connecting, release queued opens up to [`OPEN_CONCURRENCY`], open a
    /// workspace that waited for the catalog, forget decrypted names on lock.
    pub(crate) fn workspaces_pump(&mut self, effects: &mut Vec<Effect>) {
        if self.vault.active && self.lock_state().is_locked() {
            if self.tabs.workspaces.list.is_some() || self.tabs.workspaces.dialog.is_some() {
                self.tabs.workspaces.list = None;
                self.tabs.workspaces.loading = false;
                self.close_workspace_dialog();
            }
            return;
        }
        if let Some(spec) = self.tabs.workspaces.pending_open.take() {
            if self.workspace_waits_for_catalog(&spec) {
                self.tabs.workspaces.pending_open = Some(spec);
            } else {
                return self.recreate_workspace(spec, effects);
            }
        }
        let still_connecting = |app: &Self, s: SessionId| {
            app.tabs.sessions.contains(&s)
                && app
                    .tabs
                    .list
                    .iter()
                    .find_map(|t| t.panes.get(&pane_of(s)))
                    .is_some_and(|p| p.life == PaneLife::Connecting)
        };
        let connecting: BTreeSet<SessionId> = self
            .tabs
            .workspaces
            .connecting
            .iter()
            .copied()
            .filter(|s| still_connecting(self, *s))
            .collect();
        self.tabs.workspaces.connecting = connecting;
        while self.tabs.workspaces.connecting.len() < OPEN_CONCURRENCY {
            let Some(q) = self.tabs.workspaces.queue.pop_front() else {
                break;
            };
            if !self.tabs.sessions.contains(&q.session) {
                continue; // closed while it waited
            }
            self.tabs.workspaces.connecting.insert(q.session);
            effects.extend(q.effects);
        }
        let ws = &mut self.tabs.workspaces;
        ws.peak = ws.peak.max(ws.connecting.len());
    }

    /// Sessions waiting for a slot.
    pub fn workspace_queue_len(&self) -> usize {
        self.tabs.workspaces.queue.len()
    }
}

#[cfg(test)]
#[path = "workspaces_tests.rs"]
mod tests;
