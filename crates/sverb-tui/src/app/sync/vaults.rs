//! M5-02: Settings → Vaults in the reducer (SPEC §13.1, §13.2): shared vaults of
//! the account's orgs ("needs key" for org admins without a grant), create,
//! grant with a permission, revoke (asks first), and the admin reconcile. The
//! work runs in the sync service; results come back as [`VaultsResult`].

use crate::app::sync_ui::{SyncEffect, VaultEntry, VaultMemberEntry, VaultOp, VaultsPanel};
use crate::app::{App, Effect, ToastLevel};
use crate::views::dialogs::{ModalDialog, rotation};
use crate::views::{DialogId, DialogKind};
use crate::widgets::dialog::{Button, Modal};

/// The result of a [`VaultOp`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultsResult {
    /// The vaults and the shown vault's members.
    Loaded {
        /// Vaults (org, then name).
        vaults: Vec<VaultEntry>,
        /// The shown vault (id text).
        shown: Option<String>,
        /// Its members.
        members: Vec<VaultMemberEntry>,
        /// Orgs where vaults can be created.
        admin_orgs: Vec<(String, String)>,
    },
    /// Something changed (toast text); the page reloads showing `vault`.
    Changed {
        /// Toast text.
        message: String,
        /// The vault to show after the reload.
        vault: Option<String>,
    },
    /// A request failed (a key-change refusal says so loudly).
    Failed(String),
    // M5-04
    /// A key rotation's progress (opens / updates the progress dialog).
    Rotation {
        /// Vault (id text).
        vault: String,
        /// Phase label.
        phase: String,
        /// Done in this phase.
        done: usize,
        /// Total in this phase (0: no counts).
        total: usize,
    },
    /// A key rotation finished (toast text); the page reloads showing `vault`.
    RotationDone {
        /// Toast text.
        message: String,
        /// Vault (id text).
        vault: String,
    },
    /// A key rotation failed (it stays open on the server and can be resumed).
    RotationFailed(String),
}

impl App {
    pub(crate) fn vaults_request(&mut self, op: VaultOp, effects: &mut Vec<Effect>) {
        let v = &mut self.sync.model.vaults;
        v.loading = true;
        v.error = None;
        self.views.settings.set_panel(self.sync.panel());
        self.needs_redraw = true;
        effects.push(Effect::Sync(SyncEffect::Vaults(op)));
    }

    pub(crate) fn confirm_vault_revoke(
        &mut self,
        vault: String,
        vault_name: &str,
        user: String,
        email: &str,
        me: bool,
        effects: &mut Vec<Effect>,
    ) {
        // M5-04: revoking someone else rotates the vault key right away.
        let (title, body, label) = rotation::revoke_text(vault_name, email, me);
        let modal = Modal::confirm(
            title,
            &body,
            vec![
                Button::new("revoke", label, 'r').danger(),
                Button::new("cancel", "Cancel", 'c').safe(),
            ],
            1,
            true,
        );
        self.push_modal(
            ModalDialog::new(modal).on(
                "button:revoke",
                vec![Effect::Sync(SyncEffect::Vaults(VaultOp::Revoke {
                    vault,
                    user,
                }))],
            ),
            effects,
        );
    }

    pub(crate) fn on_vaults_result(&mut self, res: VaultsResult, effects: &mut Vec<Effect>) {
        self.sync.model.vaults.loading = false;
        match res {
            VaultsResult::Loaded {
                vaults,
                shown,
                members,
                admin_orgs,
            } => {
                let shown = shown
                    .and_then(|id| vaults.iter().position(|v| v.id == id))
                    .unwrap_or(0);
                self.sync.model.vaults = VaultsPanel {
                    loading: false,
                    error: None,
                    vaults,
                    shown,
                    members,
                    admin_orgs,
                };
            }
            VaultsResult::Changed { message, vault } => {
                self.push_toast(ToastLevel::Success, message, effects);
                self.vaults_request(VaultOp::Load { vault }, effects);
            }
            VaultsResult::Failed(e) => {
                self.sync.model.vaults.error = Some(e.clone());
                self.push_toast(ToastLevel::Error, e, effects);
            }
            // M5-04
            VaultsResult::Rotation {
                vault,
                phase,
                done,
                total,
            } => self.on_rotation_progress(&vault, &phase, done, total, effects),
            VaultsResult::RotationDone { message, vault } => {
                self.close_rotation_dialog();
                self.push_toast(ToastLevel::Success, message, effects);
                self.vaults_request(VaultOp::Load { vault: Some(vault) }, effects);
            }
            VaultsResult::RotationFailed(e) => {
                self.close_rotation_dialog();
                self.sync.model.vaults.error = Some(e.clone());
                self.push_toast(ToastLevel::Error, e, effects);
            }
        }
        self.views.settings.set_panel(self.sync.panel());
        self.needs_redraw = true;
    }
}

// M5-04: the key rotation dialogs.
impl App {
    /// The name shown for a shared vault (id text): its listed name, else a
    /// short id.
    pub(crate) fn shared_vault_label(&self, vault: &str) -> String {
        self.sync
            .model
            .vaults
            .vaults
            .iter()
            .find(|v| v.id == vault)
            .map_or_else(
                || format!("shared vault {}", vault.get(..8).unwrap_or(vault)),
                |v| v.name.clone(),
            )
    }

    fn rotation_dialog_open(&self) -> Option<DialogId> {
        let id = self.sync.model.rotation_dialog?;
        self.dialogs.iter().any(|d| d.id == id).then_some(id)
    }

    fn on_rotation_progress(
        &mut self,
        vault: &str,
        phase: &str,
        done: usize,
        total: usize,
        effects: &mut Vec<Effect>,
    ) {
        let name = self.shared_vault_label(vault);
        let id = match self.rotation_dialog_open() {
            Some(id) => id,
            None if phase == "Starting" => {
                let id = self.push_modal(rotation::progress(&name), effects);
                self.sync.model.rotation_dialog = Some(id);
                id
            }
            // Hidden by the user: keep it hidden.
            None => return,
        };
        let body = rotation::progress_body(&name, phase, done, total);
        if let Some(DialogKind::Modal(m)) = self
            .dialogs
            .iter_mut()
            .find(|d| d.id == id)
            .map(|d| &mut d.kind)
        {
            m.modal.body = body;
        }
        self.needs_redraw = true;
    }

    fn close_rotation_dialog(&mut self) {
        if let Some(id) = self.sync.model.rotation_dialog.take() {
            self.dialogs.retain(|d| d.id != id);
            self.needs_redraw = true;
        }
    }

    /// An abandoned rotation of a vault this account manages: ask to restart it.
    pub(crate) fn prompt_abandoned_rotation(&mut self, vault: &str, effects: &mut Vec<Effect>) {
        let name = self.shared_vault_label(vault);
        self.push_modal(rotation::abandoned_prompt(vault, &name), effects);
    }
}
