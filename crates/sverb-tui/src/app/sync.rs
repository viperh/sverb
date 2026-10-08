//! M4-07: `UiEvent::Sync` in the reducer. M4-09: the sync model behind
//! [`SyncUi`](super::sync_ui::SyncUi): status for the bars, the Settings → Sync /
//! Devices / Team pages, the account wizard, and the per-session clock-skew toasts.
//!
//! Sync builds only; every other part of the UI goes through the facade.

use std::collections::BTreeSet;

use sverb_store::{PinnedKey, VaultKind};
use sverb_sync::{LocalSyncInfo, SyncEvent, SyncStatus, ToastLevel as SyncToast};

use super::sync_ui::{
    DeviceRow, DevicesPanel, SyncEffect, SyncLevel, SyncPanel, WizardCmd, WizardFlow, WizardScreen,
};
use super::{App, Effect, ToastLevel};
use crate::services::vault::vault_display_name;
use crate::views::dialogs::ModalDialog;
use crate::views::{
    DialogKind, Section,
    settings::{
        SettingsPage, SettingsRequest,
        account_wizard::{AccountWizardDialog, WizardAnswer},
    },
};
use crate::widgets::dialog::{Button, Modal};

/// Recent errors kept for the Sync page.
pub(crate) const MAX_ERRORS: usize = 5;

/// Whether this device syncs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Link {
    /// Not known yet (locked, or the service has not answered).
    #[default]
    Unknown,
    /// No `sync_state` row (§1.1).
    LocalOnly,
    /// A server is set up.
    Connected,
}

/// What the UI knows about sync.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncModel {
    /// Local-only or connected.
    pub link: Link,
    /// The engine's last status.
    pub status: Option<SyncStatus>,
    /// Server, account, last sync, pending.
    pub info: Option<LocalSyncInfo>,
    /// Recent errors, newest last.
    pub errors: Vec<String>,
    /// Settings → Devices.
    pub devices: DevicesPanel,
    /// Devices a clock-skew toast was shown for (once per device per session).
    pub skew_warned: BTreeSet<String>,
}

/// From the sync service (`services::sync`), besides engine events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncUiEvent {
    /// The local state (after start, a cycle, a login or logout).
    Info(LocalSyncInfo),
    /// `GET /v1/devices`.
    Devices(Result<Vec<DeviceRow>, String>),
    /// A revoke finished.
    Revoked {
        /// The device.
        id: String,
        /// It was this device (now logged out).
        this_device: bool,
        /// Error text on failure.
        result: Result<(), String>,
    },
    /// Disconnect finished (message for the toast).
    Disconnected(Result<String, String>),
    /// The next wizard screen.
    Wizard(WizardScreen),
    /// Team pins (Settings → Team).
    TeamPins(Vec<PinnedKey>),
}

/// How a status reads.
pub(crate) fn level(status: &SyncStatus) -> Option<SyncLevel> {
    Some(match status {
        SyncStatus::Disabled => return None,
        SyncStatus::Synced => SyncLevel::Ok,
        SyncStatus::Syncing => SyncLevel::Busy,
        SyncStatus::Offline { .. } | SyncStatus::NeedsLogin => SyncLevel::Warn,
        SyncStatus::Error { .. } => SyncLevel::Error,
    })
}

impl SyncModel {
    pub(crate) fn connected(&self) -> bool {
        self.link == Link::Connected
    }

    pub(crate) fn indicator(&self) -> Option<(String, SyncLevel)> {
        if !self.connected() {
            return None;
        }
        let status = self.status.as_ref()?;
        Some((status.short(), level(status)?))
    }

    pub(crate) fn panel(&self) -> SyncPanel {
        let info = self.info.clone().unwrap_or_default();
        SyncPanel {
            available: true,
            connected: self.connected(),
            status: self.indicator(),
            server: info.server_url,
            email: info.email,
            signed_in: info.signed_in,
            last_sync_ms: info.last_sync_ms,
            pending: info
                .pending
                .iter()
                .map(|p| {
                    let name = match p.kind {
                        Some(kind) => vault_display_name(p.vault, kind),
                        None => vault_display_name(p.vault, VaultKind::Shared),
                    };
                    (name, p.pending)
                })
                .collect(),
            errors: self.errors.clone(),
            devices: self.devices.clone(),
        }
    }

    fn push_error(&mut self, message: String) {
        if self.errors.last() != Some(&message) {
            self.errors.push(message);
        }
        if self.errors.len() > MAX_ERRORS {
            self.errors.remove(0);
        }
    }
}

impl App {
    /// Hands the current panel to the Settings view.
    fn sync_changed(&mut self) {
        self.views.settings.set_panel(self.sync.panel());
        self.needs_redraw = true;
    }

    pub(crate) fn on_sync(&mut self, ev: SyncEvent, effects: &mut Vec<Effect>) {
        match ev {
            SyncEvent::Toast { level, message } => {
                let level = match level {
                    SyncToast::Info => ToastLevel::Info,
                    SyncToast::Warn => ToastLevel::Warning,
                    SyncToast::Error => {
                        self.sync.model.push_error(message.clone());
                        self.sync_changed();
                        ToastLevel::Error
                    }
                };
                self.push_toast(level, message, effects);
            }
            // M4-09: once per device per session.
            SyncEvent::ClockSkew { device, .. } => {
                if self.sync.model.skew_warned.insert(device.clone()) {
                    self.push_toast(
                        ToastLevel::Warning,
                        format!("Clock skew detected on device {device}"),
                        effects,
                    );
                }
            }
            SyncEvent::Status(status) => {
                let m = &mut self.sync.model;
                match &status {
                    SyncStatus::Disabled => m.link = Link::LocalOnly,
                    SyncStatus::Error { message } => {
                        let message = message.clone();
                        m.link = Link::Connected;
                        m.push_error(message);
                    }
                    _ => m.link = Link::Connected,
                }
                let settled = !matches!(status, SyncStatus::Syncing);
                m.status = Some(status);
                // Pending counts and the last sync time changed.
                if settled {
                    effects.push(Effect::Sync(SyncEffect::Refresh));
                }
                self.sync_changed();
            }
            SyncEvent::Applied { .. } | SyncEvent::ReadOnly { .. } => {}
        }
    }

    pub(crate) fn on_sync_ui(&mut self, ev: SyncUiEvent, effects: &mut Vec<Effect>) {
        match ev {
            SyncUiEvent::Info(info) => {
                let m = &mut self.sync.model;
                m.link = if info.connected() {
                    Link::Connected
                } else {
                    Link::LocalOnly
                };
                if !info.connected() {
                    m.status = None;
                    m.devices = DevicesPanel::default();
                }
                m.info = Some(info);
                self.sync_changed();
            }
            SyncUiEvent::Devices(res) => {
                let d = &mut self.sync.model.devices;
                d.loading = false;
                match res {
                    Ok(rows) => {
                        d.rows = rows;
                        d.error = None;
                    }
                    Err(e) => d.error = Some(e),
                }
                self.sync_changed();
            }
            SyncUiEvent::Revoked {
                id,
                this_device,
                result,
            } => match result {
                Ok(()) if this_device => {
                    self.push_toast(
                        ToastLevel::Info,
                        "This device was revoked and logged out; local data is kept".into(),
                        effects,
                    );
                    effects.push(Effect::Sync(SyncEffect::Refresh));
                }
                Ok(()) => {
                    self.sync.model.devices.rows.retain(|r| r.id != id);
                    self.sync_changed();
                    self.push_toast(ToastLevel::Info, "Device revoked".into(), effects);
                }
                Err(e) => {
                    self.push_toast(ToastLevel::Error, format!("Revoke failed: {e}"), effects);
                }
            },
            SyncUiEvent::Disconnected(res) => match res {
                Ok(msg) => {
                    self.push_toast(ToastLevel::Info, msg, effects);
                    effects.push(Effect::Sync(SyncEffect::Refresh));
                }
                Err(e) => {
                    self.push_toast(
                        ToastLevel::Error,
                        format!("Disconnect failed: {e}"),
                        effects,
                    );
                }
            },
            SyncUiEvent::Wizard(screen) => {
                if let Some(d) = self.wizard_dialog_mut() {
                    d.set_screen(screen);
                    self.needs_redraw = true;
                }
            }
            SyncUiEvent::TeamPins(pins) => {
                self.views.settings.team.set_pins(&pins);
                self.needs_redraw = true;
            }
        }
    }

    fn wizard_dialog_mut(&mut self) -> Option<&mut AccountWizardDialog> {
        self.dialogs
            .iter_mut()
            .rev()
            .find_map(|d| match &mut d.kind {
                DialogKind::AccountWizard(w) => Some(&mut **w),
                _ => None,
            })
    }

    /// Settings → Sync (the details panel): the palette's "Sync status" and a click
    /// on the top-bar indicator.
    pub(crate) fn open_sync_page(&mut self, page: SettingsPage, effects: &mut Vec<Effect>) {
        self.open_section(Section::Settings);
        self.views.settings.show(page);
        self.take_settings_request(effects);
        self.needs_redraw = true;
    }

    /// Opens the account wizard.
    pub(crate) fn open_account_wizard(&mut self, flow: WizardFlow, effects: &mut Vec<Effect>) {
        if self.wizard_dialog_mut().is_some() {
            return;
        }
        self.push_dialog(DialogKind::AccountWizard(Box::new(
            AccountWizardDialog::new(flow),
        )));
        effects.push(Effect::Sync(SyncEffect::Wizard(WizardCmd::Start(flow))));
    }

    /// The wizard dialog's answer, right after its key.
    pub(crate) fn take_wizard_answer(&mut self, effects: &mut Vec<Effect>) {
        let Some(answer) = self
            .wizard_dialog_mut()
            .and_then(AccountWizardDialog::take_answer)
        else {
            return;
        };
        self.needs_redraw = true;
        match answer {
            WizardAnswer::Cmd(cmd) => effects.push(Effect::Sync(SyncEffect::Wizard(cmd))),
            WizardAnswer::Closed { done, relock } => {
                self.dialogs
                    .retain(|d| !matches!(d.kind, DialogKind::AccountWizard(_)));
                if !done {
                    effects.push(Effect::Sync(SyncEffect::Wizard(WizardCmd::Cancel)));
                    return;
                }
                effects.push(Effect::Sync(SyncEffect::Refresh));
                if relock {
                    self.push_toast(
                        ToastLevel::Info,
                        "Signed in. Unlock with your account password to load the account vault"
                            .into(),
                        effects,
                    );
                    self.lock_vault(effects);
                } else {
                    // Registration keeps this vault: sync starts now.
                    effects.push(Effect::Sync(SyncEffect::Start));
                }
            }
        }
    }

    /// Settings view requests (the Sync, Devices and Team pages).
    pub(crate) fn sync_settings_request(
        &mut self,
        req: SettingsRequest,
        effects: &mut Vec<Effect>,
    ) {
        match req {
            SettingsRequest::Connect(flow) => self.open_account_wizard(flow, effects),
            SettingsRequest::SyncNow => effects.push(Effect::Sync(SyncEffect::SyncNow)),
            SettingsRequest::Disconnect => {
                let modal = Modal::confirm(
                    "Disconnect from the server?",
                    "This device signs out. Shared vaults are removed from it; your personal \
                     vault and master password stay, and changes queue for a later upload.",
                    vec![
                        Button::new("disconnect", "Disconnect", 'd').danger(),
                        Button::new("cancel", "Cancel", 'c').safe(),
                    ],
                    1,
                    true,
                );
                self.push_modal(
                    ModalDialog::new(modal).on(
                        "button:disconnect",
                        vec![Effect::Sync(SyncEffect::Disconnect)],
                    ),
                    effects,
                );
            }
            SettingsRequest::RefreshDevices => {
                self.sync.model.devices.loading = true;
                self.sync_changed();
                effects.push(Effect::Sync(SyncEffect::ListDevices));
            }
            SettingsRequest::Revoke { id, name, current } => {
                let body = if current {
                    format!(
                        "\"{name}\" is THIS device: revoking it logs you out here. \
                         Your personal data stays on this device."
                    )
                } else {
                    format!("\"{name}\" loses access to the account at once.")
                };
                let modal = Modal::confirm(
                    "Revoke device?",
                    &body,
                    vec![
                        Button::new("revoke", "Revoke", 'r').danger(),
                        Button::new("cancel", "Cancel", 'c').safe(),
                    ],
                    1,
                    true,
                );
                self.push_modal(
                    ModalDialog::new(modal).on(
                        "button:revoke",
                        vec![Effect::Sync(SyncEffect::RevokeDevice { id })],
                    ),
                    effects,
                );
            }
            SettingsRequest::LoadTeam => effects.push(Effect::Sync(SyncEffect::TeamPins)),
            SettingsRequest::TeamVerify {
                user,
                accept_new_key,
            } => effects.push(Effect::Sync(SyncEffect::TeamVerify {
                user,
                accept_new_key,
            })),
        }
    }
}
