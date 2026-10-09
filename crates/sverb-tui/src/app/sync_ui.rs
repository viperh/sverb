//! What the UI shows of sync, behind one facade.
//!
//! [`SyncUi`] is the **single `cfg(feature = "sync")` boundary** of the UI: the top
//! bar, the status bar, the palette and the Settings section ask it, and it answers
//! `None` / `false` in local-only mode (§1.1: no `sync_state` row) and in builds
//! compiled without sync. The model behind it ([`SyncModel`], `app/sync.rs`) only
//! exists in sync builds.
//!
//! Two kinds of "off":
//! * compiled without `sync`: no sync code, UI or commands (the facade is empty);
//! * compiled with sync, local-only: the Sync / Team / Share UI is hidden, and
//!   Settings → Sync shows "Not connected · Connect to a server".
//!
//! The plain-data types here ([`SyncEffect`], [`SyncPanel`], [`WizardScreen`]) exist
//! in every build so effects and views need no `cfg`; services drop sync effects in a
//! local-only build.

use std::fmt;

use sverb_core::vault::LockState;

#[cfg(feature = "sync")]
pub use super::sync::{SyncModel, SyncUiEvent, TeamResult, VaultsResult};
use super::{App, Effect, VaultPassword};

/// How the sync state reads (top bar color).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncLevel {
    /// `⟳ synced`.
    Ok,
    /// `syncing`.
    Busy,
    /// `offline (N pending)`, sign-in required.
    Warn,
    /// `error`.
    Error,
}

/// A device in Settings → Devices (from `GET /v1/devices`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRow {
    /// Device id (UUID text).
    pub id: String,
    /// Name (`-` when unknown).
    pub name: String,
    /// Platform (`-` when unknown).
    pub platform: String,
    /// Created, UNIX ms.
    pub created_ms: Option<i64>,
    /// Last seen, UNIX ms.
    pub last_seen_ms: Option<i64>,
    /// This device.
    pub current: bool,
}

/// The devices list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DevicesPanel {
    /// A request is running.
    pub loading: bool,
    /// The last request failed.
    pub error: Option<String>,
    /// Active devices, this one first.
    pub rows: Vec<DeviceRow>,
}

/// An org in Settings → Team.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgEntry {
    /// Id (UUID text).
    pub id: String,
    /// Name.
    pub name: String,
    /// This account's role.
    pub role: sverb_proto::orgs::Role,
}

/// A member of the shown org.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberEntry {
    /// User id (UUID text).
    pub user_id: String,
    /// The user id's bytes (matches the key pins).
    pub user_bytes: [u8; 16],
    /// Email.
    pub email: String,
    /// Role.
    pub role: sverb_proto::orgs::Role,
}

/// Settings → Team: orgs, the shown org's members, its audit log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TeamPanel {
    /// A request is running.
    pub loading: bool,
    /// The last error.
    pub error: Option<String>,
    /// This account's orgs.
    pub orgs: Vec<OrgEntry>,
    /// The shown org (index into `orgs`).
    pub org: usize,
    /// Its members, owners first.
    pub members: Vec<MemberEntry>,
    /// Its audit log (admins), newest first, as display lines.
    pub audit: Vec<String>,
}

impl TeamPanel {
    /// The shown org.
    pub fn current(&self) -> Option<&OrgEntry> {
        self.orgs.get(self.org)
    }
}

/// A shared vault in Settings → Vaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultEntry {
    /// Vault id (UUID text).
    pub id: String,
    /// Owning org (UUID text).
    pub org_id: String,
    /// Owning org's name.
    pub org_name: String,
    /// Name (opened with the vault key; `Shared <id>` without one).
    pub name: String,
    /// This account's effective permission.
    pub permission: sverb_proto::sync::Permission,
    /// This device holds the key (`false`: "needs key", §13.1).
    pub has_key: bool,
}

/// An org member as seen from the shown vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultMemberEntry {
    /// User id (UUID text).
    pub user_id: String,
    /// Email.
    pub email: String,
    /// Org role (owners and admins manage implicitly).
    pub org_role: sverb_proto::orgs::Role,
    /// Explicit vault permission (`None`: no grant).
    pub permission: Option<sverb_proto::sync::Permission>,
    /// Holds the current key.
    pub has_key: bool,
}

/// Settings → Vaults: the shared vaults of the account's orgs and the shown
/// vault's members.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VaultsPanel {
    /// A request is running.
    pub loading: bool,
    /// The last error.
    pub error: Option<String>,
    /// Vaults, by org then name.
    pub vaults: Vec<VaultEntry>,
    /// The shown vault (index into `vaults`).
    pub shown: usize,
    /// Its members (org members with their vault permission).
    pub members: Vec<VaultMemberEntry>,
    /// Orgs where this account may create vaults (admin+): `(id, name)`.
    pub admin_orgs: Vec<(String, String)>,
}

impl VaultsPanel {
    /// The shown vault.
    pub fn current(&self) -> Option<&VaultEntry> {
        self.vaults.get(self.shown)
    }
}

/// A Settings → Vaults request for the sync service (ids as UUID text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultOp {
    /// Load the vaults (and the members of `vault`, else of the first).
    Load {
        /// The vault to show.
        vault: Option<String>,
    },
    /// Create a shared vault in `org`.
    Create {
        /// Org.
        org: String,
        /// Name.
        name: String,
    },
    /// Grant (or change) a member's access (§13.2; keys checked against the pins).
    Grant {
        /// Vault.
        vault: String,
        /// Member.
        user: String,
        /// Permission.
        permission: sverb_proto::sync::Permission,
    },
    /// Revoke a member's access (or leave).
    Revoke {
        /// Vault.
        vault: String,
        /// Member.
        user: String,
    },
    /// Grant `manage` to org admins without a key (§13.1 reconcile).
    Reconcile,
    /// Rotate the vault key (or resume / restart an interrupted rotation).
    Rotate {
        /// Vault.
        vault: String,
    },
}

/// Everything Settings → Sync / Devices render (plain data, every build).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncPanel {
    /// The build has sync.
    pub available: bool,
    /// A server is set up (`false`: local-only).
    pub connected: bool,
    /// The engine's status (short form) and how it reads.
    pub status: Option<(String, SyncLevel)>,
    /// Server URL.
    pub server: Option<String>,
    /// Account email.
    pub email: Option<String>,
    /// Tokens are stored.
    pub signed_in: bool,
    /// Last successful sync, UNIX ms.
    pub last_sync_ms: Option<i64>,
    /// Pending changes per vault (vault name, count).
    pub pending: Vec<(String, u64)>,
    /// Recent errors, newest last (ErrorReport text).
    pub errors: Vec<String>,
    /// Settings → Devices.
    pub devices: DevicesPanel,
    /// Settings → Team.
    pub team: TeamPanel,
    /// Settings → Vaults.
    pub vaults: VaultsPanel,
}

/// The account flows behind "Connect to a server".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardFlow {
    /// Log in to an existing account (§2.2, §2.5).
    Login,
    /// Create an account from this vault (§2.1).
    Register,
}

/// Input for the account wizard running in the sync service.
#[derive(Clone, PartialEq, Eq)]
pub enum WizardCmd {
    /// Start (or restart) a flow.
    Start(WizardFlow),
    /// The current field's text, then "Next".
    Submit(VaultPassword),
    /// One of the screen's choices.
    Choice(char),
    /// Back one step (or cancel on the first).
    Back,
    /// Abandon the flow (secrets dropped).
    Cancel,
}

impl fmt::Debug for WizardCmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start(flow) => f.debug_tuple("Start").field(flow).finish(),
            Self::Submit(_) => f.write_str("Submit([REDACTED])"),
            Self::Choice(c) => f.debug_tuple("Choice").field(c).finish(),
            Self::Back => f.write_str("Back"),
            Self::Cancel => f.write_str("Cancel"),
        }
    }
}

/// The field a wizard screen asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WizardPrompt {
    /// Label (`Server URL`, `Email`, …).
    pub label: String,
    /// Masked input.
    pub secret: bool,
}

/// One screen of the account wizard (sent by the sync service after every input).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct WizardScreen {
    /// Title.
    pub title: String,
    /// Text lines (the recovery words, the import preview, warnings).
    pub body: Vec<String>,
    /// The field, if the step asks for text.
    pub prompt: Option<WizardPrompt>,
    /// Keys and what they do (`('y', "I wrote it down")`).
    pub choices: Vec<(char, String)>,
    /// The last error.
    pub error: Option<String>,
    /// Waiting for the server.
    pub busy: bool,
    /// Finished; closing the dialog starts sync.
    pub done: bool,
    /// The vault must be unlocked again (the account vault replaced the local one).
    pub relock: bool,
}

impl fmt::Debug for WizardScreen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The body may hold the recovery words.
        f.debug_struct("WizardScreen")
            .field("title", &self.title)
            .field("prompt", &self.prompt)
            .field("busy", &self.busy)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

/// A request for the sync service (`services::sync`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncEffect {
    /// The vault was unlocked: read the local state, start the engine if set up.
    Start,
    /// The vault was locked: stop the engine (WS closed, keys dropped).
    Stop,
    /// Run a cycle now.
    SyncNow,
    /// Re-read the local state (server, account, last sync, pending).
    Refresh,
    /// Settings → Sync → Disconnect (logout, personal data kept).
    Disconnect,
    /// Load the devices list.
    ListDevices,
    /// Revoke a device (this one: logout).
    RevokeDevice {
        /// Device id.
        id: String,
    },
    /// Drive the account wizard.
    Wizard(WizardCmd),
    /// Load the team pins (Settings → Team).
    TeamPins,
    /// A Settings → Team answer: mark verified / accept a new key.
    TeamVerify {
        /// The member.
        user: [u8; 16],
        /// Accept their new key (else mark verified).
        accept_new_key: bool,
    },
    /// Settings → Team: an org request.
    Team(TeamOp),
    /// Settings → Vaults: a shared-vault request.
    Vaults(VaultOp),
}

/// An org request for the sync service (ids as UUID text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TeamOp {
    /// Load the orgs and the members of `org` (else the first org).
    Load {
        /// The org to show.
        org: Option<String>,
    },
    /// Create an org.
    Create {
        /// Name.
        name: String,
    },
    /// Invite to `org` (`email: None`: a link invite).
    Invite {
        /// Org.
        org: String,
        /// Bound email.
        email: Option<String>,
    },
    /// Accept a pasted invite link.
    Accept {
        /// The link.
        link: String,
    },
    /// Change a member's role.
    SetRole {
        /// Org.
        org: String,
        /// Member.
        user: String,
        /// New role.
        role: sverb_proto::orgs::Role,
    },
    /// Remove a member (or leave).
    Remove {
        /// Org.
        org: String,
        /// Member.
        user: String,
    },
    /// Load the audit log.
    Audit {
        /// Org.
        org: String,
    },
}

/// The UI side of sync. Empty in builds without sync.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncUi {
    #[cfg(feature = "sync")]
    pub(crate) model: SyncModel,
}

impl SyncUi {
    /// Sync is set up on this device (a server is configured). `false` in local-only
    /// mode and in builds without sync: the Sync, Team and Share UI is hidden.
    pub fn connected(&self) -> bool {
        #[cfg(feature = "sync")]
        {
            self.model.connected()
        }
        #[cfg(not(feature = "sync"))]
        {
            false
        }
    }

    /// The top-bar indicator (`⟳ synced`, `offline (3 pending)`, …); `None` hides it.
    pub fn indicator(&self) -> Option<(String, SyncLevel)> {
        #[cfg(feature = "sync")]
        {
            self.model.indicator()
        }
        #[cfg(not(feature = "sync"))]
        {
            None
        }
    }

    /// Settings → Sync / Devices.
    pub fn panel(&self) -> SyncPanel {
        #[cfg(feature = "sync")]
        {
            self.model.panel()
        }
        #[cfg(not(feature = "sync"))]
        {
            SyncPanel::default()
        }
    }
}

impl App {
    /// The sync facade.
    pub fn sync_ui(&self) -> &SyncUi {
        &self.sync
    }

    /// Unlock starts the engine, lock stops it (§12: sync runs while unlocked).
    pub(crate) fn sync_lock_transition(&mut self, was: LockState, effects: &mut Vec<Effect>) {
        if !cfg!(feature = "sync") {
            return;
        }
        let now = self.lock_state();
        if now == was {
            return;
        }
        match now {
            LockState::Unlocked => effects.push(Effect::Sync(SyncEffect::Start)),
            _ => effects.push(Effect::Sync(SyncEffect::Stop)),
        }
    }
}

impl App {
    /// The Settings view's request, right after its key.
    pub(crate) fn take_settings_request(&mut self, effects: &mut Vec<Effect>) {
        let Some(req) = self.views.settings.take_request() else {
            return;
        };
        #[cfg(feature = "sync")]
        self.sync_settings_request(req, effects);
        #[cfg(not(feature = "sync"))]
        let _ = (req, effects);
    }

    /// The account wizard's answer, right after its key.
    pub(crate) fn take_sync_dialog_answer(&mut self, effects: &mut Vec<Effect>) {
        #[cfg(feature = "sync")]
        self.take_wizard_answer(effects);
        #[cfg(not(feature = "sync"))]
        let _ = effects;
    }

    /// `sync_status`, `sync_now`, `devices`, `team_keys` (enabled only when sync is set
    /// up). Returns whether `action` was one of them.
    pub(crate) fn apply_sync_action(
        &mut self,
        action: crate::keymap::action::ActionName,
        effects: &mut Vec<Effect>,
    ) -> bool {
        use crate::keymap::action::ActionName as A;
        use crate::views::settings::SettingsPage;
        if !matches!(
            action,
            A::SyncStatus | A::SyncNow | A::Devices | A::TeamKeys
        ) {
            return false;
        }
        if !self.sync.connected() {
            return true;
        }
        #[cfg(feature = "sync")]
        match action {
            A::SyncNow => effects.push(Effect::Sync(SyncEffect::SyncNow)),
            A::Devices => self.open_sync_page(SettingsPage::Devices, effects),
            A::TeamKeys => self.open_sync_page(SettingsPage::Team, effects),
            _ => self.open_sync_page(SettingsPage::Sync, effects),
        }
        #[cfg(not(feature = "sync"))]
        let _ = (effects, SettingsPage::Sync);
        true
    }

    /// A click on the top bar's sync indicator opens Settings → Sync.
    pub(crate) fn sync_indicator_click(
        &mut self,
        mouse: crossterm::event::MouseEvent,
        effects: &mut Vec<Effect>,
    ) -> bool {
        use crossterm::event::{MouseButton, MouseEventKind};
        if !matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
            return false;
        }
        let Some((text, _)) = self.sync.indicator() else {
            return false;
        };
        let bar = self.shell_rects().top_bar;
        if !crate::widgets::topbar::sync_hit(bar, &text, mouse) {
            return false;
        }
        #[cfg(feature = "sync")]
        self.open_sync_page(crate::views::settings::SettingsPage::Sync, effects);
        #[cfg(not(feature = "sync"))]
        let _ = effects;
        true
    }
}

impl App {
    /// The Settings view starts with the facade's panel (local-only until told
    /// otherwise; `available` says whether this build has sync).
    pub(crate) fn with_settings_panel(mut self) -> Self {
        let mut panel = self.sync.panel();
        panel.available = cfg!(feature = "sync");
        self.views.settings.set_panel(panel);
        self
    }
}
