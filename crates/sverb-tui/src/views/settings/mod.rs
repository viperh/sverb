//! Settings views (synced mode adds Sync and Team pages).
//!
//! M4-09: the Settings section. In local-only mode (§1.1) it has one page:
//!
//! ```text
//! ┌ Settings ─────────────────────────────────────────────┐
//! │ Sync                                                   │
//! │ Not connected · Connect to a server                    │
//! │                                                        │
//! │ [Enter] Log in to a server   [n] Create an account     │
//! └────────────────────────────────────────────────────────┘
//! ```
//!
//! Signed in, `Sync · Devices · Team` (`1` `2` `3`, `←` `→`):
//! * **Sync**: status, server, account, last successful sync, pending changes per
//!   vault, recent errors; `s` sync now, `d` disconnect (asks).
//! * **Devices**: `GET /v1/devices` (name, platform, created, last seen, this device);
//!   `x` / `Delete` revokes (asks; revoking this device logs out), `r` reloads.
//! * **Team**: the M5-03 trust page ([`team_verify`]).
//!
//! The view renders a [`SyncPanel`] the reducer hands it ([`SettingsView::set_panel`])
//! and leaves what the user asked for in [`SettingsView::take_request`].

// M5-03: Settings → Team: safety numbers, ✓ verification, key-change warnings
// (§13.3). Sync builds only (team features need an account).
#[cfg(feature = "sync")]
pub mod team_verify;

// M4-09: the account wizard dialog (log in / create an account).
pub mod account_wizard;

// M5-02: Settings → Vaults (shared vaults, grants, §13.1–§13.2).
pub mod vaults;

use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    style::Modifier,
    text::{Line, Span},
    widgets::{Block, Paragraph, Wrap},
};
use sverb_core::model::UnixMillis;

use crate::{
    app::sync_ui::{SyncLevel, SyncPanel, TeamOp, WizardFlow},
    theme::Theme,
    views::{Outcome, RenderCx, View, ViewCx, ViewEvent, logs::list::format_time},
};

/// The exact local-only text of Settings → Sync (§1.1).
pub const NOT_CONNECTED: &str = "Not connected · Connect to a server";

/// A Settings page.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SettingsPage {
    /// Sync status (the details panel).
    #[default]
    Sync,
    /// The account's devices.
    Devices,
    /// Team keys (M5-03).
    Team,
    // M5-02
    /// Shared vaults (M5-02).
    Vaults,
}

impl SettingsPage {
    const ALL: [Self; 4] = [Self::Sync, Self::Devices, Self::Team, Self::Vaults];

    fn title(self) -> &'static str {
        match self {
            Self::Sync => "Sync",
            Self::Devices => "Devices",
            Self::Team => "Team",
            // M5-02
            Self::Vaults => "Vaults",
        }
    }
}

/// What the user asked for (taken by the reducer right after the key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsRequest {
    /// Open the account wizard.
    Connect(WizardFlow),
    /// Run a cycle now.
    SyncNow,
    /// Disconnect (asks first).
    Disconnect,
    /// Reload the devices.
    RefreshDevices,
    /// Revoke a device (asks first).
    Revoke {
        /// Device id.
        id: String,
        /// Its name.
        name: String,
        /// This device (revoking it logs out).
        current: bool,
    },
    /// Load the team pins (the Team page was opened).
    LoadTeam,
    /// A Team page answer.
    TeamVerify {
        /// The member.
        user: [u8; 16],
        /// Accept a changed key (else mark verified).
        accept_new_key: bool,
    },
    // M5-01
    /// An org request (no confirmation needed).
    Team(TeamOp),
    /// Remove a member or leave (asks first).
    TeamRemove {
        /// Org id.
        org: String,
        /// Org name.
        org_name: String,
        /// Member id.
        user: String,
        /// Their email.
        email: String,
        /// It is this account (leaving).
        me: bool,
    },
    // M5-02
    /// A Settings → Vaults request (no confirmation needed).
    Vaults(crate::app::sync_ui::VaultOp),
    /// Revoke a member's vault access or leave (asks first).
    VaultRevoke {
        /// Vault id.
        vault: String,
        /// Vault name.
        vault_name: String,
        /// Member id.
        user: String,
        /// Their email.
        email: String,
        /// It is this account (leaving).
        me: bool,
    },
}

// M5-01
/// What the Team page's input line is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeamInput {
    /// A new org's name.
    CreateOrg,
    /// The email to invite (empty: a link invite).
    Invite,
    /// A pasted invite link.
    Accept,
}

impl TeamInput {
    fn label(self) -> &'static str {
        match self {
            Self::CreateOrg => "New org name",
            Self::Invite => "Invite email (empty: a single-use link)",
            Self::Accept => "Invite link",
        }
    }
}

/// The Settings section.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SettingsView {
    /// What to show (from `SyncUi::panel`).
    pub panel: SyncPanel,
    /// The page.
    pub page: SettingsPage,
    /// Highlighted device.
    pub device_selected: usize,
    /// Times are shown at this UTC offset (seconds east); `None`: local time.
    pub utc_offset_secs: Option<i32>,
    /// M5-03: the Team page.
    #[cfg(feature = "sync")]
    pub team: team_verify::TeamVerifyView,
    // M5-01
    /// Highlighted member on the Team page.
    pub member_selected: usize,
    /// The Team page's input line, while open.
    pub input: Option<(TeamInput, String)>,
    // M5-02
    /// The Vaults page's cursor and input line.
    pub vaults: vaults::VaultsState,
    request: Option<SettingsRequest>,
}

impl SettingsView {
    /// Replaces the panel; a page that is no longer available falls back to Sync.
    pub fn set_panel(&mut self, panel: SyncPanel) {
        self.panel = panel;
        if !self.pages().contains(&self.page) {
            self.page = SettingsPage::Sync;
        }
        self.device_selected = self
            .device_selected
            .min(self.panel.devices.rows.len().saturating_sub(1));
        // M5-01
        self.member_selected = self
            .member_selected
            .min(self.panel.team.members.len().saturating_sub(1));
        // M5-02
        self.vaults.clamp(&self.panel.vaults);
    }

    /// The Team page edits text (Insert mode).
    pub fn wants_text(&self) -> bool {
        (self.page == SettingsPage::Team && self.input.is_some())
            // M5-02
            || (self.page == SettingsPage::Vaults && self.vaults.input.is_some())
    }

    /// The pages shown now: only Sync until a server is connected.
    pub fn pages(&self) -> &'static [SettingsPage] {
        if self.panel.connected {
            &SettingsPage::ALL
        } else {
            &SettingsPage::ALL[..1]
        }
    }

    /// Show `page` (if available). Returns the request it needs (devices / pins).
    pub fn show(&mut self, page: SettingsPage) {
        if !self.pages().contains(&page) {
            return;
        }
        self.page = page;
        self.request = match page {
            SettingsPage::Devices => Some(SettingsRequest::RefreshDevices),
            SettingsPage::Team => Some(SettingsRequest::LoadTeam),
            SettingsPage::Sync => None,
            // M5-02
            SettingsPage::Vaults => Some(SettingsRequest::Vaults(
                crate::app::sync_ui::VaultOp::Load {
                    vault: self.panel.vaults.current().map(|v| v.id.clone()),
                },
            )),
        };
    }

    /// Takes the pending request.
    pub fn take_request(&mut self) -> Option<SettingsRequest> {
        // M5-03: the Team page's answers.
        #[cfg(feature = "sync")]
        if self.request.is_none()
            && let Some(req) = self.team.take_request()
        {
            use team_verify::TeamVerifyRequest as R;
            let (user, accept_new_key) = match req {
                R::MarkVerified(u) => (u, false),
                R::AcceptNewKey(u) => (u, true),
            };
            return Some(SettingsRequest::TeamVerify {
                user,
                accept_new_key,
            });
        }
        self.request.take()
    }

    fn cycle_page(&mut self, delta: isize) {
        let pages = self.pages();
        let i = pages.iter().position(|p| *p == self.page).unwrap_or(0);
        let n = isize::try_from(pages.len()).unwrap_or(1);
        let next = (isize::try_from(i).unwrap_or(0) + delta).rem_euclid(n);
        let page = pages[usize::try_from(next).unwrap_or(0)];
        self.show(page);
    }

    fn time(&self, ms: i64, cx: &RenderCx<'_>) -> String {
        format_time(
            UnixMillis(ms),
            &cx.config.ui.date_format,
            self.utc_offset_secs,
        )
    }

    fn sync_lines(&self, cx: &RenderCx<'_>) -> Vec<Line<'static>> {
        let theme = cx.theme;
        let p = &self.panel;
        let mut lines = Vec::new();
        if !p.connected {
            lines.push(Line::styled(
                NOT_CONNECTED,
                theme.base.add_modifier(Modifier::BOLD),
            ));
            lines.push(Line::raw(""));
            lines.push(Line::from(vec![
                Span::styled("[Enter]", theme.accent),
                Span::raw(" Log in to a server   "),
                Span::styled("[n]", theme.accent),
                Span::raw(" Create an account"),
            ]));
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                "sverb works fully offline. Nothing is sent anywhere until you connect a server.",
                theme.dim,
            ));
            return lines;
        }
        let row = |label: &str, value: Span<'static>| {
            Line::from(vec![Span::styled(format!("{label:<12}"), theme.dim), value])
        };
        let status = match &p.status {
            Some((text, level)) => Span::styled(text.clone(), level_style(*level, theme)),
            None => Span::styled("starting…", theme.dim),
        };
        lines.push(row("Status", status));
        if let Some(server) = &p.server {
            lines.push(row("Server", Span::raw(server.clone())));
        }
        if let Some(email) = &p.email {
            lines.push(row("Account", Span::raw(email.clone())));
        }
        if !p.signed_in {
            lines.push(row(
                "Signed in",
                Span::styled("no: log in again (Enter)", theme.warn),
            ));
        }
        let last = p
            .last_sync_ms
            .map_or_else(|| "never".to_owned(), |ms| self.time(ms, cx));
        lines.push(row("Last sync", Span::raw(last)));
        if p.pending.is_empty() {
            lines.push(row("Pending", Span::raw("nothing")));
        }
        for (i, (vault, n)) in p.pending.iter().enumerate() {
            let label = if i == 0 { "Pending" } else { "" };
            lines.push(row(label, Span::raw(format!("{vault}: {n}"))));
        }
        for (i, e) in p.errors.iter().rev().enumerate() {
            let label = if i == 0 { "Errors" } else { "" };
            lines.push(row(label, Span::styled(e.clone(), theme.error)));
        }
        lines.push(Line::raw(""));
        let mut keys = vec![
            Span::styled("[s]", theme.accent),
            Span::raw(" Sync now   "),
            Span::styled("[d]", theme.accent),
            Span::raw(" Disconnect"),
        ];
        if !p.signed_in {
            keys.push(Span::raw("   "));
            keys.push(Span::styled("[Enter]", theme.accent));
            keys.push(Span::raw(" Log in"));
        }
        lines.push(Line::from(keys));
        lines
    }

    fn device_lines(&self, cx: &RenderCx<'_>) -> Vec<Line<'static>> {
        let theme = cx.theme;
        let d = &self.panel.devices;
        let mut lines = Vec::new();
        if d.loading {
            lines.push(Line::styled("Loading devices…", theme.dim));
        }
        if let Some(e) = &d.error {
            lines.push(Line::styled(e.clone(), theme.error));
        }
        if d.rows.is_empty() && !d.loading && d.error.is_none() {
            lines.push(Line::styled("No devices.", theme.dim));
        }
        for (i, r) in d.rows.iter().enumerate() {
            let created = r
                .created_ms
                .map_or_else(|| "-".to_owned(), |t| self.time(t, cx));
            let seen = r
                .last_seen_ms
                .map_or_else(|| "-".to_owned(), |t| self.time(t, cx));
            let cursor = if i == self.device_selected {
                "› "
            } else {
                "  "
            };
            let mut spans = vec![
                Span::raw(cursor),
                Span::styled(format!("{:<20}", r.name), theme.base),
                Span::styled(format!("{:<10}", r.platform), theme.dim),
                Span::raw(format!("created {created:<17} seen {seen}")),
            ];
            if r.current {
                spans.push(Span::styled("  this device", theme.accent));
            }
            let line = Line::from(spans);
            lines.push(if i == self.device_selected && cx.focused {
                line.patch_style(theme.selection)
            } else {
                line
            });
        }
        lines.push(Line::raw(""));
        lines.push(Line::from(vec![
            Span::styled("[x]", theme.accent),
            Span::raw(" Revoke   "),
            Span::styled("[r]", theme.accent),
            Span::raw(" Reload"),
        ]));
        lines
    }

    fn handle_key(&mut self, code: KeyCode, mods: KeyModifiers) -> bool {
        if mods.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) || !self.panel.available {
            return false;
        }
        // M5-02: the Vaults page's input line.
        if self.page == SettingsPage::Vaults && self.vaults.input.is_some() {
            return self.vaults_input_key(code);
        }
        // M5-01: the input line takes every key.
        if self.wants_text() {
            return self.input_key(code);
        }
        match code {
            KeyCode::Left | KeyCode::Char('[') if self.panel.connected => self.cycle_page(-1),
            KeyCode::Right | KeyCode::Char(']') if self.panel.connected => self.cycle_page(1),
            KeyCode::Char(c @ '1'..='4') if self.panel.connected => {
                let i = usize::from(c as u8 - b'1');
                self.show(SettingsPage::ALL[i]);
            }
            _ => {
                return match self.page {
                    SettingsPage::Sync => self.sync_key(code),
                    SettingsPage::Devices => self.devices_key(code),
                    // M5-01
                    SettingsPage::Team => self.team_key(code),
                    // M5-02
                    SettingsPage::Vaults => self.vaults_key(code),
                };
            }
        }
        true
    }

    fn sync_key(&mut self, code: KeyCode) -> bool {
        let p = &self.panel;
        self.request = match code {
            KeyCode::Enter if !p.connected || !p.signed_in => {
                Some(SettingsRequest::Connect(WizardFlow::Login))
            }
            KeyCode::Char('n') if !p.connected => {
                Some(SettingsRequest::Connect(WizardFlow::Register))
            }
            KeyCode::Char('s') if p.connected => Some(SettingsRequest::SyncNow),
            KeyCode::Char('d') if p.connected => Some(SettingsRequest::Disconnect),
            _ => return false,
        };
        true
    }

    // M5-01 ---------------------------------------------------------------- Team

    fn input_key(&mut self, code: KeyCode) -> bool {
        let Some((purpose, text)) = self.input.as_mut() else {
            return false;
        };
        match code {
            KeyCode::Esc => self.input = None,
            KeyCode::Backspace => {
                text.pop();
            }
            KeyCode::Char(c) => text.push(c),
            KeyCode::Enter => {
                let (purpose, text) = (*purpose, text.trim().to_owned());
                self.input = None;
                let org = self.panel.team.current().map(|o| o.id.clone());
                self.request = match (purpose, org) {
                    (TeamInput::CreateOrg, _) if !text.is_empty() => {
                        Some(SettingsRequest::Team(TeamOp::Create { name: text }))
                    }
                    (TeamInput::Accept, _) if !text.is_empty() => {
                        Some(SettingsRequest::Team(TeamOp::Accept { link: text }))
                    }
                    (TeamInput::Invite, Some(org)) => Some(SettingsRequest::Team(TeamOp::Invite {
                        org,
                        email: (!text.is_empty()).then_some(text),
                    })),
                    _ => None,
                };
            }
            _ => {}
        }
        true
    }

    /// Pastes go to the input line.
    pub fn paste(&mut self, text: &str) -> bool {
        // M5-02
        if self.page == SettingsPage::Vaults
            && let Some(t) = self.vaults.input.as_mut()
        {
            t.push_str(text.trim());
            return true;
        }
        match self.input.as_mut() {
            Some((_, t)) if self.page == SettingsPage::Team => {
                t.push_str(text.trim());
                true
            }
            _ => false,
        }
    }

    fn team_key(&mut self, code: KeyCode) -> bool {
        use sverb_proto::orgs::Role;
        let t = &self.panel.team;
        let org = t.current().cloned();
        let admin = org.as_ref().is_some_and(|o| o.role >= Role::Admin);
        let member = t.members.get(self.member_selected).cloned();
        match code {
            KeyCode::Down | KeyCode::Char('j') => {
                self.member_selected =
                    (self.member_selected + 1).min(t.members.len().saturating_sub(1));
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.member_selected = self.member_selected.saturating_sub(1);
            }
            KeyCode::Char('c') => self.input = Some((TeamInput::CreateOrg, String::new())),
            KeyCode::Char('a') => self.input = Some((TeamInput::Accept, String::new())),
            KeyCode::Char('i') if admin => self.input = Some((TeamInput::Invite, String::new())),
            KeyCode::Char('r') => {
                self.request = Some(SettingsRequest::Team(TeamOp::Load {
                    org: org.map(|o| o.id),
                }));
            }
            KeyCode::Char('o') if t.orgs.len() > 1 => {
                let next = t.orgs[(t.org + 1) % t.orgs.len()].id.clone();
                self.member_selected = 0;
                self.request = Some(SettingsRequest::Team(TeamOp::Load { org: Some(next) }));
            }
            KeyCode::Char('l') if admin => {
                if let Some(o) = org {
                    self.request = Some(SettingsRequest::Team(TeamOp::Audit { org: o.id }));
                }
            }
            KeyCode::Char(c @ ('p' | 'd')) if admin => {
                let (Some(o), Some(m)) = (org, member) else {
                    return true;
                };
                let role = match (c, m.role) {
                    ('p', Role::Member) => Role::Admin,
                    ('p', _) => Role::Owner,
                    ('d', Role::Owner) => Role::Admin,
                    _ => Role::Member,
                };
                if role != m.role {
                    self.request = Some(SettingsRequest::Team(TeamOp::SetRole {
                        org: o.id,
                        user: m.user_id,
                        role,
                    }));
                }
            }
            KeyCode::Char('x') | KeyCode::Delete => {
                let (Some(o), Some(m)) = (org, member) else {
                    return true;
                };
                self.request = Some(SettingsRequest::TeamRemove {
                    org: o.id,
                    org_name: o.name,
                    me: m
                        .email
                        .eq_ignore_ascii_case(self.panel.email.as_deref().unwrap_or("")),
                    user: m.user_id,
                    email: m.email,
                });
            }
            KeyCode::Enter | KeyCode::Char('v') =>
            {
                #[cfg(feature = "sync")]
                if let Some(m) = member {
                    self.team.open_verify(m.user_bytes);
                }
            }
            _ => return false,
        }
        true
    }

    fn team_lines(&self, cx: &RenderCx<'_>) -> Vec<Line<'static>> {
        let theme = cx.theme;
        let t = &self.panel.team;
        let mut lines = Vec::new();
        if t.loading {
            lines.push(Line::styled("Loading…", theme.dim));
        }
        if let Some(e) = &t.error {
            lines.push(Line::styled(e.clone(), theme.error));
        }
        let key = |k: &str, label: &str| {
            vec![
                Span::styled(format!("[{k}]"), theme.accent),
                Span::raw(format!(" {label}   ")),
            ]
        };
        match t.current() {
            None if !t.loading => {
                lines.push(Line::raw("You are not in any org."));
                lines.push(Line::raw(""));
                let mut k = key("c", "Create an org");
                k.extend(key("a", "Accept an invite"));
                lines.push(Line::from(k));
            }
            None => {}
            Some(org) => {
                let mut head = vec![
                    Span::styled("Org  ", theme.dim),
                    Span::styled(org.name.clone(), theme.base.add_modifier(Modifier::BOLD)),
                    Span::styled(format!("  (you: {})", org.role), theme.dim),
                ];
                if t.orgs.len() > 1 {
                    head.push(Span::styled(
                        format!("  {}/{} · o next", t.org + 1, t.orgs.len()),
                        theme.dim,
                    ));
                }
                lines.push(Line::from(head));
                lines.push(Line::raw(""));
                for (i, m) in t.members.iter().enumerate() {
                    let cursor = if i == self.member_selected {
                        "› "
                    } else {
                        "  "
                    };
                    #[cfg_attr(not(feature = "sync"), allow(unused_mut))]
                    let mut spans = vec![
                        Span::raw(cursor),
                        Span::styled(format!("{:<7}", m.role.as_str()), theme.dim),
                        Span::raw(m.email.clone()),
                    ];
                    #[cfg(feature = "sync")]
                    match self.team.state_of(&m.user_bytes) {
                        Some(sverb_store::PinState::Verified) => {
                            spans.push(Span::styled("  ✓", theme.ok));
                        }
                        Some(sverb_store::PinState::KeyChanged) => {
                            spans.push(Span::styled("  ⚠ key changed", theme.error));
                        }
                        _ => {}
                    }
                    let line = Line::from(spans);
                    lines.push(if i == self.member_selected && cx.focused {
                        line.patch_style(theme.selection)
                    } else {
                        line
                    });
                }
                lines.push(Line::raw(""));
                let mut k = Vec::new();
                if org.role >= sverb_proto::orgs::Role::Admin {
                    k.extend(key("i", "Invite"));
                    k.extend(key("p/d", "Promote/demote"));
                    k.extend(key("l", "Audit log"));
                }
                k.extend(key("x", "Remove/leave"));
                k.extend(key("v", "Verify keys"));
                lines.push(Line::from(k));
                let mut k = key("c", "New org");
                k.extend(key("a", "Accept invite"));
                k.extend(key("r", "Reload"));
                lines.push(Line::from(k));
            }
        }
        if let Some((purpose, text)) = &self.input {
            lines.push(Line::raw(""));
            lines.push(Line::from(vec![
                Span::styled(format!("{}: ", purpose.label()), theme.dim),
                Span::raw(text.clone()),
                Span::styled("▏", theme.accent),
            ]));
        }
        if !t.audit.is_empty() {
            lines.push(Line::raw(""));
            lines.push(Line::styled("Audit log (newest first)", theme.dim));
            lines.extend(t.audit.iter().map(|a| Line::raw(format!("  {a}"))));
        }
        lines
    }

    fn devices_key(&mut self, code: KeyCode) -> bool {
        let n = self.panel.devices.rows.len();
        match code {
            KeyCode::Down | KeyCode::Char('j') => {
                self.device_selected = (self.device_selected + 1).min(n.saturating_sub(1));
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.device_selected = self.device_selected.saturating_sub(1);
            }
            KeyCode::Char('r') => self.request = Some(SettingsRequest::RefreshDevices),
            KeyCode::Char('x') | KeyCode::Delete => {
                let Some(r) = self.panel.devices.rows.get(self.device_selected) else {
                    return true;
                };
                self.request = Some(SettingsRequest::Revoke {
                    id: r.id.clone(),
                    name: r.name.clone(),
                    current: r.current,
                });
            }
            _ => return false,
        }
        true
    }
}

/// The style of a sync state.
pub fn level_style(level: SyncLevel, theme: &Theme) -> ratatui::style::Style {
    match level {
        SyncLevel::Ok => theme.ok,
        SyncLevel::Busy => theme.info,
        SyncLevel::Warn => theme.warn,
        SyncLevel::Error => theme.error,
    }
}

impl View for SettingsView {
    fn handle(&mut self, ev: &ViewEvent, cx: &mut ViewCx<'_>) -> Outcome {
        // M5-01: a pasted invite link goes to the input line.
        if let ViewEvent::Paste(text) = ev {
            if self.paste(text) {
                cx.request_redraw();
                return Outcome::Consumed;
            }
            return Outcome::Ignored;
        }
        let ViewEvent::Key(key) = ev else {
            return Outcome::Ignored;
        };
        // M5-03: the Team page's safety-number dialogs get keys first.
        #[cfg(feature = "sync")]
        if self.page == SettingsPage::Team
            && self.team.dialog.is_some()
            && self.team.handle(ev, cx) == Outcome::Consumed
        {
            return Outcome::Consumed;
        }
        if self.handle_key(key.code, key.modifiers) {
            cx.request_redraw();
            Outcome::Consumed
        } else {
            Outcome::Ignored
        }
    }

    // M5-01
    fn insert_mode(&self) -> bool {
        self.wants_text()
    }

    fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let theme = cx.theme;
        let block = Block::bordered()
            .title(Span::styled(" Settings ", theme.title_for(cx.focused)))
            .border_style(theme.border_for(cx.focused));
        if !self.panel.available {
            frame.render_widget(
                Paragraph::new(Line::styled(
                    "Settings live in config.toml (`sverb config edit`).",
                    theme.dim,
                ))
                .wrap(Wrap { trim: true })
                .block(block),
                area,
            );
            return;
        }
        let inner = block.inner(area);
        frame.render_widget(block, area);
        if inner.height == 0 || inner.width == 0 {
            return;
        }
        // Page tabs.
        let mut tabs = Vec::new();
        for (i, page) in self.pages().iter().enumerate() {
            if i > 0 {
                tabs.push(Span::styled(" · ", theme.dim));
            }
            let style = if *page == self.page {
                theme.accent.add_modifier(Modifier::BOLD)
            } else {
                theme.dim
            };
            tabs.push(Span::styled(page.title(), style));
        }
        frame.render_widget(
            Paragraph::new(Line::from(tabs)),
            Rect { height: 1, ..inner },
        );
        let body = Rect {
            y: inner.y.saturating_add(2),
            height: inner.height.saturating_sub(2),
            ..inner
        };
        if body.height == 0 {
            return;
        }
        let lines = match self.page {
            SettingsPage::Sync => self.sync_lines(cx),
            SettingsPage::Devices => self.device_lines(cx),
            // M5-01: orgs and members; M5-03's dialogs on top.
            SettingsPage::Team => {
                frame.render_widget(
                    Paragraph::new(self.team_lines(cx)).wrap(Wrap { trim: false }),
                    body,
                );
                #[cfg(feature = "sync")]
                self.team.render_dialog_only(frame, body, cx);
                return;
            }
            // M5-02
            SettingsPage::Vaults => self.vault_lines(cx),
        };
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), body);
    }
}
