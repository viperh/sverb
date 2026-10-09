//! Settings → Vaults (SPEC §13.1, §13.2).
//!
//! ```text
//! Sync · Devices · Team · Vaults
//!
//! Shared vaults
//! › Ops                Acme       manage
//!   Billing            Acme       manage · needs key
//!
//! Members of "Ops"
//!   alice@example.com  owner      manage  ✓ key
//!   bob@example.com    member     write   ✓ key
//!   carol@example.com  member     –
//!
//! [Tab] Vaults/members  [n] New vault  [r/w/m] Grant read/write/manage
//! [x] Revoke  [g] Grant admins  [R] Rotate key  [u] Reload
//! ```
//!
//! Revoking a member rotates the vault key right away (a progress
//! dialog); `R` rotates it on demand, resuming or restarting an interrupted
//! rotation.
//!
//! Granting fetches the member's public keys and checks them against the pins
//! in the sync service: a changed key is refused with an error that says
//! to compare safety numbers in Settings → Team. "needs key" marks a vault an org
//! admin manages implicitly but holds no grant for yet (§13.1): any `manage`
//! member's client grants it (`g`, and in the background after a sync).

use crossterm::event::KeyCode;
use ratatui::{
    style::Modifier,
    text::{Line, Span},
};
use sverb_proto::sync::Permission;

use super::{SettingsRequest, SettingsView};
use crate::app::sync_ui::{VaultOp, VaultsPanel};
use crate::views::RenderCx;

/// Which list the cursor keys move.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum VaultsFocus {
    /// The vaults.
    #[default]
    Vaults,
    /// The shown vault's members.
    Members,
}

/// The Vaults page's own state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VaultsState {
    /// Which list has the cursor.
    pub focus: VaultsFocus,
    /// Highlighted member.
    pub member: usize,
    /// The new vault's name, while typing it.
    pub input: Option<String>,
}

impl VaultsState {
    /// Keeps the cursor inside the lists.
    pub fn clamp(&mut self, panel: &VaultsPanel) {
        self.member = self.member.min(panel.members.len().saturating_sub(1));
    }
}

/// `read`, `write`, `manage` or `–`.
fn perm(p: Option<Permission>) -> &'static str {
    p.map_or("–", Permission::as_str)
}

impl SettingsView {
    fn vault_op(&mut self, op: VaultOp) {
        self.request = Some(SettingsRequest::Vaults(op));
    }

    /// The org a new vault goes to: the shown vault's org when this account
    /// administers it, else the first org it administers.
    fn create_org(&self) -> Option<String> {
        let p = &self.panel.vaults;
        let shown = p.current().map(|v| v.org_id.clone());
        shown
            .filter(|o| p.admin_orgs.iter().any(|(id, _)| id == o))
            .or_else(|| p.admin_orgs.first().map(|(id, _)| id.clone()))
    }

    pub(super) fn vaults_input_key(&mut self, code: KeyCode) -> bool {
        let Some(text) = self.vaults.input.as_mut() else {
            return false;
        };
        match code {
            KeyCode::Esc => self.vaults.input = None,
            KeyCode::Backspace => {
                text.pop();
            }
            KeyCode::Char(c) => text.push(c),
            KeyCode::Enter => {
                let name = text.trim().to_owned();
                self.vaults.input = None;
                if let (false, Some(org)) = (name.is_empty(), self.create_org()) {
                    self.vault_op(VaultOp::Create { org, name });
                }
            }
            _ => {}
        }
        true
    }

    pub(super) fn vaults_key(&mut self, code: KeyCode) -> bool {
        let p = self.panel.vaults.clone();
        let vault = p.current().cloned();
        let manage = vault
            .as_ref()
            .is_some_and(|v| v.permission == Permission::Manage && v.has_key);
        let member = p.members.get(self.vaults.member).cloned();
        match code {
            KeyCode::Tab | KeyCode::BackTab => {
                self.vaults.focus = match self.vaults.focus {
                    VaultsFocus::Vaults if !p.members.is_empty() => VaultsFocus::Members,
                    _ => VaultsFocus::Vaults,
                };
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Up | KeyCode::Char('k') => {
                let down = matches!(code, KeyCode::Down | KeyCode::Char('j'));
                match self.vaults.focus {
                    VaultsFocus::Members => {
                        self.vaults.member = if down {
                            (self.vaults.member + 1).min(p.members.len().saturating_sub(1))
                        } else {
                            self.vaults.member.saturating_sub(1)
                        };
                    }
                    VaultsFocus::Vaults => {
                        let next = if down {
                            (p.shown + 1).min(p.vaults.len().saturating_sub(1))
                        } else {
                            p.shown.saturating_sub(1)
                        };
                        if next != p.shown {
                            self.vaults.member = 0;
                            self.vault_op(VaultOp::Load {
                                vault: p.vaults.get(next).map(|v| v.id.clone()),
                            });
                        }
                    }
                }
            }
            KeyCode::Char('n') if !p.admin_orgs.is_empty() => {
                self.vaults.input = Some(String::new());
            }
            KeyCode::Char('u') => self.vault_op(VaultOp::Load {
                vault: vault.map(|v| v.id),
            }),
            KeyCode::Char('g') => self.vault_op(VaultOp::Reconcile),
            // Rotate the key (or resume / restart an interrupted rotation).
            KeyCode::Char('R') if manage => {
                if let Some(v) = vault {
                    self.vault_op(VaultOp::Rotate { vault: v.id });
                }
            }
            KeyCode::Char(c @ ('r' | 'w' | 'm'))
                if manage && self.vaults.focus == VaultsFocus::Members =>
            {
                let (Some(v), Some(m)) = (vault, member) else {
                    return true;
                };
                let permission = match c {
                    'r' => Permission::Read,
                    'w' => Permission::Write,
                    _ => Permission::Manage,
                };
                if m.permission != Some(permission) || !m.has_key {
                    self.vault_op(VaultOp::Grant {
                        vault: v.id,
                        user: m.user_id,
                        permission,
                    });
                }
            }
            KeyCode::Char('x') | KeyCode::Delete if self.vaults.focus == VaultsFocus::Members => {
                let (Some(v), Some(m)) = (vault, member) else {
                    return true;
                };
                if m.permission.is_none() {
                    return true;
                }
                let me = m
                    .email
                    .eq_ignore_ascii_case(self.panel.email.as_deref().unwrap_or(""));
                if manage || me {
                    self.request = Some(SettingsRequest::VaultRevoke {
                        vault: v.id,
                        vault_name: v.name,
                        user: m.user_id,
                        email: m.email,
                        me,
                    });
                }
            }
            _ => return false,
        }
        true
    }

    pub(super) fn vault_lines(&self, cx: &RenderCx<'_>) -> Vec<Line<'static>> {
        let theme = cx.theme;
        let p = &self.panel.vaults;
        let mut lines = Vec::new();
        if p.loading {
            lines.push(Line::styled("Loading…", theme.dim));
        }
        if let Some(e) = &p.error {
            lines.push(Line::styled(e.clone(), theme.error));
        }
        let key = |k: &str, label: &str| {
            vec![
                Span::styled(format!("[{k}]"), theme.accent),
                Span::raw(format!(" {label}   ")),
            ]
        };
        let selected = |focused: bool, line: Line<'static>| {
            if focused && cx.focused {
                line.patch_style(theme.selection)
            } else {
                line
            }
        };
        if p.vaults.is_empty() && !p.loading {
            lines.push(Line::raw("No shared vaults."));
            if p.admin_orgs.is_empty() {
                lines.push(Line::styled(
                    "Org owners and admins create shared vaults (Settings → Team).",
                    theme.dim,
                ));
            }
        } else {
            lines.push(Line::styled("Shared vaults", theme.dim));
        }
        let on_vaults = self.vaults.focus == VaultsFocus::Vaults;
        for (i, v) in p.vaults.iter().enumerate() {
            let cursor = if i == p.shown { "› " } else { "  " };
            let mut spans = vec![
                Span::raw(cursor),
                Span::styled(format!("{:<20}", v.name), theme.base),
                Span::styled(format!("{:<12}", v.org_name), theme.dim),
                Span::raw(v.permission.as_str()),
            ];
            if !v.has_key {
                spans.push(Span::styled(" · needs key", theme.warn));
            } else if v.permission == Permission::Read {
                spans.push(Span::styled(" · read-only", theme.dim));
            }
            lines.push(selected(on_vaults && i == p.shown, Line::from(spans)));
        }
        if let Some(v) = p.current() {
            lines.push(Line::raw(""));
            lines.push(Line::from(vec![
                Span::styled("Members of ", theme.dim),
                Span::styled(
                    format!("\"{}\"", v.name),
                    theme.base.add_modifier(Modifier::BOLD),
                ),
            ]));
            for (i, m) in p.members.iter().enumerate() {
                let cursor = if !on_vaults && i == self.vaults.member {
                    "› "
                } else {
                    "  "
                };
                let mut spans = vec![
                    Span::raw(cursor),
                    Span::styled(format!("{:<28}", m.email), theme.base),
                    Span::styled(format!("{:<8}", m.org_role.as_str()), theme.dim),
                    Span::raw(format!("{:<8}", perm(m.permission))),
                ];
                if m.has_key {
                    spans.push(Span::styled("✓ key", theme.ok));
                } else if m.org_role >= sverb_proto::orgs::Role::Admin {
                    spans.push(Span::styled("needs key", theme.warn));
                }
                lines.push(selected(
                    !on_vaults && i == self.vaults.member,
                    Line::from(spans),
                ));
            }
        }
        lines.push(Line::raw(""));
        let mut k = key("Tab", "Vaults/members");
        if !p.admin_orgs.is_empty() {
            k.extend(key("n", "New vault"));
        }
        k.extend(key("r/w/m", "Grant read/write/manage"));
        lines.push(Line::from(k));
        let mut k = key("x", "Revoke/leave");
        k.extend(key("g", "Grant admins"));
        if p.current()
            .is_some_and(|v| v.permission == Permission::Manage && v.has_key)
        {
            k.extend(key("R", "Rotate key"));
        }
        k.extend(key("u", "Reload"));
        lines.push(Line::from(k));
        if let Some(text) = &self.vaults.input {
            lines.push(Line::raw(""));
            lines.push(Line::from(vec![
                Span::styled("New vault name: ", theme.dim),
                Span::raw(text.clone()),
                Span::styled("▏", theme.accent),
            ]));
        }
        lines
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crossterm::event::KeyModifiers;
    use sverb_proto::orgs::Role;

    use super::*;
    use crate::app::sync_ui::{SyncPanel, VaultEntry, VaultMemberEntry};
    use crate::views::settings::SettingsPage;

    fn view() -> SettingsView {
        let mut v = SettingsView::default();
        v.set_panel(SyncPanel {
            available: true,
            connected: true,
            email: Some("alice@example.test".into()),
            vaults: VaultsPanel {
                vaults: vec![VaultEntry {
                    id: "v1".into(),
                    org_id: "o1".into(),
                    org_name: "Acme".into(),
                    name: "Ops".into(),
                    permission: Permission::Manage,
                    has_key: true,
                }],
                members: vec![
                    VaultMemberEntry {
                        user_id: "u-alice".into(),
                        email: "alice@example.test".into(),
                        org_role: Role::Owner,
                        permission: Some(Permission::Manage),
                        has_key: true,
                    },
                    VaultMemberEntry {
                        user_id: "u-bob".into(),
                        email: "bob@example.test".into(),
                        org_role: Role::Member,
                        permission: None,
                        has_key: false,
                    },
                ],
                admin_orgs: vec![("o1".into(), "Acme".into())],
                ..VaultsPanel::default()
            },
            ..SyncPanel::default()
        });
        v.page = SettingsPage::Vaults;
        v
    }

    fn key(v: &mut SettingsView, code: KeyCode) -> Option<SettingsRequest> {
        assert!(
            v.handle_key(code, KeyModifiers::NONE),
            "{code:?} not handled"
        );
        v.take_request()
    }

    #[test]
    fn grant_revoke_and_create() {
        let mut v = view();
        // Grants only from the members list.
        assert!(!v.handle_key(KeyCode::Char('w'), KeyModifiers::NONE));
        key(&mut v, KeyCode::Tab);
        assert_eq!(v.vaults.focus, VaultsFocus::Members);
        key(&mut v, KeyCode::Char('j'));
        assert_eq!(
            key(&mut v, KeyCode::Char('w')),
            Some(SettingsRequest::Vaults(VaultOp::Grant {
                vault: "v1".into(),
                user: "u-bob".into(),
                permission: Permission::Write,
            }))
        );
        // Bob has no grant: nothing to revoke. Alice leaving asks first.
        assert_eq!(key(&mut v, KeyCode::Char('x')), None);
        key(&mut v, KeyCode::Char('k'));
        assert!(matches!(
            key(&mut v, KeyCode::Char('x')),
            Some(SettingsRequest::VaultRevoke { me: true, .. })
        ));
        // A new vault in the shown vault's org.
        key(&mut v, KeyCode::Char('n'));
        assert!(v.wants_text());
        for c in "Billing".chars() {
            key(&mut v, KeyCode::Char(c));
        }
        assert_eq!(
            key(&mut v, KeyCode::Enter),
            Some(SettingsRequest::Vaults(VaultOp::Create {
                org: "o1".into(),
                name: "Billing".into(),
            }))
        );
        assert_eq!(
            key(&mut v, KeyCode::Char('g')),
            Some(SettingsRequest::Vaults(VaultOp::Reconcile))
        );
        assert_eq!(
            key(&mut v, KeyCode::Char('R')),
            Some(SettingsRequest::Vaults(VaultOp::Rotate {
                vault: "v1".into()
            }))
        );
    }

    #[test]
    fn read_members_cannot_grant() {
        let mut v = view();
        let mut panel = v.panel.clone();
        panel.vaults.vaults[0].permission = Permission::Read;
        v.set_panel(panel);
        key(&mut v, KeyCode::Tab);
        key(&mut v, KeyCode::Char('j'));
        assert!(!v.handle_key(KeyCode::Char('m'), KeyModifiers::NONE));
        assert!(v.take_request().is_none());
        // Nor rotate.
        assert!(!v.handle_key(KeyCode::Char('R'), KeyModifiers::NONE));
        assert!(v.take_request().is_none());
    }
}
