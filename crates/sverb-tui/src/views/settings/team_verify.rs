//! Settings → Team trust (SPEC §13.3).
//!
//! ```text
//! ┌ Team keys ───────────────────────────────────────────────┐
//! │ › alice@example.com (you)                                 │
//! │   ✓ bob@example.com                                       │
//! │   ⚠ key changed  carol@example.com                        │
//! │     dave@example.com             not verified             │
//! └───────────────────────────────────────────────────────────┘
//! ```
//!
//! Every pinned member (pins are device-local, `sverb_store::pins`) with their
//! trust state: ✓ verified, `⚠ key changed` (red), or not verified. `v` / `Enter`
//! opens the safety-number dialog (60 digits in 12 groups, the same on both
//! devices); `y` marks the member verified, or, after a key change, accepts the
//! new key. A key change seen for the first time opens a **red warning modal**.
//!
//! The view is pure: answers are left in [`TeamVerifyView::request`] for the
//! reducer, which runs them with [`execute`] and feeds the reloaded pins back with
//! [`TeamVerifyView::set_pins`] (wiring into the Settings → Team page lands with

use std::collections::HashSet;

use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph, Wrap},
};
use sverb_crypto::fingerprint::safety_number;
use sverb_store::{PinState, PinnedKey, Store};

use crate::views::{Outcome, RenderCx, View, ViewCx, ViewEvent};

/// A user id (16 bytes, the server's account UUID).
pub type UserId = [u8; 16];

/// One listed member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberRow {
    /// The user.
    pub user_id: UserId,
    /// Display name (the server's label, else the id).
    pub label: String,
    /// Trust state.
    pub state: PinState,
    /// This account.
    pub is_self: bool,
    /// The fingerprint a safety number is computed from (the pending new key
    /// while a change is pending).
    pub fingerprint: [u8; 32],
}

impl MemberRow {
    fn new(pin: &PinnedKey) -> Self {
        Self {
            user_id: pin.user_id,
            label: pin.label.clone().unwrap_or_else(|| uuid_text(&pin.user_id)),
            state: pin.state(),
            is_self: pin.is_self,
            fingerprint: pin.current_fingerprint(),
        }
    }
}

/// What the user asked for; taken by the reducer and run with [`execute`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeamVerifyRequest {
    /// The safety numbers matched: mark the member verified (✓).
    MarkVerified(UserId),
    /// The new key's safety number matched: accept it (and mark it verified).
    AcceptNewKey(UserId),
}

/// The dialogs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TeamVerifyDialog {
    /// Compare the safety number; `y` confirms.
    Verify {
        /// The member.
        user_id: UserId,
        /// Their name.
        label: String,
        /// 60 digits in 12 groups.
        safety_number: String,
        /// A key change is pending (`y` accepts the new key).
        key_changed: bool,
    },
    /// The loud warning shown when a member's key changed.
    KeyChanged {
        /// The member.
        user_id: UserId,
        /// Their name.
        label: String,
    },
}

/// The Team trust page.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TeamVerifyView {
    /// Members, this account first.
    pub rows: Vec<MemberRow>,
    /// Selected row.
    pub selected: usize,
    /// This account's fingerprint (safety numbers need it).
    pub own_fingerprint: Option<[u8; 32]>,
    /// The open dialog.
    pub dialog: Option<TeamVerifyDialog>,
    /// A request for the reducer, taken right after the key.
    pub request: Option<TeamVerifyRequest>,
    /// Key changes already warned about (one modal per change).
    warned: HashSet<UserId>,
}

impl TeamVerifyView {
    /// Replaces the members with `pins`. A key change not warned about yet
    /// opens the red warning modal (unless another dialog is open).
    pub fn set_pins(&mut self, pins: &[PinnedKey]) {
        let selected = self.rows.get(self.selected).map(|r| r.user_id);
        self.own_fingerprint = pins.iter().find(|p| p.is_self).map(|p| p.fingerprint);
        self.rows = pins.iter().map(MemberRow::new).collect();
        self.rows.sort_by(|a, b| {
            b.is_self
                .cmp(&a.is_self)
                .then_with(|| a.label.to_lowercase().cmp(&b.label.to_lowercase()))
        });
        self.selected = selected
            .and_then(|id| self.rows.iter().position(|r| r.user_id == id))
            .unwrap_or(0);
        // A resolved change can be warned about again if it happens again.
        self.warned.retain(|id| {
            pins.iter()
                .any(|p| p.user_id == *id && p.state() == PinState::KeyChanged)
        });
        if self.dialog.is_none()
            && let Some(row) = self
                .rows
                .iter()
                .find(|r| r.state == PinState::KeyChanged && !self.warned.contains(&r.user_id))
        {
            self.warned.insert(row.user_id);
            self.dialog = Some(TeamVerifyDialog::KeyChanged {
                user_id: row.user_id,
                label: row.label.clone(),
            });
        }
    }

    /// Takes the pending request.
    pub fn take_request(&mut self) -> Option<TeamVerifyRequest> {
        self.request.take()
    }

    /// The row of `user`.
    pub fn row(&self, user: &UserId) -> Option<&MemberRow> {
        self.rows.iter().find(|r| r.user_id == *user)
    }

    pub(crate) fn open_verify(&mut self, user: UserId) {
        let Some(row) = self.row(&user).cloned() else {
            return;
        };
        if row.is_self {
            return;
        }
        let safety_number = self
            .own_fingerprint
            .map(|mine| safety_number(&mine, &row.fingerprint))
            .unwrap_or_default();
        self.dialog = Some(TeamVerifyDialog::Verify {
            user_id: row.user_id,
            label: row.label,
            safety_number,
            key_changed: row.state == PinState::KeyChanged,
        });
    }

    fn handle_dialog(&mut self, code: KeyCode) {
        let Some(dialog) = self.dialog.clone() else {
            return;
        };
        match dialog {
            TeamVerifyDialog::Verify {
                user_id,
                key_changed,
                safety_number,
                ..
            } => match code {
                KeyCode::Char('y' | 'Y') if !safety_number.is_empty() => {
                    self.request = Some(if key_changed {
                        TeamVerifyRequest::AcceptNewKey(user_id)
                    } else {
                        TeamVerifyRequest::MarkVerified(user_id)
                    });
                    self.dialog = None;
                }
                KeyCode::Char('n' | 'N' | 'q') | KeyCode::Esc | KeyCode::Enter => {
                    self.dialog = None;
                }
                _ => {}
            },
            TeamVerifyDialog::KeyChanged { user_id, .. } => match code {
                KeyCode::Char('v') => self.open_verify(user_id),
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => self.dialog = None,
                _ => {}
            },
        }
    }
}

impl View for TeamVerifyView {
    fn handle(&mut self, ev: &ViewEvent, cx: &mut ViewCx<'_>) -> Outcome {
        let ViewEvent::Key(key) = ev else {
            return Outcome::Ignored;
        };
        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return Outcome::Ignored;
        }
        if self.dialog.is_some() {
            self.handle_dialog(key.code);
            cx.request_redraw();
            return Outcome::Consumed;
        }
        match key.code {
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected + 1 < self.rows.len() {
                    self.selected += 1;
                }
            }
            KeyCode::Up | KeyCode::Char('k') => self.selected = self.selected.saturating_sub(1),
            KeyCode::Enter | KeyCode::Char('v') => {
                let Some(id) = self.rows.get(self.selected).map(|r| r.user_id) else {
                    return Outcome::Ignored;
                };
                self.open_verify(id);
            }
            _ => return Outcome::Ignored,
        }
        cx.request_redraw();
        Outcome::Consumed
    }

    fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let theme = cx.theme;
        let block = Block::bordered()
            .title(Span::styled(" Team keys ", theme.title_for(cx.focused)))
            .border_style(theme.border_for(cx.focused));
        let mut lines: Vec<Line<'static>> = Vec::new();
        if self.rows.is_empty() {
            lines.push(Line::styled(
                "No team members seen yet. Keys are pinned the first time they are seen.",
                theme.dim,
            ));
        }
        for (i, row) in self.rows.iter().enumerate() {
            let cursor = if i == self.selected { "› " } else { "  " };
            let mut spans = vec![Span::raw(cursor)];
            match (row.is_self, row.state) {
                (true, _) => spans.push(Span::styled(format!("{} (you)", row.label), theme.base)),
                (false, PinState::Verified) => {
                    spans.push(Span::styled("✓ ", theme.ok));
                    spans.push(Span::raw(row.label.clone()));
                }
                (false, PinState::KeyChanged) => {
                    spans.push(Span::styled(
                        "⚠ key changed  ",
                        theme.error.add_modifier(Modifier::BOLD),
                    ));
                    spans.push(Span::styled(row.label.clone(), theme.error));
                }
                (false, PinState::Pinned) => {
                    spans.push(Span::raw("  "));
                    spans.push(Span::raw(row.label.clone()));
                    spans.push(Span::styled("  not verified", theme.dim));
                }
            }
            let line = Line::from(spans);
            lines.push(if i == self.selected && cx.focused {
                line.patch_style(theme.selection)
            } else {
                line
            });
        }
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            "v verify (compare safety numbers)   j/k move",
            theme.dim,
        ));
        frame.render_widget(Paragraph::new(lines).block(block).style(theme.base), area);
        if let Some(d) = &self.dialog {
            render_dialog(d, frame, area, cx);
        }
    }
}

impl TeamVerifyView {
    /// Draws only the open dialog (Settings → Team draws its own member list).
    pub fn render_dialog_only(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        if let Some(d) = &self.dialog {
            render_dialog(d, frame, area, cx);
        }
    }

    /// The trust state of `user`, if pinned.
    pub fn state_of(&self, user: &UserId) -> Option<PinState> {
        self.row(user).map(|r| r.state)
    }
}

/// The safety number as 3 lines of 4 groups.
pub fn safety_number_lines(number: &str) -> Vec<String> {
    let groups: Vec<&str> = number.split(' ').collect();
    groups.chunks(4).map(|c| c.join(" ")).collect()
}

fn render_dialog(d: &TeamVerifyDialog, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
    let theme = cx.theme;
    let (title, border, body): (&str, Style, Vec<Line<'static>>) = match d {
        TeamVerifyDialog::Verify {
            label,
            safety_number,
            key_changed,
            ..
        } => {
            let mut body = Vec::new();
            if *key_changed {
                body.push(Line::styled(
                    format!("{label}'s key CHANGED. Compare the NEW safety number:"),
                    theme.error.add_modifier(Modifier::BOLD),
                ));
            } else {
                body.push(Line::raw(format!("Safety number with {label}:")));
            }
            body.push(Line::raw(""));
            if safety_number.is_empty() {
                body.push(Line::styled(
                    "Your own keys are not pinned yet: sign in to sync first.",
                    theme.warn,
                ));
            } else {
                for l in safety_number_lines(safety_number) {
                    body.push(Line::styled(format!("  {l}"), theme.accent));
                }
            }
            body.push(Line::raw(""));
            body.push(Line::raw(
                "Compare it with the number on their device (in person or a trusted call).",
            ));
            body.push(Line::raw(if *key_changed {
                "Accept new key? [y/N]"
            } else {
                "Mark as verified? [y/N]"
            }));
            let border = if *key_changed {
                theme.error
            } else {
                theme.border_focused
            };
            (" Verify member ", border, body)
        }
        TeamVerifyDialog::KeyChanged { label, .. } => (
            " ⚠ KEY CHANGED ",
            theme.error,
            vec![
                Line::styled(
                    format!("The public key of {label} CHANGED."),
                    theme.error.add_modifier(Modifier::BOLD),
                ),
                Line::raw(""),
                Line::raw("This only happens when the account was re-created, or when the"),
                Line::raw("server substituted the key (an attack). Until you compare safety"),
                Line::raw("numbers and accept the new key, vault access granted to or by"),
                Line::raw("this member is blocked."),
                Line::raw(""),
                Line::raw("v compare safety numbers   Esc later"),
            ],
        ),
    };
    let w = area.width.min(76);
    let inner = usize::from(w.saturating_sub(2)).max(1);
    let rows: usize = body.iter().map(|l| l.width().max(1).div_ceil(inner)).sum();
    let h = u16::try_from(rows)
        .unwrap_or(u16::MAX)
        .saturating_add(2)
        .min(area.height);
    let rect = Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    };
    frame.render_widget(Clear, rect);
    frame.render_widget(
        Paragraph::new(body)
            .wrap(Wrap { trim: false })
            .block(
                Block::bordered()
                    .title(Span::styled(title, border.add_modifier(Modifier::BOLD)))
                    .border_style(border),
            )
            .style(theme.base),
        rect,
    );
}

fn uuid_text(id: &UserId) -> String {
    let h: String = id.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// Runs `req` against `store` and returns the reloaded pins (for
/// [`TeamVerifyView::set_pins`]).
///
/// # Errors
/// The store's error.
pub async fn execute(store: &Store, req: TeamVerifyRequest) -> sverb_store::Result<Vec<PinnedKey>> {
    match req {
        TeamVerifyRequest::MarkVerified(user) => {
            store.set_pin_verified(user, true).await?;
        }
        TeamVerifyRequest::AcceptNewKey(user) => {
            store.accept_new_key(user, true).await?;
        }
    }
    store.list_pins().await
}

#[cfg(test)]
#[path = "../../services/team_verify_tests.rs"]
mod tests;
