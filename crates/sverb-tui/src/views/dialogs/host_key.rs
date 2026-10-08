//! M1-15: the host-key dialogs (SPEC §9.5, §6.1.1 step 3).
//!
//! **Unknown key:** a centered modal with the host (and the jump hop), key type,
//! `SHA256:` fingerprint and randomart. `a` accept & save, `o` accept once (this
//! connection only), `r` / `Esc` reject.
//!
//! ```text
//! ┌ Unknown host key ─────────────────────────────┐
//! │ The authenticity of web (10.0.0.5:22) can't   │
//! │ be established.                               │
//! │ Key type:     ssh-ed25519                     │
//! │ Fingerprint:  SHA256:uYxmMoF3aflKiV/iuu80y…   │
//! │ +--[ED25519 256]--+                           │
//! │ |         .       |                           │
//! │ …                                             │
//! │ [a]ccept & save   [o]nce   [r]eject           │
//! └───────────────────────────────────────────────┘
//! ```
//!
//! **Changed key:** a full-screen red warning (theme `error`, plus a bold
//! "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED" headline so it reads in monochrome)
//! with the old and new fingerprints. Only `r` / `Esc` (reject) acts by default;
//! `R` opens "Replace…", where the user must type the host name exactly; only then is
//! the key accepted and saved (the verifier replaces the host's old key of that type).
//!
//! The dialog answers with a [`Decision`]; the reducer sends it to the session
//! (`Effect::HostKeyDecision`). The session itself rejects after 120 s, which closes the
//! dialog (the session leaves `AwaitingHostKey`).

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph, Wrap},
};
use sverb_conn::{Decision, Verification};

use crate::{app::SessionId, views::RenderCx, widgets::form::TextInput};

/// Where the dialog is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyStage {
    /// The question (unknown key) or the warning (changed key).
    Ask,
    /// Changed key, `R` pressed: type the host name to replace the trusted key.
    ConfirmReplace {
        /// What was typed.
        input: TextInput,
        /// The last attempt did not match.
        mismatch: bool,
    },
}

/// The unknown-key modal or the changed-key screen for one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKeyDialog {
    /// The session whose handshake waits.
    pub session: SessionId,
    /// The pane's label (host label or address).
    pub label: String,
    /// What the session asked.
    pub verification: Verification,
    /// Where the dialog is.
    pub stage: HostKeyStage,
}

impl HostKeyDialog {
    /// The dialog for `verification` from `session`.
    pub fn new(session: SessionId, label: impl Into<String>, verification: Verification) -> Self {
        Self {
            session,
            label: label.into(),
            verification,
            stage: HostKeyStage::Ask,
        }
    }

    /// A changed key (the red screen) rather than an unknown one.
    pub fn changed(&self) -> bool {
        self.verification.changed
    }

    /// The host name the user must type to replace a changed key.
    pub fn hostname(&self) -> &str {
        let d = &self.verification.details;
        if d.hostname.is_empty() {
            // Older events without details: `host:port`.
            self.verification
                .host
                .rsplit_once(':')
                .map_or(self.verification.host.as_str(), |(h, _)| h)
        } else {
            &d.hostname
        }
    }

    /// The hostname prompt is open (it edits text).
    pub fn wants_text(&self) -> bool {
        matches!(self.stage, HostKeyStage::ConfirmReplace { .. })
    }

    /// Apply a key. `Some(decision)`: answered (the dialog closes).
    pub fn handle_key(&mut self, key: &KeyEvent) -> Option<Decision> {
        let changed = self.changed();
        let hostname = self.hostname().to_owned();
        match &mut self.stage {
            HostKeyStage::Ask => match key.code {
                KeyCode::Char('a' | 'A') if !changed => Some(Decision::AcceptAndSave),
                KeyCode::Char('o' | 'O') if !changed => Some(Decision::AcceptOnce),
                KeyCode::Char('R') if changed => {
                    self.stage = HostKeyStage::ConfirmReplace {
                        input: TextInput::default(),
                        mismatch: false,
                    };
                    None
                }
                // Some terminals report shift-r as `r` with SHIFT.
                KeyCode::Char('r') if changed && key.modifiers.contains(KeyModifiers::SHIFT) => {
                    self.stage = HostKeyStage::ConfirmReplace {
                        input: TextInput::default(),
                        mismatch: false,
                    };
                    None
                }
                KeyCode::Char('r') | KeyCode::Esc => Some(Decision::Reject),
                KeyCode::Char('R') => Some(Decision::Reject),
                _ => None,
            },
            HostKeyStage::ConfirmReplace { input, mismatch } => match key.code {
                KeyCode::Esc => {
                    self.stage = HostKeyStage::Ask;
                    None
                }
                KeyCode::Enter => {
                    if input.text() == hostname {
                        Some(Decision::AcceptAndSave)
                    } else {
                        *mismatch = true;
                        None
                    }
                }
                _ => {
                    if input.handle_key(key).handled() {
                        *mismatch = false;
                    }
                    None
                }
            },
        }
    }

    /// A paste into the hostname prompt.
    pub fn paste(&mut self, text: &str) {
        if let HostKeyStage::ConfirmReplace { input, mismatch } = &mut self.stage {
            input.insert_str(text.trim());
            *mismatch = false;
        }
    }

    fn hop_line(&self) -> Option<String> {
        let v = &self.verification;
        (v.of > 1).then(|| format!("hop {}/{} ({})", v.hop, v.of, self.hostname()))
    }

    fn host_text(&self) -> String {
        let v = &self.verification;
        let addr = if v.details.hostname.is_empty() {
            v.host.clone()
        } else {
            format!("{}:{}", v.details.hostname, v.details.port)
        };
        if self.label.is_empty() || self.label == v.details.hostname {
            addr
        } else {
            format!("{} ({addr})", self.label)
        }
    }

    /// The body lines (without the buttons).
    pub fn lines(&self, cx: &RenderCx<'_>) -> Vec<Line<'static>> {
        let theme = cx.theme;
        let v = &self.verification;
        let d = &v.details;
        let label = |k: &str| Span::styled(format!("{k:<13} "), theme.dim);
        let mut lines = Vec::new();
        if self.changed() {
            let headline = theme.error.add_modifier(Modifier::BOLD);
            lines.push(Line::styled(
                "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!",
                headline,
            ));
            lines.push(Line::raw(""));
            lines.push(Line::raw(format!(
                "The host key of {} is not the one sverb trusts.",
                self.host_text()
            )));
            lines.push(Line::raw(
                "Someone could be eavesdropping on you right now (man-in-the-middle attack),",
            ));
            lines.push(Line::raw("or the host key has just been changed."));
        } else {
            lines.push(Line::raw(format!(
                "The authenticity of {} can't be established.",
                self.host_text()
            )));
        }
        if let Some(hop) = self.hop_line() {
            lines.push(Line::from(vec![label("Jump hop:"), Span::raw(hop)]));
        }
        lines.push(Line::raw(""));
        if !d.key_type.is_empty() {
            lines.push(Line::from(vec![
                label("Key type:"),
                Span::raw(d.key_type.clone()),
            ]));
        }
        if self.changed() {
            for old in &d.old_fingerprints {
                lines.push(Line::from(vec![
                    label("Trusted key:"),
                    Span::raw(old.clone()),
                ]));
            }
            lines.push(Line::from(vec![
                label("Offered key:"),
                Span::styled(v.fingerprint.clone(), theme.error),
            ]));
        } else {
            lines.push(Line::from(vec![
                label("Fingerprint:"),
                Span::styled(v.fingerprint.clone(), theme.accent),
            ]));
        }
        if let Some(note) = &d.note {
            lines.push(Line::from(vec![
                label("Certificate:"),
                Span::styled(note.clone(), theme.warn),
            ]));
        }
        if !d.randomart.is_empty() {
            lines.push(Line::raw(""));
            lines.extend(d.randomart.lines().map(|l| Line::raw(l.to_owned())));
        }
        lines.push(Line::raw(""));
        lines
    }

    fn buttons(&self, cx: &RenderCx<'_>) -> Vec<Line<'static>> {
        let theme = cx.theme;
        let key = Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED);
        let button = |pre: &str, k: &str, post: &str| {
            vec![
                Span::raw(format!("{pre}[")),
                Span::styled(k.to_owned(), key),
                Span::raw(format!("]{post}   ")),
            ]
        };
        match &self.stage {
            HostKeyStage::Ask if self.changed() => {
                let mut spans = button("", "r", "eject (Esc)");
                spans.extend(button("", "R", "eplace…"));
                vec![Line::from(spans)]
            }
            HostKeyStage::Ask => {
                let mut spans = button("", "a", "ccept & save");
                spans.extend(button("", "o", "nce"));
                spans.extend(button("", "r", "eject"));
                vec![Line::from(spans)]
            }
            HostKeyStage::ConfirmReplace { input, mismatch } => {
                let mut lines = vec![
                    Line::raw(format!(
                        "To replace the trusted key, type the host name ({}) and press Enter:",
                        self.hostname()
                    )),
                    input.line(40, theme.base.add_modifier(Modifier::UNDERLINED), true),
                ];
                if *mismatch {
                    lines.push(Line::styled(
                        "That is not the host name; the key was not replaced.",
                        theme.error.add_modifier(Modifier::BOLD),
                    ));
                }
                lines.push(Line::styled("Esc back", theme.dim));
                lines
            }
        }
    }

    /// Draw: the changed-key screen full screen, the unknown-key modal centered.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        if area.width < 3 || area.height < 3 {
            return;
        }
        let theme = cx.theme;
        let mut lines = self.lines(cx);
        lines.extend(self.buttons(cx));
        if self.changed() {
            let red = theme.error.add_modifier(Modifier::BOLD);
            let block = Block::bordered()
                .title(Span::styled(" Host key changed ", red))
                .border_style(red);
            frame.render_widget(Clear, area);
            frame.render_widget(
                Paragraph::new(lines)
                    .wrap(Wrap { trim: false })
                    .style(theme.base)
                    .block(block),
                area,
            );
            return;
        }
        let width = lines
            .iter()
            .map(Line::width)
            .max()
            .unwrap_or(0)
            .saturating_add(4)
            .max(40);
        let height = lines.len().saturating_add(2);
        let rect = super::centered(area, width, height);
        frame.render_widget(Clear, rect);
        let block = Block::bordered()
            .title(Span::styled(
                " Unknown host key ",
                theme.title_for(cx.focused),
            ))
            .border_style(theme.border_for(cx.focused));
        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .style(theme.base)
                .block(block),
            rect,
        );
    }
}
