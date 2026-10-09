//! M6-03: the approval modal (§14.1 step 6): a viewer with the right link key wants
//! to see a shared pane.
//!
//! ```text
//! ┌ Viewer wants to join ───────────────────┐
//! │ bob wants to view "web-1".              │
//! │ Account: bob@example.com                │
//! │ From:    198.51.100.0/24                │
//! │                                         │
//! │ [a]pprove · [d]eny                      │
//! └─────────────────────────────────────────┘
//! ```
//!
//! `a` admits, `d` (or `Esc`) refuses. Viewers whose join request fails the link-key
//! check never get here.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Paragraph, Wrap},
};
use sverb_proto::share::ShareMode;

use super::{ShareAnswer, frame_block};
use crate::app::SessionId;
use crate::app::share::ViewerInfo;
use crate::views::RenderCx;

/// The approval modal's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApproveDialog {
    /// The shared pane.
    pub session: SessionId,
    /// Its label.
    pub label: String,
    /// The share's mode.
    pub mode: ShareMode,
    /// Who asks.
    pub viewer: ViewerInfo,
    /// Set by `a` / `d`.
    pub answer: Option<ShareAnswer>,
}

impl ApproveDialog {
    /// The modal for `viewer` of `session`.
    pub fn new(
        session: SessionId,
        label: impl Into<String>,
        mode: ShareMode,
        viewer: ViewerInfo,
    ) -> Self {
        Self {
            session,
            label: label.into(),
            mode,
            viewer,
            answer: None,
        }
    }

    /// A key; returns whether the modal closes.
    pub fn handle_key(&mut self, key: &KeyEvent) -> bool {
        let (session, viewer) = (self.session, self.viewer.id);
        self.answer = match key.code {
            KeyCode::Char('a' | 'A') => Some(ShareAnswer::Approve { session, viewer }),
            KeyCode::Char('d' | 'D') | KeyCode::Esc => Some(ShareAnswer::Deny { session, viewer }),
            _ => None,
        };
        self.answer.is_some()
    }

    /// Draw it.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let t = cx.theme;
        let rect = crate::views::dialogs::centered(area, 56, 7);
        if rect.width < 20 || rect.height < 4 {
            return;
        }
        let inner = frame_block(frame, rect, "Viewer wants to join", "", cx);
        let verb = match self.mode {
            ShareMode::View => "view",
            ShareMode::Control => "join (control mode)",
        };
        let field = |k: &str, v: Option<&str>| {
            Line::from(vec![
                Span::styled(format!("{k:<9}"), t.dim),
                Span::raw(v.unwrap_or("—").to_owned()),
            ])
        };
        let lines = vec![
            Line::from(vec![
                Span::styled(self.viewer.display_name(), t.accent),
                Span::raw(format!(
                    " wants to {verb} \"{}\".",
                    crate::widgets::truncate(&self.label, 30)
                )),
            ]),
            field("Account:", self.viewer.account.as_deref()),
            field("From:", self.viewer.ip_hint.as_deref()),
            Line::raw(""),
            Line::from(vec![
                Span::styled("[a]", t.accent),
                Span::raw("pprove · "),
                Span::styled("[d]", t.accent),
                Span::raw("eny"),
            ]),
        ];
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    }
}
