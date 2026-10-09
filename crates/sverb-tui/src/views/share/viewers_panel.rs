//! M6-03: the viewers panel (`leader S` on a shared pane; §14.1 step 7, §14.3).
//!
//! ```text
//! ┌ Shared · control ─────────────────────────────────────┐
//! │ Link: sverb://join/sync.example.com/0190…#k3y…         │
//! │ Expires 14:32 · 2 viewers                              │
//! │                                                        │
//! │ › bob            control   198.51.100.0/24             │
//! │   anonymous      view                                  │
//! └ c control · k kick · y copy link · s stop · Esc close ─┘
//! ```
//!
//! `c` grants or revokes control (control-mode shares only), `k` kicks, `y` copies
//! the link, `s` stops sharing. The panel stays open (and follows the viewers)
//! until `Esc` or `s`.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::Paragraph,
};
use sverb_proto::share::ShareMode;

use super::{ShareAnswer, frame_block};
use crate::app::SessionId;
use crate::app::share::ViewerInfo;
use crate::views::RenderCx;

/// The viewers panel's state (refreshed by the reducer as viewers come and go).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewersPanel {
    /// The shared pane.
    pub session: SessionId,
    /// The share's mode.
    pub mode: ShareMode,
    /// The link (`None` while the share is being created).
    pub link: Option<String>,
    /// Expiry, as shown (`HH:MM`).
    pub expires: Option<String>,
    /// Admitted viewers.
    pub viewers: Vec<ViewerInfo>,
    /// The selected viewer.
    pub cursor: usize,
    /// Set by the last key.
    pub answer: Option<ShareAnswer>,
}

impl ViewersPanel {
    /// An empty panel for `session`.
    pub fn new(session: SessionId, mode: ShareMode) -> Self {
        Self {
            session,
            mode,
            link: None,
            expires: None,
            viewers: Vec::new(),
            cursor: 0,
            answer: None,
        }
    }

    /// Replace the viewers (keeps the cursor in range).
    pub fn set_viewers(&mut self, viewers: Vec<ViewerInfo>) {
        self.viewers = viewers;
        self.cursor = self.cursor.min(self.viewers.len().saturating_sub(1));
    }

    /// A key; returns whether the panel closes.
    pub fn handle_key(&mut self, key: &KeyEvent) -> bool {
        let session = self.session;
        let selected = self.viewers.get(self.cursor);
        self.answer = None;
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => return true,
            KeyCode::Up | KeyCode::Char('K') => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j' | 'J') => {
                if self.cursor + 1 < self.viewers.len() {
                    self.cursor += 1;
                }
            }
            KeyCode::Char('c') if self.mode == ShareMode::Control => {
                if let Some(v) = selected {
                    self.answer = Some(ShareAnswer::SetControl {
                        session,
                        viewer: v.id,
                        granted: !v.control,
                    });
                }
            }
            KeyCode::Char('k') => {
                if let Some(v) = selected {
                    self.answer = Some(ShareAnswer::Kick {
                        session,
                        viewer: v.id,
                    });
                }
            }
            KeyCode::Char('y') => self.answer = Some(ShareAnswer::CopyLink { session }),
            KeyCode::Char('s') => {
                self.answer = Some(ShareAnswer::Stop { session });
                return true;
            }
            _ => {}
        }
        false
    }

    /// Draw it.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let t = cx.theme;
        let height = 6 + self.viewers.len().max(1);
        let rect = crate::views::dialogs::centered(area, 72, height);
        if rect.width < 24 || rect.height < 5 {
            return;
        }
        let title = match self.mode {
            ShareMode::View => "Shared · view",
            ShareMode::Control => "Shared · control",
        };
        let footer = if self.mode == ShareMode::Control {
            "c control · k kick · y copy link · s stop · Esc close"
        } else {
            "k kick · y copy link · s stop · Esc close"
        };
        let inner = frame_block(frame, rect, title, footer, cx);
        let w = usize::from(inner.width.saturating_sub(6));
        let link = self.link.as_deref().unwrap_or("creating…");
        let n = self.viewers.len();
        let mut lines = vec![
            Line::from(vec![
                Span::styled("Link: ", t.dim),
                Span::raw(crate::widgets::truncate(link, w).to_owned()),
            ]),
            Line::styled(
                format!(
                    "Expires {} · {n} viewer{}",
                    self.expires.as_deref().unwrap_or("—"),
                    if n == 1 { "" } else { "s" }
                ),
                t.dim,
            ),
            Line::raw(""),
        ];
        if self.viewers.is_empty() {
            lines.push(Line::styled(
                "No viewers yet. Send the link to someone.",
                t.dim,
            ));
        }
        for (i, v) in self.viewers.iter().enumerate() {
            let selected = i == self.cursor;
            let style = if selected { t.selection } else { t.base };
            let access = if v.control { "control" } else { "view" };
            lines.push(Line::from(vec![
                Span::styled(if selected { "› " } else { "  " }, t.accent),
                Span::styled(
                    format!("{:<20}", crate::widgets::truncate(&v.display_name(), 20)),
                    style,
                ),
                Span::styled(
                    format!("{access:<9}"),
                    if v.control { t.warn } else { t.dim },
                ),
                Span::styled(v.ip_hint.clone().unwrap_or_default(), t.dim),
            ]));
        }
        frame.render_widget(Paragraph::new(lines), inner);
    }
}
