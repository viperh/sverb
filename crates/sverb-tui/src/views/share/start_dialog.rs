//! M6-03: the start dialog (`leader S` on a pane that isn't shared; §14.1 step 1).
//!
//! ```text
//! ┌ Share this pane ─────────────────────────────┐
//! │ › Mode            [view]  control             │
//! │   Expires in      15 min  [1 h]  4 h  24 h    │
//! │   Viewers need a sverb account   [ ]          │
//! │   Skip approval                  [ ]          │
//! └ ↑↓ move · ←→/Space change · Enter share · Esc ┘
//! ```
//!
//! View mode, 1 h, no account requirement and approval are the defaults. Checking
//! "Skip approval" shows a warning: anyone with the link then sees the pane at once.

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
use crate::app::share::{EXPIRY_LABELS, ShareStartOptions};
use crate::views::RenderCx;

const ROWS: usize = 4;

/// The start dialog's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartDialog {
    /// The pane to share.
    pub session: SessionId,
    /// Its label (title line).
    pub label: String,
    /// The choices so far.
    pub options: ShareStartOptions,
    /// The focused row (mode, expiry, account, skip approval).
    pub row: usize,
    /// Set by `Enter`.
    pub answer: Option<ShareAnswer>,
}

impl StartDialog {
    /// The dialog for `session` with the defaults.
    pub fn new(session: SessionId, label: impl Into<String>) -> Self {
        Self {
            session,
            label: label.into(),
            options: ShareStartOptions::default(),
            row: 0,
            answer: None,
        }
    }

    fn change(&mut self, forward: bool) {
        let o = &mut self.options;
        match self.row {
            0 => {
                o.mode = match o.mode {
                    ShareMode::View => ShareMode::Control,
                    ShareMode::Control => ShareMode::View,
                };
            }
            1 => {
                let n = EXPIRY_LABELS.len();
                o.expiry = if forward {
                    (o.expiry + 1) % n
                } else {
                    (o.expiry + n - 1) % n
                };
            }
            2 => o.require_account = !o.require_account,
            _ => o.skip_approval = !o.skip_approval,
        }
    }

    /// A key; returns whether the dialog closes.
    pub fn handle_key(&mut self, key: &KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => return true,
            KeyCode::Enter => {
                self.answer = Some(ShareAnswer::Start {
                    session: self.session,
                    options: self.options,
                });
                return true;
            }
            KeyCode::Up | KeyCode::BackTab | KeyCode::Char('k') => {
                self.row = (self.row + ROWS - 1) % ROWS;
            }
            KeyCode::Down | KeyCode::Tab | KeyCode::Char('j') => self.row = (self.row + 1) % ROWS,
            KeyCode::Left | KeyCode::Char('h') => self.change(false),
            KeyCode::Right | KeyCode::Char(' ' | 'l') => self.change(true),
            _ => {}
        }
        false
    }

    /// Draw it.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let t = cx.theme;
        let o = &self.options;
        let height = if o.skip_approval { 10 } else { 8 };
        let rect = crate::views::dialogs::centered(area, 64, height);
        if rect.width < 20 || rect.height < 4 {
            return;
        }
        let inner = frame_block(
            frame,
            rect,
            "Share this pane",
            "↑↓ move · ←→ change · Enter share · Esc cancel",
            cx,
        );
        let choice = |on: bool, text: &str| -> Span<'static> {
            if on {
                Span::styled(format!("[{text}]"), t.accent)
            } else {
                Span::styled(format!(" {text} "), t.dim)
            }
        };
        let check = |on: bool| if on { "[x]" } else { "[ ]" };
        let marker = |row: usize| -> Span<'static> {
            if row == self.row {
                Span::styled("› ", t.accent)
            } else {
                Span::raw("  ")
            }
        };
        let label = |row: usize, text: &str| -> Span<'static> {
            let style = if row == self.row { t.selection } else { t.base };
            Span::styled(format!("{text:<30}"), style)
        };
        let mut expiry = Vec::new();
        for (i, l) in EXPIRY_LABELS.iter().enumerate() {
            expiry.push(choice(o.expiry == i, l));
            expiry.push(Span::raw(" "));
        }
        let mut lines = vec![
            Line::from(Span::styled(
                crate::widgets::truncate(&self.label, 58),
                t.dim,
            )),
            Line::from(vec![
                marker(0),
                label(0, "Mode"),
                choice(o.mode == ShareMode::View, "view"),
                Span::raw(" "),
                choice(o.mode == ShareMode::Control, "control"),
            ]),
            Line::from([vec![marker(1), label(1, "Expires in")], expiry].concat()),
            Line::from(vec![
                marker(2),
                label(2, "Viewers need a sverb account"),
                Span::raw(check(o.require_account)),
            ]),
            Line::from(vec![
                marker(3),
                label(3, "Skip approval"),
                Span::raw(check(o.skip_approval)),
            ]),
        ];
        if o.skip_approval {
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                "⚠ Anyone with the link sees this pane at once, without asking you.",
                t.warn,
            ));
        }
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    }
}
