//! M6-03: the terminal-sharing dialogs (SPEC §14.1, §14.3).
//!
//! - [`start_dialog`]: `leader S` on an unshared pane: mode, expiry, account
//!   requirement, skip approval;
//! - [`approve_dialog`]: the approval modal for each viewer (§14.1 step 6);
//! - [`viewers_panel`]: `leader S` on a shared pane: the link, the viewers with their
//!   control state, kick, grant / revoke control, copy link, stop sharing.
//!
//! The dialogs are plain state: a key records an answer, and the reducer takes it
//! right after the key (`App::take_share_answer`) and turns it into
//! `Effect::Share` requests. [`letterbox`] places a viewer pane's host-sized screen
//! inside the local pane (centered, or clipped when the pane is smaller).

use ratatui::{Frame, layout::Rect};

use super::{Outcome, RenderCx, ViewCx, ViewEvent};

pub mod approve_dialog;
pub mod start_dialog;
pub mod viewers_panel;

pub use approve_dialog::ApproveDialog;
pub use start_dialog::StartDialog;
pub use viewers_panel::ViewersPanel;

use crate::app::SessionId;
use crate::app::share::ShareStartOptions;

/// What a share dialog decided (taken by the reducer after each key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareAnswer {
    /// Start sharing `session` with these options.
    Start {
        /// The pane.
        session: SessionId,
        /// The choices.
        options: ShareStartOptions,
    },
    /// Admit a viewer.
    Approve {
        /// The shared pane.
        session: SessionId,
        /// The viewer.
        viewer: u32,
    },
    /// Refuse a viewer.
    Deny {
        /// The shared pane.
        session: SessionId,
        /// The viewer.
        viewer: u32,
    },
    /// Grant or revoke a viewer's control.
    SetControl {
        /// The shared pane.
        session: SessionId,
        /// The viewer.
        viewer: u32,
        /// Grant.
        granted: bool,
    },
    /// Disconnect a viewer.
    Kick {
        /// The shared pane.
        session: SessionId,
        /// The viewer.
        viewer: u32,
    },
    /// Copy the link again.
    CopyLink {
        /// The shared pane.
        session: SessionId,
    },
    /// Stop sharing.
    Stop {
        /// The shared pane.
        session: SessionId,
    },
}

/// One of the share dialogs on the dialog stack (`DialogKind::Share`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareDialog {
    /// The start dialog.
    Start(StartDialog),
    /// A viewer waits for approval.
    Approve(ApproveDialog),
    /// The viewers panel.
    Viewers(ViewersPanel),
}

impl ShareDialog {
    /// Handle an event (modal: consumes everything). Closes itself when done.
    pub fn handle(&mut self, ev: &ViewEvent, cx: &mut ViewCx<'_>) -> Outcome {
        cx.request_redraw();
        let ViewEvent::Key(key) = ev else {
            return Outcome::Consumed;
        };
        let close = match self {
            Self::Start(d) => d.handle_key(key),
            Self::Approve(d) => d.handle_key(key),
            Self::Viewers(d) => d.handle_key(key),
        };
        // An answer is taken (and the dialog closed) by the reducer.
        if close && !self.has_answer() {
            cx.close();
        }
        Outcome::Consumed
    }

    fn has_answer(&self) -> bool {
        match self {
            Self::Start(d) => d.answer.is_some(),
            Self::Approve(d) => d.answer.is_some(),
            Self::Viewers(d) => d.answer.is_some(),
        }
    }

    /// The answer recorded by the last key, if any.
    pub fn take_answer(&mut self) -> Option<ShareAnswer> {
        match self {
            Self::Start(d) => d.answer.take(),
            Self::Approve(d) => d.answer.take(),
            Self::Viewers(d) => d.answer.take(),
        }
    }

    /// Draw it.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        match self {
            Self::Start(d) => d.render(frame, area, cx),
            Self::Approve(d) => d.render(frame, area, cx),
            Self::Viewers(d) => d.render(frame, area, cx),
        }
    }
}

/// Where a `cols`×`rows` screen goes inside `inner` (a pane's content area):
/// centered with padding when the pane is larger, clipped (top-left kept) when it
/// is smaller (§14.3).
pub fn letterbox(inner: Rect, cols: u16, rows: u16) -> Rect {
    let w = cols.min(inner.width);
    let h = rows.min(inner.height);
    Rect {
        x: inner.x + (inner.width - w) / 2,
        y: inner.y + (inner.height - h) / 2,
        width: w,
        height: h,
    }
}

/// A dialog frame: clears `rect` and draws the bordered block; returns the inside.
pub(crate) fn frame_block(
    frame: &mut Frame<'_>,
    rect: Rect,
    title: &str,
    footer: &str,
    cx: &RenderCx<'_>,
) -> Rect {
    use ratatui::text::Span;
    use ratatui::widgets::{Block, Clear};
    frame.render_widget(Clear, rect);
    let mut block = Block::bordered()
        .title(Span::styled(format!(" {title} "), cx.theme.title_for(true)))
        .border_style(cx.theme.border_for(true))
        .style(cx.theme.base);
    if !footer.is_empty() {
        block = block.title_bottom(Span::styled(format!(" {footer} "), cx.theme.dim));
    }
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    inner
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letterbox_centers_or_clips() {
        let inner = Rect::new(1, 1, 100, 30);
        // Larger pane: centered.
        assert_eq!(letterbox(inner, 80, 24), Rect::new(11, 4, 80, 24));
        // Same size: fills it.
        assert_eq!(letterbox(inner, 100, 30), inner);
        // Smaller pane: clipped to it.
        assert_eq!(letterbox(inner, 132, 43), inner);
        // Wider but shorter: centered one way, clipped the other.
        assert_eq!(letterbox(inner, 120, 10), Rect::new(1, 11, 100, 10));
        // Degenerate.
        assert_eq!(letterbox(Rect::new(0, 0, 0, 0), 80, 24).area(), 0);
    }
}
