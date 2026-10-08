//! M1-04: the lock overlay (SPEC §5.3, `tasks/03-KEYBINDINGS.md` §4.4).
//!
//! While the vault is locked, every pane (and the section area) is covered: nothing
//! decrypted is visible and keys are never forwarded to a session. Only the unlock
//! prompt and `leader q` work.

use ratatui::{
    Frame,
    layout::Rect,
    text::Line,
    widgets::{Block, Clear, Paragraph},
};

use crate::theme::Theme;
use crate::widgets::topbar::lock_icon;

/// Cover `area` with the lock overlay. `leader_hint` is the effective leader (e.g.
/// `ctrl-\`) for the quit hint. Infallible for any area size.
pub fn render(frame: &mut Frame<'_>, area: Rect, theme: &Theme, ascii: bool, leader_hint: &str) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    frame.render_widget(Clear, area);
    let block = Block::bordered()
        .border_style(theme.dim)
        .style(theme.base);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let lines = vec![
        Line::styled(format!("{} Vault locked", lock_icon(ascii)), theme.dim),
        Line::styled(format!("{leader_hint} q quit"), theme.dim),
    ];
    // At the top: the unlock prompt sits in the middle of the screen.
    frame.render_widget(Paragraph::new(lines).centered(), inner);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    #[test]
    fn renders_at_any_size() {
        for (w, h) in [(0, 0), (1, 1), (3, 2), (40, 10)] {
            let mut t = Terminal::new(TestBackend::new(w.max(1), h.max(1))).unwrap_or_else(|_| unreachable!());
            let _ = t.draw(|f| render(f, Rect::new(0, 0, w, h), &Theme::default(), true, "ctrl-\\"));
        }
    }
}
