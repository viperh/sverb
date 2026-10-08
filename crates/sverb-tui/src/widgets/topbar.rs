//! The top bar (SPEC §8.1): app name, vault selector, sync indicator, lock icon.
//!
//! `sverb ─ Personal ▾ ─────────────────────── ⟳ synced · 🔒`
//!
//! - The vault selector shows `Personal` until vaults exist (M1-04/M5-02); `▾` hints
//!   that it is selectable.
//! - The sync indicator is hidden in local-only mode (§1.1) and until M4-09.
//! - The lock icon shows while the vault is locked (M1-04): `🔒`, or `[L]` when the
//!   glyph isn't a known double-width character (checked with `unicode-width`, through
//!   ratatui) or ASCII-only output is wanted.

use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{truncate, width};
use crate::theme::Theme;

/// The lock glyph.
pub const LOCK_GLYPH: &str = "🔒";
/// Its ASCII fallback.
pub const LOCK_ASCII: &str = "[L]";

/// What the top bar shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopBarInfo {
    /// The active vault's name.
    pub vault: String,
    /// Sync status; `None` hides the indicator.
    pub sync: Option<String>,
    /// The vault is locked.
    pub locked: bool,
    /// Use ASCII instead of symbols.
    pub ascii: bool,
}

impl Default for TopBarInfo {
    fn default() -> Self {
        Self {
            vault: "Personal".to_owned(),
            sync: None,
            locked: false,
            ascii: false,
        }
    }
}

/// The lock icon: the glyph when it has the expected width of 2 cells, else `[L]`.
pub fn lock_icon(ascii: bool) -> &'static str {
    if ascii || width(LOCK_GLYPH) != 2 {
        LOCK_ASCII
    } else {
        LOCK_GLYPH
    }
}

/// Draw the top bar into the one-row `area`.
pub fn render(frame: &mut Frame<'_>, area: Rect, info: &TopBarInfo, theme: &Theme) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let mut right = Vec::new();
    if let Some(sync) = &info.sync {
        right.push(sync.clone());
    }
    if info.locked {
        right.push(lock_icon(info.ascii).to_owned());
    }
    let right = if right.is_empty() {
        String::new()
    } else {
        format!(" {} ", right.join(" · "))
    };
    let caret = if info.ascii { "v" } else { "▾" };
    let left_name = " sverb ";
    let vault = format!(" {} {caret} ", info.vault);
    let total = usize::from(area.width);
    let fixed = width(left_name) + 1 + width(&vault) + width(&right);
    let fill = total.saturating_sub(fixed);
    let line = Line::from(vec![
        Span::styled(left_name, theme.accent),
        Span::styled("─", theme.border),
        Span::styled(vault, theme.top_bar),
        Span::styled("─".repeat(fill), theme.border),
        Span::styled(right, theme.top_bar),
    ]);
    let text = if fixed > total {
        Line::from(Span::styled(truncate(" sverb", total), theme.accent))
    } else {
        line
    };
    frame.render_widget(Paragraph::new(text).style(theme.top_bar), area);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_icon_falls_back_to_ascii() {
        assert_eq!(lock_icon(false), LOCK_GLYPH);
        assert_eq!(lock_icon(true), LOCK_ASCII);
    }
}
