//! The top bar (SPEC §8.1): app name, vault selector, sync indicator, lock icon.
//!
//! `sverb ─ Personal ▾ ─────────────────────── ⟳ synced · 🔒`
//!
//! - The vault selector shows `Personal` until vaults exist; `▾` hints
//!   that it is selectable.
//! - The sync indicator is hidden in local-only mode (§1.1). It shows the
//!   status with a color for its level (`SyncUi::indicator`); a click on it opens
//!   Settings → Sync ([`sync_hit`]).
//! - The lock icon shows while the vault is locked: `🔒`, or `[L]` when the
//!   glyph isn't a known double-width character (checked with `unicode-width`, through
//!   ratatui) or ASCII-only output is wanted.

use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{truncate, width};
use crate::{app::sync_ui::SyncLevel, theme::Theme, views::settings::level_style};

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
    /// How the sync status reads (its color).
    pub sync_level: Option<SyncLevel>,
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
            sync_level: None,
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
    // The sync part in its level's color.
    let sync_style = info.sync_level.map_or(theme.top_bar, |l| {
        theme.top_bar.patch(level_style(l, theme))
    });
    let right_spans: Vec<Span<'static>> = if right.is_empty() {
        Vec::new()
    } else if let Some(sync) = &info.sync {
        let rest = right[1..]
            .iter()
            .map(|r| format!(" · {r}"))
            .collect::<String>();
        vec![
            Span::styled(" ", theme.top_bar),
            Span::styled(sync.clone(), sync_style),
            Span::styled(format!("{rest} "), theme.top_bar),
        ]
    } else {
        vec![Span::styled(
            format!(" {} ", right.join(" · ")),
            theme.top_bar,
        )]
    };
    let right = right_spans
        .iter()
        .map(|s| s.content.as_ref())
        .collect::<String>();
    let caret = if info.ascii { "v" } else { "▾" };
    let left_name = " sverb ";
    let vault = format!(" {} {caret} ", info.vault);
    let total = usize::from(area.width);
    let fixed = width(left_name) + 1 + width(&vault) + width(&right);
    let fill = total.saturating_sub(fixed);
    let mut spans = vec![
        Span::styled(left_name, theme.accent),
        Span::styled("─", theme.border),
        Span::styled(vault, theme.top_bar),
        Span::styled("─".repeat(fill), theme.border),
    ];
    spans.extend(right_spans);
    let line = Line::from(spans);
    let text = if fixed > total {
        Line::from(Span::styled(truncate(" sverb", total), theme.accent))
    } else {
        line
    };
    frame.render_widget(Paragraph::new(text).style(theme.top_bar), area);
}

/// Whether `mouse` hit the sync indicator `text` drawn at the right end of the
/// top bar `area` (the lock icon is not shown while the UI is usable).
pub fn sync_hit(area: Rect, text: &str, mouse: crossterm::event::MouseEvent) -> bool {
    let w = u16::try_from(width(text) + 2).unwrap_or(u16::MAX);
    let right = area.x.saturating_add(area.width);
    mouse.row == area.y && mouse.column < right && mouse.column >= right.saturating_sub(w)
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
