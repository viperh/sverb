//! The tab bar row above the main area (SPEC §8.1, §8.4).
//!
//! M1-17: draws the session tabs (`1 prod-web-1 ┬ 2 db-primary ● ┬ 3 local ┬ +`) with
//! their markers; the geometry (overflow scrolling with `‹`/`›`, hit testing) is
//! [`crate::views::sessions::tabs::bar_segments`]. With no tab open it shows a hint on how
//! to open one.

use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::truncate;
use crate::theme::Theme;
// M1-17
use crate::views::sessions::tabs::{Segment, TabItem, bar_segments};

/// One tab (M1-17: [`TabItem`] with markers).
pub type Tab = TabItem;

/// Draw the tab bar. `empty_hint` is shown when there are no tabs.
pub fn render(frame: &mut Frame<'_>, area: Rect, tabs: &[Tab], empty_hint: &str, theme: &Theme) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let max = usize::from(area.width);
    let line = if tabs.is_empty() {
        Line::from(Span::styled(truncate(empty_hint, max), theme.dim))
    } else {
        // M1-17: the same segments mouse clicks are tested against.
        let spans: Vec<Span<'_>> = bar_segments(tabs, area.width)
            .into_iter()
            .map(|seg| {
                let style = match seg.kind {
                    Segment::Tab(i) if tabs[i].active => theme.title_focused,
                    Segment::Tab(_) => theme.dim,
                    Segment::MoreLeft(_) | Segment::MoreRight(_) => theme.accent,
                    Segment::Separator | Segment::Plus => theme.border,
                };
                Span::styled(seg.text, style)
            })
            .collect();
        Line::from(spans)
    };
    frame.render_widget(Paragraph::new(line), area);
}
