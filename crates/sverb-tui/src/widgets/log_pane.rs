//! bottom, auto-scrolling unless scrolled up (`PageUp`/`PageDown`/`End` when focused),
//! one level color per line.

use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph},
};
use sverb_core::logging::{LogLine, LogRing};
use tracing::Level;

use crate::theme::Theme;

/// The style for a log level.
pub fn level_style(level: Level, theme: &Theme) -> Style {
    match level {
        Level::ERROR => theme.error,
        Level::WARN => theme.warn,
        Level::INFO => theme.info,
        _ => theme.dim,
    }
}

/// One line as shown: time of day, level, target, message (`LogLine`'s format
/// without the date).
pub fn format_line(line: &LogLine) -> String {
    let full = line.to_string();
    // `YYYY-MM-DDT` is 11 bytes of ASCII.
    full.get(11..).unwrap_or(&full).to_owned()
}

/// Draw the pane. `scroll` is how many lines it is scrolled up from the newest.
pub fn render(
    frame: &mut Frame<'_>,
    area: Rect,
    ring: Option<&LogRing>,
    scroll: usize,
    focused: bool,
    theme: &Theme,
) {
    if area.width < 3 || area.height < 3 {
        return;
    }
    let title = if scroll > 0 {
        format!(" Log · ↑{scroll} · End follows ")
    } else {
        " Log (debug) ".to_owned()
    };
    let block = Block::bordered()
        .title(Span::styled(title, theme.title_for(focused)))
        .border_style(theme.border_for(focused));
    let inner = block.inner(area);
    frame.render_widget(Clear, area);
    frame.render_widget(block.style(theme.base), area);
    let rows = usize::from(inner.height);
    let lines: Vec<LogLine> = ring.map(|r| r.tail(rows + scroll)).unwrap_or_default();
    let end = lines.len().saturating_sub(scroll);
    let start = end.saturating_sub(rows);
    let shown: Vec<Line<'_>> = lines[start..end]
        .iter()
        .map(|l| Line::from(Span::styled(format_line(l), level_style(l.level, theme))))
        .collect();
    frame.render_widget(Paragraph::new(shown), inner);
}
