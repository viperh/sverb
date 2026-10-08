//! The toast stack (SPEC §8.7): top right of the body, newest at the bottom, each at
//! most [`TOAST_MAX_WIDTH`] cells wide and wrapped to at most 3 lines.

use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph},
};

use super::{width, wrap};
use crate::{
    app::{Toast, ToastLevel},
    theme::Theme,
};

/// Maximum toast width including the border.
pub const TOAST_MAX_WIDTH: u16 = 50;
/// Maximum message lines per toast.
pub const TOAST_MAX_LINES: usize = 3;

/// The style for a level.
pub fn level_style(level: ToastLevel, theme: &Theme) -> Style {
    match level {
        ToastLevel::Error => theme.error,
        ToastLevel::Warning => theme.warn,
        ToastLevel::Success => theme.ok,
        _ => theme.info,
    }
}

/// Draw `toasts` (oldest first) into the top-right corner of `area`.
pub fn render(frame: &mut Frame<'_>, area: Rect, toasts: &[Toast], theme: &Theme) {
    if area.width < 5 || area.height < 3 {
        return;
    }
    let max_w = TOAST_MAX_WIDTH.min(area.width);
    let mut y = area.y;
    let bottom = area.y + area.height;
    for toast in toasts {
        let text = if toast.count > 1 {
            format!("{} (×{})", toast.message, toast.count)
        } else {
            toast.message.clone()
        };
        let lines = wrap(&text, usize::from(max_w - 2), TOAST_MAX_LINES);
        let inner_w = lines.iter().map(|l| width(l)).max().unwrap_or(0);
        let title = format!(" {} ", toast.level.label());
        let w = u16::try_from(inner_w.max(width(&title) + 1) + 2)
            .unwrap_or(max_w)
            .min(max_w);
        let h = u16::try_from(lines.len().max(1) + 2).unwrap_or(5);
        if y + h > bottom {
            break;
        }
        let rect = Rect {
            x: area.x + area.width - w,
            y,
            width: w,
            height: h,
        };
        let style = level_style(toast.level, theme);
        frame.render_widget(Clear, rect);
        let block = Block::bordered()
            .title(Span::styled(title, style))
            .border_style(style)
            .style(theme.toast);
        let body: Vec<Line<'_>> = lines.into_iter().map(Line::raw).collect();
        frame.render_widget(Paragraph::new(body).block(block), rect);
        y += h;
    }
}
