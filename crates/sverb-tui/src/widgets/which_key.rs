//! The which-key popup (M0-10 entries, M0-11 placement and styling): bottom right of
//! the body, just above the status bar, a multi-column `key → description` list
//! grouped like `tasks/03-KEYBINDINGS.md` §4.5. Entries flow top-to-bottom into as
//! many columns as needed. `toggle_log_pane` is left out without `--debug`.

use ratatui::{
    Frame,
    layout::Rect,
    style::Modifier,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph},
};

use crate::{
    keymap::{Keymap, action::ActionName, whichkey},
    theme::Theme,
};

/// Draw the popup into the bottom-right corner of `area`.
pub fn render(frame: &mut Frame<'_>, area: Rect, keymap: &Keymap, theme: &Theme, debug: bool) {
    if area.width < 4 || area.height < 3 {
        return;
    }
    let mut groups = whichkey::entries(keymap);
    if !debug {
        for (_, es) in &mut groups {
            es.retain(|e| !e.actions.contains(&ActionName::ToggleLogPane));
        }
        groups.retain(|(_, es)| !es.is_empty());
    }
    let key_w = groups
        .iter()
        .flat_map(|(_, es)| es.iter().map(|e| e.keys.chars().count()))
        .max()
        .unwrap_or(1)
        .min(9);
    let heading = theme.accent.add_modifier(Modifier::UNDERLINED);
    let key_style = theme.accent;
    let mut lines: Vec<Line<'static>> = Vec::new();
    for (group, es) in &groups {
        lines.push(Line::styled(group.title(), heading));
        for e in es {
            lines.push(Line::from(vec![
                Span::styled(format!("{:>key_w$} ", e.keys), key_style),
                Span::raw(e.label.clone()),
            ]));
        }
    }

    let inner_w = usize::from(area.width - 2);
    let max_rows = usize::from(area.height - 2).max(1);
    let natural = lines.iter().map(Line::width).max().unwrap_or(1) + 2;
    // Enough columns to show every line; more (up to 4) if they fit at natural width.
    let needed = lines.len().div_ceil(max_rows).max(1);
    let cols = needed
        .max((inner_w / natural).clamp(1, 4))
        .min(lines.len().max(1));
    let rows = lines.len().div_ceil(cols).clamp(1, max_rows);
    // Columns narrower than their text are clipped (labels are short by design).
    let col_w = natural.min(inner_w / cols).max(1);
    let width = u16::try_from((cols * col_w).min(inner_w) + 2).unwrap_or(area.width);
    let height = u16::try_from(rows + 2)
        .unwrap_or(area.height)
        .min(area.height);
    let rect = Rect {
        x: area.x + area.width - width,
        y: area.y + area.height - height,
        width,
        height,
    };
    frame.render_widget(Clear, rect);
    let title = format!(" {} … ", keymap.leader().hint());
    let block = Block::bordered()
        .title(Span::styled(title, theme.title_focused))
        .title_bottom(Span::styled(" esc cancel ", theme.dim))
        .border_style(theme.border_focused)
        .style(theme.base);
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    for (i, chunk) in lines.chunks(rows).enumerate().take(cols) {
        let x = u16::try_from(i * col_w).unwrap_or(u16::MAX);
        if x >= inner.width {
            break;
        }
        let col = Rect {
            x: inner.x + x,
            width: (inner.width - x).min(u16::try_from(col_w).unwrap_or(u16::MAX)),
            ..inner
        };
        frame.render_widget(Paragraph::new(chunk.to_vec()), col);
    }
}
