//! Pane geometry in the session area.
//!
//! The layout tree (`sverb_core::layout`) tiles the main area; every pane draws its own
//! 1-cell border (`TerminalPane`), so a pane's terminal size is its rect minus 2 in each
//! dimension ([`content_size`]). That size is what `SessionCmd::Resize` carries.

use ratatui::layout::Rect;
use sverb_core::layout::{self, Layout, PaneId};

/// Smallest terminal size sent to a session (a pane squeezed below its border).
pub const MIN_CONTENT: (u16, u16) = (1, 1);

/// ratatui → core.
pub fn to_core(r: Rect) -> layout::Rect {
    layout::Rect::new(r.x, r.y, r.width, r.height)
}

/// core → ratatui.
pub fn from_core(r: layout::Rect) -> Rect {
    Rect::new(r.x, r.y, r.width, r.height)
}

/// Each pane's rect inside `area` (the main area), in layout order. A zoomed pane
///  takes the whole area.
pub fn pane_rects(layout: &Layout, zoomed: Option<PaneId>, area: Rect) -> Vec<(PaneId, Rect)> {
    if let Some(z) = zoomed.filter(|z| layout.contains(*z)) {
        return vec![(z, area)];
    }
    layout
        .rects(to_core(area))
        .into_iter()
        .map(|(p, r)| (p, from_core(r)))
        .collect()
}

/// The terminal size (cols, rows) of a pane drawn in `rect` (inside its border).
pub fn content_size(rect: Rect) -> (u16, u16) {
    (
        rect.width.saturating_sub(2).max(MIN_CONTENT.0),
        rect.height.saturating_sub(2).max(MIN_CONTENT.1),
    )
}

/// The content area of a pane drawn in `rect`.
pub fn content_rect(rect: Rect) -> Rect {
    from_core(to_core(rect).inner())
}

#[cfg(test)]
mod tests {
    use sverb_core::layout::SplitDir;

    use super::*;

    #[test]
    fn content_sizes_inside_borders() {
        let l = Layout::leaf(PaneId(1))
            .split(PaneId(1), SplitDir::Vertical, PaneId(2))
            .unwrap_or_else(|| unreachable!());
        let rects = pane_rects(&l, None, Rect::new(0, 1, 100, 30));
        assert_eq!(content_size(rects[0].1), (48, 28));
        assert_eq!(content_size(rects[1].1), (48, 28));
        assert_eq!(content_rect(rects[1].1), Rect::new(51, 2, 48, 28));
        let zoomed = pane_rects(&l, Some(PaneId(2)), Rect::new(0, 1, 100, 30));
        assert_eq!(zoomed, [(PaneId(2), Rect::new(0, 1, 100, 30))]);
        assert_eq!(content_size(Rect::new(0, 0, 1, 1)), (1, 1));
    }
}
