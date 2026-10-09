//! Tab titles, markers and the tab bar's geometry (SPEC §8.1, §8.4).
//!
//! ```text
//!  1 prod-web-1 ┬ 2 db-primary ● ┬ 3 local ┬ +
//! ```
//!
//! When the tabs don't fit, the bar shows a window of tabs around the active one with
//! `‹` / `›` at the ends (clicking them goes to the previous / next hidden tab). The same
//! [`bar_segments`] drive drawing (`widgets::tabbar`) and mouse hit testing, so a click
//! lands on what is drawn.

use crate::widgets::{truncate, width};

/// Longest tab label in cells (longer ones end in `…`).
pub const MAX_LABEL: usize = 24;

/// The trailing "new tab" button.
pub const PLUS: &str = "┬ + ";
/// Between two tabs.
pub const SEPARATOR: &str = "┬";
/// More tabs to the left.
pub const MORE_LEFT: &str = "‹";
/// More tabs to the right.
pub const MORE_RIGHT: &str = "›";

/// What a tab's markers show.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MarkerSet {
    /// Background output.
    pub activity: bool,
    /// A bell in the background.
    pub bell: bool,
    /// A pane is disconnected or exited.
    pub disconnected: bool,
    /// A pane waits for a password / passphrase.
    pub auth: bool,
    /// A pane is zoomed.
    pub zoomed: bool,
}

impl MarkerSet {
    /// The marker text (with a leading space when not empty). `ascii` uses `* ! x k Z`.
    pub fn text(self, ascii: bool) -> String {
        let mut out = String::new();
        let mut push = |on: bool, uni: &str, asc: &str| {
            if on {
                out.push(' ');
                out.push_str(if ascii { asc } else { uni });
            }
        };
        push(self.zoomed, "Z", "Z");
        push(self.activity, "●", "*");
        push(self.bell, "🔔", "!");
        push(self.auth, "🔑", "k");
        push(self.disconnected, "✕", "x");
        out
    }
}

/// The title of a tab: the user's override, else the focused pane's OSC title (with
/// `terminal.use_osc_title`), else its label (host label; the shell name for local tabs).
pub fn title(
    title_override: Option<&str>,
    label: &str,
    osc_title: Option<&str>,
    use_osc_title: bool,
) -> String {
    if let Some(t) = title_override.filter(|t| !t.is_empty()) {
        return t.to_owned();
    }
    match osc_title.filter(|t| use_osc_title && !t.is_empty()) {
        Some(t) => t.to_owned(),
        None => label.to_owned(),
    }
}

/// One tab as the bar shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TabItem {
    /// The title (cut to [`MAX_LABEL`] when drawn).
    pub label: String,
    /// The active tab.
    pub active: bool,
    /// Marker text ([`MarkerSet::text`]).
    pub markers: String,
}

impl TabItem {
    /// ` N label markers `.
    pub fn text(&self, number: usize) -> String {
        format!(
            " {number} {}{} ",
            truncate(&self.label, MAX_LABEL),
            self.markers
        )
    }
}

/// What a bar segment is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Segment {
    /// Tab `index` (0-based).
    Tab(usize),
    /// A separator.
    Separator,
    /// `‹`: go to tab `index` (the nearest hidden one on the left).
    MoreLeft(usize),
    /// `›`: go to tab `index` (the nearest hidden one on the right).
    MoreRight(usize),
    /// The `+` button (new tab: host picker).
    Plus,
}

/// A drawn piece of the bar: `text` at column offset `x` (relative to the bar).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BarSegment {
    /// What it is.
    pub kind: Segment,
    /// What is drawn.
    pub text: String,
    /// Column offset from the bar's left edge.
    pub x: u16,
    /// Width in cells.
    pub width: u16,
}

fn cells(s: &str) -> u16 {
    u16::try_from(width(s)).unwrap_or(u16::MAX)
}

/// Lay out `tabs` in a bar `bar_width` cells wide: all of them when they fit, else a
/// window around the active tab with `‹`/`›`. The `+` button stays at the end when it
/// fits.
pub fn bar_segments(tabs: &[TabItem], bar_width: u16) -> Vec<BarSegment> {
    if tabs.is_empty() || bar_width == 0 {
        return Vec::new();
    }
    let texts: Vec<String> = tabs
        .iter()
        .enumerate()
        .map(|(i, t)| t.text(i + 1))
        .collect();
    let widths: Vec<u16> = texts.iter().map(|t| cells(t)).collect();
    let sep = cells(SEPARATOR);
    let plus = cells(PLUS);
    let span = |s: usize, e: usize| -> u32 {
        let tabs: u32 = widths[s..e].iter().map(|w| u32::from(*w)).sum();
        tabs + u32::from(sep) * u32::try_from(e - s).unwrap_or(0).saturating_sub(1)
    };
    let n = tabs.len();
    let budget = u32::from(bar_width);
    let (start, end) = if span(0, n) + u32::from(plus) <= budget {
        (0, n)
    } else {
        // Room for `‹` and `›` and the `+`; grow the window around the active tab.
        let active = tabs.iter().position(|t| t.active).unwrap_or(0);
        let inner = budget.saturating_sub(2 + u32::from(plus));
        let (mut s, mut e) = (active, active + 1);
        loop {
            let mut grew = false;
            if e < n && span(s, e + 1) <= inner {
                e += 1;
                grew = true;
            }
            if s > 0 && span(s - 1, e) <= inner {
                s -= 1;
                grew = true;
            }
            if !grew {
                break;
            }
        }
        (s, e)
    };
    let mut out = Vec::new();
    let mut x = 0u16;
    let mut push = |kind: Segment, text: String, out: &mut Vec<BarSegment>| {
        let w = cells(&text);
        if x >= bar_width {
            return;
        }
        let room = bar_width - x;
        let (text, w) = if w > room {
            let t = truncate(&text, usize::from(room));
            let w = cells(&t);
            (t, w)
        } else {
            (text, w)
        };
        out.push(BarSegment {
            kind,
            text,
            x,
            width: w,
        });
        x = x.saturating_add(w);
    };
    if start > 0 {
        push(Segment::MoreLeft(start - 1), MORE_LEFT.to_owned(), &mut out);
    }
    for (i, text) in texts.into_iter().enumerate().take(end).skip(start) {
        if i > start {
            push(Segment::Separator, SEPARATOR.to_owned(), &mut out);
        }
        push(Segment::Tab(i), text, &mut out);
    }
    if end < n {
        push(Segment::MoreRight(end), MORE_RIGHT.to_owned(), &mut out);
    }
    push(Segment::Plus, PLUS.to_owned(), &mut out);
    out
}

/// The segment under column offset `col` (relative to the bar). Separators don't count.
pub fn hit(segments: &[BarSegment], col: u16) -> Option<Segment> {
    segments
        .iter()
        .find(|s| col >= s.x && col < s.x.saturating_add(s.width))
        .map(|s| s.kind)
        .filter(|k| *k != Segment::Separator)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(label: &str, active: bool) -> TabItem {
        TabItem {
            label: label.to_owned(),
            active,
            markers: String::new(),
        }
    }

    fn line(segs: &[BarSegment]) -> String {
        segs.iter().map(|s| s.text.as_str()).collect()
    }

    #[test]
    fn all_tabs_fit() {
        let mut tabs = vec![
            item("prod-web-1", true),
            item("db-primary", false),
            item("local", false),
        ];
        tabs[1].markers = MarkerSet {
            activity: true,
            ..MarkerSet::default()
        }
        .text(false);
        let segs = bar_segments(&tabs, 80);
        assert_eq!(line(&segs), " 1 prod-web-1 ┬ 2 db-primary ● ┬ 3 local ┬ + ");
        assert_eq!(hit(&segs, 1), Some(Segment::Tab(0)));
        assert_eq!(hit(&segs, 14), None, "separator");
        assert_eq!(hit(&segs, 16), Some(Segment::Tab(1)));
        let plus = segs.last().unwrap_or_else(|| unreachable!());
        assert_eq!(hit(&segs, plus.x + 2), Some(Segment::Plus));
    }

    #[test]
    fn overflow_scrolls_around_the_active_tab() {
        let tabs: Vec<TabItem> = (0..8).map(|i| item(&format!("host-{i}"), i == 5)).collect();
        let segs = bar_segments(&tabs, 40);
        let text = line(&segs);
        assert!(width(&text) <= 40, "{text}");
        assert!(text.starts_with(MORE_LEFT), "{text}");
        assert!(text.contains(" 6 host-5 "), "{text}");
        assert!(text.ends_with(PLUS), "{text}");
        let left = segs.iter().find_map(|s| match s.kind {
            Segment::MoreLeft(i) => Some(i),
            _ => None,
        });
        assert!(left.is_some_and(|i| i < 5));
        // The first tab active: no `‹`.
        let tabs: Vec<TabItem> = (0..8).map(|i| item(&format!("host-{i}"), i == 0)).collect();
        let text = line(&bar_segments(&tabs, 40));
        assert!(text.starts_with(" 1 host-0"), "{text}");
        assert!(text.contains(MORE_RIGHT), "{text}");
    }

    #[test]
    fn titles_and_markers() {
        assert_eq!(title(None, "web", Some("vim"), false), "web");
        assert_eq!(title(None, "web", Some("vim"), true), "vim");
        assert_eq!(title(None, "web", Some(""), true), "web");
        assert_eq!(title(Some("db"), "web", Some("vim"), true), "db");
        let all = MarkerSet {
            activity: true,
            bell: true,
            disconnected: true,
            auth: true,
            zoomed: false,
        };
        assert_eq!(all.text(false), " ● 🔔 🔑 ✕");
        assert_eq!(all.text(true), " * ! k x");
        let long = "x".repeat(300);
        let t = item(&long, true).text(1);
        assert!(t.contains('…') && width(&t) <= MAX_LABEL + 4, "{t}");
    }
}
