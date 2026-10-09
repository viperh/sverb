//! The status bar (SPEC §8.1).
//!
//! Segments, left to right: mode, focused session, forwards, `REC ●`, `BROADCAST ×N`,
//! sync, and the key hint (right-aligned). Empty segments are not drawn. When the row
//! is too narrow, segments are dropped by **priority**, lowest first:
//!
//! | priority | segment |
//! |---|---|
//! | 1 (kept longest) | mode |
//! | 2 | key hint (`^\ ? help`, from the real leader) |
//! | 3 | `BROADCAST ×N` (typing goes to several panes: never hide it lightly) |
//! | 4 | `REC ●` |
//! | 5 | session info |
//! | 6 | sync |
//! | 7 (dropped first) | forwards |
//!
//! If mode and hint alone don't fit, the hint is truncated.

use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{truncate, width};
use crate::{app::Mode, theme::Theme};

/// Separator between segments.
const SEP: &str = " │ ";

/// What the status bar shows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StatusInfo {
    /// Input mode label (`NORMAL`, `TERMINAL`, …).
    pub mode: String,
    pub session: Option<String>,
    /// Active forwards summary.
    pub forwards: Option<String>,
    /// Recording the focused session.
    pub recording: bool,
    /// Broadcast input to N panes.
    pub broadcast: Option<u32>,
    /// After `BROADCAST ×N`, in parentheses: `M skipped` or `pending`.
    pub broadcast_note: Option<String>,
    pub sync: Option<String>,
    /// Key hint, rendered from the leader.
    pub hint: String,
}

impl StatusInfo {
    /// Info with just a mode and a hint.
    pub fn new(mode: Mode, hint: String) -> Self {
        Self {
            mode: mode.label().to_owned(),
            hint,
            ..Self::default()
        }
    }
}

/// A status segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Segment {
    /// Mode.
    Mode,
    /// Session info.
    Session,
    /// Forwards.
    Forwards,
    /// Recording.
    Recording,
    /// Broadcast.
    Broadcast,
    /// Sync.
    Sync,
    /// Key hint.
    Hint,
}

impl Segment {
    /// Lower is more important.
    pub fn priority(self) -> u8 {
        match self {
            Self::Mode => 1,
            Self::Hint => 2,
            Self::Broadcast => 3,
            Self::Recording => 4,
            Self::Session => 5,
            Self::Sync => 6,
            Self::Forwards => 7,
        }
    }
}

/// The non-empty segments in display order (hint last), with their text.
fn all_segments(info: &StatusInfo) -> Vec<(Segment, String)> {
    let mut out = vec![(Segment::Mode, format!(" {} ", info.mode))];
    if let Some(s) = info.session.as_ref().filter(|s| !s.is_empty()) {
        out.push((Segment::Session, s.clone()));
    }
    if let Some(s) = info.forwards.as_ref().filter(|s| !s.is_empty()) {
        out.push((Segment::Forwards, s.clone()));
    }
    if info.recording {
        out.push((Segment::Recording, "REC ●".to_owned()));
    }
    if let Some(n) = info.broadcast {
        // `BROADCAST ×2 (1 skipped)`.
        let text = match info.broadcast_note.as_deref().filter(|s| !s.is_empty()) {
            Some(note) => format!("BROADCAST ×{n} ({note})"),
            None => format!("BROADCAST ×{n}"),
        };
        out.push((Segment::Broadcast, text));
    }
    if let Some(s) = info.sync.as_ref().filter(|s| !s.is_empty()) {
        out.push((Segment::Sync, s.clone()));
    }
    if !info.hint.is_empty() {
        out.push((Segment::Hint, format!("{} ", info.hint)));
    }
    out
}

fn total_width(segs: &[(Segment, String)]) -> usize {
    let left: Vec<_> = segs.iter().filter(|(s, _)| *s != Segment::Hint).collect();
    let hint = segs
        .iter()
        .find(|(s, _)| *s == Segment::Hint)
        .map_or(0, |(_, t)| width(t) + 1);
    let seps = left.len().saturating_sub(1) * width(SEP);
    left.iter().map(|(_, t)| width(t)).sum::<usize>() + seps + hint
}

/// The segments that fit in `max` cells, in display order.
pub fn fit(info: &StatusInfo, max: usize) -> Vec<(Segment, String)> {
    let mut segs = all_segments(info);
    while total_width(&segs) > max {
        let Some(drop) = segs
            .iter()
            .enumerate()
            .filter(|(_, (s, _))| !matches!(s, Segment::Mode | Segment::Hint))
            .max_by_key(|(_, (s, _))| s.priority())
            .map(|(i, _)| i)
        else {
            break;
        };
        segs.remove(drop);
    }
    // Still too wide: shorten the hint, then the mode.
    let over = total_width(&segs).saturating_sub(max);
    if over > 0
        && let Some((_, hint)) = segs.iter_mut().find(|(s, _)| *s == Segment::Hint)
    {
        let w = width(hint).saturating_sub(over);
        *hint = truncate(hint, w);
        if hint.is_empty() {
            segs.retain(|(s, _)| *s != Segment::Hint);
        }
    }
    segs
}

/// Cells the fitted status needs (for the merged tab-bar row).
pub fn needed_width(info: &StatusInfo, max: usize) -> u16 {
    u16::try_from(total_width(&fit(info, max)).min(max)).unwrap_or(u16::MAX)
}

/// Draw the status bar into the one-row `area`.
pub fn render(frame: &mut Frame<'_>, area: Rect, info: &StatusInfo, theme: &Theme) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let segs = fit(info, usize::from(area.width));
    let style_of = |s: Segment| -> Style {
        match s {
            Segment::Mode => theme.status_mode,
            Segment::Recording => theme.error,
            Segment::Broadcast => theme.warn,
            _ => theme.status,
        }
    };
    let mut spans: Vec<Span<'_>> = Vec::new();
    let mut hint = None;
    for (seg, text) in segs {
        if seg == Segment::Hint {
            hint = Some(text);
            continue;
        }
        if !spans.is_empty() {
            spans.push(Span::styled(SEP, theme.status));
        }
        spans.push(Span::styled(text, theme.status.patch(style_of(seg))));
    }
    let left = Line::from(spans);
    frame.render_widget(Paragraph::new(left).style(theme.status), area);
    if let Some(hint) = hint {
        let w = u16::try_from(width(&hint))
            .unwrap_or(u16::MAX)
            .min(area.width);
        let rect = Rect {
            x: area.x + area.width - w,
            width: w,
            ..area
        };
        frame.render_widget(Paragraph::new(Line::raw(hint)).style(theme.status), rect);
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    fn full() -> StatusInfo {
        StatusInfo {
            mode: "NORMAL".into(),
            session: Some("ubuntu@prod-web-1 · ssh · 23ms".into()),
            forwards: Some("⇄ L:5432→db:5432".into()),
            recording: true,
            broadcast: Some(3),
            broadcast_note: None,
            sync: Some("⟳ synced".into()),
            hint: "^\\ ? help".into(),
        }
    }

    fn kinds(segs: &[(Segment, String)]) -> Vec<Segment> {
        segs.iter().map(|(s, _)| *s).collect()
    }

    #[test]
    fn t10_low_priority_segments_drop_first() {
        let all = kinds(&fit(&full(), 300));
        assert_eq!(
            all,
            [
                Segment::Mode,
                Segment::Session,
                Segment::Forwards,
                Segment::Recording,
                Segment::Broadcast,
                Segment::Sync,
                Segment::Hint
            ]
        );
        let at60 = fit(&full(), 60);
        let k = kinds(&at60);
        assert!(
            k.contains(&Segment::Mode) && k.contains(&Segment::Hint),
            "{at60:?}"
        );
        assert!(!k.contains(&Segment::Forwards), "{at60:?}");
        assert!(!k.contains(&Segment::Sync), "{at60:?}");
        assert!(total_width(&at60) <= 60);
        // Whatever is dropped, it is always the lowest priority left.
        for w in 0..=120 {
            let k = kinds(&fit(&full(), w));
            let kept_max = k
                .iter()
                .filter(|s| !matches!(s, Segment::Mode | Segment::Hint))
                .map(|s| s.priority())
                .max()
                .unwrap_or(0);
            for dropped in kinds(&all_segments(&full())) {
                if !k.contains(&dropped) && !matches!(dropped, Segment::Mode | Segment::Hint) {
                    assert!(dropped.priority() > kept_max, "w={w}: {k:?}");
                }
            }
        }
    }

    #[test]
    fn tiny_widths_shorten_the_hint() {
        let segs = fit(&full(), 14);
        assert_eq!(kinds(&segs)[0], Segment::Mode);
        assert!(total_width(&segs) <= 14 || kinds(&segs) == [Segment::Mode]);
    }
}
