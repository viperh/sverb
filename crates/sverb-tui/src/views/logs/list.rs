//! M3-06: the Logs section list (SPEC §9.12, §8.5).
//!
//! ```text
//! ┌ Logs · failed · host: web ─────────────────────────────────────────────────────┐
//! │ Time              Host            Result             Duration  In       Out  Rec│
//! │ 2026-10-07 12:34  web-1           ok                 1h02m     1.2 MiB  3 KiB ● │
//! │ 2026-10-07 12:30  db              auth failed        2s        0 B      0 B     │
//! │ Enter reconnect · i details · p replay · e export · d delete · D clear older… · │
//! └────────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! Newest first. `/` filters by host (fuzzy, on the label and the target), `r` cycles the
//! result filter (all → ok → failed). Actions that need the app (reconnect, dialogs,
//! effects) are left in [`LogsView::request`] and taken by the reducer right after the
//! key (`app/logs.rs`).
//!
//! The list is a small local table: the shared list component (M1-06, `widgets/list.rs`)
//! was not merged when this was written. Switching means feeding [`LogsView::visible`]
//! rows to `ListView` and keeping [`LogsView::selected`] as the selection id.

use std::{collections::BTreeMap, fmt::Write as _, path::PathBuf, time::Duration};

use chrono::{DateTime, FixedOffset, Local, Utc};
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Block, Paragraph},
};
use sverb_core::model::{ConnLog, ConnResult, ItemId, UnixMillis};

use crate::{
    app::SessionId,
    theme::Theme,
    views::{Outcome, RenderCx, View, ViewCx, ViewEvent},
};

/// One row: a `ConnLog` item and its device-local recording, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    /// The ConnLog item id (also the recording's `conn_id`).
    pub id: ItemId,
    /// The entry.
    pub log: ConnLog,
    /// The recording file (`device_local.recording_dir`).
    pub recording: Option<PathBuf>,
}

impl LogEntry {
    /// Host column text: the label, or the target, or `?`.
    pub fn host(&self) -> &str {
        if !self.log.label.is_empty() {
            &self.log.label
        } else {
            self.log.target.as_deref().unwrap_or("?")
        }
    }
}

/// The result filter (`r` cycles it).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ResultFilter {
    /// Everything.
    #[default]
    All,
    /// Successful attempts.
    Ok,
    /// Failed attempts.
    Failed,
}

impl ResultFilter {
    /// The next filter in the cycle.
    pub fn next(self) -> Self {
        match self {
            Self::All => Self::Ok,
            Self::Ok => Self::Failed,
            Self::Failed => Self::All,
        }
    }

    /// Title label.
    pub fn label(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Ok => "ok",
            Self::Failed => "failed",
        }
    }

    /// Whether `log` passes.
    pub fn matches(self, log: &ConnLog) -> bool {
        match self {
            Self::All => true,
            Self::Ok => log.result == Some(ConnResult::Ok),
            Self::Failed => log.is_failure(),
        }
    }
}

/// What the user asked the reducer to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogsRequest {
    /// `Enter`: open a new session for the entry's host.
    Reconnect(ItemId),
    /// `i`: the full error details.
    Details(ItemId),
    /// `p`: replay the recording.
    Replay(ItemId),
    /// `e`: export the recording.
    Export(ItemId),
    /// `d`: delete the entry (asks about its recording).
    Delete(ItemId),
    /// `D`: delete everything older than… (asks for the days).
    ClearOlder,
}

/// The Logs section's state.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LogsView {
    /// Every entry, newest first.
    pub entries: Vec<LogEntry>,
    /// The service delivered the list (after unlock).
    pub loaded: bool,
    /// The host filter (fuzzy).
    pub host_filter: String,
    /// `/` was pressed: keys edit the host filter until `Enter`/`Esc` (Insert mode).
    pub editing_filter: bool,
    /// The result filter.
    pub result_filter: ResultFilter,
    /// The highlighted entry.
    pub selected: Option<ItemId>,
    /// Select this entry as soon as it is in the list (the banner's `leader i`).
    pub focus_on: Option<ItemId>,
    /// The current ConnLog entry of each session (from `ConnLogEvent::Started`).
    pub sessions: BTreeMap<SessionId, ItemId>,
    /// A request for the reducer, taken right after the key.
    pub request: Option<LogsRequest>,
    /// Show times in this UTC offset (seconds) instead of local time (tests).
    pub utc_offset_secs: Option<i32>,
}

impl LogsView {
    /// Replace the list (sorted newest first).
    pub fn set_entries(&mut self, mut entries: Vec<LogEntry>) {
        sort(&mut entries);
        self.entries = entries;
        self.loaded = true;
        self.apply_focus();
    }

    /// Insert or replace one entry.
    pub fn upsert(&mut self, entry: LogEntry) {
        match self.entries.iter_mut().find(|e| e.id == entry.id) {
            Some(e) => *e = entry,
            None => self.entries.push(entry),
        }
        sort(&mut self.entries);
        self.apply_focus();
    }

    /// Drop entries.
    pub fn remove(&mut self, ids: &[ItemId]) {
        self.entries.retain(|e| !ids.contains(&e.id));
        if self.selected.is_some_and(|s| ids.contains(&s)) {
            self.selected = None;
        }
    }

    /// Forget everything decrypted (on lock).
    pub fn clear(&mut self) {
        self.entries.clear();
        self.loaded = false;
        self.selected = None;
        self.request = None;
    }

    /// An entry by id.
    pub fn get(&self, id: ItemId) -> Option<&LogEntry> {
        self.entries.iter().find(|e| e.id == id)
    }

    /// Select `id` now if it is listed, else as soon as it arrives. Clears filters that
    /// would hide it.
    pub fn focus(&mut self, id: ItemId) {
        self.focus_on = Some(id);
        self.apply_focus();
    }

    fn apply_focus(&mut self) {
        let Some(id) = self.focus_on else {
            return;
        };
        if self.get(id).is_some() {
            self.focus_on = None;
            self.selected = Some(id);
            if !self.visible().iter().any(|e| e.id == id) {
                self.host_filter.clear();
                self.result_filter = ResultFilter::All;
            }
        }
    }

    /// The rows that pass both filters, newest first.
    pub fn visible(&self) -> Vec<&LogEntry> {
        self.entries
            .iter()
            .filter(|e| self.result_filter.matches(&e.log))
            .filter(|e| {
                fuzzy(&self.host_filter, e.host())
                    || e.log
                        .target
                        .as_deref()
                        .is_some_and(|t| fuzzy(&self.host_filter, t))
            })
            .collect()
    }

    /// Index of the highlighted row in [`LogsView::visible`] (the first row when the
    /// selection is filtered out).
    pub fn selected_index(&self) -> Option<usize> {
        let rows = self.visible();
        if rows.is_empty() {
            return None;
        }
        Some(
            self.selected
                .and_then(|id| rows.iter().position(|e| e.id == id))
                .unwrap_or(0),
        )
    }

    /// The highlighted entry (among the visible ones).
    pub fn selected_entry(&self) -> Option<&LogEntry> {
        let rows = self.visible();
        self.selected_index().and_then(|i| rows.get(i).copied())
    }

    fn move_to(&mut self, index: usize) {
        let rows = self.visible();
        if let Some(e) = rows.get(index.min(rows.len().saturating_sub(1))) {
            self.selected = Some(e.id);
        }
    }

    fn move_by(&mut self, delta: isize) {
        let Some(cur) = self.selected_index() else {
            return;
        };
        self.move_to(cur.saturating_add_signed(delta));
    }

    fn request_for(&mut self, make: impl FnOnce(ItemId) -> LogsRequest) -> bool {
        match self.selected_entry().map(|e| e.id) {
            Some(id) => {
                self.request = Some(make(id));
                true
            }
            None => false,
        }
    }

    fn handle_filter_key(&mut self, code: KeyCode, mods: KeyModifiers) {
        match code {
            KeyCode::Esc => {
                self.editing_filter = false;
                self.host_filter.clear();
            }
            KeyCode::Enter => self.editing_filter = false,
            KeyCode::Backspace => {
                self.host_filter.pop();
            }
            KeyCode::Char(c) if !mods.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) => {
                self.host_filter.push(c);
            }
            _ => {}
        }
    }
}

/// Newest first; ties by id (UUIDv7, so creation order) newest first.
fn sort(entries: &mut [LogEntry]) {
    entries.sort_by(|a, b| {
        b.log
            .started_at
            .cmp(&a.log.started_at)
            .then_with(|| b.id.cmp(&a.id))
    });
}

/// Case-insensitive subsequence match (`pw1` matches `prod-web-1`). Empty matches all.
pub fn fuzzy(needle: &str, haystack: &str) -> bool {
    let mut hay = haystack.chars().flat_map(char::to_lowercase);
    needle
        .chars()
        .flat_map(char::to_lowercase)
        .filter(|c| !c.is_whitespace())
        .all(|n| hay.any(|h| h == n))
}

impl View for LogsView {
    fn handle(&mut self, ev: &ViewEvent, cx: &mut ViewCx<'_>) -> Outcome {
        let ViewEvent::Key(key) = ev else {
            if let (ViewEvent::Paste(text), true) = (ev, self.editing_filter) {
                self.host_filter
                    .extend(text.chars().filter(|c| !c.is_control()));
                cx.request_redraw();
                return Outcome::Consumed;
            }
            return Outcome::Ignored;
        };
        if self.editing_filter {
            self.handle_filter_key(key.code, key.modifiers);
            cx.request_redraw();
            return Outcome::Consumed;
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if key.modifiers.intersects(KeyModifiers::ALT) {
            return Outcome::Ignored;
        }
        let half_page = 10;
        let handled = match (key.code, ctrl) {
            (KeyCode::Char('j') | KeyCode::Down, false) => {
                self.move_by(1);
                true
            }
            (KeyCode::Char('k') | KeyCode::Up, false) => {
                self.move_by(-1);
                true
            }
            (KeyCode::Char('d'), true) | (KeyCode::PageDown, _) => {
                self.move_by(half_page);
                true
            }
            (KeyCode::Char('u'), true) | (KeyCode::PageUp, _) => {
                self.move_by(-half_page);
                true
            }
            (KeyCode::Char('g') | KeyCode::Home, false) => {
                self.move_to(0);
                true
            }
            (KeyCode::Char('G') | KeyCode::End, false) => {
                self.move_to(usize::MAX);
                true
            }
            (KeyCode::Char('/'), false) => {
                self.editing_filter = true;
                true
            }
            (KeyCode::Char('r'), false) => {
                self.result_filter = self.result_filter.next();
                true
            }
            (KeyCode::Esc, false) if !self.host_filter.is_empty() => {
                self.host_filter.clear();
                true
            }
            (KeyCode::Enter, false) => self.request_for(LogsRequest::Reconnect),
            (KeyCode::Char('i'), false) => self.request_for(LogsRequest::Details),
            (KeyCode::Char('p'), false) => self.request_for(LogsRequest::Replay),
            (KeyCode::Char('e'), false) => self.request_for(LogsRequest::Export),
            (KeyCode::Char('d'), false) => self.request_for(LogsRequest::Delete),
            (KeyCode::Char('D'), false) => {
                self.request = Some(LogsRequest::ClearOlder);
                true
            }
            _ => false,
        };
        if handled {
            cx.request_redraw();
            Outcome::Consumed
        } else {
            Outcome::Ignored
        }
    }

    // M1-06: Insert mode while the host filter is edited (`q`, `?` are typed, not run).
    fn insert_mode(&self) -> bool {
        self.editing_filter
    }

    fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let theme = cx.theme;
        let mut title = " Logs ".to_owned();
        if self.result_filter != ResultFilter::All {
            title = format!(" Logs · {} ", self.result_filter.label());
        }
        if !self.host_filter.is_empty() || self.editing_filter {
            let cursor = if self.editing_filter { "▏" } else { "" };
            let _ = write!(title, "· host: {}{cursor} ", self.host_filter);
        }
        let block = Block::bordered()
            .title(Span::styled(title, theme.title_for(cx.focused)))
            .border_style(theme.border_for(cx.focused));
        let inner = block.inner(area);
        frame.render_widget(block, area);
        if inner.is_empty() {
            return;
        }
        let width = usize::from(inner.width);
        let height = usize::from(inner.height);
        let mut lines: Vec<Line<'_>> = Vec::with_capacity(height);
        let rows = self.visible();
        if !self.loaded {
            lines.push(Line::styled(
                "Connection logs appear after unlock.",
                theme.dim,
            ));
        } else if self.entries.is_empty() {
            lines.push(Line::styled("No connection logs yet.", theme.dim));
        } else if rows.is_empty() {
            lines.push(Line::styled("No entries match the filters.", theme.dim));
        } else {
            let cols = Columns::for_width(width);
            lines.push(Line::styled(cols.header(), theme.accent));
            // Header and footer take one row each when there is room.
            let footer = usize::from(height >= 4);
            let room = height.saturating_sub(1 + footer).max(1);
            let selected = self.selected_index().unwrap_or(0);
            let first = selected.saturating_sub(room.saturating_sub(1));
            for (i, e) in rows.iter().enumerate().skip(first).take(room) {
                let style = if i == selected && cx.focused {
                    theme.selection
                } else {
                    result_style(&e.log, theme)
                };
                let text = cols.row(e, &cx.config.ui.date_format, self.utc_offset_secs);
                lines.push(Line::styled(fit(&text, width), style));
            }
            if footer == 1 {
                while lines.len() < height - 1 {
                    lines.push(Line::raw(""));
                }
                lines.push(Line::styled(
                    fit(
                        "⏎ reconnect · i details · p replay · e export · d delete · \
                         D clear older · / host · r result",
                        width,
                    ),
                    theme.dim,
                ));
            }
        }
        frame.render_widget(Paragraph::new(lines).style(theme.base), inner);
    }
}

fn result_style(log: &ConnLog, theme: &Theme) -> Style {
    match &log.result {
        None => theme.info,
        Some(ConnResult::Ok) => theme.base,
        Some(_) => theme.error,
    }
}

/// Column widths for a table `width` cells wide.
struct Columns {
    host: usize,
    bytes: bool,
}

const TIME_W: usize = 16;
const RESULT_W: usize = 17;
const DUR_W: usize = 8;
const BYTES_W: usize = 9;
const REC_W: usize = 3;

impl Columns {
    fn for_width(width: usize) -> Self {
        let fixed = TIME_W + RESULT_W + DUR_W + REC_W + 4;
        let with_bytes = fixed + 2 * (BYTES_W + 1);
        let bytes = width >= with_bytes + 12;
        let used = if bytes { with_bytes } else { fixed };
        Self {
            host: width.saturating_sub(used + 1).max(4),
            bytes,
        }
    }

    /// One line from the cells `[time, host, result, duration, in, out, rec]`.
    fn line(&self, cells: [&str; 7]) -> String {
        let [time, host, result, dur, inb, outb, rec] = cells;
        let mut s = format!(
            "{} {} {} {}",
            pad(time, TIME_W),
            pad(host, self.host),
            pad(result, RESULT_W),
            pad(dur, DUR_W)
        );
        if self.bytes {
            let _ = write!(s, " {} {}", pad(inb, BYTES_W), pad(outb, BYTES_W));
        }
        let _ = write!(s, " {}", pad(rec, REC_W));
        s
    }

    fn header(&self) -> String {
        self.line(["Time", "Host", "Result", "Duration", "In", "Out", "Rec"])
    }

    fn row(&self, e: &LogEntry, date_format: &str, offset: Option<i32>) -> String {
        let result = match &e.log.result {
            None => "connected…",
            Some(r) => r.label(),
        };
        let dur = e
            .log
            .duration()
            .map_or_else(|| "—".to_owned(), format_duration);
        let rec = if e.recording.is_some() { "●" } else { "" };
        self.line([
            &format_time(e.log.started_at, date_format, offset),
            e.host(),
            result,
            &dur,
            &format_bytes(e.log.bytes_in),
            &format_bytes(e.log.bytes_out),
            rec,
        ])
    }
}

/// `s` padded or cut (with `…`) to exactly `w` cells.
fn pad(s: &str, w: usize) -> String {
    let cut = fit(s, w);
    let len = Span::raw(cut.as_str()).width();
    format!("{cut}{}", " ".repeat(w.saturating_sub(len)))
}

/// `s` cut to at most `w` cells, with `…` when cut.
pub(crate) fn fit(s: &str, w: usize) -> String {
    if Span::raw(s).width() <= w {
        return s.to_owned();
    }
    if w == 0 {
        return String::new();
    }
    let mut out = String::new();
    for c in s.chars() {
        let mut buf = [0; 4];
        if Span::raw(out.as_str()).width() + Span::raw(&*c.encode_utf8(&mut buf)).width() + 1 > w {
            break;
        }
        out.push(c);
    }
    out.push('…');
    out
}

/// A timestamp in `ui.date_format` (local time, or `offset` seconds east of UTC).
/// Never panics on a bad format string.
pub fn format_time(t: UnixMillis, fmt: &str, offset: Option<i32>) -> String {
    let Some(utc) = DateTime::<Utc>::from_timestamp_millis(t.0) else {
        return "--".to_owned();
    };
    let mut out = String::new();
    let ok = match offset.and_then(FixedOffset::east_opt) {
        Some(off) => write!(out, "{}", utc.with_timezone(&off).format(fmt)),
        None => write!(out, "{}", utc.with_timezone(&Local).format(fmt)),
    };
    if ok.is_err() {
        out = utc.to_rfc3339();
    }
    out
}

/// `12s`, `4m05s`, `1h02m`, `3d04h`.
pub fn format_duration(d: Duration) -> String {
    let s = d.as_secs();
    match s {
        0..60 => format!("{s}s"),
        60..3600 => format!("{}m{:02}s", s / 60, s % 60),
        3600..86_400 => format!("{}h{:02}m", s / 3600, (s / 60) % 60),
        _ => format!("{}d{:02}h", s / 86_400, (s / 3600) % 24),
    }
}

/// `512 B`, `1.2 KiB`, `3.4 MiB`, `1.0 GiB`.
pub fn format_bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    #[allow(clippy::cast_precision_loss)]
    let mut v = n as f64 / 1024.0;
    let mut unit = 0;
    while v >= 1024.0 && unit + 1 < UNITS.len() {
        v /= 1024.0;
        unit += 1;
    }
    format!("{v:.1} {}", UNITS[unit])
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn fuzzy_is_a_case_insensitive_subsequence() {
        assert!(fuzzy("", "anything"));
        assert!(fuzzy("pw1", "prod-web-1"));
        assert!(fuzzy("WEB", "prod-web-1"));
        assert!(!fuzzy("xyz", "prod-web-1"));
        assert!(!fuzzy("1w", "prod-web-1"));
    }

    #[test]
    fn formats() {
        assert_eq!(format_duration(Duration::from_secs(12)), "12s");
        assert_eq!(format_duration(Duration::from_secs(245)), "4m05s");
        assert_eq!(format_duration(Duration::from_secs(3720)), "1h02m");
        assert_eq!(format_duration(Duration::from_secs(273_600)), "3d04h");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1229), "1.2 KiB");
        assert_eq!(format_bytes(3 * 1024 * 1024), "3.0 MiB");
        assert_eq!(
            format_time(UnixMillis(1_791_376_440_000), "%Y-%m-%d %H:%M", Some(0)),
            "2026-10-07 12:34"
        );
        assert_eq!(
            format_time(UnixMillis(1_791_376_440_000), "%H:%M", Some(3600)),
            "13:34"
        );
        assert_eq!(pad("abc", 5), "abc  ");
        assert_eq!(pad("abcdef", 4), "abc…");
    }
}
