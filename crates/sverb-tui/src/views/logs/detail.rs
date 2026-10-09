//! The Logs detail pane and the Logs dialogs (error details, delete, clear older,
//! export, replay). Their keys are handled by the reducer (`app/logs.rs`).

use std::{
    fmt,
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph, Wrap},
};
use sverb_core::model::{ConnResult, ItemId};

use super::{
    ReplayView,
    list::{LogEntry, format_bytes, format_duration, format_time},
};
use crate::views::RenderCx;

/// "Delete this entry?" (`d`). `y` deletes it with its recording, `k` keeps the
/// recording, `n`/`Esc` cancels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogsDelete {
    /// The entries.
    pub ids: Vec<ItemId>,
    /// The entry's host, for the question.
    pub label: String,
    /// It has a recording (the question offers keeping it).
    pub has_recording: bool,
}

/// "Clear entries older than N days" (`D`). Digits edit the days, `Tab` toggles deleting
/// their recordings, `Enter` clears, `Esc` cancels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogsClear {
    /// The days, as typed.
    pub days: String,
    /// Also delete the entries' recordings.
    pub delete_recordings: bool,
}

/// "Export the recording to…" (`e`). The path is edited; `Enter` exports, `Esc` cancels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogsExport {
    /// The recording file.
    pub src: PathBuf,
    /// Destination (relative paths are relative to sverb's working directory, `~/`
    /// is the home directory).
    pub path: String,
}

/// The replay player in a dialog. A shared handle: the player is not plain data (it
/// owns an emulator), so two handles compare equal only when they are the same player.
#[derive(Clone)]
pub struct ReplayHandle(Arc<Mutex<ReplayView>>);

impl ReplayHandle {
    /// Wrap a player.
    pub fn new(view: ReplayView) -> Self {
        Self(Arc::new(Mutex::new(view)))
    }

    /// The player.
    pub fn lock(&self) -> MutexGuard<'_, ReplayView> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl PartialEq for ReplayHandle {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for ReplayHandle {}

impl fmt::Debug for ReplayHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplayHandle").finish_non_exhaustive()
    }
}

/// The Logs dialogs (one `DialogKind::Logs` variant).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogsDialog {
    /// Full details of one entry (`i`).
    Detail(Box<LogEntry>),
    /// Delete confirmation.
    Delete(LogsDelete),
    /// Clear older than….
    Clear(LogsClear),
    /// Export destination.
    Export(LogsExport),
    /// The replay player.
    Replay(ReplayHandle),
}

/// The detail lines of an entry (detail pane and `i` dialog).
pub fn detail_lines(e: &LogEntry, cx: &RenderCx<'_>, offset: Option<i32>) -> Vec<Line<'static>> {
    let theme = cx.theme;
    let fmt = &cx.config.ui.date_format;
    let row = |k: &str, v: String| {
        Line::from(vec![
            Span::styled(format!("{k:<10}"), theme.dim),
            Span::raw(v),
        ])
    };
    let log = &e.log;
    let mut lines = vec![
        row("Host", e.host().to_owned()),
        row(
            "Target",
            log.target
                .clone()
                .unwrap_or_else(|| "local shell".to_owned()),
        ),
        row("Started", format_time(log.started_at, fmt, offset)),
        row(
            "Ended",
            log.ended_at.map_or_else(
                || "still connected".to_owned(),
                |t| format_time(t, fmt, offset),
            ),
        ),
        row(
            "Duration",
            log.duration()
                .map_or_else(|| "—".to_owned(), format_duration),
        ),
    ];
    let result = match &log.result {
        None => "connected…".to_owned(),
        Some(ConnResult::NetworkError(m)) => format!("network error: {m}"),
        Some(r) => r.label().to_owned(),
    };
    let style = if log.is_failure() {
        theme.error
    } else {
        theme.base
    };
    lines.push(Line::from(vec![
        Span::styled(format!("{:<10}", "Result"), theme.dim),
        Span::styled(result, style),
    ]));
    lines.push(row(
        "Bytes",
        format!(
            "{} in · {} out",
            format_bytes(log.bytes_in),
            format_bytes(log.bytes_out)
        ),
    ));
    lines.push(row(
        "Recording",
        e.recording
            .as_ref()
            .map_or_else(|| "none".to_owned(), |p| p.display().to_string()),
    ));
    if let Some(detail) = &log.error_detail {
        lines.push(Line::raw(""));
        lines.push(Line::styled("Error details", theme.accent));
        for (i, msg) in detail.iter().enumerate() {
            let text = if i == 0 {
                msg.clone()
            } else {
                format!("  caused by: {msg}")
            };
            lines.push(Line::styled(
                text,
                if i == 0 { theme.error } else { theme.base },
            ));
        }
    }
    lines
}

/// The detail pane next to the list.
pub fn render_detail_pane(
    entry: Option<&LogEntry>,
    offset: Option<i32>,
    frame: &mut Frame<'_>,
    area: Rect,
    cx: &RenderCx<'_>,
) {
    let block = Block::bordered()
        .title(Span::styled(" Details ", cx.theme.title_for(cx.focused)))
        .border_style(cx.theme.border_for(cx.focused));
    let lines = match entry {
        Some(e) => detail_lines(e, cx, offset),
        None => vec![Line::styled("Nothing selected.", cx.theme.dim)],
    };
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .style(cx.theme.base)
            .block(block),
        area,
    );
}

/// Draw a Logs dialog over `area` (the whole frame).
pub fn render_dialog(
    dialog: &LogsDialog,
    offset: Option<i32>,
    frame: &mut Frame<'_>,
    area: Rect,
    cx: &RenderCx<'_>,
) {
    let (title, lines): (&str, Vec<Line<'static>>) = match dialog {
        LogsDialog::Replay(handle) => {
            let rect = inset(area, 2, 1);
            frame.render_widget(Clear, rect);
            handle.lock().render(frame, rect, cx.theme, cx.focused);
            return;
        }
        LogsDialog::Detail(entry) => {
            let mut lines = detail_lines(entry, cx, offset);
            lines.push(Line::raw(""));
            lines.push(Line::styled("Esc / q close", cx.theme.dim));
            (" Connection log ", lines)
        }
        LogsDialog::Delete(d) => {
            let question = if d.ids.len() == 1 {
                format!("Delete the log entry for {}?", d.label)
            } else {
                format!("Delete {} log entries?", d.ids.len())
            };
            let keys = if d.has_recording {
                "y delete with its recording · k keep the recording · n / Esc cancel"
            } else {
                "y delete · n / Esc cancel"
            };
            (
                " Delete ",
                vec![Line::raw(question), Line::raw(""), Line::raw(keys)],
            )
        }
        LogsDialog::Clear(c) => (
            " Clear logs ",
            vec![
                Line::raw(format!("Delete entries older than {}▏ days", c.days)),
                Line::raw(format!(
                    "[{}] also delete their recordings (Tab)",
                    if c.delete_recordings { "x" } else { " " }
                )),
                Line::raw(""),
                Line::raw("Enter clear · Esc cancel"),
            ],
        ),
        LogsDialog::Export(x) => (
            " Export recording ",
            vec![
                Line::raw("Export as a plain asciicast file (not encrypted):"),
                Line::raw(format!("{}▏", x.path)),
                Line::raw(""),
                Line::raw("Enter export · Esc cancel"),
            ],
        ),
    };
    let width = lines
        .iter()
        .map(Line::width)
        .max()
        .unwrap_or(0)
        .max(title.len())
        .saturating_add(4);
    let height = lines.len().saturating_add(2);
    let rect = centered(area, width, height);
    frame.render_widget(Clear, rect);
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .style(cx.theme.base)
            .block(
                Block::bordered()
                    .title(Span::styled(title, cx.theme.title_for(cx.focused)))
                    .border_style(cx.theme.border_for(cx.focused)),
            ),
        rect,
    );
}

/// `area` shrunk by `dx` columns and `dy` rows on each side (never below 0×0).
fn inset(area: Rect, dx: u16, dy: u16) -> Rect {
    let dx = dx.min(area.width / 4);
    let dy = dy.min(area.height / 4);
    Rect {
        x: area.x + dx,
        y: area.y + dy,
        width: area.width - 2 * dx,
        height: area.height - 2 * dy,
    }
}

/// A `w`×`h` rect centered in `area` (clamped to it).
fn centered(area: Rect, w: usize, h: usize) -> Rect {
    let w = u16::try_from(w).unwrap_or(u16::MAX).min(area.width);
    let h = u16::try_from(h).unwrap_or(u16::MAX).min(area.height);
    Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    }
}
