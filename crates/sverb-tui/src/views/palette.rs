//! The command palette overlay (SPEC §8.3, §8.2, §14.1).
//!
//! `leader p` (every mode) and `ctrl-k` (Normal mode) open it. It is a centered box (60%
//! of the width, up to [`MAX_ROWS`] result rows) with an input line and results grouped
//! by source under headers. The reducer (`app/palette.rs`) computes the results (it
//! needs the keymap, the search index, the tabs) and carries out the answer; this module
//! owns the dialog state, its keys and its drawing.
//!
//! Keys: typing edits the input (the reducer re-ranks), `↑`/`↓` or `ctrl-p`/`ctrl-n`
//! move, `Enter` runs the selection, `ctrl-enter` connects a host in a split, `tab`
//! opens a host's secondary menu (connect, split, edit, copy the `ssh` command, run a
//! snippet on it), `Esc` closes (the menu first). The palette edits text, so the mode is
//! Insert and the leader still works.

use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph},
};
use sverb_core::model::ItemId;

use super::{RenderCx, Section, ViewCx, ViewEvent};
use crate::{app::SessionId, keymap::action::ActionName, widgets::truncate};

/// Result rows shown at most (headers included).
pub const MAX_ROWS: usize = 20;

/// Palette picks remembered for the recency boost (device-local `meta`).
pub const RECENTS_LEN: usize = 20;

/// The `meta` key holding the recent picks (JSON array of [`PaletteTarget::recent_key`]).
/// Device-local: `meta` is never synced and never part of an item.
pub const RECENTS_META_KEY: &str = "palette_recents";

/// Recents persistence for the palette service (`services/palette.rs`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PaletteEffect {
    /// Read the recent picks (answered with `PaletteEvent::Recents`).
    LoadRecents,
    /// Store the recent picks, most recent first (at most [`RECENTS_LEN`]).
    SaveRecents(Vec<String>),
}

/// Results of the palette service.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PaletteEvent {
    /// The stored recent picks, most recent first.
    Recents(Vec<String>),
}

/// Where a result comes from: its header, in this order when there is no query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PaletteGroup {
    /// Quick connect and share links (always on top).
    Special,
    /// Recent picks (shown with an empty query).
    Recent,
    /// Registry actions.
    Actions,
    /// Hosts.
    Hosts,
    /// Snippets.
    Snippets,
    /// Open tabs and panes.
    Tabs,
    /// Section views and settings pages.
    Settings,
}

impl PaletteGroup {
    /// The header text.
    pub fn title(self) -> &'static str {
        match self {
            Self::Special => "Go",
            Self::Recent => "Recent",
            Self::Actions => "Actions",
            Self::Hosts => "Hosts",
            Self::Snippets => "Snippets",
            Self::Tabs => "Tabs",
            Self::Settings => "Views & settings",
        }
    }
}

/// What a result does.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PaletteTarget {
    /// Run an action exactly as its key binding would.
    Action(ActionName),
    /// Connect to a saved host (new tab; `ctrl-enter` a split).
    Host(ItemId),
    /// Run a snippet in the current pane (the variable form if needed).
    Snippet(ItemId),
    /// Switch to the pane showing this session.
    Pane(SessionId),
    /// Open a section view.
    Section(Section),
    /// Quick connect to `user@host[:port]`.
    QuickConnect(String),
    /// Join a shared terminal from a pasted link.
    Join(String),
}

impl PaletteTarget {
    /// The key stored in the recents (`action:split_horizontal`, `host:<id>`, …);
    /// `None` for targets that are not remembered (panes, typed targets, links).
    pub fn recent_key(&self) -> Option<String> {
        match self {
            Self::Action(a) => Some(format!("action:{a}")),
            Self::Host(id) => Some(format!("host:{id}")),
            Self::Snippet(id) => Some(format!("snippet:{id}")),
            Self::Section(s) => Some(format!("section:{}", s.title().to_lowercase())),
            Self::Pane(_) | Self::QuickConnect(_) | Self::Join(_) => None,
        }
    }

    /// The inverse of [`PaletteTarget::recent_key`].
    pub fn from_recent_key(key: &str) -> Option<Self> {
        let (kind, rest) = key.split_once(':')?;
        match kind {
            "action" => rest.parse().ok().map(Self::Action),
            "host" => rest.parse().ok().map(Self::Host),
            "snippet" => rest.parse().ok().map(Self::Snippet),
            "section" => Section::ALL
                .into_iter()
                .find(|s| s.title().eq_ignore_ascii_case(rest))
                .map(Self::Section),
            _ => None,
        }
    }
}

/// One result row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaletteEntry {
    /// What it does.
    pub target: PaletteTarget,
    /// Its header.
    pub group: PaletteGroup,
    /// Main text.
    pub title: String,
    /// Secondary text (address, action name, …).
    pub detail: String,
    /// The key binding, from the effective keymap (actions only).
    pub hint: Option<String>,
    /// Ranking score (fuzzy score plus recency boost; 0 without a query).
    pub score: u32,
}

/// The entries of a host's secondary menu (`tab`), in display order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostAction {
    /// Connect in a new tab.
    Connect,
    /// Connect in a split of the current tab.
    ConnectSplit,
    /// Open the host form.
    Edit,
    /// Copy the `ssh` command.
    CopyCommand,
    /// Pick a snippet to run on this host.
    RunSnippet,
}

impl HostAction {
    /// Every entry, in menu order.
    pub const ALL: [Self; 5] = [
        Self::Connect,
        Self::ConnectSplit,
        Self::Edit,
        Self::CopyCommand,
        Self::RunSnippet,
    ];

    /// Menu text.
    pub fn label(self) -> &'static str {
        match self {
            Self::Connect => "Connect in a new tab",
            Self::ConnectSplit => "Connect in a split",
            Self::Edit => "Edit host",
            Self::CopyCommand => "Copy ssh command",
            Self::RunSnippet => "Run snippet on it…",
        }
    }
}

/// A host's secondary menu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostMenu {
    /// The host.
    pub host: ItemId,
    /// Its label.
    pub label: String,
    /// Highlighted entry (into [`HostAction::ALL`]).
    pub selected: usize,
}

/// What the user chose; the reducer takes it after the key (`App::take_palette_answer`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaletteAnswer {
    /// `Enter` (`split`: `ctrl-enter`) on a result.
    Run {
        /// The result.
        target: PaletteTarget,
        /// Open a host in a split instead of a new tab.
        split: bool,
    },
    /// A host's secondary-menu entry.
    Host {
        /// The host.
        host: ItemId,
        /// Its label.
        label: String,
        /// The entry.
        action: HostAction,
    },
}

/// The palette dialog.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PaletteState {
    /// The input line.
    pub input: String,
    /// Results in display order (grouped; headers are drawn between groups).
    pub entries: Vec<PaletteEntry>,
    /// Highlighted result (into `entries`).
    pub selected: usize,
    /// A host's secondary menu.
    pub menu: Option<HostMenu>,
    /// "Run snippet on `<host>`": only snippets are listed and run on this host.
    pub on_host: Option<(ItemId, String)>,
    /// The input changed: the reducer recomputes `entries`.
    pub stale: bool,
    /// The user's choice.
    pub answer: Option<PaletteAnswer>,
}

impl PaletteState {
    /// An empty palette (the reducer fills `entries`).
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the results, keeping the highlight in range.
    pub fn set_entries(&mut self, entries: Vec<PaletteEntry>) {
        self.entries = entries;
        self.selected = self.selected.min(self.entries.len().saturating_sub(1));
        self.stale = false;
    }

    /// The highlighted result.
    pub fn current(&self) -> Option<&PaletteEntry> {
        self.entries.get(self.selected)
    }

    /// The user's choice, once.
    pub fn take_answer(&mut self) -> Option<PaletteAnswer> {
        self.answer.take()
    }

    fn edited(&mut self) {
        self.stale = true;
        self.selected = 0;
    }

    fn step(&mut self, down: bool) {
        let last = self.entries.len().saturating_sub(1);
        self.selected = if down {
            (self.selected + 1).min(last)
        } else {
            self.selected.saturating_sub(1)
        };
    }

    /// Keys and pastes. Typing marks the results stale; `Enter`/the menu set the answer.
    pub fn handle(&mut self, ev: &ViewEvent, cx: &mut ViewCx<'_>) {
        cx.request_redraw();
        match ev {
            ViewEvent::Paste(text) => {
                if self.menu.is_none() {
                    // A pasted link or target: one line, no surrounding whitespace.
                    let line = text.replace(['\r', '\n'], " ");
                    self.input.push_str(line.trim());
                    self.edited();
                }
            }
            ViewEvent::Key(key) => {
                let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
                let alt = key.modifiers.contains(KeyModifiers::ALT);
                if let Some(menu) = &mut self.menu {
                    let last = HostAction::ALL.len() - 1;
                    match key.code {
                        KeyCode::Esc | KeyCode::Tab | KeyCode::BackTab => self.menu = None,
                        KeyCode::Down => menu.selected = (menu.selected + 1).min(last),
                        KeyCode::Char('n') if ctrl => {
                            menu.selected = (menu.selected + 1).min(last);
                        }
                        KeyCode::Up => menu.selected = menu.selected.saturating_sub(1),
                        KeyCode::Char('p') if ctrl => {
                            menu.selected = menu.selected.saturating_sub(1);
                        }
                        KeyCode::Enter => {
                            let action = HostAction::ALL[menu.selected.min(last)];
                            self.answer = Some(PaletteAnswer::Host {
                                host: menu.host,
                                label: menu.label.clone(),
                                action,
                            });
                            self.menu = None;
                        }
                        _ => {}
                    }
                    return;
                }
                match key.code {
                    KeyCode::Esc => cx.close(),
                    KeyCode::Down => self.step(true),
                    KeyCode::Up => self.step(false),
                    KeyCode::Char('n') if ctrl => self.step(true),
                    KeyCode::Char('p') if ctrl => self.step(false),
                    KeyCode::PageDown => {
                        for _ in 0..MAX_ROWS / 2 {
                            self.step(true);
                        }
                    }
                    KeyCode::PageUp => {
                        for _ in 0..MAX_ROWS / 2 {
                            self.step(false);
                        }
                    }
                    KeyCode::Enter => {
                        if let Some(entry) = self.current() {
                            self.answer = Some(PaletteAnswer::Run {
                                target: entry.target.clone(),
                                split: ctrl,
                            });
                        }
                    }
                    KeyCode::Tab => {
                        if let Some(PaletteEntry {
                            target: PaletteTarget::Host(host),
                            title,
                            ..
                        }) = self.current()
                        {
                            self.menu = Some(HostMenu {
                                host: *host,
                                label: title.clone(),
                                selected: 0,
                            });
                        }
                    }
                    KeyCode::Backspace => {
                        if self.input.pop().is_none() && self.on_host.is_some() {
                            // Backspace on an empty "run on host" palette: back to all.
                            self.on_host = None;
                        }
                        self.edited();
                    }
                    KeyCode::Char('u') if ctrl => {
                        self.input.clear();
                        self.edited();
                    }
                    KeyCode::Char(c) if !ctrl && !alt => {
                        self.input.push(c);
                        self.edited();
                    }
                    _ => {}
                }
            }
            ViewEvent::Mouse(_) => {}
        }
    }

    /// Draw the overlay. Never panics, whatever the area.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let theme = cx.theme;
        let rows = self.rows();
        let Some(rect) = palette_rect(area, rows.len().max(1)) else {
            return;
        };
        frame.render_widget(Clear, rect);
        let title = match &self.on_host {
            Some((_, label)) => format!(" Run snippet on {} ", truncate(label, 30)),
            None => " Command palette ".to_owned(),
        };
        let block = Block::bordered()
            .title(Span::styled(title, theme.title_for(true)))
            .border_style(theme.border_for(true));
        let inner = block.inner(rect);
        frame.render_widget(block, rect);
        if inner.width == 0 || inner.height == 0 {
            return;
        }
        let width = usize::from(inner.width);
        let mut lines = vec![Line::from(vec![
            Span::styled("› ", theme.accent),
            Span::styled(format!("{}▏", self.input), theme.base),
        ])];
        let room = usize::from(inner.height).saturating_sub(2).min(MAX_ROWS);
        if self.entries.is_empty() {
            lines.push(Line::styled(
                if self.input.trim().is_empty() {
                    "type to search actions, hosts, snippets, tabs"
                } else {
                    "no matches"
                },
                theme.dim,
            ));
        }
        let at = rows
            .iter()
            .position(|r| *r == Row::Entry(self.selected))
            .unwrap_or(0);
        let skip = (at + 1).saturating_sub(room);
        for row in rows.iter().skip(skip).take(room) {
            match *row {
                Row::Header(group) => {
                    lines.push(Line::styled(group.title().to_owned(), theme.accent));
                }
                Row::Entry(i) => {
                    let entry = &self.entries[i];
                    let style = if i == self.selected {
                        theme.selection
                    } else {
                        theme.base
                    };
                    lines.push(entry_line(
                        entry,
                        width,
                        i == self.selected,
                        style,
                        theme.dim,
                    ));
                }
            }
        }
        while lines.len() < usize::from(inner.height).saturating_sub(1) {
            lines.push(Line::raw(""));
        }
        let help = if self
            .current()
            .is_some_and(|e| matches!(e.target, PaletteTarget::Host(_)))
        {
            "↑↓ move · enter connect · ctrl-enter split · tab more · esc close"
        } else {
            "↑↓ move · enter run · > actions @ hosts ! snippets #tag · esc close"
        };
        lines.truncate(usize::from(inner.height).saturating_sub(1));
        lines.push(Line::styled(truncate(help, width), theme.dim));
        frame.render_widget(Paragraph::new(lines).style(theme.base), inner);
        if let Some(menu) = &self.menu {
            render_menu(menu, frame, rect, cx);
        }
    }

    /// Headers and entries in display order.
    fn rows(&self) -> Vec<Row> {
        let mut rows = Vec::with_capacity(self.entries.len() + 6);
        let mut last = None;
        for (i, e) in self.entries.iter().enumerate() {
            if last != Some(e.group) {
                rows.push(Row::Header(e.group));
                last = Some(e.group);
            }
            rows.push(Row::Entry(i));
        }
        rows
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Row {
    Header(PaletteGroup),
    Entry(usize),
}

/// 60% of the width (at least 40 columns when there is room), `rows` result rows (at
/// most [`MAX_ROWS`]) plus the input, help and borders; a quarter of the way down.
fn palette_rect(area: Rect, rows: usize) -> Option<Rect> {
    let w = (u32::from(area.width) * 60 / 100) as u16;
    let w = w.max(40.min(area.width.saturating_sub(2))).min(area.width);
    let wanted = u16::try_from(rows.min(MAX_ROWS) + 4).unwrap_or(u16::MAX);
    let h = wanted.max(8).min(area.height);
    if w < 12 || h < 5 {
        return None;
    }
    let x = area.x + (area.width - w) / 2;
    let y = area.y + (area.height - h) / 4;
    Some(Rect::new(x, y, w, h))
}

fn entry_line(
    entry: &PaletteEntry,
    width: usize,
    selected: bool,
    style: Style,
    dim: Style,
) -> Line<'static> {
    let hint = entry.hint.clone().unwrap_or_default();
    let hint_w = hint.chars().count();
    let avail = width.saturating_sub(2 + hint_w + usize::from(hint_w > 0));
    let title = truncate(&entry.title, avail);
    let title_w = title.chars().count();
    let detail_room = avail.saturating_sub(title_w + 2);
    let detail = if entry.detail.is_empty() || detail_room < 4 {
        String::new()
    } else {
        format!("  {}", truncate(&entry.detail, detail_room))
    };
    let used = 2 + title_w + detail.chars().count();
    let pad = width.saturating_sub(used + hint_w);
    // The selected row keeps one style across its width; others dim the extras.
    let extra = if selected { style } else { dim };
    Line::from(vec![
        Span::styled(format!("  {title}"), style),
        Span::styled(detail, extra),
        Span::styled(" ".repeat(pad), style),
        Span::styled(hint, extra),
    ])
}

fn render_menu(menu: &HostMenu, frame: &mut Frame<'_>, over: Rect, cx: &RenderCx<'_>) {
    let theme = cx.theme;
    let w = 30.min(over.width.saturating_sub(4));
    let h = u16::try_from(HostAction::ALL.len() + 2)
        .unwrap_or(7)
        .min(over.height.saturating_sub(2));
    if w < 10 || h < 3 {
        return;
    }
    let rect = Rect::new(over.x + over.width - w - 2, over.y + 2, w, h);
    frame.render_widget(Clear, rect);
    let lines: Vec<Line<'_>> = HostAction::ALL
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let style = if i == menu.selected {
                theme.selection
            } else {
                theme.base
            };
            Line::styled(format!(" {}", a.label()), style)
        })
        .collect();
    let block = Block::bordered()
        .title(Span::styled(
            format!(
                " {} ",
                truncate(&menu.label, usize::from(w).saturating_sub(4))
            ),
            theme.title_for(true),
        ))
        .border_style(theme.border_for(true));
    frame.render_widget(Paragraph::new(lines).style(theme.base).block(block), rect);
}

/// `sverb://join/…` or `https://<server>/s/<id>#<key>`: a share link.
pub fn share_link(input: &str) -> Option<&str> {
    let s = input.trim();
    if s.contains(char::is_whitespace) {
        return None;
    }
    if s.strip_prefix("sverb://join/")
        .is_some_and(|rest| !rest.is_empty())
    {
        return Some(s);
    }
    let rest = s.strip_prefix("https://")?;
    let (host, path) = rest.split_once('/')?;
    let (id, key) = path.strip_prefix("s/")?.split_once('#')?;
    (!host.is_empty() && !id.is_empty() && !id.contains('/') && !key.is_empty()).then_some(s)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn recent_keys_round_trip() {
        let id = ItemId::from_bytes([7; 16]);
        for t in [
            PaletteTarget::Action(ActionName::SplitHorizontal),
            PaletteTarget::Host(id),
            PaletteTarget::Snippet(id),
            PaletteTarget::Section(Section::Known),
        ] {
            let key = t.recent_key().unwrap();
            assert_eq!(PaletteTarget::from_recent_key(&key), Some(t));
        }
        assert_eq!(PaletteTarget::Pane(SessionId(1)).recent_key(), None);
        assert_eq!(PaletteTarget::from_recent_key("action:nope"), None);
        assert_eq!(PaletteTarget::from_recent_key("garbage"), None);
    }

    #[test]
    fn share_links_are_recognized() {
        assert!(share_link("sverb://join/abc123#k").is_some());
        assert!(share_link("https://share.example.com/s/abc#key").is_some());
        assert!(share_link("https://share.example.com/s/abc").is_none());
        assert!(share_link("https://share.example.com/x/abc#k").is_none());
        assert!(share_link("sverb://join/").is_none());
        assert!(share_link("root@10.0.0.9").is_none());
    }

    #[test]
    fn palette_rect_degrades_without_panicking() {
        for (w, h) in [(0, 0), (1, 1), (10, 4), (12, 5), (80, 24), (160, 48)] {
            let r = palette_rect(Rect::new(0, 0, w, h), 30);
            if let Some(r) = r {
                assert!(r.width <= w && r.height <= h);
            }
        }
        let r = palette_rect(Rect::new(0, 0, 100, 40), 50).unwrap();
        assert_eq!(r.width, 60);
        assert_eq!(r.height, 24);
        let r = palette_rect(Rect::new(0, 0, 100, 40), 6).unwrap();
        assert_eq!(r.height, 10);
    }
}
