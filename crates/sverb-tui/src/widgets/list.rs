//! M1-06: the shared list component (SPEC §8.5), used by Hosts, Keychain, Forwards,
//! Snippets, Known Hosts and Logs.
//!
//! [`ListView<R>`] is plain state over the view's rows (`R: ListRow`), with a [`View`]
//! impl so reducer tests drive it with keys. The owning view handles its own action
//! keys (`Enter`, `a`, `e`, `d`, …) after the list returns [`Outcome::Ignored`], and
//! asks [`ListView::targets`] what a bulk action applies to (the marks, else the
//! cursor row).
//!
//! - **Data:** `set_rows` with the rows of an `IndexSnapshot` query (M1-05), in view
//!   order. A [`RowRenderer`] draws the columns, a [`DetailRenderer`] the detail pane.
//! - **Virtualized:** only the visible rows are drawn; the selection stays in view
//!   with a scrolloff of 2.
//! - **Filter:** `/` opens a filter line (Insert mode) with live results and match
//!   highlights; `Esc` clears and closes it (the selection stays on the same item if
//!   it is still listed), `Enter` keeps it and returns to the list. Matching uses the
//!   index's query (`FilterSource::Index`) or the same fuzzy matcher locally.
//! - **Multi-select:** `Space` toggles a mark (and moves down), `V`/`ctrl-a` mark every
//!   visible row, `Esc` clears the marks. The title shows `3 selected`.
//! - **Sort:** `s` cycles the view's sort keys, `S` reverses.
//! - **Tree:** optional; groups collapse/expand with `h`/`l`/`←`/`→`. The collapsed set
//!   lives in this state for the session (never synced).
//! - **Detail pane:** right of the list (55/45) at ≥ 100 columns; narrower, `i` toggles
//!   a full-screen detail.
//! - **Navigation:** `j/k`, arrows, `g/G`, `Home/End`, `ctrl-d/ctrl-u`, `PageUp/PageDown`,
//!   mouse wheel and click.
//!
//! No information is carried by color alone: the cursor row is drawn with the
//! selection style (reverse + bold without color) and a `›`, marks with `*`, matches
//! bold + underlined.

use std::{
    cell::Cell,
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt,
    sync::Arc,
};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEventKind};
use nucleo_matcher::{
    Config as MatcherConfig, Matcher, Utf32Str,
    pattern::{CaseMatching, Normalization, Pattern},
};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Block, Paragraph, Wrap},
};
use sverb_core::{
    model::ItemId,
    search::{IndexSnapshot, Query, Scope},
};

use crate::{
    theme::Theme,
    views::{Outcome, RenderCx, View, ViewCx, ViewEvent},
    widgets::{
        form::{TextEdit, TextInput, highlighted, match_style},
        truncate, width,
    },
};

/// Rows kept between the cursor and the top/bottom edge while scrolling.
pub const SCROLLOFF: usize = 2;
/// Width from which the detail pane is shown beside the list.
pub const DETAIL_MIN_WIDTH: u16 = 100;
/// Rows moved per mouse wheel step.
const WHEEL_STEP: isize = 3;

/// A row of a [`ListView`].
pub trait ListRow: Clone + fmt::Debug + PartialEq + Eq {
    /// Stable identity (marks, the cursor and the collapsed set survive refreshes).
    type Key: Clone + fmt::Debug + Ord;

    /// The row's key.
    fn key(&self) -> Self::Key;

    /// Primary text; match highlights index its chars.
    fn label(&self) -> &str;

    /// What the local filter matches (default: the label).
    fn filter_text(&self) -> String {
        self.label().to_owned()
    }

    /// The indexed item, for `FilterSource::Index` (rows without one match locally).
    fn item_id(&self) -> Option<ItemId> {
        None
    }

    /// Tree mode: the parent row's key.
    fn parent(&self) -> Option<Self::Key> {
        None
    }

    /// Tree mode: a group node (collapsible, not markable).
    fn is_group(&self) -> bool {
        false
    }

    /// Secondary text for the default renderer (dimmed after the label).
    fn secondary(&self) -> String {
        String::new()
    }
}

/// What a [`RowRenderer`] gets for one row.
#[derive(Debug, Clone, Copy)]
pub struct RowCx<'a> {
    /// Matched char indices into [`ListRow::label`].
    pub highlights: &'a [u32],
    /// Cells available for the row's content.
    pub width: usize,
    /// The cursor is on this row.
    pub selected: bool,
    /// The row is marked.
    pub marked: bool,
    /// The style to build on (the selection style on the cursor row).
    pub base: Style,
    /// The theme.
    pub theme: &'a Theme,
}

/// Draws a row's columns (icons, label, secondary text, chips).
pub trait RowRenderer<R> {
    /// The row's spans (after the cursor/mark/indent prefix).
    fn spans(&self, row: &R, cx: &RowCx<'_>) -> Vec<Span<'static>>;
}

/// Draws the selected item's details.
pub trait DetailRenderer<R> {
    /// The detail lines for `row` (wrapped to `width` by the pane).
    fn lines(&self, row: &R, theme: &Theme, width: usize) -> Vec<Line<'static>>;
}

/// The default row renderer: the highlighted label, then [`ListRow::secondary`] dimmed.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultRenderer;

impl<R: ListRow> RowRenderer<R> for DefaultRenderer {
    fn spans(&self, row: &R, cx: &RowCx<'_>) -> Vec<Span<'static>> {
        let label = truncate(row.label(), cx.width);
        let mut spans = highlighted(
            &label,
            cx.highlights,
            cx.base,
            match_style(cx.base, cx.theme),
        );
        let secondary = row.secondary();
        let used = width(&label);
        if !secondary.is_empty() && used + 3 < cx.width {
            let dim = if cx.selected { cx.base } else { cx.theme.dim };
            spans.push(Span::styled(
                format!("  {}", truncate(&secondary, cx.width - used - 2)),
                dim,
            ));
        }
        spans
    }
}

/// A sort order a view offers (`s` cycles, `S` reverses).
pub struct SortKey<R> {
    /// Shown in the title (`name`, `last connected`, `address`).
    pub name: &'static str,
    /// The order.
    pub cmp: fn(&R, &R) -> Ordering,
}

impl<R> SortKey<R> {
    /// A sort key.
    pub const fn new(name: &'static str, cmp: fn(&R, &R) -> Ordering) -> Self {
        Self { name, cmp }
    }
}

impl<R> Clone for SortKey<R> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<R> Copy for SortKey<R> {}

impl<R> PartialEq for SortKey<R> {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl<R> Eq for SortKey<R> {}

impl<R> fmt::Debug for SortKey<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SortKey({})", self.name)
    }
}

/// Where filter matches come from.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum FilterSource {
    /// Fuzzy-match [`ListRow::filter_text`] here (same matcher as the index).
    #[default]
    Local,
    /// Run the query language (`#tag`, `@vault`, …) on the search index (M1-05).
    Index {
        /// The current snapshot.
        snapshot: Arc<IndexSnapshot>,
        /// What to search.
        scope: Scope,
    },
}

/// What an empty list shows.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EmptyState {
    /// The message (`No hosts yet`).
    pub message: String,
    /// Key hints (`("a", "add a host")`).
    pub hints: Vec<(String, String)>,
}

impl EmptyState {
    /// An empty state.
    pub fn new(message: &str, hints: &[(&str, &str)]) -> Self {
        Self {
            message: message.to_owned(),
            hints: hints
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        }
    }
}

/// One listed row.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Visible {
    /// Index into `rows`.
    idx: usize,
    /// Tree depth.
    depth: u16,
    /// Matched char indices into the label.
    highlights: Vec<u32>,
    /// Tree mode: the row has children.
    has_children: bool,
}

/// The shared list component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListView<R: ListRow> {
    title: String,
    rows: Vec<R>,
    visible: Vec<Visible>,
    cursor: usize,
    filter: TextInput,
    /// The filter line is shown.
    filter_open: bool,
    /// Keys edit the filter (Insert mode).
    filter_editing: bool,
    source: FilterSource,
    marks: BTreeSet<R::Key>,
    sort_keys: Vec<SortKey<R>>,
    sort: usize,
    reversed: bool,
    tree: bool,
    collapsed: BTreeSet<R::Key>,
    detail_full: bool,
    empty: EmptyState,
    /// First listed row on screen (kept between frames).
    offset: Cell<usize>,
    /// Rows that fit at the last render (half-page moves use it).
    viewport: Cell<usize>,
    /// Where the rows were drawn (mouse clicks).
    rows_area: Cell<Rect>,
}

impl<R: ListRow> ListView<R> {
    /// An empty list titled `title`.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            rows: Vec::new(),
            visible: Vec::new(),
            cursor: 0,
            filter: TextInput::default(),
            filter_open: false,
            filter_editing: false,
            source: FilterSource::Local,
            marks: BTreeSet::new(),
            sort_keys: Vec::new(),
            sort: 0,
            reversed: false,
            tree: false,
            collapsed: BTreeSet::new(),
            detail_full: false,
            empty: EmptyState::default(),
            offset: Cell::new(0),
            viewport: Cell::new(10),
            rows_area: Cell::new(Rect::default()),
        }
    }

    /// Offer these sort keys (the first is the initial order).
    #[must_use]
    pub fn with_sort_keys(mut self, keys: Vec<SortKey<R>>) -> Self {
        self.sort_keys = keys;
        self.rebuild();
        self
    }

    /// Tree mode (groups with [`ListRow::parent`]).
    #[must_use]
    pub fn with_tree(mut self, tree: bool) -> Self {
        self.tree = tree;
        self.rebuild();
        self
    }

    /// The empty state.
    #[must_use]
    pub fn with_empty(mut self, empty: EmptyState) -> Self {
        self.empty = empty;
        self
    }

    /// Replace the rows (view order). The cursor stays on the same key when it is
    /// still listed; marks of vanished rows are dropped.
    pub fn set_rows(&mut self, rows: Vec<R>) {
        let keys: BTreeSet<R::Key> = rows.iter().map(ListRow::key).collect();
        self.marks.retain(|k| keys.contains(k));
        // M1-07: take the cursor's key before the old indices go stale.
        let keep = self.selected_key();
        self.rows = rows;
        self.rebuild_keeping(keep);
    }

    /// Change the filter source (e.g. a new index snapshot).
    pub fn set_source(&mut self, source: FilterSource) {
        self.source = source;
        self.rebuild();
    }

    /// All rows.
    pub fn rows(&self) -> &[R] {
        &self.rows
    }

    /// The listed rows, in display order.
    pub fn visible_rows(&self) -> impl Iterator<Item = &R> {
        self.visible.iter().map(|v| &self.rows[v.idx])
    }

    /// Number of listed rows.
    pub fn visible_len(&self) -> usize {
        self.visible.len()
    }

    /// Match highlights of the listed row at `i`.
    pub fn highlights(&self, i: usize) -> &[u32] {
        self.visible.get(i).map_or(&[], |v| &v.highlights)
    }

    /// The cursor position among the listed rows.
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// The row under the cursor.
    pub fn selected(&self) -> Option<&R> {
        self.visible.get(self.cursor).map(|v| &self.rows[v.idx])
    }

    /// Its key.
    pub fn selected_key(&self) -> Option<R::Key> {
        self.selected().map(ListRow::key)
    }

    /// Put the cursor on `key` if it is listed.
    pub fn select_key(&mut self, key: &R::Key) -> bool {
        match self
            .visible
            .iter()
            .position(|v| self.rows[v.idx].key() == *key)
        {
            Some(i) => {
                self.cursor = i;
                true
            }
            None => false,
        }
    }

    /// The marked keys.
    pub fn marks(&self) -> &BTreeSet<R::Key> {
        &self.marks
    }

    /// What a bulk action applies to: the marks (in display order, then any marked
    /// rows hidden by the filter) or else the cursor row.
    pub fn targets(&self) -> Vec<R::Key> {
        if self.marks.is_empty() {
            return self.selected_key().into_iter().collect();
        }
        let mut out: Vec<R::Key> = self
            .visible_rows()
            .map(ListRow::key)
            .filter(|k| self.marks.contains(k))
            .collect();
        for k in &self.marks {
            if !out.contains(k) {
                out.push(k.clone());
            }
        }
        out
    }

    /// Clear the marks (after a bulk action).
    pub fn clear_marks(&mut self) {
        self.marks.clear();
    }

    /// The filter text.
    pub fn filter_text(&self) -> &str {
        self.filter.text()
    }

    /// The filter line has the keys (Insert mode, M0-10).
    pub fn insert_mode(&self) -> bool {
        self.filter_editing
    }

    /// The current sort key's name and whether it is reversed.
    pub fn sort(&self) -> Option<(&'static str, bool)> {
        self.sort_keys
            .get(self.sort)
            .map(|k| (k.name, self.reversed))
    }

    /// Collapsed groups (to persist for the session).
    pub fn collapsed(&self) -> &BTreeSet<R::Key> {
        &self.collapsed
    }

    /// Restore collapsed groups.
    pub fn set_collapsed(&mut self, collapsed: BTreeSet<R::Key>) {
        self.collapsed = collapsed;
        self.rebuild();
    }

    /// The full-screen detail is open.
    pub fn detail_full(&self) -> bool {
        self.detail_full
    }

    /// The title text (`Hosts · 3 selected`).
    pub fn title_text(&self) -> String {
        let mut t = self.title.clone();
        if !self.marks.is_empty() {
            t.push_str(&format!(" · {} selected", self.marks.len()));
        }
        t
    }

    // ------------------------------------------------------------ rebuild

    /// The order of `rows` (indices) under the current sort.
    fn sorted(&self) -> Vec<usize> {
        let mut order: Vec<usize> = (0..self.rows.len()).collect();
        if let Some(key) = self.sort_keys.get(self.sort) {
            let rows = &self.rows;
            order.sort_by(|a, b| {
                let o = (key.cmp)(&rows[*a], &rows[*b]);
                if self.reversed { o.reverse() } else { o }
            });
        } else if self.reversed {
            order.reverse();
        }
        order
    }

    /// Matches for the current filter: row index → highlights.
    fn matches(&self) -> HashMap<usize, Vec<u32>> {
        let q = self.filter.text();
        let mut out = HashMap::new();
        let mut matcher = Matcher::new(MatcherConfig::DEFAULT);
        let pattern = Pattern::parse(q, CaseMatching::Smart, Normalization::Smart);
        let local = |row: &R, matcher: &mut Matcher| -> Option<Vec<u32>> {
            let mut buf = Vec::new();
            pattern.score(Utf32Str::new(&row.filter_text(), &mut buf), matcher)?;
            let mut idx = Vec::new();
            let mut buf = Vec::new();
            pattern.indices(Utf32Str::new(row.label(), &mut buf), matcher, &mut idx);
            idx.sort_unstable();
            idx.dedup();
            Some(idx)
        };
        let hits: Option<BTreeMap<ItemId, Vec<u32>>> = match &self.source {
            FilterSource::Local => None,
            FilterSource::Index { snapshot, scope } => Some(
                snapshot
                    .query(&Query::parse(q), *scope)
                    .into_iter()
                    .map(|h| (h.item_id, h.highlights))
                    .collect(),
            ),
        };
        for (i, row) in self.rows.iter().enumerate() {
            let m = match (&hits, row.item_id()) {
                (Some(hits), Some(id)) => hits.get(&id).cloned(),
                _ => local(row, &mut matcher),
            };
            if let Some(h) = m {
                out.insert(i, h);
            }
        }
        out
    }

    /// Recompute the listed rows; keep the cursor on the same key if possible.
    fn rebuild(&mut self) {
        let keep = self.selected_key();
        self.rebuild_keeping(keep);
    }

    /// [`Self::rebuild`] with the key to keep the cursor on (M1-07).
    fn rebuild_keeping(&mut self, keep: Option<R::Key>) {
        let order = self.sorted();
        self.visible = if !self.filter.is_empty() {
            let mut m = self.matches();
            order
                .into_iter()
                .filter_map(|idx| {
                    m.remove(&idx).map(|highlights| Visible {
                        idx,
                        depth: 0,
                        highlights,
                        has_children: false,
                    })
                })
                .collect()
        } else if self.tree {
            self.tree_rows(&order)
        } else {
            order
                .into_iter()
                .map(|idx| Visible {
                    idx,
                    depth: 0,
                    highlights: Vec::new(),
                    has_children: false,
                })
                .collect()
        };
        let found = keep.is_some_and(|k| self.select_key(&k));
        if !found {
            self.cursor = self.cursor.min(self.visible.len().saturating_sub(1));
        }
    }

    fn tree_rows(&self, order: &[usize]) -> Vec<Visible> {
        let present: BTreeMap<R::Key, usize> = self
            .rows
            .iter()
            .enumerate()
            .map(|(i, r)| (r.key(), i))
            .collect();
        let mut children: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        let mut roots = Vec::new();
        for &i in order {
            match self.rows[i].parent().and_then(|p| present.get(&p).copied()) {
                Some(p) if p != i => children.entry(p).or_default().push(i),
                _ => roots.push(i),
            }
        }
        let mut out = Vec::new();
        // Iterative DFS; `seen` guards against parent cycles in bad data.
        let mut seen = vec![false; self.rows.len()];
        let mut stack: Vec<(usize, u16)> = roots.into_iter().rev().map(|i| (i, 0)).collect();
        while let Some((i, depth)) = stack.pop() {
            if std::mem::replace(&mut seen[i], true) {
                continue;
            }
            let kids = children.get(&i);
            out.push(Visible {
                idx: i,
                depth,
                highlights: Vec::new(),
                has_children: kids.is_some_and(|k| !k.is_empty()),
            });
            if let Some(kids) = kids
                && !self.collapsed.contains(&self.rows[i].key())
            {
                stack.extend(kids.iter().rev().map(|&k| (k, depth.saturating_add(1))));
            }
        }
        out
    }

    // ------------------------------------------------------------ input

    fn move_to(&mut self, i: usize) {
        self.cursor = i.min(self.visible.len().saturating_sub(1));
    }

    fn move_by(&mut self, delta: isize) {
        let i = self.cursor.saturating_add_signed(delta);
        self.move_to(i);
    }

    fn close_filter(&mut self) {
        self.filter.clear();
        self.filter_open = false;
        self.filter_editing = false;
        self.rebuild();
    }

    fn toggle_group(&mut self, expand: bool) -> bool {
        let Some(v) = self.visible.get(self.cursor) else {
            return false;
        };
        let row = &self.rows[v.idx];
        let key = row.key();
        if expand {
            if v.has_children && self.collapsed.remove(&key) {
                self.rebuild();
            }
            return true;
        }
        if v.has_children && !self.collapsed.contains(&key) {
            self.collapsed.insert(key);
            self.rebuild();
        } else if let Some(parent) = row.parent() {
            self.select_key(&parent);
        }
        true
    }

    fn on_filter_key(&mut self, key: &KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Esc => self.close_filter(),
            KeyCode::Enter => {
                self.filter_editing = false;
                if self.filter.is_empty() {
                    self.filter_open = false;
                }
            }
            KeyCode::Down => self.move_by(1),
            KeyCode::Up => self.move_by(-1),
            KeyCode::Char('n') if ctrl => self.move_by(1),
            KeyCode::Char('p') if ctrl => self.move_by(-1),
            _ => {
                if self.filter.handle_key(key) == TextEdit::Changed {
                    self.rebuild();
                }
            }
        }
    }

    /// Apply one key in the list (not the filter line).
    fn on_key(&mut self, key: &KeyEvent) -> bool {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if key.modifiers.contains(KeyModifiers::ALT) {
            return false;
        }
        let half = isize::try_from((self.viewport.get() / 2).max(1)).unwrap_or(1);
        let page = isize::try_from(self.viewport.get().max(1)).unwrap_or(1);
        if self.detail_full && matches!(key.code, KeyCode::Esc | KeyCode::Char('i')) && !ctrl {
            self.detail_full = false;
            return true;
        }
        match key.code {
            KeyCode::Char('d') if ctrl => self.move_by(half),
            KeyCode::Char('u') if ctrl => self.move_by(-half),
            KeyCode::Char('a') if ctrl => self.mark_all(),
            _ if ctrl => return false,
            KeyCode::Char('j') | KeyCode::Down => self.move_by(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_by(-1),
            KeyCode::Char('g') | KeyCode::Home => self.move_to(0),
            KeyCode::Char('G') | KeyCode::End => self.move_to(usize::MAX),
            KeyCode::PageDown => self.move_by(page),
            KeyCode::PageUp => self.move_by(-page),
            KeyCode::Char('/') => {
                self.filter_open = true;
                self.filter_editing = true;
            }
            KeyCode::Char(' ') => {
                if let Some(row) = self.selected()
                    && !row.is_group()
                {
                    let k = row.key();
                    if !self.marks.remove(&k) {
                        self.marks.insert(k);
                    }
                }
                self.move_by(1);
            }
            KeyCode::Char('V') => self.mark_all(),
            KeyCode::Char('s') if !self.sort_keys.is_empty() => {
                self.sort = (self.sort + 1) % self.sort_keys.len();
                self.reversed = false;
                self.rebuild();
            }
            KeyCode::Char('S') => {
                self.reversed = !self.reversed;
                self.rebuild();
            }
            KeyCode::Char('h') | KeyCode::Left if self.tree => return self.toggle_group(false),
            KeyCode::Char('l') | KeyCode::Right if self.tree => return self.toggle_group(true),
            KeyCode::Char('i') => self.detail_full = !self.detail_full,
            KeyCode::Esc if !self.marks.is_empty() => self.marks.clear(),
            KeyCode::Esc if self.filter_open => self.close_filter(),
            _ => return false,
        }
        true
    }

    fn mark_all(&mut self) {
        let keys: Vec<R::Key> = self
            .visible_rows()
            .filter(|r| !r.is_group())
            .map(ListRow::key)
            .collect();
        self.marks.extend(keys);
    }

    fn on_mouse(&mut self, ev: &crossterm::event::MouseEvent) -> bool {
        match ev.kind {
            MouseEventKind::ScrollDown => self.move_by(WHEEL_STEP),
            MouseEventKind::ScrollUp => self.move_by(-WHEEL_STEP),
            MouseEventKind::Down(MouseButton::Left) => {
                let area = self.rows_area.get();
                if !area.contains(ratatui::layout::Position::new(ev.column, ev.row)) {
                    return false;
                }
                let i = self.offset.get() + usize::from(ev.row - area.y);
                if i >= self.visible.len() {
                    return false;
                }
                self.cursor = i;
            }
            _ => return false,
        }
        true
    }

    // ------------------------------------------------------------ render

    /// Scroll offset keeping the cursor `SCROLLOFF` rows from the edges.
    fn scroll_for(&self, height: usize) -> usize {
        let n = self.visible.len();
        if height == 0 || n <= height {
            return 0;
        }
        let so = SCROLLOFF.min((height - 1) / 2);
        let mut off = self.offset.get();
        if self.cursor < off + so {
            off = self.cursor.saturating_sub(so);
        }
        if self.cursor + so >= off + height {
            off = self.cursor + so + 1 - height;
        }
        off.min(n - height)
    }

    /// Draw with the view's renderers.
    pub fn render_with(
        &self,
        frame: &mut Frame<'_>,
        area: Rect,
        cx: &RenderCx<'_>,
        rows: &dyn RowRenderer<R>,
        detail: Option<&dyn DetailRenderer<R>>,
    ) {
        if area.width < 3 || area.height < 3 {
            return;
        }
        if let (true, Some(detail)) = (self.detail_full, detail) {
            self.render_detail(frame, area, cx, detail, true);
            return;
        }
        let (list_area, detail_area) = match detail {
            Some(_) if area.width >= DETAIL_MIN_WIDTH => {
                let [l, d] =
                    Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)])
                        .areas(area);
                (l, Some(d))
            }
            _ => (area, None),
        };
        self.render_list(frame, list_area, cx, rows);
        if let (Some(d), Some(detail)) = (detail_area, detail) {
            let unfocused = RenderCx {
                focused: false,
                ..*cx
            };
            self.render_detail(frame, d, &unfocused, detail, false);
        }
    }

    fn render_list(
        &self,
        frame: &mut Frame<'_>,
        area: Rect,
        cx: &RenderCx<'_>,
        renderer: &dyn RowRenderer<R>,
    ) {
        let theme = cx.theme;
        let mut block = Block::bordered()
            .title(Span::styled(
                format!(" {} ", self.title_text()),
                theme.title_for(cx.focused),
            ))
            .border_style(theme.border_for(cx.focused));
        if let Some((name, rev)) = self.sort() {
            block = block.title_top(
                Line::styled(
                    format!(" {name} {} ", if rev { "↑" } else { "↓" }),
                    theme.dim,
                )
                .right_aligned(),
            );
        }
        if !self.rows.is_empty() {
            block = block.title_bottom(
                Line::styled(
                    format!(" {}/{} ", self.visible.len(), self.rows.len()),
                    theme.dim,
                )
                .right_aligned(),
            );
        }
        let inner = block.inner(area);
        frame.render_widget(block.style(theme.base), area);
        if inner.height == 0 || inner.width == 0 {
            return;
        }
        let w = usize::from(inner.width);
        let mut y = inner.y;
        if self.filter_open {
            let mut spans = vec![Span::styled("/", theme.accent)];
            let editing = self.filter_editing && cx.focused;
            spans.extend(
                self.filter
                    .line(w.saturating_sub(1), theme.base, editing)
                    .spans,
            );
            frame.render_widget(Line::from(spans), Rect::new(inner.x, y, inner.width, 1));
            y += 1;
        }
        let rows_area = Rect::new(inner.x, y, inner.width, inner.bottom() - y);
        self.rows_area.set(rows_area);
        let h = usize::from(rows_area.height);
        self.viewport.set(h.max(1));
        if self.visible.is_empty() {
            frame.render_widget(Paragraph::new(self.empty_lines(theme)), rows_area);
            return;
        }
        let offset = self.scroll_for(h);
        self.offset.set(offset);
        let end = (offset + h).min(self.visible.len());
        let lines: Vec<Line<'static>> = self.visible[offset..end]
            .iter()
            .enumerate()
            .map(|(n, v)| self.row_line(offset + n, v, w, cx, renderer))
            .collect();
        frame.render_widget(Paragraph::new(lines), rows_area);
    }

    fn row_line(
        &self,
        i: usize,
        v: &Visible,
        w: usize,
        cx: &RenderCx<'_>,
        renderer: &dyn RowRenderer<R>,
    ) -> Line<'static> {
        let theme = cx.theme;
        let row = &self.rows[v.idx];
        let selected = i == self.cursor;
        let marked = self.marks.contains(&row.key());
        let base = if selected && cx.focused {
            theme.selection
        } else {
            theme.base
        };
        let mut prefix = String::with_capacity(8);
        prefix.push(if selected { '›' } else { ' ' });
        prefix.push(if marked { '*' } else { ' ' });
        for _ in 0..v.depth {
            prefix.push_str("  ");
        }
        if self.tree && self.filter.is_empty() {
            if v.has_children {
                let open = !self.collapsed.contains(&row.key());
                prefix.push_str(if open { "▾ " } else { "▸ " });
            } else if row.is_group() {
                prefix.push_str("  ");
            }
        }
        let used = width(&prefix);
        let mut spans = vec![Span::styled(prefix, base)];
        let rcx = RowCx {
            highlights: &v.highlights,
            width: w.saturating_sub(used),
            selected,
            marked,
            base,
            theme,
        };
        spans.extend(renderer.spans(row, &rcx));
        let total: usize = spans.iter().map(Span::width).sum();
        if selected && total < w {
            spans.push(Span::styled(" ".repeat(w - total), base));
        }
        Line::from(spans)
    }

    fn empty_lines(&self, theme: &Theme) -> Vec<Line<'static>> {
        if !self.filter.is_empty() {
            return vec![Line::styled(
                format!("No matches for “{}”", self.filter.text()),
                theme.dim,
            )];
        }
        let mut lines = vec![Line::styled(self.empty.message.clone(), theme.accent)];
        for (k, what) in &self.empty.hints {
            lines.push(Line::from(vec![
                Span::styled(format!("{k:>8}"), theme.base),
                Span::styled(format!("  {what}"), theme.dim),
            ]));
        }
        lines
    }

    fn render_detail(
        &self,
        frame: &mut Frame<'_>,
        area: Rect,
        cx: &RenderCx<'_>,
        detail: &dyn DetailRenderer<R>,
        full: bool,
    ) {
        let theme = cx.theme;
        let title = self
            .selected()
            .map_or_else(|| " Details ".to_owned(), |r| format!(" {} ", r.label()));
        let mut block = Block::bordered()
            .title(Span::styled(title, theme.title_for(cx.focused)))
            .border_style(theme.border_for(cx.focused));
        if full {
            block = block.title_bottom(Span::styled(" i / esc close ", theme.dim));
        }
        let inner = block.inner(area);
        let lines = self.selected().map_or_else(
            || vec![Line::styled("Nothing selected", theme.dim)],
            |r| detail.lines(r, theme, usize::from(inner.width)),
        );
        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .block(block)
                .style(theme.base),
            area,
        );
    }
}

impl<R: ListRow> View for ListView<R> {
    fn handle(&mut self, ev: &ViewEvent, cx: &mut ViewCx<'_>) -> Outcome {
        let consumed = match ev {
            ViewEvent::Key(key) if self.filter_editing => {
                self.on_filter_key(key);
                true
            }
            ViewEvent::Key(key) => self.on_key(key),
            ViewEvent::Paste(text) if self.filter_editing => {
                if self.filter.insert_str(text) {
                    self.rebuild();
                }
                true
            }
            ViewEvent::Mouse(m) => self.on_mouse(m),
            ViewEvent::Paste(_) => false,
        };
        if consumed {
            cx.request_redraw();
            Outcome::Consumed
        } else {
            Outcome::Ignored
        }
    }

    fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        self.render_with(frame, area, cx, &DefaultRenderer, None);
    }

    fn insert_mode(&self) -> bool {
        self.filter_editing
    }
}
