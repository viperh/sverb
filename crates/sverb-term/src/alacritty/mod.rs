//! [`AlacrittyEmulator`]: the [`Emulator`] implementation on `alacritty_terminal` (SPEC §7.1).

mod listener;
mod sidechannel;
mod snapshot;

use std::time::Instant;

use alacritty_terminal::Term;
use alacritty_terminal::event::{Event, WindowSize};
use alacritty_terminal::grid::Dimensions;
use alacritty_terminal::index::{Column, Direction as AlacDirection, Line, Point};
use alacritty_terminal::term::cell::Flags;
use alacritty_terminal::term::color::COUNT as COLOR_COUNT;
use alacritty_terminal::term::search::RegexSearch;
use alacritty_terminal::term::{ClipboardType, Config, Osc52, TermMode};
use alacritty_terminal::vte::ansi::{
    CursorShape as AlacShape, NamedColor, Processor, Rgb as AlacRgb, StdSyncHandler,
};
use bytes::Bytes;
use ratatui_core::buffer::Buffer;
use ratatui_core::layout::Rect;
use regex::Regex;

use self::listener::Listener;
use self::sidechannel::{SideEvent, SideScanner};
use self::snapshot::SnapshotExtras;
use crate::emulator::{
    ClipboardTarget, ColorScheme, CursorInfo, Direction, Emulator, EmulatorConfig, GridPoint,
    HyperlinkInfo, Match, TermEvent, ViewState,
};
use crate::modes::{CursorShape, KittyKeyboardFlags, MouseEncoding, MouseMode, TermModes};
use crate::policy::{MAX_CLIPBOARD_WRITE_BYTES, sanitize_title};

/// Smallest grid alacritty accepts.
const MIN_COLS: u16 = 2;
const MIN_ROWS: u16 = 1;

#[derive(Debug, Clone, Copy)]
struct Size {
    cols: usize,
    rows: usize,
}

impl Dimensions for Size {
    fn total_lines(&self) -> usize {
        self.rows
    }
    fn screen_lines(&self) -> usize {
        self.rows
    }
    fn columns(&self) -> usize {
        self.cols
    }
}

/// `Emulator` backed by `alacritty_terminal::Term` and `vte::ansi::Processor`.
pub struct AlacrittyEmulator {
    term: Term<Listener>,
    processor: Processor<StdSyncHandler>,
    listener: Listener,
    side: SideScanner,
    responses: Vec<Bytes>,
    events: Vec<TermEvent>,
    scheme: ColorScheme,
    cell_width: u16,
    cell_height: u16,
    modify_other_keys: u8,
    urxvt_mouse: bool,
    /// Trailing bytes of an incomplete UTF-8 sequence held back from the previous `feed`
    /// (see [`incomplete_utf8_tail`]).
    utf8_carry: Vec<u8>,
    /// OSC 133 command capture (`crate::osc133`).
    osc133: crate::osc133::CommandTracker,
}

impl std::fmt::Debug for AlacrittyEmulator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (cols, rows) = self.size();
        f.debug_struct("AlacrittyEmulator")
            .field("cols", &cols)
            .field("rows", &rows)
            .field("scrollback_len", &self.scrollback_len())
            .field("pending_responses", &self.responses.len())
            .field("pending_events", &self.events.len())
            .finish_non_exhaustive()
    }
}

impl AlacrittyEmulator {
    /// A new emulator. `config.scrollback` is fixed for the emulator's lifetime.
    #[must_use]
    pub fn new(config: EmulatorConfig) -> Self {
        let listener = Listener::default();
        let term_config = Config {
            scrolling_history: config.scrollback,
            // Let the remote request kitty keyboard flags (SPEC §7.3); the encoder honors them.
            kitty_keyboard: true,
            // Defense in depth: alacritty itself drops OSC 52 reads, and the listener drops
            // any `ClipboardLoad` that would get through.
            osc52: Osc52::OnlyCopy,
            ..Config::default()
        };
        let size = Size {
            cols: usize::from(config.cols.max(MIN_COLS)),
            rows: usize::from(config.rows.max(MIN_ROWS)),
        };
        let term = Term::new(term_config, &size, listener.clone());
        Self {
            term,
            processor: Processor::new(),
            listener,
            side: SideScanner::default(),
            responses: Vec::new(),
            events: Vec::new(),
            scheme: ColorScheme::default(),
            cell_width: 0,
            cell_height: 0,
            modify_other_keys: 0,
            urxvt_mouse: false,
            utf8_carry: Vec::new(),
            osc133: crate::osc133::CommandTracker::new(),
        }
    }

    /// Read access to the underlying terminal, for the renderer.
    #[allow(dead_code)]
    pub(crate) fn term(&self) -> &Term<Listener> {
        &self.term
    }

    /// Apply a pending synchronized update (DECSET 2026) whose timeout has expired.
    ///
    /// `feed` does this on entry; call it from a timer if the remote can go quiet mid-update.
    pub fn flush_expired_sync(&mut self) {
        let expired = self
            .processor
            .sync_timeout()
            .sync_timeout()
            .is_some_and(|t| t <= Instant::now());
        if expired {
            self.processor.stop_sync(&mut self.term);
            self.drain_listener();
        }
    }

    /// Force out any synchronized update still buffered (tests, snapshots on demand).
    pub fn flush_sync(&mut self) {
        if self.processor.sync_timeout().sync_timeout().is_some() {
            self.processor.stop_sync(&mut self.term);
            self.drain_listener();
        }
    }

    /// A deterministic text dump of the visible screen, for tests and fixture snapshots.
    ///
    /// Each row is printed between `|` markers (wide-char spacers omitted), followed by a
    /// `cursor:` line and `modes:`. With `attrs`, every non-default cell is listed with its
    /// colors, flags, combining chars and hyperlink, which makes two dumps equal only when the
    /// visible grids (chars + attributes) are identical.
    #[must_use]
    pub fn screen_dump(&self, attrs: bool) -> String {
        use std::fmt::Write as _;
        let grid = self.term.grid();
        let mut out = String::new();
        for line in 0..grid.screen_lines() {
            let row = &grid[Line(line as i32)];
            out.push('|');
            for col in 0..grid.columns() {
                let cell = &row[Column(col)];
                if cell.flags.contains(Flags::WIDE_CHAR_SPACER) {
                    continue;
                }
                out.push(cell.c);
                for c in cell.zerowidth().into_iter().flatten() {
                    out.push(*c);
                }
            }
            out.push_str("|\n");
        }
        if attrs {
            let default = alacritty_terminal::term::cell::Cell::default();
            for line in 0..grid.screen_lines() {
                let row = &grid[Line(line as i32)];
                for col in 0..grid.columns() {
                    let cell = &row[Column(col)];
                    if cell.fg == default.fg
                        && cell.bg == default.bg
                        && cell.flags.is_empty()
                        && cell.extra.is_none()
                    {
                        continue;
                    }
                    let _ = writeln!(
                        out,
                        "{line},{col}: {:?} fg={:?} bg={:?} flags={:?} ul={:?} zw={:?} link={:?}",
                        cell.c,
                        cell.fg,
                        cell.bg,
                        cell.flags,
                        cell.underline_color(),
                        cell.zerowidth(),
                        cell.hyperlink()
                            .map(|l| (l.id().to_owned(), l.uri().to_owned())),
                    );
                }
            }
            let c = &grid.cursor;
            let _ = writeln!(
                out,
                "pen: fg={:?} bg={:?} flags={:?} wrap_pending={}",
                c.template.fg, c.template.bg, c.template.flags, c.input_needs_wrap
            );
        }
        let cur = self.cursor();
        let _ = writeln!(
            out,
            "cursor: line={} col={} shape={:?} blinking={} visible={}",
            cur.point.line, cur.point.column, cur.shape, cur.blinking, cur.visible
        );
        let _ = writeln!(out, "modes: {:?}", self.modes());
        out
    }

    fn feed_complete(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let side = self.side.scan(bytes);
        let mut last = 0;
        for (end, ev) in side {
            self.processor.advance(&mut self.term, &bytes[last..end]);
            last = end;
            self.drain_listener();
            self.apply_side(ev);
        }
        self.processor.advance(&mut self.term, &bytes[last..]);
        self.drain_listener();
    }

    fn apply_side(&mut self, ev: SideEvent) {
        match ev {
            SideEvent::Cwd { host, path } => self.events.push(TermEvent::Cwd { host, path }),
            SideEvent::PromptMark(kind) => {
                let p = self.term.grid().cursor.point;
                let cursor = GridPoint::new(p.line.0, p.column.0);
                let history_len = self.term.grid().history_size();
                self.events.push(TermEvent::PromptMark {
                    kind,
                    cursor,
                    history_len,
                });
                // The command text is read now, before its output reaches the grid.
                let mut tracker = std::mem::take(&mut self.osc133);
                let done = tracker.on_mark(kind, cursor, history_len, self);
                self.osc133 = tracker;
                if let Some(command) = done {
                    self.events.push(TermEvent::Command(command));
                }
            }
            SideEvent::ModifyOtherKeys(level) => self.modify_other_keys = level,
            SideEvent::UrxvtMouse(on) => self.urxvt_mouse = on,
            SideEvent::Reset => {
                self.modify_other_keys = 0;
                self.urxvt_mouse = false;
            }
        }
    }

    /// Color for an alacritty color index: a remote override (OSC 4/10/11/12 set) wins, else the
    /// pane's scheme.
    fn color_for_index(&self, index: usize) -> Option<AlacRgb> {
        if index < COLOR_COUNT
            && let Some(rgb) = self.term.colors()[index]
        {
            return Some(rgb);
        }
        let rgb = match index {
            0..=255 => self.scheme.indexed(u8::try_from(index).ok()?),
            i if i == NamedColor::Foreground as usize => self.scheme.foreground,
            i if i == NamedColor::Background as usize => self.scheme.background,
            i if i == NamedColor::Cursor as usize => self.scheme.cursor,
            _ => return None,
        };
        Some(AlacRgb {
            r: rgb.r,
            g: rgb.g,
            b: rgb.b,
        })
    }

    fn drain_listener(&mut self) {
        for event in self.listener.drain() {
            match event {
                // Replies generated by alacritty from its own state (SPEC §17).
                Event::PtyWrite(text) => self.responses.push(Bytes::from(text)),
                Event::Title(title) => self
                    .events
                    .push(TermEvent::Title(Some(sanitize_title(&title)))),
                Event::ResetTitle => self.events.push(TermEvent::Title(None)),
                Event::Bell => self.events.push(TermEvent::Bell),
                Event::ClipboardStore(ty, text) => {
                    if text.len() <= MAX_CLIPBOARD_WRITE_BYTES {
                        let target = match ty {
                            ClipboardType::Clipboard => ClipboardTarget::Clipboard,
                            ClipboardType::Selection => ClipboardTarget::Selection,
                        };
                        self.events
                            .push(TermEvent::ClipboardWriteRequest { target, text });
                    }
                }
                Event::ColorRequest(index, format) => {
                    if let Some(rgb) = self.color_for_index(index) {
                        self.responses.push(Bytes::from(format(rgb)));
                    }
                }
                Event::TextAreaSizeRequest(format) => {
                    let (cols, rows) = self.size();
                    let size = WindowSize {
                        num_lines: rows,
                        num_cols: cols,
                        cell_width: self.cell_width,
                        cell_height: self.cell_height,
                    };
                    self.responses.push(Bytes::from(format(size)));
                }
                // SECURITY: never answered (the listener already drops it).
                Event::ClipboardLoad(..)
                | Event::MouseCursorDirty
                | Event::CursorBlinkingChange
                | Event::Wakeup
                | Event::Exit
                | Event::ChildExit(_) => {}
            }
        }
    }

    fn to_alac_point(&self, p: GridPoint) -> Point {
        let grid = self.term.grid();
        let top = grid.topmost_line().0;
        let bottom = grid.bottommost_line().0;
        let line = p.line.clamp(top, bottom);
        let column = p.column.min(grid.columns() - 1);
        Point::new(Line(line), Column(column))
    }
}

/// Length of an incomplete UTF-8 sequence at the end of `bytes` (0 if the input ends on a
/// complete character, an ASCII byte or an invalid sequence).
fn incomplete_utf8_tail(bytes: &[u8]) -> usize {
    let n = bytes.len();
    for back in 1..=n.min(3) {
        let b = bytes[n - back];
        if b & 0b1100_0000 == 0b1000_0000 {
            continue; // continuation byte: keep looking for the lead
        }
        let needed = match b {
            0xC2..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF4 => 4,
            _ => return 0,
        };
        return if back < needed { back } else { 0 };
    }
    0
}

fn from_alac_point(p: Point) -> GridPoint {
    GridPoint::new(p.line.0, p.column.0)
}

impl Emulator for AlacrittyEmulator {
    fn feed(&mut self, bytes: &[u8]) {
        self.flush_expired_sync();
        // Never hand the parser a chunk that ends inside a UTF-8 sequence: vte 0.15's partial
        // UTF-8 path drops the bytes following the completed character when the next chunk
        // continues with more text (e.g. `"\xd7"` + `"\x9d \xd7\xa2"` loses the space).
        // Holding back the incomplete tail keeps vte on its whole-buffer path.
        if self.utf8_carry.is_empty() {
            let keep = bytes.len() - incomplete_utf8_tail(bytes);
            self.feed_complete(&bytes[..keep]);
            self.utf8_carry.extend_from_slice(&bytes[keep..]);
        } else {
            let mut data = std::mem::take(&mut self.utf8_carry);
            data.extend_from_slice(bytes);
            let keep = data.len() - incomplete_utf8_tail(&data);
            self.feed_complete(&data[..keep]);
            data.drain(..keep);
            self.utf8_carry = data;
        }
    }

    fn resize(&mut self, cols: u16, rows: u16) {
        let size = Size {
            cols: usize::from(cols.max(MIN_COLS)),
            rows: usize::from(rows.max(MIN_ROWS)),
        };
        self.term.resize(size);
        self.drain_listener();
    }

    fn modes(&self) -> TermModes {
        let m = *self.term.mode();
        let mouse_mode = if m.contains(TermMode::MOUSE_MOTION) {
            MouseMode::Motion
        } else if m.contains(TermMode::MOUSE_DRAG) {
            MouseMode::Drag
        } else if m.contains(TermMode::MOUSE_REPORT_CLICK) {
            MouseMode::Click
        } else {
            MouseMode::None
        };
        let mouse_encoding = if m.contains(TermMode::SGR_MOUSE) {
            MouseEncoding::Sgr
        } else if self.urxvt_mouse {
            MouseEncoding::Urxvt
        } else if m.contains(TermMode::UTF8_MOUSE) {
            MouseEncoding::Utf8
        } else {
            MouseEncoding::Default
        };
        let cursor = self.cursor();
        TermModes {
            app_cursor: m.contains(TermMode::APP_CURSOR),
            app_keypad: m.contains(TermMode::APP_KEYPAD),
            mouse_mode,
            mouse_encoding,
            bracketed_paste: m.contains(TermMode::BRACKETED_PASTE),
            focus_reporting: m.contains(TermMode::FOCUS_IN_OUT),
            alt_screen: m.contains(TermMode::ALT_SCREEN),
            alternate_scroll: m.contains(TermMode::ALTERNATE_SCROLL),
            line_feed_new_line: m.contains(TermMode::LINE_FEED_NEW_LINE),
            modify_other_keys: self.modify_other_keys,
            kitty_keyboard: KittyKeyboardFlags(snapshot::kitty_bits(m)),
            cursor_shape: cursor.shape,
            cursor_blinking: cursor.blinking,
            cursor_visible: cursor.visible,
        }
    }

    fn render(&self, area: Rect, buf: &mut Buffer, view: &ViewState) {
        // The styled renderer.
        crate::render::render_term(&self.term, self.cursor(), area, buf, view);
    }

    fn take_responses(&mut self) -> Vec<Bytes> {
        std::mem::take(&mut self.responses)
    }

    fn take_events(&mut self) -> Vec<TermEvent> {
        std::mem::take(&mut self.events)
    }

    fn scrollback_len(&self) -> usize {
        self.term.grid().history_size()
    }

    fn search(&self, re: &Regex, dir: Direction, from: GridPoint) -> Option<Match> {
        // alacritty's DFA search is case-insensitive for all-lowercase patterns; wrapping the
        // pattern in a case-sensitive group gives `regex::Regex` semantics (inline flags inside
        // the pattern still apply).
        let mut search = RegexSearch::new(&format!("(?-i:{})", re.as_str())).ok()?;
        let origin = self.to_alac_point(from);
        let (direction, side) = match dir {
            Direction::Backward => (AlacDirection::Left, AlacDirection::Left),
            Direction::Forward => (AlacDirection::Right, AlacDirection::Right),
        };
        let m = self
            .term
            .search_next(&mut search, origin, direction, side, None)?;
        Some(Match {
            start: from_alac_point(*m.start()),
            end: from_alac_point(*m.end()),
        })
    }

    fn snapshot_vt(&self) -> Bytes {
        let extras = SnapshotExtras {
            modify_other_keys: self.modify_other_keys,
            urxvt_mouse: self.urxvt_mouse,
        };
        Bytes::from(snapshot::snapshot_vt(&self.term, extras))
    }

    fn cursor(&self) -> CursorInfo {
        let grid = self.term.grid();
        let mut point = grid.cursor.point;
        if point.column.0 > 0 && grid[point].flags.contains(Flags::WIDE_CHAR_SPACER) {
            point.column -= 1;
        }
        let style = self.term.cursor_style();
        let (shape, shape_visible) = match style.shape {
            AlacShape::Block => (CursorShape::Block, true),
            AlacShape::Underline => (CursorShape::Underline, true),
            AlacShape::Beam => (CursorShape::Bar, true),
            AlacShape::HollowBlock => (CursorShape::HollowBlock, true),
            AlacShape::Hidden => (CursorShape::Block, false),
        };
        CursorInfo {
            point: from_alac_point(point),
            shape,
            blinking: style.blinking,
            visible: shape_visible && self.term.mode().contains(TermMode::SHOW_CURSOR),
        }
    }

    fn grid_text(&self, start: GridPoint, end: GridPoint) -> String {
        let (start, end) = if end < start {
            (end, start)
        } else {
            (start, end)
        };
        self.term
            .bounds_to_string(self.to_alac_point(start), self.to_alac_point(end))
    }

    fn set_color_scheme(&mut self, scheme: &ColorScheme) {
        self.scheme = scheme.clone();
    }

    fn set_pixel_size(&mut self, cell_width: u16, cell_height: u16) {
        self.cell_width = cell_width;
        self.cell_height = cell_height;
    }

    fn hyperlink_at(&self, point: GridPoint) -> Option<HyperlinkInfo> {
        let p = self.to_alac_point(point);
        let link = self.term.grid()[p].hyperlink()?;
        Some(HyperlinkInfo {
            id: link.id().to_owned(),
            uri: link.uri().to_owned(),
        })
    }

    fn prompt_state(&self) -> crate::osc133::PromptState {
        let p = self.term.grid().cursor.point;
        self.osc133.prompt_state(
            GridPoint::new(p.line.0, p.column.0),
            self.term.grid().history_size(),
            self,
        )
    }

    fn row(&self, line: i32) -> Option<crate::selection::GridRow> {
        use crate::selection::{GridRow, RowCell};
        let grid = self.term.grid();
        if line < grid.topmost_line().0 || line > grid.bottommost_line().0 {
            return None;
        }
        let row = &grid[Line(line)];
        let cols = grid.columns();
        let cells = (0..cols)
            .map(|col| {
                let cell = &row[Column(col)];
                let width = if cell
                    .flags
                    .intersects(Flags::WIDE_CHAR_SPACER | Flags::LEADING_WIDE_CHAR_SPACER)
                {
                    0
                } else if cell.flags.contains(Flags::WIDE_CHAR) {
                    2
                } else {
                    1
                };
                RowCell {
                    c: cell.c,
                    zerowidth: cell.zerowidth().map(<[char]>::to_vec).unwrap_or_default(),
                    width,
                }
            })
            .collect();
        let wrapped = cols > 0 && row[Column(cols - 1)].flags.contains(Flags::WRAPLINE);
        Some(GridRow { cells, wrapped })
    }

    fn size(&self) -> (u16, u16) {
        let grid = self.term.grid();
        (
            u16::try_from(grid.columns()).unwrap_or(u16::MAX),
            u16::try_from(grid.screen_lines()).unwrap_or(u16::MAX),
        )
    }
}
