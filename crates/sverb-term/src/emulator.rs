//! The [`Emulator`] trait (SPEC §7.1) and the emulator-agnostic types it uses.
//!
//! Nothing here mentions `alacritty_terminal`, so a fallback implementation (e.g. on the `vt100`
//! crate, SPEC §22.4) only has to implement this trait. See `docs/emulator.md`.

use bytes::Bytes;
use ratatui_core::buffer::Buffer;
use ratatui_core::layout::Rect;
use ratatui_core::style::Color;
use regex::Regex;
use std::sync::Arc;

use crate::color::ColorDepth;
use crate::modes::{CursorShape, TermModes};

/// Default scrollback, in lines (SPEC §7.1, `terminal.scrollback`).
pub const DEFAULT_SCROLLBACK: usize = 10_000;

/// Construction parameters for an emulator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmulatorConfig {
    pub cols: u16,
    pub rows: u16,
    /// Maximum scrollback lines (`terminal.scrollback`).
    pub scrollback: usize,
}

impl Default for EmulatorConfig {
    fn default() -> Self {
        Self {
            cols: 80,
            rows: 24,
            scrollback: DEFAULT_SCROLLBACK,
        }
    }
}

/// A position in the grid.
///
/// `line` 0 is the top row of the live screen; negative lines are scrollback (`-1` is the most
/// recent history line). `column` is 0-based.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GridPoint {
    pub line: i32,
    pub column: usize,
}

impl GridPoint {
    #[must_use]
    pub fn new(line: i32, column: usize) -> Self {
        Self { line, column }
    }
}

/// Search direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Towards older content (up/left).
    Backward,
    /// Towards newer content (down/right).
    Forward,
}

/// A search match, both ends inclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Match {
    pub start: GridPoint,
    pub end: GridPoint,
}

/// Cursor state for the renderer and the runtime (DECSCUSR passthrough).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CursorInfo {
    /// Position on the live screen (`line` is always `>= 0`).
    pub point: GridPoint,
    pub shape: CursorShape,
    pub blinking: bool,
    pub visible: bool,
}

/// Which clipboard an OSC 52 request targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClipboardTarget {
    /// `c`.
    Clipboard,
    /// `p` / `s` (primary selection).
    Selection,
}

/// OSC 133 semantic prompt marks (used by M7-01).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PromptMarkKind {
    /// `A`: prompt start.
    PromptStart,
    /// `B`: command input start (prompt end).
    CommandStart,
    /// `C`: command output start.
    OutputStart,
    /// `D[;exit]`: command finished.
    CommandFinished { exit_code: Option<i32> },
}

/// Something the emulator reports to the UI. Drained with [`Emulator::take_events`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TermEvent {
    /// OSC 0/2 title; `None` resets to the default title. Already sanitized
    /// (≤ 256 chars, no control chars, SPEC §17).
    Title(Option<String>),
    /// BEL.
    Bell,
    /// OSC 52 write. The UI applies `clipboard.allow_remote_write` (SPEC §7.3). Reads are never
    /// reported: they are denied inside the emulator.
    ClipboardWriteRequest {
        target: ClipboardTarget,
        text: String,
    },
    /// OSC 7 working directory (`file://host/path`), percent-decoded and sanitized.
    Cwd { host: Option<String>, path: String },
    /// OSC 133 mark at the cursor position when the mark was parsed. `history_len` is the
    /// scrollback length at that moment, so `history_len + cursor.line` identifies the row until
    /// the scrollback wraps.
    PromptMark {
        kind: PromptMarkKind,
        cursor: GridPoint,
        history_len: usize,
    },
    // M7-01
    /// A command the shell ran, captured from the grid between the OSC 133 `B` and `C`
    /// marks, with the `D` exit code (`crate::osc133`). Reported after its `PromptMark`.
    Command(crate::osc133::ShellCommand),
}

/// An OSC 8 hyperlink attached to a cell (for hover and opening, SPEC §17).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HyperlinkInfo {
    pub id: String,
    pub uri: String,
}

// M1-10: `Rgb`, `ColorScheme` and `xterm_256` moved to `crate::scheme` (re-exported here so
// existing paths keep working).
pub use crate::scheme::{ColorScheme, Rgb, xterm_256};

/// A selection to highlight (M3-04 fills it in). Both ends inclusive, in [`GridPoint`]s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Selection {
    pub start: GridPoint,
    pub end: GridPoint,
    /// Rectangular (block) selection instead of a stream of lines.
    pub block: bool,
}

/// Overlay colors, taken from the UI theme by the pane widget (the emulator stays
/// theme-agnostic). `Reset` means "attribute only".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OverlayStyle {
    /// Background of search matches (UI theme `selection`).
    pub match_bg: Color,
    /// Background of the current search match (UI theme `accent`).
    pub current_match_bg: Color,
    /// Foreground of a hovered hyperlink (UI theme `accent`).
    pub link_fg: Color,
}

impl Default for OverlayStyle {
    fn default() -> Self {
        Self {
            match_bg: Color::Indexed(3),
            current_match_bg: Color::Indexed(11),
            link_fg: Color::Indexed(12),
        }
    }
}

/// How a pane is being viewed (SPEC §7.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ViewState {
    /// Lines scrolled up into scrollback; 0 = live.
    pub scroll_offset: usize,
    pub focused: bool,
    // M1-10
    /// The pane's palette; `None` is the `terminal` scheme (no remapping).
    pub scheme: Option<Arc<ColorScheme>>,
    /// What the outer terminal can show.
    pub depth: ColorDepth,
    /// Selection (M3-04).
    pub selection: Option<Selection>,
    /// Search matches (M3-04).
    pub search_matches: Vec<Match>,
    /// The current search match (M3-04).
    pub current_match: Option<Match>,
    /// The cells of the hyperlink under the mouse.
    pub hovered_link: Option<Match>,
    /// Overlay colors from the UI theme.
    pub overlay: OverlayStyle,
    /// The pane receives broadcast input (M3-02). The pane widget draws the border; the
    /// emulator ignores it.
    pub broadcast_highlight: bool,
}

/// A terminal emulator (SPEC §7.1). Object-safe; used as `Box<dyn Emulator>`.
pub trait Emulator: Send {
    /// Parse remote output (always UTF-8; see [`crate::charset`]).
    fn feed(&mut self, bytes: &[u8]);

    /// Resize the grid. Zero dimensions are clamped to the emulator minimum.
    fn resize(&mut self, cols: u16, rows: u16);

    /// Modes requested by the remote.
    fn modes(&self) -> TermModes;

    /// Draw the visible grid into `buf` with colors, attributes, the hollow cursor of an
    /// unfocused pane, overlays and the scroll indicator (M1-10, `crate::render`). The
    /// focused pane's real cursor is placed by the caller from [`Emulator::cursor`].
    fn render(&self, area: Rect, buf: &mut Buffer, view: &ViewState);

    /// Replies the terminal owes the remote (DA1/DA2, DSR, DECRQM, color and size queries).
    /// Must be written back to the channel, or vim/fish hang.
    fn take_responses(&mut self) -> Vec<Bytes>;

    /// Events for the UI (title, bell, OSC 52 writes, OSC 7, OSC 133).
    fn take_events(&mut self) -> Vec<TermEvent>;

    /// Number of scrollback lines currently held.
    fn scrollback_len(&self) -> usize;

    /// Next regex match from `from` in `dir`, across the screen and scrollback.
    fn search(&self, re: &Regex, dir: Direction, from: GridPoint) -> Option<Match>;

    /// A VT byte stream that recreates the visible screen and modes in a fresh emulator of the
    /// same size (SPEC §14.2). No scrollback.
    fn snapshot_vt(&self) -> Bytes;

    /// Cursor position, shape and visibility.
    fn cursor(&self) -> CursorInfo;

    /// Text between two points (inclusive), rows joined with `\n` (soft-wrapped rows are joined
    /// without a newline).
    fn grid_text(&self, start: GridPoint, end: GridPoint) -> String;

    /// Palette used to answer OSC 4/10/11/12 queries.
    fn set_color_scheme(&mut self, scheme: &ColorScheme);

    /// Outer-terminal cell size in pixels (0 if unknown), for `CSI 14 t` replies.
    fn set_pixel_size(&mut self, cell_width: u16, cell_height: u16);

    /// OSC 8 hyperlink at a point, if any. Emulators without hyperlink support return `None`.
    fn hyperlink_at(&self, _point: GridPoint) -> Option<HyperlinkInfo> {
        None
    }

    /// Current (cols, rows).
    fn size(&self) -> (u16, u16);

    // M3-04
    /// The text of one row (`line` as in [`GridPoint`]), `None` outside the screen and
    /// scrollback. Copy mode, selection and search read the grid through this
    /// ([`crate::selection::EmulatorGrid`]). Emulators without it return `None`.
    fn row(&self, _line: i32) -> Option<crate::selection::GridRow> {
        None
    }

    // M7-01
    /// Shell integration state: whether OSC 133 marks were seen, and the command line
    /// typed so far while the shell reads one. Emulators without it report nothing.
    fn prompt_state(&self) -> crate::osc133::PromptState {
        crate::osc133::PromptState::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trait_is_object_safe_and_send() {
        fn assert_send<T: Send + ?Sized>() {}
        assert_send::<Box<dyn Emulator>>();
    }
}
