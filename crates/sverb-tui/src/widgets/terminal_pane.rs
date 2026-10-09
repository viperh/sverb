//! The `TerminalPane` widget (M1-10, SPEC §7.2): a session's emulator inside a border,
//! with a title and the pane-state overlays.
//!
//! ```text
//! ┌ web-1 ─────────────────────────────┐   border: focused / unfocused / broadcast
//! │ $ ls                               │   content: `Emulator::render` (sverb-term)
//! │ …                                  │
//! │┌──────────────────────────────────┐│   overlay (here: disconnected banner, M1-16)
//! ││ Disconnected: connection reset   ││
//! ││ [Enter] reconnect · ^\ x close · ││
//! │└──────────────────────────────────┘│
//! └────────────────────────────────────┘
//! ```
//!
//! - **Title**: the OSC title when `terminal.use_osc_title` is on and the remote set one,
//!   else the pane label (host label, M1-13).
//! - **Content**: the emulator mutex is held only for the synchronous render and the cursor
//!   query, never across an `.await` (M1-08).
//! - **Cursor**: for the focused pane with no overlay, [`TerminalPane::render`] returns where
//!   the real terminal cursor goes and its shape (the runtime passes the shape through with
//!   DECSCUSR). Unfocused panes get the hollow cursor from the emulator renderer.
//! - **Overlays** ([`PaneOverlay`]) are drawn over the content. The keys they mention are
//!   handled by their owners (M1-16 disconnected/exited, M1-04 vault lock, M1-12 local
//!   exit; `tasks/03-KEYBINDINGS.md` §4.4). **Locked** blanks the content first, so nothing
//!   of the session is visible while the vault is locked.
//! - **Colors**: the content uses the pane's terminal color scheme ([`PaneInfo::scheme`] or
//!   `terminal.color_scheme`); the border, title and overlays use the UI theme.

use std::sync::Arc;

use ratatui::{
    buffer::Buffer,
    layout::{Position, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph, Widget, Wrap},
};
use sverb_conn::{SessionRegistry, SharedEmulator};
use sverb_term::scheme::{self, ColorScheme, SchemeCatalog, SchemeLoadError};
use sverb_term::{ColorDepth, CursorShape, OverlayStyle, ViewState};

use crate::{app::SessionId, theme::Theme};

/// Where the renderer finds a session's emulator.
pub trait PaneSource {
    /// The emulator of a live session.
    fn emulator(&self, id: SessionId) -> Option<SharedEmulator>;
}

/// No emulators (reducer tests, frames drawn without a session manager).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPanes;

impl PaneSource for NoPanes {
    fn emulator(&self, _id: SessionId) -> Option<SharedEmulator> {
        None
    }
}

impl PaneSource for SessionRegistry {
    fn emulator(&self, id: SessionId) -> Option<SharedEmulator> {
        self.term(sverb_conn::SessionId(id.0))
    }
}

impl<F: Fn(SessionId) -> Option<SharedEmulator>> PaneSource for F {
    fn emulator(&self, id: SessionId) -> Option<SharedEmulator> {
        self(id)
    }
}

/// A pane state overlay (`tasks/03-KEYBINDINGS.md` §4.4). Set by the tasks owning the state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum PaneOverlay {
    /// Live session: no overlay.
    #[default]
    None,
    /// Connecting (spinner frame, detail such as "hop 1/2" or "authenticating").
    Connecting {
        /// Advances the spinner.
        frame: usize,
        /// What is happening.
        detail: String,
    },
    /// Disconnected (M1-16): the reconnect banner
    /// `Disconnected (<reason>) — [Enter] reconnect · leader x close · leader i details`.
    Disconnected {
        /// Why (short, SPEC §6.1.9).
        reason: String,
        /// Auto-reconnect gave up after this many attempts.
        gave_up: Option<u32>,
    },
    /// Auto-reconnect countdown (M1-16):
    /// `Reconnecting in 4 s (attempt 3/10) — [Enter] now · [Esc] cancel · leader x close`.
    Reconnecting {
        /// Seconds until the next attempt.
        in_secs: u64,
        /// The attempt that starts when the countdown ends (1-based).
        attempt: u32,
        /// Attempts at most.
        of: u32,
    },
    /// The remote shell or local process exited (M1-12, M1-16): a footer, not a banner
    /// (SPEC §6.1.9).
    Exited {
        /// Exit code, if known.
        code: Option<i32>,
        /// An SSH session ended (`Session ended (exit N) — [Enter] reconnect`) rather
        /// than a local process (`Process exited (code N) — [Enter] restart`).
        remote: bool,
    },
    /// The vault is locked (M1-04): content hidden.
    Locked,
    /// The session task crashed.
    Crashed,
    // M3-03
    /// A workspace pane whose host was deleted: no session runs behind it.
    Missing {
        /// What is missing (`Host missing (deleted)`).
        what: String,
    },
}

/// Per-pane UI state kept by the reducer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PaneInfo {
    /// Host label (or `local`); the title when there is no OSC title.
    pub label: String,
    /// Title set by the remote (OSC 0/2).
    pub osc_title: Option<String>,
    /// The host's `color_scheme` (falls back to `terminal.color_scheme`).
    pub scheme: Option<String>,
    /// Overlay drawn over the content.
    pub overlay: PaneOverlay,
    /// Lines scrolled back (M3-04 drives it).
    pub scroll_offset: usize,
    /// The pane receives broadcast input (M3-02).
    pub broadcast: bool,
    /// The host item id (M1-13), so host edits find the host's panes.
    pub host: Option<String>,
    // M1-16
    /// Disconnect / reconnect bookkeeping (`app/sessions/reconnect.rs`).
    pub reconnect: ReconnectInfo,
}

// M1-16
/// What the reducer remembers about a pane's link between a drop and the next
/// connection (SPEC §6.1.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconnectInfo {
    /// Auto-reconnect attempts made since the last successful connection.
    pub attempt: u32,
    /// The running auto-reconnect countdown.
    pub countdown: Option<Countdown>,
    /// The user cancelled auto-reconnect (`Esc`) for this drop.
    pub cancelled: bool,
    /// A reconnect the user or the countdown asked for is in progress: the pane takes
    /// no input until it connects (prompts are dialogs and still work).
    pub in_progress: bool,
    /// The last error the session reported (`leader i` details).
    pub last_error: Option<sverb_core::error_report::ErrorReport>,
    /// Why the session disconnected last.
    pub reason: Option<String>,
}

// M1-16
/// An auto-reconnect countdown, ticked by `TimerKind::DialogTick(tick)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Countdown {
    /// The timer id (allocated from the dialog ids, so it never collides with one).
    pub tick: crate::views::DialogId,
    /// The attempt that starts when it ends (1-based).
    pub attempt: u32,
    /// Milliseconds left.
    pub remaining_ms: u64,
    /// The length of the pending tick in milliseconds.
    pub step_ms: u64,
}

// M3-04
/// Extra drawing for a pane in copy mode (or with a mouse selection), computed while the
/// emulator is locked for the draw ([`TerminalPane::render_with`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PaneDecor {
    /// The copy-mode cursor (grid coordinates); it becomes the real cursor of a focused pane.
    pub copy_cursor: Option<sverb_term::GridPoint>,
    /// Right-aligned text on the top border (`COPY · +12 lines`).
    pub badge: Option<String>,
    /// A line over the bottom row (the `/` prompt, "search wrapped", the match count).
    pub footer: Option<String>,
}

/// The real terminal cursor for the focused pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaneCursor {
    /// Absolute screen position.
    pub position: Position,
    /// Shape to pass through with DECSCUSR.
    pub shape: CursorShape,
    /// Blinking (DECSCUSR odd values).
    pub blinking: bool,
}

/// Everything needed to draw one pane.
#[derive(Debug)]
pub struct TerminalPane<'a> {
    /// Pane state.
    pub info: &'a PaneInfo,
    /// The UI theme (chrome and overlays).
    pub theme: &'a Theme,
    /// The pane has keyboard focus.
    pub focused: bool,
    /// The content's color scheme (`None` = `terminal`).
    pub scheme: Option<Arc<ColorScheme>>,
    /// Color depth of the outer terminal (`Mono` under `NO_COLOR`).
    pub depth: ColorDepth,
    /// `terminal.use_osc_title`.
    pub use_osc_title: bool,
    /// The leader as shown in hints (`^\`).
    pub leader: String,
}

impl TerminalPane<'_> {
    /// The title line text.
    pub fn title(&self) -> &str {
        match &self.info.osc_title {
            Some(t) if self.use_osc_title && !t.is_empty() => t,
            _ => &self.info.label,
        }
    }

    /// The emulator view for the content area.
    pub fn view(&self) -> ViewState {
        let fg = |s: Style| s.fg.unwrap_or(Color::Reset);
        ViewState {
            scroll_offset: self.info.scroll_offset,
            focused: self.focused,
            scheme: self.scheme.clone(),
            depth: self.depth,
            overlay: OverlayStyle {
                // M3-04: the current match must stand out from the others; themes whose
                // selection color is the accent color mark the other matches in `warn`.
                match_bg: if fg(self.theme.selection) == fg(self.theme.accent) {
                    fg(self.theme.warn)
                } else {
                    fg(self.theme.selection)
                },
                current_match_bg: fg(self.theme.accent),
                link_fg: fg(self.theme.accent),
            },
            broadcast_highlight: self.info.broadcast,
            ..ViewState::default()
        }
    }

    /// Draw the pane into `area`. Returns the real cursor for a focused live pane.
    pub fn render(
        &self,
        area: Rect,
        buf: &mut Buffer,
        emulator: Option<&SharedEmulator>,
    ) -> Option<PaneCursor> {
        self.render_with(area, buf, emulator, &|_, _| PaneDecor::default())
    }

    // M3-04
    /// [`TerminalPane::render`] with `decorate` adjusting the view (scroll offset, selection,
    /// search matches, hovered link) while the emulator is locked, and returning the copy
    /// cursor, the border badge and the footer line.
    pub fn render_with(
        &self,
        area: Rect,
        buf: &mut Buffer,
        emulator: Option<&SharedEmulator>,
        decorate: &dyn Fn(&dyn sverb_term::Emulator, &mut ViewState) -> PaneDecor,
    ) -> Option<PaneCursor> {
        let theme = self.theme;
        let border = if self.info.broadcast {
            theme.broadcast_border
        } else {
            theme.border_for(self.focused)
        };
        // M3-02: `≋` marks broadcast members (also readable without color).
        let marker = if self.info.broadcast {
            crate::views::sessions::broadcast::MARKER.to_owned() + " "
        } else {
            String::new()
        };
        let block = Block::bordered().border_style(border).title(Span::styled(
            format!(" {marker}{} ", super::truncate(self.title(), 64)),
            theme.title_for(self.focused),
        ));
        let inner = block.inner(area);
        block.render(area, buf);
        if inner.is_empty() {
            return None;
        }

        let mut view = self.view();
        let mut cursor = None;
        match emulator {
            Some(emu) if self.info.overlay != PaneOverlay::Locked => {
                // Locked only for this synchronous draw (never across an `.await`).
                let term = emu.lock();
                // M3-04: copy mode / mouse selection overlays.
                let decor = decorate(&**term, &mut view);
                term.render(inner, buf, &view);
                let info = term.cursor();
                drop(term);
                if let Some(p) = decor.copy_cursor {
                    cursor = self.copy_cursor(p, inner, &view);
                }
                self.render_decor(area, inner, buf, &decor);
                if decor.copy_cursor.is_some() {
                    // The copy cursor replaces the terminal cursor.
                } else if self.focused && self.info.overlay == PaneOverlay::None {
                    cursor =
                        sverb_term::render::cursor_position(&info, inner, &view).map(|position| {
                            PaneCursor {
                                position,
                                shape: info.shape,
                                blinking: info.blinking,
                            }
                        });
                }
            }
            _ => Clear.render(inner, buf),
        }
        self.render_overlay(inner, buf, emulator.is_some());
        cursor
    }

    // M3-04
    /// The copy cursor as the real cursor (focused pane, visible row) or a reversed cell.
    fn copy_cursor(
        &self,
        p: sverb_term::GridPoint,
        inner: Rect,
        view: &ViewState,
    ) -> Option<PaneCursor> {
        let y = i64::from(p.line) + i64::try_from(view.scroll_offset).unwrap_or(0);
        let y = u16::try_from(y).ok().filter(|y| *y < inner.height)?;
        let x = u16::try_from(p.column).ok().filter(|x| *x < inner.width)?;
        let position = Position::new(inner.x + x, inner.y + y);
        if self.focused && self.info.overlay == PaneOverlay::None {
            Some(PaneCursor {
                position,
                shape: CursorShape::Block,
                blinking: false,
            })
        } else {
            None
        }
    }

    // M3-04
    fn render_decor(&self, area: Rect, inner: Rect, buf: &mut Buffer, decor: &PaneDecor) {
        if let Some(badge) = &decor.badge {
            let text = format!(" {badge} ");
            let w = u16::try_from(text.chars().count()).unwrap_or(u16::MAX);
            // Keep the corner and the title's first cells.
            if area.width > w + 4 {
                let x = area.x + area.width - 1 - w;
                buf.set_string(x, area.y, text, self.theme.accent);
            }
        }
        if let Some(text) = &decor.footer
            && inner.height > 0
        {
            footer(inner, buf, self.theme, text);
        }
    }

    fn render_overlay(&self, inner: Rect, buf: &mut Buffer, live: bool) {
        let theme = self.theme;
        let leader = &self.leader;
        match &self.info.overlay {
            PaneOverlay::None if live => {}
            PaneOverlay::None => {
                centered(inner, buf, vec![Line::styled("Session ended.", theme.dim)]);
            }
            PaneOverlay::Connecting { frame, detail } => {
                // M7-07: frames from `theme::glyphs` (static with `ui.reduce_motion`).
                let spin = theme.spinner(*frame);
                let mut lines = vec![Line::styled(format!("{spin} connecting…"), theme.accent)];
                if !detail.is_empty() {
                    lines.push(Line::styled(detail.clone(), theme.dim));
                }
                centered(inner, buf, lines);
            }
            // M1-16
            PaneOverlay::Disconnected { reason, gave_up } => banner(
                inner,
                buf,
                theme,
                theme.error,
                match gave_up {
                    Some(n) => format!("Disconnected ({reason}) — gave up after {n} attempts"),
                    None => format!("Disconnected ({reason})"),
                },
                format!("[Enter] reconnect · {leader} x close · {leader} i details"),
            ),
            PaneOverlay::Reconnecting {
                in_secs,
                attempt,
                of,
            } => banner(
                inner,
                buf,
                theme,
                theme.warn,
                format!("Reconnecting in {in_secs} s (attempt {attempt}/{of})"),
                format!("[Enter] now · [Esc] cancel · {leader} x close"),
            ),
            PaneOverlay::Exited { code, remote } => {
                let text = match (remote, code) {
                    (true, Some(c)) => {
                        format!("Session ended (exit {c}) — [Enter] reconnect · {leader} x close")
                    }
                    (true, None) => {
                        format!("Session ended — [Enter] reconnect · {leader} x close")
                    }
                    (false, Some(c)) => {
                        format!("Process exited (code {c}) — [Enter] restart · {leader} x close")
                    }
                    (false, None) => {
                        format!("Process exited — [Enter] restart · {leader} x close")
                    }
                };
                footer(inner, buf, theme, &text);
            }
            PaneOverlay::Locked => {
                Clear.render(inner, buf);
                centered(
                    inner,
                    buf,
                    vec![
                        Line::styled("🔒 Vault locked", theme.accent),
                        Line::styled(format!("unlock to continue · {leader} q quit"), theme.dim),
                    ],
                );
            }
            PaneOverlay::Crashed => banner(
                inner,
                buf,
                theme,
                theme.error,
                "Session crashed (see the log)".to_owned(),
                format!("{leader} x close"),
            ),
            // M3-03
            PaneOverlay::Missing { what } => {
                Clear.render(inner, buf);
                banner(
                    inner,
                    buf,
                    theme,
                    theme.warn,
                    what.clone(),
                    format!("{leader} x close"),
                );
            }
        }
    }
}

/// Lines centered in `area` (no background change).
fn centered(area: Rect, buf: &mut Buffer, lines: Vec<Line<'_>>) {
    let h = u16::try_from(lines.len())
        .unwrap_or(u16::MAX)
        .min(area.height);
    let y = area.y + (area.height - h) / 2;
    Paragraph::new(lines)
        .centered()
        .render(Rect::new(area.x, y, area.width, h), buf);
}

/// A bordered two-line banner at the bottom of `area`, over the content.
fn banner(
    area: Rect,
    buf: &mut Buffer,
    theme: &Theme,
    title: Style,
    message: String,
    keys: String,
) {
    if area.height < 4 {
        return footer(area, buf, theme, &format!("{message} · {keys}"));
    }
    let rect = Rect::new(area.x, area.y + area.height - 4, area.width, 4);
    Clear.render(rect, buf);
    Paragraph::new(vec![
        Line::styled(message, title),
        Line::styled(keys, theme.dim),
    ])
    .wrap(Wrap { trim: true })
    .block(Block::bordered().border_style(theme.border_focused))
    .style(theme.toast)
    .render(rect, buf);
}

/// One reversed line at the bottom of `area`.
fn footer(area: Rect, buf: &mut Buffer, theme: &Theme, text: &str) {
    let rect = Rect::new(area.x, area.y + area.height - 1, area.width, 1);
    let style = theme.status.add_modifier(Modifier::BOLD);
    Clear.render(rect, buf);
    Paragraph::new(Line::styled(
        super::truncate(text, usize::from(area.width)),
        style,
    ))
    .style(style)
    .render(rect, buf);
}

/// The DECSCUSR command for a pane cursor (`None`: the user's default shape). A hollow
/// block is sent as a block (DECSCUSR has no hollow shape).
pub fn cursor_style(shape: Option<(CursorShape, bool)>) -> crossterm::cursor::SetCursorStyle {
    use crossterm::cursor::SetCursorStyle as S;
    match shape {
        None => S::DefaultUserShape,
        Some((CursorShape::Block | CursorShape::HollowBlock, true)) => S::BlinkingBlock,
        Some((CursorShape::Block | CursorShape::HollowBlock, false)) => S::SteadyBlock,
        Some((CursorShape::Underline, true)) => S::BlinkingUnderScore,
        Some((CursorShape::Underline, false)) => S::SteadyUnderScore,
        Some((CursorShape::Bar, true)) => S::BlinkingBar,
        Some((CursorShape::Bar, false)) => S::SteadyBar,
    }
}

/// The outer terminal's cell size in pixels (`(0, 0)` if unknown), for `CSI 14 t` replies
/// and `window_change` pixel parameters.
pub fn cell_pixel_size() -> (u16, u16) {
    crossterm::terminal::window_size()
        .ok()
        .filter(|w| w.columns > 0 && w.rows > 0)
        .map_or((0, 0), |w| (w.width / w.columns, w.height / w.rows))
}

/// A pane's size in pixels for `window_change` (0 when the cell size is unknown).
pub fn pane_pixel_size(cols: u16, rows: u16, cell: (u16, u16)) -> (u32, u32) {
    (
        u32::from(cols) * u32::from(cell.0),
        u32::from(rows) * u32::from(cell.1),
    )
}

/// Load the terminal color schemes: built-ins plus `themes_dir/*.toml`. The user names are
/// published for config validation (`UiThemeCatalog`). Broken files are returned so the
/// caller can report them; the others still load.
pub fn load_schemes(
    themes_dir: Option<&std::path::Path>,
) -> (Arc<SchemeCatalog>, Vec<SchemeLoadError>) {
    match themes_dir {
        Some(dir) => {
            let (catalog, errors) = SchemeCatalog::load(dir);
            (Arc::new(catalog), errors)
        }
        None => (Arc::new(SchemeCatalog::builtin_only()), Vec::new()),
    }
}

/// The color depth for pane content: the UI depth, or `Mono` under `NO_COLOR`.
pub fn pane_depth(theme_depth: ColorDepth, no_color: bool) -> ColorDepth {
    if no_color {
        ColorDepth::Mono
    } else {
        theme_depth
    }
}

/// Resolve a scheme name against a catalog (`terminal` and unknown names → `None`).
pub fn resolve_scheme(catalog: &SchemeCatalog, name: &str) -> Option<Arc<ColorScheme>> {
    if name == scheme::TERMINAL {
        None
    } else {
        catalog.get(name)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used)]

    use ratatui::style::Color;
    use sverb_term::{AlacrittyEmulator, Emulator, EmulatorConfig};

    use super::*;

    pub(crate) fn new_emulator(cols: u16, rows: u16, bytes: &[u8]) -> SharedEmulator {
        let mut e = AlacrittyEmulator::new(EmulatorConfig {
            cols,
            rows,
            scrollback: 100,
        });
        e.feed(bytes);
        let boxed: Box<dyn Emulator> = Box::new(e);
        Arc::new(boxed.into())
    }

    fn pane<'a>(info: &'a PaneInfo, theme: &'a Theme, focused: bool) -> TerminalPane<'a> {
        TerminalPane {
            info,
            theme,
            focused,
            scheme: None,
            depth: ColorDepth::TrueColor,
            use_osc_title: false,
            leader: "^\\".to_owned(),
        }
    }

    fn text(buf: &Buffer) -> String {
        let a = buf.area;
        let mut s = String::new();
        for y in 0..a.height {
            for x in 0..a.width {
                s.push_str(buf[(x, y)].symbol());
            }
            s.push('\n');
        }
        s
    }

    #[test]
    fn content_title_and_cursor() {
        let theme = Theme::default();
        let info = PaneInfo {
            label: "web-1".to_owned(),
            osc_title: Some("vim".to_owned()),
            ..PaneInfo::default()
        };
        let emu = new_emulator(20, 4, b"\x1b[31mhi");
        let area = Rect::new(0, 0, 22, 6);
        let mut buf = Buffer::empty(area);
        let cursor = pane(&info, &theme, true).render(area, &mut buf, Some(&emu));
        let t = text(&buf);
        assert!(t.contains("web-1"), "{t}");
        assert!(t.contains("hi"));
        assert_eq!(buf[(1, 1)].fg, Color::Indexed(1));
        assert_eq!(cursor.map(|c| c.position), Some(Position::new(3, 1)));

        let mut p = pane(&info, &theme, false);
        p.use_osc_title = true;
        assert_eq!(p.title(), "vim");
        let mut buf = Buffer::empty(area);
        assert_eq!(p.render(area, &mut buf, Some(&emu)), None, "unfocused");
        assert!(
            buf[(3, 1)].modifier.contains(Modifier::UNDERLINED),
            "hollow"
        );
    }

    #[test]
    fn overlays() {
        let theme = Theme::default();
        let emu = new_emulator(60, 8, b"secret output");
        let area = Rect::new(0, 0, 62, 10);
        for (overlay, needle) in [
            (
                PaneOverlay::Disconnected {
                    reason: "reset".to_owned(),
                    gave_up: None,
                },
                "[Enter] reconnect · ^\\ x close · ^\\ i details",
            ),
            (
                PaneOverlay::Exited {
                    code: Some(1),
                    remote: false,
                },
                "code 1",
            ),
            (PaneOverlay::Crashed, "crashed"),
            // M3-03
            (
                PaneOverlay::Missing {
                    what: "Host missing (deleted)".to_owned(),
                },
                "Host missing",
            ),
            (
                PaneOverlay::Reconnecting {
                    in_secs: 3,
                    attempt: 2,
                    of: 10,
                },
                "in 3 s (attempt 2/10)",
            ),
            (
                PaneOverlay::Connecting {
                    frame: 0,
                    detail: "hop 1/2".to_owned(),
                },
                "connecting",
            ),
        ] {
            let info = PaneInfo {
                overlay,
                ..PaneInfo::default()
            };
            let mut buf = Buffer::empty(area);
            let cursor = pane(&info, &theme, true).render(area, &mut buf, Some(&emu));
            assert_eq!(cursor, None, "no cursor under an overlay");
            assert!(text(&buf).contains(needle), "{needle}\n{}", text(&buf));
        }
        let info = PaneInfo {
            overlay: PaneOverlay::Locked,
            ..PaneInfo::default()
        };
        let mut buf = Buffer::empty(area);
        pane(&info, &theme, true).render(area, &mut buf, Some(&emu));
        let t = text(&buf);
        assert!(t.contains("Vault locked"));
        assert!(!t.contains("secret"), "content hidden while locked");
    }

    #[test]
    fn broadcast_border_and_no_emulator() {
        let theme = Theme::default();
        let info = PaneInfo {
            broadcast: true,
            ..PaneInfo::default()
        };
        let area = Rect::new(0, 0, 30, 5);
        let mut buf = Buffer::empty(area);
        pane(&info, &theme, false).render(area, &mut buf, None);
        assert_eq!(buf[(0, 0)].fg, theme.broadcast_border.fg.unwrap());
        assert!(text(&buf).contains("Session ended."));
    }

    // M3-04
    #[test]
    fn decor_badge_footer_and_copy_cursor() {
        let theme = Theme::default();
        let info = PaneInfo::default();
        let emu = new_emulator(20, 4, b"one\r\ntwo");
        let area = Rect::new(0, 0, 22, 6);
        let mut buf = Buffer::empty(area);
        let cursor = pane(&info, &theme, true).render_with(area, &mut buf, Some(&emu), &|e, v| {
            assert_eq!(e.size(), (20, 4));
            v.scroll_offset = 0;
            PaneDecor {
                copy_cursor: Some(sverb_term::GridPoint::new(0, 1)),
                badge: Some("COPY".to_owned()),
                footer: Some("/foo".to_owned()),
            }
        });
        let t = text(&buf);
        assert!(t.lines().next().unwrap().contains(" COPY "), "{t}");
        assert!(t.lines().nth(4).unwrap().contains("/foo"), "{t}");
        assert_eq!(cursor.map(|c| c.position), Some(Position::new(2, 1)));
    }

    #[test]
    fn decscusr() {
        use crossterm::cursor::SetCursorStyle as S;
        let code = |s: S| {
            let mut out = String::new();
            crossterm::Command::write_ansi(&s, &mut out).unwrap();
            out
        };
        assert_eq!(code(cursor_style(None)), code(S::DefaultUserShape));
        assert_eq!(
            code(cursor_style(Some((CursorShape::Bar, false)))),
            "\x1b[6 q"
        );
        assert_eq!(
            code(cursor_style(Some((CursorShape::Underline, true)))),
            "\x1b[3 q"
        );
    }

    #[test]
    fn helpers() {
        assert_eq!(pane_pixel_size(80, 24, (9, 18)), (720, 432));
        assert_eq!(pane_pixel_size(80, 24, (0, 0)), (0, 0));
        assert_eq!(pane_depth(ColorDepth::TrueColor, true), ColorDepth::Mono);
        let cat = SchemeCatalog::builtin_only();
        assert!(resolve_scheme(&cat, "terminal").is_none());
        assert!(resolve_scheme(&cat, "nope").is_none());
        assert!(resolve_scheme(&cat, "nord").is_some());
        // Tiny areas never panic.
        let theme = Theme::default();
        let info = PaneInfo {
            overlay: PaneOverlay::Disconnected {
                reason: "x".to_owned(),
                gave_up: None,
            },
            ..PaneInfo::default()
        };
        for (w, h) in [(0, 0), (1, 1), (2, 2), (3, 3), (5, 4)] {
            let area = Rect::new(0, 0, w, h);
            let mut buf = Buffer::empty(area);
            pane(&info, &theme, true).render(area, &mut buf, None);
        }
    }
}
