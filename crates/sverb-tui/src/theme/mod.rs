//! UI themes (M0-11, SPEC §8.8).
//!
//! A [`UiTheme`] names colors by role (`border`, `accent`, `selection`, …). The
//! reducer keeps a resolved [`Theme`]: ready-to-use [`Style`]s, computed once from the
//! theme, `NO_COLOR` and the color depth ([`ThemeEnv`]). Views only ever use the
//! resolved styles, so they never branch on monochrome or color depth themselves.
//!
//! - **`NO_COLOR`** (any non-empty value): every role resolves to `Color::Reset`;
//!   focus and selection are shown with reverse video and bold only.
//! - **Color depth**: without truecolor ([`ColorDepth::detect`]) RGB roles are
//!   downsampled to the 256-color palette ([`color::downsample`]).
//!
//! Theme names are validated by [`UiThemeCatalog`] (the real `ThemeCatalog`).

pub mod builtin;
pub mod color;
// M7-07
pub mod glyphs;

use std::ffi::OsStr;

use ratatui::style::{Color, Modifier, Style};
use sverb_core::config::{ThemeCatalog, TruecolorMode};

pub use self::color::ColorDepth;

/// Colors by role. Built-ins are in [`builtin`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UiTheme {
    /// Theme name (`ui.theme`).
    pub name: &'static str,
    /// Background of the whole UI (`Reset` = the terminal's own).
    pub bg: Color,
    /// Default text.
    pub fg: Color,
    /// Secondary text (hints, timestamps, empty states).
    pub dim: Color,
    /// Borders of unfocused regions.
    pub border: Color,
    /// Border of the focused region.
    pub border_focused: Color,
    /// Highlights: titles of focused regions, the mode segment, the sidebar marker.
    pub accent: Color,
    /// Selected row (combined with [`UiTheme::selection_modifier`]).
    pub selection: Color,
    /// Sidebar background.
    pub sidebar_bg: Color,
    /// Status bar background.
    pub status_bg: Color,
    /// Status bar text.
    pub status_fg: Color,
    /// Success.
    pub ok: Color,
    /// Warnings.
    pub warn: Color,
    /// Errors.
    pub error: Color,
    /// Information.
    pub info: Color,
    /// Border of panes receiving broadcast input (M3-02).
    pub broadcast_border: Color,
    /// Toast background.
    pub toast_bg: Color,
    /// How the selected row is marked besides its color (default: reverse).
    pub selection_modifier: Modifier,
}

/// What the outer terminal supports, read once at startup by the runtime.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ThemeEnv {
    /// `NO_COLOR` is set to a non-empty value.
    pub no_color: bool,
    /// `COLORTERM` says `truecolor`/`24bit` (the depth itself also depends on `ui.truecolor`).
    pub colorterm_truecolor: bool,
}

impl ThemeEnv {
    /// From the values of `NO_COLOR` and `COLORTERM` (pure, so tests needn't touch the env).
    pub fn from_vars(no_color: Option<&OsStr>, colorterm: Option<&OsStr>) -> Self {
        let colorterm = colorterm.and_then(OsStr::to_str);
        Self {
            no_color: no_color.is_some_and(|v| !v.is_empty()),
            colorterm_truecolor: ColorDepth::detect(TruecolorMode::Auto, colorterm)
                == ColorDepth::TrueColor,
        }
    }

    /// The process environment.
    pub fn from_process() -> Self {
        // M7-04: the shared detection (`runtime::capabilities`, also used by `sverb doctor`).
        Self::from_term_env(&crate::runtime::capabilities::TermEnv::from_process())
    }

    // M7-04
    /// From the shared terminal environment.
    pub fn from_term_env(env: &crate::runtime::capabilities::TermEnv) -> Self {
        Self {
            no_color: env.no_color,
            colorterm_truecolor: env.truecolor(),
        }
    }

    /// The color depth for a `ui.truecolor` setting.
    pub fn depth(self, mode: TruecolorMode) -> ColorDepth {
        ColorDepth::detect(mode, self.colorterm_truecolor.then_some("truecolor"))
    }
}

/// A resolved theme: one [`Style`] per use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Theme {
    /// The theme's name.
    pub name: &'static str,
    /// `NO_COLOR` is in effect.
    pub monochrome: bool,
    /// The whole screen.
    pub base: Style,
    /// Secondary text.
    pub dim: Style,
    /// Unfocused borders.
    pub border: Style,
    /// The focused region's border.
    pub border_focused: Style,
    /// The focused region's title.
    pub title_focused: Style,
    /// Accent text (headings, the sidebar marker).
    pub accent: Style,
    /// The selected row.
    pub selection: Style,
    /// The sidebar background.
    pub sidebar: Style,
    /// The status bar (and the merged tab-bar row).
    pub status: Style,
    /// The status bar's mode segment.
    pub status_mode: Style,
    /// The top bar.
    pub top_bar: Style,
    /// Success text.
    pub ok: Style,
    /// Warning text.
    pub warn: Style,
    /// Error text.
    pub error: Style,
    /// Info text.
    pub info: Style,
    /// Broadcast pane border (M3-02).
    pub broadcast_border: Style,
    /// Toast body.
    pub toast: Style,
    // M7-07 (spec additions `ui.ascii`, `ui.reduce_motion`)
    /// Draw ASCII instead of box-drawing and symbol glyphs ([`glyphs::asciify`]).
    pub ascii: bool,
    /// No animated glyphs ([`glyphs::spinner`]).
    pub reduce_motion: bool,
}

impl Default for Theme {
    fn default() -> Self {
        Self::resolve(
            builtin::DEFAULT_THEME,
            TruecolorMode::On,
            ThemeEnv::default(),
        )
    }
}

impl Theme {
    /// Resolve `name` (unknown names fall back to `default-dark`; config validation
    /// rejects them earlier) for `ui.truecolor` and the terminal environment.
    pub fn resolve(name: &str, truecolor: TruecolorMode, env: ThemeEnv) -> Self {
        let ui = builtin::by_name(name).unwrap_or(&builtin::DEFAULT_DARK);
        Self::from_ui(ui, env.depth(truecolor), env.no_color)
    }

    /// Resolve a [`UiTheme`] at a color depth, optionally monochrome.
    pub fn from_ui(ui: &UiTheme, depth: ColorDepth, no_color: bool) -> Self {
        if no_color {
            return Self::monochrome(ui.name);
        }
        let c = |color: Color| color::downsample(color, depth);
        let fg = |color: Color| Style::new().fg(c(color));
        let bold = Modifier::BOLD;
        Self {
            name: ui.name,
            monochrome: false,
            base: Style::new().fg(c(ui.fg)).bg(c(ui.bg)),
            dim: fg(ui.dim),
            border: fg(ui.border),
            border_focused: fg(ui.border_focused),
            title_focused: fg(ui.accent).add_modifier(bold),
            accent: fg(ui.accent).add_modifier(bold),
            selection: fg(ui.selection).add_modifier(ui.selection_modifier | bold),
            sidebar: Style::new().bg(c(ui.sidebar_bg)),
            status: Style::new().fg(c(ui.status_fg)).bg(c(ui.status_bg)),
            status_mode: Style::new()
                .fg(c(ui.status_bg))
                .bg(c(ui.accent))
                .add_modifier(bold),
            top_bar: Style::new().fg(c(ui.fg)).bg(c(ui.bg)),
            ok: fg(ui.ok),
            warn: fg(ui.warn).add_modifier(bold),
            error: fg(ui.error).add_modifier(bold),
            info: fg(ui.info),
            broadcast_border: fg(ui.broadcast_border),
            toast: Style::new().fg(c(ui.fg)).bg(c(ui.toast_bg)),
            ascii: false,
            reduce_motion: false,
        }
    }

    /// `NO_COLOR`: no colors at all; focus and selection use reverse video and bold.
    fn monochrome(name: &'static str) -> Self {
        let plain = Style::new();
        let bold = Style::new().add_modifier(Modifier::BOLD);
        let rev_bold = Style::new().add_modifier(Modifier::REVERSED | Modifier::BOLD);
        let rev = Style::new().add_modifier(Modifier::REVERSED);
        Self {
            name,
            monochrome: true,
            base: plain,
            dim: plain,
            border: plain,
            border_focused: bold,
            title_focused: rev_bold,
            accent: bold,
            selection: rev_bold,
            sidebar: plain,
            status: rev,
            status_mode: bold,
            top_bar: plain,
            ok: plain,
            warn: bold,
            error: bold,
            info: plain,
            broadcast_border: bold,
            toast: plain,
            ascii: false,
            reduce_motion: false,
        }
    }

    // M7-07
    /// With the glyph settings: ASCII output and reduced motion.
    #[must_use]
    pub fn with_glyphs(mut self, ascii: bool, reduce_motion: bool) -> Self {
        self.ascii = ascii;
        self.reduce_motion = reduce_motion;
        self
    }

    /// The spinner glyph for `frame` (static with `ui.reduce_motion`).
    pub fn spinner(&self, frame: usize) -> char {
        glyphs::spinner(frame, self.reduce_motion)
    }

    /// Border style for a region.
    pub fn border_for(&self, focused: bool) -> Style {
        if focused {
            self.border_focused
        } else {
            self.border
        }
    }

    /// Title style for a region.
    pub fn title_for(&self, focused: bool) -> Style {
        if focused {
            self.title_focused
        } else {
            self.border
        }
    }
}

/// The real [`ThemeCatalog`] for `config.toml` validation: the built-in UI themes and
/// (M1-10) the terminal color schemes: built-ins plus the user schemes published by the
/// last `SchemeCatalog::load` (`widgets::terminal_pane::load_schemes`).
#[derive(Debug, Clone, Copy, Default)]
pub struct UiThemeCatalog;

impl ThemeCatalog for UiThemeCatalog {
    fn has_ui_theme(&self, name: &str) -> bool {
        builtin::by_name(name).is_some()
    }

    fn has_color_scheme(&self, name: &str) -> bool {
        // M1-10: the color scheme catalog.
        sverb_term::scheme::scheme_known(name)
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;

    fn colors(style: Style) -> [Option<Color>; 2] {
        [style.fg, style.bg]
    }

    #[test]
    fn catalog_knows_the_builtins() {
        for name in builtin::BUILTIN_NAMES {
            assert!(UiThemeCatalog.has_ui_theme(name), "{name}");
        }
        assert!(!UiThemeCatalog.has_ui_theme("solarized"));
        // M1-10: terminal color schemes.
        for name in sverb_term::scheme::BUILTIN_NAMES {
            assert!(UiThemeCatalog.has_color_scheme(name), "{name}");
        }
        assert!(!UiThemeCatalog.has_color_scheme("solarized"));
    }

    #[test]
    fn no_color_means_no_colors() {
        for name in builtin::BUILTIN_NAMES {
            let env = ThemeEnv {
                no_color: true,
                colorterm_truecolor: true,
            };
            let t = Theme::resolve(name, TruecolorMode::On, env);
            assert!(t.monochrome);
            for s in [
                t.base,
                t.dim,
                t.border,
                t.border_focused,
                t.title_focused,
                t.accent,
                t.selection,
                t.sidebar,
                t.status,
                t.status_mode,
                t.top_bar,
                t.ok,
                t.warn,
                t.error,
                t.info,
                t.broadcast_border,
                t.toast,
            ] {
                assert!(
                    colors(s)
                        .iter()
                        .all(|c| c.is_none() || *c == Some(Color::Reset)),
                    "{name}: {s:?}"
                );
            }
            assert!(
                t.selection
                    .add_modifier
                    .contains(Modifier::REVERSED | Modifier::BOLD)
            );
        }
    }

    #[test]
    fn no_color_needs_a_non_empty_value() {
        let set = OsString::from("1");
        let empty = OsString::new();
        assert!(ThemeEnv::from_vars(Some(&set), None).no_color);
        assert!(!ThemeEnv::from_vars(Some(&empty), None).no_color);
        assert!(!ThemeEnv::from_vars(None, None).no_color);
    }

    // T-18 (theme side): `auto` follows COLORTERM; RGB roles are downsampled without it.
    #[test]
    fn depth_follows_colorterm_and_downsamples() {
        let truecolor = ThemeEnv::from_vars(None, Some(OsStr::new("truecolor")));
        assert_eq!(truecolor.depth(TruecolorMode::Auto), ColorDepth::TrueColor);
        let unset = ThemeEnv::from_vars(None, None);
        assert_eq!(unset.depth(TruecolorMode::Auto), ColorDepth::Indexed256);
        assert_eq!(unset.depth(TruecolorMode::On), ColorDepth::TrueColor);

        let t = Theme::resolve("default-dark", TruecolorMode::Auto, unset);
        assert!(
            matches!(t.border.fg, Some(Color::Indexed(_))),
            "{:?}",
            t.border
        );
        let t = Theme::resolve("default-dark", TruecolorMode::Auto, truecolor);
        assert!(
            matches!(t.border.fg, Some(Color::Rgb(..))),
            "{:?}",
            t.border
        );
    }

    #[test]
    fn unknown_theme_falls_back_to_default_dark() {
        let t = Theme::resolve("nope", TruecolorMode::On, ThemeEnv::default());
        assert_eq!(t.name, "default-dark");
    }
}
