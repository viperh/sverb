//! The built-in UI themes (SPEC §8.8): `default-dark`, `default-light`, `high-contrast`.
//!
//! User UI themes are not in the spec (only terminal color schemes are, §7.4).

use ratatui::style::{Color, Modifier};

use super::UiTheme;

/// The default theme name (`ui.theme` default).
pub const DEFAULT_THEME: &str = "default-dark";

/// Names of the built-in themes, in display order.
pub const BUILTIN_NAMES: [&str; 3] = ["default-dark", "default-light", "high-contrast"];

/// Dark chrome on the terminal's own background.
pub const DEFAULT_DARK: UiTheme = UiTheme {
    name: "default-dark",
    bg: Color::Reset,
    fg: Color::Reset,
    dim: Color::Rgb(128, 128, 128),
    border: Color::Rgb(88, 88, 88),
    border_focused: Color::Rgb(97, 175, 239),
    accent: Color::Rgb(97, 175, 239),
    selection: Color::Rgb(97, 175, 239),
    sidebar_bg: Color::Reset,
    status_bg: Color::Rgb(40, 44, 52),
    status_fg: Color::Rgb(171, 178, 191),
    ok: Color::Rgb(152, 195, 121),
    warn: Color::Rgb(229, 192, 123),
    error: Color::Rgb(224, 108, 117),
    info: Color::Rgb(97, 175, 239),
    broadcast_border: Color::Rgb(198, 120, 221),
    toast_bg: Color::Rgb(40, 44, 52),
    selection_modifier: Modifier::REVERSED,
};

/// Light chrome with its own background.
pub const DEFAULT_LIGHT: UiTheme = UiTheme {
    name: "default-light",
    bg: Color::Rgb(250, 250, 250),
    fg: Color::Rgb(56, 58, 66),
    dim: Color::Rgb(140, 141, 147),
    border: Color::Rgb(190, 190, 190),
    border_focused: Color::Rgb(64, 120, 242),
    accent: Color::Rgb(64, 120, 242),
    selection: Color::Rgb(64, 120, 242),
    sidebar_bg: Color::Rgb(240, 240, 240),
    status_bg: Color::Rgb(229, 229, 230),
    status_fg: Color::Rgb(56, 58, 66),
    ok: Color::Rgb(80, 161, 79),
    warn: Color::Rgb(193, 132, 1),
    error: Color::Rgb(228, 86, 73),
    info: Color::Rgb(1, 132, 188),
    broadcast_border: Color::Rgb(166, 38, 164),
    toast_bg: Color::Rgb(240, 240, 240),
    selection_modifier: Modifier::REVERSED,
};

/// The 16 base colors only, at maximum contrast (also fine on 16-color terminals).
pub const HIGH_CONTRAST: UiTheme = UiTheme {
    name: "high-contrast",
    bg: Color::Black,
    fg: Color::White,
    dim: Color::Gray,
    border: Color::White,
    border_focused: Color::Yellow,
    accent: Color::Yellow,
    selection: Color::Yellow,
    sidebar_bg: Color::Black,
    status_bg: Color::White,
    status_fg: Color::Black,
    ok: Color::LightGreen,
    warn: Color::LightYellow,
    error: Color::LightRed,
    info: Color::LightCyan,
    broadcast_border: Color::LightMagenta,
    toast_bg: Color::Black,
    selection_modifier: Modifier::REVERSED,
};

/// A built-in theme by name.
pub fn by_name(name: &str) -> Option<&'static UiTheme> {
    [&DEFAULT_DARK, &DEFAULT_LIGHT, &HIGH_CONTRAST]
        .into_iter()
        .find(|t| t.name == name)
}
