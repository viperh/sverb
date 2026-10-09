//! Terminal modes requested by the remote application (SPEC §7.1, §7.3).
//!
//! These are emulator-agnostic: the key/mouse encoders and the runtime layer read them through
//! [`crate::Emulator::modes`] and never see `alacritty_terminal` types.

/// Mouse reporting mode requested by the remote (DECSET 1000/1002/1003).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum MouseMode {
    /// No mouse reporting: the mouse drives sverb.
    #[default]
    None,
    /// `?1000`: report button presses and releases.
    Click,
    /// `?1002`: also report motion while a button is held.
    Drag,
    /// `?1003`: report all motion.
    Motion,
}

/// Mouse report encoding requested by the remote (DECSET 1005/1006/1015).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum MouseEncoding {
    /// Legacy X10 encoding (`ESC [ M b x y`, coordinates limited to 223).
    #[default]
    Default,
    /// `?1005`: UTF-8 extended coordinates.
    Utf8,
    /// `?1006`: SGR encoding (`ESC [ < b ; x ; y M/m`).
    Sgr,
    /// `?1015`: urxvt decimal encoding (`ESC [ b ; x ; y M`).
    Urxvt,
}

/// Cursor shape (DECSCUSR).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum CursorShape {
    #[default]
    Block,
    Underline,
    Bar,
    /// Hollow block; only used for unfocused panes by the renderer, never requested remotely.
    HollowBlock,
}

impl CursorShape {
    /// The `DECSCUSR` parameter (`ESC [ n SP q`) for this shape.
    #[must_use]
    pub fn decscusr(self, blinking: bool) -> u8 {
        let base = match self {
            Self::Block | Self::HollowBlock => 1,
            Self::Underline => 3,
            Self::Bar => 5,
        };
        if blinking { base } else { base + 1 }
    }
}

/// Kitty keyboard protocol flags requested by the remote (`CSI > flags u`).
///
/// Bit values follow the protocol: 1 disambiguate, 2 report event types, 4 report alternate keys,
/// 8 report all keys as escape codes, 16 report associated text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct KittyKeyboardFlags(pub u8);

impl KittyKeyboardFlags {
    pub const DISAMBIGUATE_ESC_CODES: u8 = 1;
    pub const REPORT_EVENT_TYPES: u8 = 2;
    pub const REPORT_ALTERNATE_KEYS: u8 = 4;
    pub const REPORT_ALL_KEYS_AS_ESC: u8 = 8;
    pub const REPORT_ASSOCIATED_TEXT: u8 = 16;

    /// Whether `flag` (one of the constants) is set.
    #[must_use]
    pub fn contains(self, flag: u8) -> bool {
        self.0 & flag == flag
    }

    /// Whether the remote enabled the kitty protocol at all.
    #[must_use]
    pub fn is_active(self) -> bool {
        self.0 != 0
    }
}

/// Every mode the input encoders and the runtime need from the emulator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(clippy::struct_excessive_bools)]
pub struct TermModes {
    /// DECCKM (`?1`): application cursor keys.
    pub app_cursor: bool,
    /// DECKPAM (`ESC =`): application keypad.
    pub app_keypad: bool,
    pub mouse_mode: MouseMode,
    pub mouse_encoding: MouseEncoding,
    /// `?2004`.
    pub bracketed_paste: bool,
    /// `?1004`.
    pub focus_reporting: bool,
    /// `?1049`/`?47`/`?1047`.
    pub alt_screen: bool,
    /// `?1007`: wheel sends arrow keys on the alternate screen.
    pub alternate_scroll: bool,
    /// LNM (`CSI 20 h`): Enter sends `\r\n`.
    pub line_feed_new_line: bool,
    /// xterm modifyOtherKeys level (`CSI > 4 ; n m`): 0, 1 or 2.
    pub modify_other_keys: u8,
    pub kitty_keyboard: KittyKeyboardFlags,
    pub cursor_shape: CursorShape,
    pub cursor_blinking: bool,
    /// DECTCEM (`?25`).
    pub cursor_visible: bool,
}

impl Default for TermModes {
    fn default() -> Self {
        Self {
            app_cursor: false,
            app_keypad: false,
            mouse_mode: MouseMode::None,
            mouse_encoding: MouseEncoding::Default,
            bracketed_paste: false,
            focus_reporting: false,
            alt_screen: false,
            alternate_scroll: true,
            line_feed_new_line: false,
            modify_other_keys: 0,
            kitty_keyboard: KittyKeyboardFlags(0),
            cursor_shape: CursorShape::Block,
            cursor_blinking: false,
            cursor_visible: true,
        }
    }
}

// The input encoders (keys, mouse, paste) live in `src/input/`. They are declared
// here because `lib.rs` was held by another agent; `lib.rs` re-exports them as
#[path = "input/mod.rs"]
pub mod input;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decscusr_values() {
        assert_eq!(CursorShape::Block.decscusr(true), 1);
        assert_eq!(CursorShape::Block.decscusr(false), 2);
        assert_eq!(CursorShape::Underline.decscusr(false), 4);
        assert_eq!(CursorShape::Bar.decscusr(true), 5);
    }
}
