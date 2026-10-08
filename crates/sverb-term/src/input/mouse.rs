//! M1-11: mouse events → the remote or sverb (SPEC §7.3).
//!
//! [`route_mouse`] decides who gets an event that landed inside a pane:
//!
//! - **Shift** always gives the mouse to sverb (selection, focus, scrollback).
//! - The remote enabled reporting (`?1000` click, `?1002` drag, `?1003` motion): the event is
//!   encoded with the requested encoding — SGR (`?1006`, `CSI < b ; x ; y M/m`), urxvt
//!   (`?1015`, `CSI b ; x ; y M`), UTF-8 (`?1005`) or the default X10 (`CSI M Cb Cx Cy`).
//!   Mode 1000 reports presses, releases and the wheel only; 1002 adds motion with a button
//!   held; 1003 adds all motion. Events the mode doesn't ask for are dropped (they don't
//!   drive sverb either, since the remote owns the mouse).
//! - No reporting, alternate screen, `?1007` alternate scroll on (the default): the wheel
//!   sends [`WHEEL_LINES`] `Up`/`Down` arrow keys per notch, encoded for the pane's DECCKM
//!   (xterm's `alternateScroll`; this is what lets `less`, `man` and `vim` scroll).
//! - Otherwise sverb handles it (click to focus, wheel to scroll back 3 lines per notch,
//!   drag to select).
//!
//! **X10 coordinate cap (T-08):** X10 can only carry coordinates up to 223. An event beyond
//! that is **not sent** (the route is [`MouseRoute::Drop`]); xterm does the same rather than
//! clamping, which would report a click on the wrong cell. UTF-8 mode reaches 2015.
//!
//! Coordinates in [`MouseInput`] are pane-relative and 0-based; reports are 1-based.

use bytes::Bytes;

use super::keys::{EncodeOpts, Key, KeyInput, KeyMods, encode_key};
use crate::modes::{MouseEncoding, MouseMode, TermModes};

/// Lines (or arrow keys) per wheel notch.
pub const WHEEL_LINES: usize = 3;

/// Largest coordinate X10 can encode (`255 - 32`).
const X10_MAX: u16 = 223;
/// Largest coordinate the UTF-8 encoding can carry (xterm's limit).
const UTF8_MAX: u16 = 2015;

/// A mouse button.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MouseButton {
    Left,
    Middle,
    Right,
}

impl MouseButton {
    const fn code(self) -> u16 {
        match self {
            Self::Left => 0,
            Self::Middle => 1,
            Self::Right => 2,
        }
    }
}

/// What the mouse did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MouseAction {
    Press(MouseButton),
    Release(MouseButton),
    /// Motion with a button held.
    Drag(MouseButton),
    /// Motion without a button.
    Move,
    WheelUp,
    WheelDown,
    WheelLeft,
    WheelRight,
}

/// A mouse event inside a pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MouseInput {
    pub action: MouseAction,
    /// Pane-relative column, 0-based.
    pub col: u16,
    /// Pane-relative row, 0-based.
    pub row: u16,
    pub mods: KeyMods,
}

/// Where a mouse event goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MouseRoute {
    /// Bytes for the remote (a mouse report, or arrow keys for alternate scroll).
    Remote(Bytes),
    /// sverb handles it (focus, scrollback, selection, tabs, sidebar).
    Sverb,
    /// Nobody: the remote owns the mouse but didn't ask for this event.
    Drop,
}

/// Decide who gets a mouse event inside a pane with `modes`.
#[must_use]
pub fn route_mouse(ev: &MouseInput, modes: &TermModes) -> MouseRoute {
    if ev.mods.contains(KeyMods::SHIFT) {
        return MouseRoute::Sverb;
    }
    let wanted = match modes.mouse_mode {
        MouseMode::None => return alternate_scroll(ev, modes),
        MouseMode::Click => !matches!(ev.action, MouseAction::Drag(_) | MouseAction::Move),
        MouseMode::Drag => !matches!(ev.action, MouseAction::Move),
        MouseMode::Motion => true,
    };
    if !wanted {
        return MouseRoute::Drop;
    }
    encode_mouse(ev, modes).map_or(MouseRoute::Drop, MouseRoute::Remote)
}

fn alternate_scroll(ev: &MouseInput, modes: &TermModes) -> MouseRoute {
    let key = match ev.action {
        MouseAction::WheelUp => Key::Up,
        MouseAction::WheelDown => Key::Down,
        _ => return MouseRoute::Sverb,
    };
    if !(modes.alt_screen && modes.alternate_scroll) {
        return MouseRoute::Sverb;
    }
    // Plain arrows: the wheel's modifiers aren't part of the key.
    let Some(one) = encode_key(KeyInput::plain(key), modes, &EncodeOpts::default()) else {
        return MouseRoute::Sverb;
    };
    MouseRoute::Remote(Bytes::from(one.repeat(WHEEL_LINES)))
}

/// The xterm button code (before the encoding's offset).
fn button_code(ev: &MouseInput, legacy_release: bool) -> u16 {
    let base = match ev.action {
        MouseAction::Press(b) => b.code(),
        MouseAction::Release(b) => {
            if legacy_release {
                3
            } else {
                b.code()
            }
        }
        MouseAction::Drag(b) => b.code() + 32,
        MouseAction::Move => 3 + 32,
        MouseAction::WheelUp => 64,
        MouseAction::WheelDown => 65,
        MouseAction::WheelLeft => 66,
        MouseAction::WheelRight => 67,
    };
    let mut mods = 0;
    if ev.mods.contains(KeyMods::SHIFT) {
        mods |= 4;
    }
    if ev.mods.contains(KeyMods::ALT) {
        mods |= 8;
    }
    if ev.mods.contains(KeyMods::CTRL) {
        mods |= 16;
    }
    base | mods
}

/// Encode a mouse report with the pane's encoding (ignores the mouse *mode*; see
/// [`route_mouse`]). `None` when the coordinates don't fit the encoding.
#[must_use]
pub fn encode_mouse(ev: &MouseInput, modes: &TermModes) -> Option<Bytes> {
    let x = ev.col.checked_add(1)?;
    let y = ev.row.checked_add(1)?;
    let out = match modes.mouse_encoding {
        MouseEncoding::Sgr => {
            let fin = if matches!(ev.action, MouseAction::Release(_)) {
                'm'
            } else {
                'M'
            };
            format!("\x1b[<{};{x};{y}{fin}", button_code(ev, false)).into_bytes()
        }
        MouseEncoding::Urxvt => {
            format!("\x1b[{};{x};{y}M", button_code(ev, true) + 32).into_bytes()
        }
        MouseEncoding::Default => {
            if x > X10_MAX || y > X10_MAX {
                return None;
            }
            let cb = u8::try_from(button_code(ev, true) + 32).ok()?;
            let cx = u8::try_from(x + 32).ok()?;
            let cy = u8::try_from(y + 32).ok()?;
            vec![0x1b, b'[', b'M', cb, cx, cy]
        }
        MouseEncoding::Utf8 => {
            if x > UTF8_MAX || y > UTF8_MAX {
                return None;
            }
            let mut out = b"\x1b[M".to_vec();
            for v in [button_code(ev, true) + 32, x + 32, y + 32] {
                let c = char::from_u32(u32::from(v))?;
                let mut buf = [0_u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
            out
        }
    };
    Some(Bytes::from(out))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn modes(mode: MouseMode, encoding: MouseEncoding) -> TermModes {
        TermModes {
            mouse_mode: mode,
            mouse_encoding: encoding,
            ..TermModes::default()
        }
    }

    fn ev(action: MouseAction, col: u16, row: u16) -> MouseInput {
        MouseInput {
            action,
            col,
            row,
            mods: KeyMods::NONE,
        }
    }

    fn remote(route: MouseRoute) -> Vec<u8> {
        match route {
            MouseRoute::Remote(b) => b.to_vec(),
            other => panic!("not forwarded: {other:?}"),
        }
    }

    /// T-07: SGR.
    #[test]
    fn t07_sgr() {
        let m = modes(MouseMode::Click, MouseEncoding::Sgr);
        let press = ev(MouseAction::Press(MouseButton::Left), 0, 0);
        assert_eq!(remote(route_mouse(&press, &m)), b"\x1b[<0;1;1M");
        let release = ev(MouseAction::Release(MouseButton::Left), 0, 0);
        assert_eq!(remote(route_mouse(&release, &m)), b"\x1b[<0;1;1m");
        let right = ev(MouseAction::Press(MouseButton::Right), 9, 4);
        assert_eq!(remote(route_mouse(&right, &m)), b"\x1b[<2;10;5M");
        let wheel = ev(MouseAction::WheelUp, 2, 3);
        assert_eq!(remote(route_mouse(&wheel, &m)), b"\x1b[<64;3;4M");
        let wheel = ev(MouseAction::WheelDown, 2, 3);
        assert_eq!(remote(route_mouse(&wheel, &m)), b"\x1b[<65;3;4M");
        let mut ctrl = ev(MouseAction::Press(MouseButton::Left), 0, 0);
        ctrl.mods = KeyMods::CTRL;
        assert_eq!(remote(route_mouse(&ctrl, &m)), b"\x1b[<16;1;1M");
        // Shift-click goes to sverb.
        let mut shift = press;
        shift.mods = KeyMods::SHIFT;
        assert_eq!(route_mouse(&shift, &m), MouseRoute::Sverb);
        // No mouse mode: sverb.
        assert_eq!(
            route_mouse(&press, &TermModes::default()),
            MouseRoute::Sverb
        );
    }

    /// T-07: X10 and urxvt.
    #[test]
    fn t07_x10_and_urxvt() {
        let x10 = modes(MouseMode::Click, MouseEncoding::Default);
        let press = ev(MouseAction::Press(MouseButton::Left), 0, 0);
        assert_eq!(remote(route_mouse(&press, &x10)), b"\x1b[M !!");
        let release = ev(MouseAction::Release(MouseButton::Left), 0, 0);
        assert_eq!(remote(route_mouse(&release, &x10)), b"\x1b[M#!!");
        let urxvt = modes(MouseMode::Click, MouseEncoding::Urxvt);
        assert_eq!(remote(route_mouse(&press, &urxvt)), b"\x1b[32;1;1M");
        assert_eq!(remote(route_mouse(&release, &urxvt)), b"\x1b[35;1;1M");
        let utf8 = modes(MouseMode::Click, MouseEncoding::Utf8);
        let far = ev(MouseAction::Press(MouseButton::Left), 299, 0);
        let mut want = b"\x1b[M ".to_vec();
        want.extend_from_slice("\u{14c}".as_bytes()); // 300 + 32
        want.push(b'!');
        assert_eq!(remote(route_mouse(&far, &utf8)), want);
    }

    /// T-08: X10 can't carry column 300: the event is not sent.
    #[test]
    fn t08_x10_cap() {
        let x10 = modes(MouseMode::Click, MouseEncoding::Default);
        let far = ev(MouseAction::Press(MouseButton::Left), 299, 0);
        assert_eq!(route_mouse(&far, &x10), MouseRoute::Drop);
        let edge = ev(MouseAction::Press(MouseButton::Left), 222, 222);
        assert_eq!(
            remote(route_mouse(&edge, &x10)),
            [0x1b, b'[', b'M', 32, 255, 255]
        );
        let past = ev(MouseAction::Press(MouseButton::Left), 223, 0);
        assert_eq!(route_mouse(&past, &x10), MouseRoute::Drop);
    }

    /// T-09: drag needs 1002, plain motion needs 1003.
    #[test]
    fn t09_drag_and_motion() {
        let drag = ev(MouseAction::Drag(MouseButton::Left), 4, 5);
        let motion = ev(MouseAction::Move, 4, 5);
        let click = modes(MouseMode::Click, MouseEncoding::Sgr);
        assert_eq!(route_mouse(&drag, &click), MouseRoute::Drop);
        assert_eq!(route_mouse(&motion, &click), MouseRoute::Drop);
        let m1002 = modes(MouseMode::Drag, MouseEncoding::Sgr);
        assert_eq!(remote(route_mouse(&drag, &m1002)), b"\x1b[<32;5;6M");
        assert_eq!(route_mouse(&motion, &m1002), MouseRoute::Drop);
        let m1003 = modes(MouseMode::Motion, MouseEncoding::Sgr);
        assert_eq!(remote(route_mouse(&motion, &m1003)), b"\x1b[<35;5;6M");
        assert_eq!(remote(route_mouse(&drag, &m1003)), b"\x1b[<32;5;6M");
    }

    /// T-10: alternate scroll.
    #[test]
    fn t10_alternate_scroll() {
        let alt = TermModes {
            alt_screen: true,
            ..TermModes::default()
        };
        let down = ev(MouseAction::WheelDown, 0, 0);
        assert_eq!(remote(route_mouse(&down, &alt)), b"\x1b[B\x1b[B\x1b[B");
        let up = ev(MouseAction::WheelUp, 0, 0);
        let app = TermModes {
            app_cursor: true,
            ..alt
        };
        assert_eq!(remote(route_mouse(&up, &app)), b"\x1bOA\x1bOA\x1bOA");
        // Primary screen: sverb scrolls back. `?1007` off: sverb too.
        assert_eq!(route_mouse(&down, &TermModes::default()), MouseRoute::Sverb);
        let off = TermModes {
            alternate_scroll: false,
            ..alt
        };
        assert_eq!(route_mouse(&down, &off), MouseRoute::Sverb);
        // Clicks on the alternate screen without mouse mode: sverb.
        let click = ev(MouseAction::Press(MouseButton::Left), 0, 0);
        assert_eq!(route_mouse(&click, &alt), MouseRoute::Sverb);
    }
}
