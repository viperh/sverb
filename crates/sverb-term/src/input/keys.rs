//! Key → bytes (SPEC §7.3).
//!
//! [`encode_key`] picks one of three encodings from the pane's modes:
//!
//! 1. **Kitty keyboard protocol** when the remote pushed flags with `DISAMBIGUATE` (1) or
//!    `REPORT_ALL_KEYS_AS_ESC` (8): `CSI code ; mods u` for anything that would be ambiguous
//!    in the legacy encoding (ctrl/alt/super combos, `Esc`, modified `Enter`/`Tab`/`Backspace`).
//!    Plain text, `Enter`, `Tab` and `Backspace` stay legacy unless flag 8 is set. Cursor,
//!    editing and `F1`–`F12` keys keep their legacy forms, as in the kitty spec.
//! 2. **xterm modifyOtherKeys** (`CSI > 4 ; n m`) when `n` is 1 or 2: ctrl combos become
//!    `CSI 27 ; mods ; code ~`. Level 2 does it for every ctrl combo on a character (and
//!    ctrl/shift on `Enter`, ctrl on `Tab`, ctrl/shift on `Esc`); level 1 only for combos
//!    that have no unambiguous legacy byte (`ctrl-1`, `ctrl-;`, `ctrl-shift-a`, `ctrl-tab`).
//!    arrows and `Home`/`End` honor DECCKM when unmodified, modified specials use
//!    `CSI 1 ; m X` / `CSI n ; m ~` (`m` = 1 + shift·1 + alt·2 + ctrl·4 + super·8), `Alt`
//!    on text prefixes `ESC`, ctrl on characters maps to C0 bytes, the keypad honors DECKPAM.
//!
//! `F13`–`F24` are sent as xterm does: shift + `F1`–`F12` (legacy), or the kitty
//! private-use codes (kitty mode). Keys with no encoding return `None`.
//!
//! Charset conversion of text happens in the session's write path, after this.

use bytes::Bytes;

use crate::modes::{KittyKeyboardFlags, TermModes};

/// Modifier bits, in xterm/kitty order (the CSI modifier parameter is `1 + bits`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyMods(u8);

impl KeyMods {
    /// No modifier.
    pub const NONE: Self = Self(0);
    /// Shift.
    pub const SHIFT: Self = Self(1);
    /// Alt / Meta.
    pub const ALT: Self = Self(1 << 1);
    /// Control.
    pub const CTRL: Self = Self(1 << 2);
    /// Super (kitty only; legacy encodings carry it in the CSI parameter of special keys).
    pub const SUPER: Self = Self(1 << 3);
    /// Every modifier.
    pub const ALL: Self = Self(0b1111);

    /// From raw bits (unknown bits dropped).
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits & Self::ALL.0)
    }

    /// Raw bits.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Whether every modifier in `other` is set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether any modifier in `other` is set.
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// Both sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Without `other`.
    #[must_use]
    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// No modifier.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The CSI modifier parameter: `1 + bits`.
    #[must_use]
    pub const fn param(self) -> u8 {
        1 + self.0
    }
}

impl std::ops::BitOr for KeyMods {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

/// A numeric keypad key (only distinguishable when the outer terminal reports it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeypadKey {
    /// `0`–`9` (values above 9 have no encoding).
    Digit(u8),
    /// `.`
    Decimal,
    /// `/`
    Divide,
    /// `*`
    Multiply,
    /// `-`
    Subtract,
    /// `+`
    Add,
    /// Keypad Enter.
    Enter,
    /// `=`
    Equal,
}

/// A key, independent of any terminal library.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Key {
    /// A character. An ASCII uppercase letter implies shift.
    Char(char),
    Enter,
    Tab,
    Backspace,
    Esc,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    Insert,
    Delete,
    PageUp,
    PageDown,
    /// `F1`–`F24` (others have no encoding).
    F(u8),
    /// A numeric keypad key.
    Keypad(KeypadKey),
}

/// A key press with modifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyInput {
    /// The key.
    pub key: Key,
    /// Modifiers.
    pub mods: KeyMods,
}

impl KeyInput {
    /// A key with modifiers.
    #[must_use]
    pub const fn new(key: Key, mods: KeyMods) -> Self {
        Self { key, mods }
    }

    /// A key without modifiers.
    #[must_use]
    pub const fn plain(key: Key) -> Self {
        Self::new(key, KeyMods::NONE)
    }
}

/// What the Backspace key sends (per host, SPEC §4.2 `backspace`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum BackspaceMode {
    /// `0x7f` (and `ctrl-backspace` sends `0x08`).
    #[default]
    Del,
    /// `0x08` (and `ctrl-backspace` sends `0x7f`).
    CtrlH,
}

impl From<sverb_core::model::Backspace> for BackspaceMode {
    fn from(b: sverb_core::model::Backspace) -> Self {
        match b {
            sverb_core::model::Backspace::Del => Self::Del,
            sverb_core::model::Backspace::CtrlH => Self::CtrlH,
        }
    }
}

/// Per-session encoding options (from the host's settings).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct EncodeOpts {
    /// What Backspace sends.
    pub backspace: BackspaceMode,
}

const ESC: u8 = 0x1b;

/// Encode a key press for a pane with `modes`. `None`: the key has no encoding.
#[must_use]
pub fn encode_key(input: KeyInput, modes: &TermModes, opts: &EncodeOpts) -> Option<Bytes> {
    let kitty = modes.kitty_keyboard;
    let out = if kitty.contains(KittyKeyboardFlags::DISAMBIGUATE_ESC_CODES)
        || kitty.contains(KittyKeyboardFlags::REPORT_ALL_KEYS_AS_ESC)
    {
        encode_kitty(input, kitty, modes, opts)
    } else {
        encode_legacy(input, modes, opts)
    }?;
    Some(Bytes::from(out))
}

/// The modifier set and base character for a `Char` key: an uppercase ASCII letter is the
/// lowercase key with shift.
fn char_parts(c: char, mods: KeyMods) -> (char, KeyMods) {
    if c.is_ascii_uppercase() {
        (c.to_ascii_lowercase(), mods | KeyMods::SHIFT)
    } else {
        (c, mods)
    }
}

/// The text a character key types (shift applied to ASCII letters).
fn char_text(c: char, mods: KeyMods) -> char {
    if mods.contains(KeyMods::SHIFT) && c.is_ascii_lowercase() {
        c.to_ascii_uppercase()
    } else {
        c
    }
}

fn push_char(out: &mut Vec<u8>, c: char) {
    let mut buf = [0_u8; 4];
    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
}

/// The C0 byte for `ctrl-<c>`, as xterm sends it.
fn ctrl_byte(c: char) -> Option<u8> {
    let c = c.to_ascii_lowercase();
    Some(match c {
        'a'..='z' => c as u8 - b'a' + 1,
        ' ' | '@' | '2' => 0,
        '[' | '3' => 0x1b,
        '\\' | '4' => 0x1c,
        ']' | '5' => 0x1d,
        '^' | '~' | '6' => 0x1e,
        '_' | '/' | '-' | '7' => 0x1f,
        '?' | '8' => 0x7f,
        _ => return None,
    })
}

fn backspace_byte(opts: &EncodeOpts, ctrl: bool) -> u8 {
    match (opts.backspace, ctrl) {
        (BackspaceMode::Del, false) | (BackspaceMode::CtrlH, true) => 0x7f,
        (BackspaceMode::Del, true) | (BackspaceMode::CtrlH, false) => 0x08,
    }
}

fn enter_bytes(modes: &TermModes) -> &'static [u8] {
    if modes.line_feed_new_line {
        b"\r\n"
    } else {
        b"\r"
    }
}

/// `CSI 27 ; m ; code ~` (xterm modifyOtherKeys).
fn modify_other(mods: KeyMods, code: u32) -> Vec<u8> {
    format!("\x1b[27;{};{code}~", mods.param()).into_bytes()
}

/// Cursor-style keys (`A B C D H F`, and `P Q R S` for F1–F4): `ESC [ X` / `ESC O X`
/// unmodified, `ESC [ 1 ; m X` modified.
fn cursor_key(final_byte: u8, mods: KeyMods, ss3: bool) -> Vec<u8> {
    if mods.is_empty() {
        vec![ESC, if ss3 { b'O' } else { b'[' }, final_byte]
    } else {
        let mut out = format!("\x1b[1;{}", mods.param()).into_bytes();
        out.push(final_byte);
        out
    }
}

/// `ESC [ n ~` / `ESC [ n ; m ~`.
fn tilde_key(n: u8, mods: KeyMods) -> Vec<u8> {
    if mods.is_empty() {
        format!("\x1b[{n}~").into_bytes()
    } else {
        format!("\x1b[{n};{}~", mods.param()).into_bytes()
    }
}

/// `F5`–`F12` tilde codes.
fn f_tilde(n: u8) -> Option<u8> {
    Some(match n {
        5 => 15,
        6 => 17,
        7 => 18,
        8 => 19,
        9 => 20,
        10 => 21,
        11 => 23,
        12 => 24,
        _ => return None,
    })
}

/// Special (non-text) keys shared by the legacy and kitty encodings.
fn special_key(key: Key, mods: KeyMods, modes: &TermModes) -> Option<Vec<u8>> {
    let app = modes.app_cursor;
    Some(match key {
        Key::Up => cursor_key(b'A', mods, app),
        Key::Down => cursor_key(b'B', mods, app),
        Key::Right => cursor_key(b'C', mods, app),
        Key::Left => cursor_key(b'D', mods, app),
        Key::Home => cursor_key(b'H', mods, app),
        Key::End => cursor_key(b'F', mods, app),
        Key::Insert => tilde_key(2, mods),
        Key::Delete => tilde_key(3, mods),
        Key::PageUp => tilde_key(5, mods),
        Key::PageDown => tilde_key(6, mods),
        Key::F(n @ 1..=4) => cursor_key(b'P' + (n - 1), mods, true),
        Key::F(n @ 5..=12) => tilde_key(f_tilde(n)?, mods),
        // xterm: F13–F24 are shift + F1–F12.
        Key::F(n @ 13..=24) => return special_key(Key::F(n - 12), mods | KeyMods::SHIFT, modes),
        _ => return None,
    })
}

fn keypad_legacy(k: KeypadKey, mods: KeyMods, modes: &TermModes) -> Option<Vec<u8>> {
    let (text, app): (&[u8], u8) = match k {
        KeypadKey::Digit(d @ 0..=9) => {
            let digit = b'0' + d;
            if modes.app_keypad && mods.is_empty() {
                return Some(vec![ESC, b'O', b'p' + d]);
            }
            return Some(vec![digit]);
        }
        KeypadKey::Digit(_) => return None,
        KeypadKey::Decimal => (b".", b'n'),
        KeypadKey::Divide => (b"/", b'o'),
        KeypadKey::Multiply => (b"*", b'j'),
        KeypadKey::Subtract => (b"-", b'm'),
        KeypadKey::Add => (b"+", b'k'),
        KeypadKey::Enter => (enter_bytes(modes), b'M'),
        KeypadKey::Equal => (b"=", b'X'),
    };
    if modes.app_keypad && mods.is_empty() {
        Some(vec![ESC, b'O', app])
    } else {
        Some(text.to_vec())
    }
}

/// Whether a ctrl combo on a character goes through modifyOtherKeys at `level`.
fn char_uses_modify_other(c: char, mods: KeyMods, level: u8) -> bool {
    if !mods.contains(KeyMods::CTRL) {
        return false;
    }
    match level {
        0 => false,
        1 => ctrl_byte(c).is_none() || c.is_ascii_uppercase() || mods.contains(KeyMods::SHIFT),
        _ => true,
    }
}

fn encode_legacy(input: KeyInput, modes: &TermModes, opts: &EncodeOpts) -> Option<Vec<u8>> {
    let KeyInput { key, mods } = input;
    let ctrl = mods.contains(KeyMods::CTRL);
    let alt = mods.contains(KeyMods::ALT);
    let shift = mods.contains(KeyMods::SHIFT);
    let level = modes.modify_other_keys;
    let mut out = Vec::new();
    match key {
        Key::Char(c) => {
            if char_uses_modify_other(c, mods, level) {
                let (_, m) = char_parts(c, mods);
                return Some(modify_other(m, u32::from(c)));
            }
            if alt {
                out.push(ESC);
            }
            match ctrl.then(|| ctrl_byte(c)).flatten() {
                Some(b) => out.push(b),
                None => push_char(&mut out, char_text(c, mods)),
            }
        }
        Key::Enter => {
            if level >= 1 && (ctrl || shift) {
                return Some(modify_other(mods, 13));
            }
            if alt {
                out.push(ESC);
            }
            out.extend_from_slice(enter_bytes(modes));
        }
        Key::Tab => {
            if level >= 1 && ctrl {
                return Some(modify_other(mods, 9));
            }
            if alt {
                out.push(ESC);
            }
            if shift {
                out.extend_from_slice(b"\x1b[Z");
            } else {
                out.push(b'\t');
            }
        }
        Key::Backspace => {
            if alt {
                out.push(ESC);
            }
            out.push(backspace_byte(opts, ctrl));
        }
        Key::Esc => {
            if level >= 1 && (ctrl || shift) {
                return Some(modify_other(mods, 27));
            }
            if alt {
                out.push(ESC);
            }
            out.push(ESC);
        }
        Key::Keypad(k) => {
            if alt {
                out.push(ESC);
            }
            out.extend(keypad_legacy(k, mods.without(KeyMods::ALT), modes)?);
        }
        other => return special_key(other, mods, modes),
    }
    Some(out)
}

/// kitty's private-use codes for F13–F24 (`57376` = F13).
const KITTY_F13: u32 = 57376;
/// kitty's code for keypad `0`.
const KITTY_KP_0: u32 = 57399;

/// `CSI code[:alternate] [; m] u`.
fn kitty_csi_u(code: u32, alternate: Option<u32>, mods: KeyMods) -> Vec<u8> {
    let mut s = format!("\x1b[{code}");
    if let Some(alt) = alternate {
        s.push_str(&format!(":{alt}"));
    }
    if !mods.is_empty() {
        s.push_str(&format!(";{}", mods.param()));
    }
    s.push('u');
    s.into_bytes()
}

fn kitty_keypad_code(k: KeypadKey) -> Option<u32> {
    Some(match k {
        KeypadKey::Digit(d @ 0..=9) => KITTY_KP_0 + u32::from(d),
        KeypadKey::Digit(_) => return None,
        KeypadKey::Decimal => 57409,
        KeypadKey::Divide => 57410,
        KeypadKey::Multiply => 57411,
        KeypadKey::Subtract => 57412,
        KeypadKey::Add => 57413,
        KeypadKey::Enter => 57414,
        KeypadKey::Equal => 57415,
    })
}

fn encode_kitty(
    input: KeyInput,
    flags: KittyKeyboardFlags,
    modes: &TermModes,
    opts: &EncodeOpts,
) -> Option<Vec<u8>> {
    let KeyInput { key, mods } = input;
    let all = flags.contains(KittyKeyboardFlags::REPORT_ALL_KEYS_AS_ESC);
    let alternates = flags.contains(KittyKeyboardFlags::REPORT_ALTERNATE_KEYS);
    match key {
        Key::Char(c) => {
            let (base, m) = char_parts(c, mods);
            // Text (no modifier but shift) stays text unless every key is reported.
            if !all && m.without(KeyMods::SHIFT).is_empty() {
                let mut out = Vec::new();
                push_char(&mut out, char_text(c, mods));
                return Some(out);
            }
            let shifted = (alternates && m.contains(KeyMods::SHIFT) && base.is_ascii_lowercase())
                .then(|| u32::from(base.to_ascii_uppercase()));
            Some(kitty_csi_u(u32::from(base), shifted, m))
        }
        Key::Enter | Key::Tab | Key::Backspace if !all && mods.is_empty() => {
            encode_legacy(input, modes, opts)
        }
        Key::Enter => Some(kitty_csi_u(13, None, mods)),
        Key::Tab => Some(kitty_csi_u(9, None, mods)),
        Key::Backspace => Some(kitty_csi_u(127, None, mods)),
        Key::Esc => Some(kitty_csi_u(27, None, mods)),
        Key::F(n @ 13..=24) => Some(kitty_csi_u(KITTY_F13 + u32::from(n - 13), None, mods)),
        Key::Keypad(k) if all || !mods.without(KeyMods::SHIFT).is_empty() => {
            Some(kitty_csi_u(kitty_keypad_code(k)?, None, mods))
        }
        Key::Keypad(k) => keypad_legacy(k, mods, modes),
        other => special_key(other, mods, modes),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use proptest::prelude::*;

    use super::*;

    const S: KeyMods = KeyMods::SHIFT;
    const A: KeyMods = KeyMods::ALT;
    const C: KeyMods = KeyMods::CTRL;
    const N: KeyMods = KeyMods::NONE;

    fn enc(key: Key, mods: KeyMods, modes: &TermModes) -> Vec<u8> {
        encode_key(KeyInput::new(key, mods), modes, &EncodeOpts::default())
            .map(|b| b.to_vec())
            .unwrap_or_default()
    }

    fn normal() -> TermModes {
        TermModes::default()
    }

    fn decckm() -> TermModes {
        TermModes {
            app_cursor: true,
            ..TermModes::default()
        }
    }

    /// One row of the reference table: key, normal-mode bytes, DECCKM bytes.
    type Row = (Key, KeyMods, &'static [u8], &'static [u8]);

    /// The §2.2 table, in both DECCKM states.
    #[test]
    fn t01_reference_table() {
        let mut rows: Vec<Row> = vec![
            (Key::Up, N, b"\x1b[A", b"\x1bOA"),
            (Key::Down, N, b"\x1b[B", b"\x1bOB"),
            (Key::Right, N, b"\x1b[C", b"\x1bOC"),
            (Key::Left, N, b"\x1b[D", b"\x1bOD"),
            (Key::Home, N, b"\x1b[H", b"\x1bOH"),
            (Key::End, N, b"\x1b[F", b"\x1bOF"),
            (Key::Up, C, b"\x1b[1;5A", b"\x1b[1;5A"),
            (Key::Down, C, b"\x1b[1;5B", b"\x1b[1;5B"),
            (Key::Right, C, b"\x1b[1;5C", b"\x1b[1;5C"),
            (Key::Left, C, b"\x1b[1;5D", b"\x1b[1;5D"),
            (Key::Home, C, b"\x1b[1;5H", b"\x1b[1;5H"),
            (Key::End, S, b"\x1b[1;2F", b"\x1b[1;2F"),
            (Key::Enter, N, b"\r", b"\r"),
            (Key::Backspace, N, b"\x7f", b"\x7f"),
            (Key::Backspace, C, b"\x08", b"\x08"),
            (Key::Char('x'), A, b"\x1bx", b"\x1bx"),
            (Key::Char('b'), A, b"\x1bb", b"\x1bb"),
            (Key::Char('f'), A, b"\x1bf", b"\x1bf"),
            (Key::Char('d'), A, b"\x1bd", b"\x1bd"),
            (Key::Char('.'), A, b"\x1b.", b"\x1b."),
            (Key::F(1), N, b"\x1bOP", b"\x1bOP"),
            (Key::F(2), N, b"\x1bOQ", b"\x1bOQ"),
            (Key::F(3), N, b"\x1bOR", b"\x1bOR"),
            (Key::F(4), N, b"\x1bOS", b"\x1bOS"),
            (Key::F(5), N, b"\x1b[15~", b"\x1b[15~"),
            (Key::F(6), N, b"\x1b[17~", b"\x1b[17~"),
            (Key::F(7), N, b"\x1b[18~", b"\x1b[18~"),
            (Key::F(8), N, b"\x1b[19~", b"\x1b[19~"),
            (Key::F(9), N, b"\x1b[20~", b"\x1b[20~"),
            (Key::F(10), N, b"\x1b[21~", b"\x1b[21~"),
            (Key::F(11), N, b"\x1b[23~", b"\x1b[23~"),
            (Key::F(12), N, b"\x1b[24~", b"\x1b[24~"),
            (Key::Tab, S, b"\x1b[Z", b"\x1b[Z"),
            (Key::Tab, N, b"\t", b"\t"),
            (Key::Esc, N, b"\x1b", b"\x1b"),
            (Key::Insert, N, b"\x1b[2~", b"\x1b[2~"),
            (Key::Delete, N, b"\x1b[3~", b"\x1b[3~"),
            (Key::PageUp, N, b"\x1b[5~", b"\x1b[5~"),
            (Key::PageDown, N, b"\x1b[6~", b"\x1b[6~"),
            (Key::Char(' '), C, b"\x00", b"\x00"),
            (Key::Char('@'), C, b"\x00", b"\x00"),
            (Key::Char('['), C, b"\x1b", b"\x1b"),
            (Key::Char('\\'), C, b"\x1c", b"\x1c"),
            (Key::Char(']'), C, b"\x1d", b"\x1d"),
            (Key::Char('^'), C, b"\x1e", b"\x1e"),
            (Key::Char('_'), C, b"\x1f", b"\x1f"),
            (Key::Char('?'), C, b"\x7f", b"\x7f"),
            (Key::Char('q'), N, b"q", b"q"),
            (Key::Char('Q'), N, b"Q", b"Q"),
            (Key::Char('é'), N, "é".as_bytes(), "é".as_bytes()),
            (Key::Keypad(KeypadKey::Digit(5)), N, b"5", b"5"),
        ];
        // Ctrl-a … Ctrl-z.
        const CTRL: [&[u8]; 26] = [
            b"\x01", b"\x02", b"\x03", b"\x04", b"\x05", b"\x06", b"\x07", b"\x08", b"\x09",
            b"\x0a", b"\x0b", b"\x0c", b"\x0d", b"\x0e", b"\x0f", b"\x10", b"\x11", b"\x12",
            b"\x13", b"\x14", b"\x15", b"\x16", b"\x17", b"\x18", b"\x19", b"\x1a",
        ];
        for (i, bytes) in CTRL.iter().enumerate() {
            let c = char::from(b'a' + u8::try_from(i).unwrap());
            rows.push((Key::Char(c), C, bytes, bytes));
        }
        assert!(rows.len() >= 60, "{} rows", rows.len());
        for (key, mods, plain, app) in rows {
            assert_eq!(enc(key, mods, &normal()), plain, "{key:?} {mods:?} normal");
            assert_eq!(enc(key, mods, &decckm()), app, "{key:?} {mods:?} DECCKM");
        }
    }

    /// The backspace variants (host `backspace = CtrlH`).
    #[test]
    fn t01_backspace_variants() {
        let ctrl_h = EncodeOpts {
            backspace: BackspaceMode::CtrlH,
        };
        let del = EncodeOpts::default();
        for modes in [normal(), decckm()] {
            let bs = |mods, opts: &EncodeOpts| {
                encode_key(KeyInput::new(Key::Backspace, mods), &modes, opts)
                    .unwrap()
                    .to_vec()
            };
            assert_eq!(bs(N, &del), b"\x7f");
            assert_eq!(bs(C, &del), b"\x08");
            assert_eq!(bs(N, &ctrl_h), b"\x08");
            assert_eq!(bs(C, &ctrl_h), b"\x7f");
            assert_eq!(bs(A, &ctrl_h), b"\x1b\x08");
        }
        assert_eq!(
            BackspaceMode::from(sverb_core::model::Backspace::CtrlH),
            BackspaceMode::CtrlH
        );
    }

    /// DECKPAM keypad.
    #[test]
    fn t01_keypad() {
        let app = TermModes {
            app_keypad: true,
            ..TermModes::default()
        };
        for d in 0..=9_u8 {
            assert_eq!(
                enc(Key::Keypad(KeypadKey::Digit(d)), N, &normal()),
                [b'0' + d]
            );
            assert_eq!(
                enc(Key::Keypad(KeypadKey::Digit(d)), N, &app),
                [0x1b, b'O', b'p' + d]
            );
        }
        assert_eq!(enc(Key::Keypad(KeypadKey::Enter), N, &app), b"\x1bOM");
        assert_eq!(enc(Key::Keypad(KeypadKey::Enter), N, &normal()), b"\r");
        assert_eq!(enc(Key::Keypad(KeypadKey::Add), N, &app), b"\x1bOk");
        assert_eq!(enc(Key::Keypad(KeypadKey::Decimal), N, &normal()), b".");
    }

    /// Modified arrows and function keys, all 7 modifier combos.
    #[test]
    fn t02_modified_specials() {
        let combos: [(KeyMods, u8); 7] = [
            (S, 2),
            (A, 3),
            (S | A, 4),
            (C, 5),
            (C | S, 6),
            (C | A, 7),
            (C | A | S, 8),
        ];
        let cursor: [(Key, char); 8] = [
            (Key::Up, 'A'),
            (Key::Down, 'B'),
            (Key::Right, 'C'),
            (Key::Left, 'D'),
            (Key::Home, 'H'),
            (Key::End, 'F'),
            (Key::F(1), 'P'),
            (Key::F(4), 'S'),
        ];
        let tilde: [(Key, u8); 8] = [
            (Key::F(5), 15),
            (Key::F(6), 17),
            (Key::F(10), 21),
            (Key::F(12), 24),
            (Key::Insert, 2),
            (Key::Delete, 3),
            (Key::PageUp, 5),
            (Key::PageDown, 6),
        ];
        for modes in [normal(), decckm()] {
            for (mods, m) in combos {
                for (key, fin) in cursor {
                    let want = format!("\x1b[1;{m}{fin}");
                    assert_eq!(enc(key, mods, &modes), want.as_bytes(), "{key:?} {mods:?}");
                }
                for (key, n) in tilde {
                    let want = format!("\x1b[{n};{m}~");
                    assert_eq!(enc(key, mods, &modes), want.as_bytes(), "{key:?} {mods:?}");
                }
            }
        }
        // F13–F24: shift + F1–F12 (xterm).
        assert_eq!(enc(Key::F(13), N, &normal()), b"\x1b[1;2P");
        assert_eq!(enc(Key::F(17), N, &normal()), b"\x1b[15;2~");
        assert_eq!(enc(Key::F(24), C, &normal()), b"\x1b[24;6~");
        assert!(enc(Key::F(25), N, &normal()).is_empty());
        assert!(enc(Key::F(0), N, &normal()).is_empty());
    }

    /// Alt + Unicode.
    #[test]
    fn t03_alt_unicode() {
        let mut want = vec![0x1b];
        want.extend_from_slice("é".as_bytes());
        assert_eq!(enc(Key::Char('é'), A, &normal()), want);
        assert_eq!(enc(Key::Char('X'), A, &normal()), b"\x1bX");
        assert_eq!(enc(Key::Char('c'), C | A, &normal()), b"\x1b\x03");
        assert_eq!(enc(Key::Enter, A, &normal()), b"\x1b\r");
    }

    /// ModifyOtherKeys.
    #[test]
    fn t04_modify_other_keys() {
        let l2 = TermModes {
            modify_other_keys: 2,
            ..TermModes::default()
        };
        assert_eq!(enc(Key::Char('i'), C, &l2), b"\x1b[27;5;105~");
        assert_eq!(enc(Key::Tab, N, &l2), b"\t");
        assert_eq!(enc(Key::Char('a'), N, &l2), b"a");
        assert_eq!(enc(Key::Char('x'), A, &l2), b"\x1bx");
        assert_eq!(enc(Key::Char('A'), C, &l2), b"\x1b[27;6;65~");
        assert_eq!(enc(Key::Enter, C, &l2), b"\x1b[27;5;13~");
        assert_eq!(enc(Key::Tab, C, &l2), b"\x1b[27;5;9~");
        assert_eq!(enc(Key::Tab, S, &l2), b"\x1b[Z");
        let l1 = TermModes {
            modify_other_keys: 1,
            ..TermModes::default()
        };
        // Level 1 keeps the unambiguous legacy bytes.
        assert_eq!(enc(Key::Char('i'), C, &l1), b"\x09");
        assert_eq!(enc(Key::Char(';'), C, &l1), b"\x1b[27;5;59~");
        assert_eq!(enc(Key::Char('A'), C, &l1), b"\x1b[27;6;65~");
        // Without modifyOtherKeys, ctrl + a key with no C0 byte sends the key.
        assert_eq!(enc(Key::Char(';'), C, &normal()), b";");
        assert_eq!(enc(Key::Char('A'), C, &normal()), b"\x01");
    }

    /// Remote kitty keyboard protocol.
    #[test]
    fn t05_remote_kitty() {
        let k1 = TermModes {
            kitty_keyboard: KittyKeyboardFlags(1),
            ..TermModes::default()
        };
        assert_eq!(enc(Key::Char('i'), C, &k1), b"\x1b[105;5u");
        assert_eq!(enc(Key::Tab, N, &k1), b"\t");
        assert_eq!(enc(Key::Tab, S, &k1), b"\x1b[9;2u");
        assert_eq!(enc(Key::Esc, N, &k1), b"\x1b[27u");
        assert_eq!(enc(Key::Char('a'), N, &k1), b"a");
        assert_eq!(enc(Key::Char('A'), N, &k1), b"A");
        assert_eq!(enc(Key::Char('x'), A, &k1), b"\x1b[120;3u");
        assert_eq!(enc(Key::Char('A'), C, &k1), b"\x1b[97;6u");
        assert_eq!(enc(Key::Enter, N, &k1), b"\r");
        assert_eq!(enc(Key::Enter, C, &k1), b"\x1b[13;5u");
        assert_eq!(enc(Key::Backspace, C, &k1), b"\x1b[127;5u");
        assert_eq!(enc(Key::Up, N, &k1), b"\x1b[A");
        assert_eq!(enc(Key::Up, C, &k1), b"\x1b[1;5A");
        assert_eq!(enc(Key::F(13), N, &k1), b"\x1b[57376u");
        // Alternate keys (flag 4) report the shifted key.
        let k5 = TermModes {
            kitty_keyboard: KittyKeyboardFlags(5),
            ..TermModes::default()
        };
        assert_eq!(enc(Key::Char('A'), C, &k5), b"\x1b[97:65;6u");
        // Report all keys (flag 8): text and Enter too.
        let k9 = TermModes {
            kitty_keyboard: KittyKeyboardFlags(9),
            ..TermModes::default()
        };
        assert_eq!(enc(Key::Char('a'), N, &k9), b"\x1b[97u");
        assert_eq!(enc(Key::Enter, N, &k9), b"\x1b[13u");
        // Only "report event types" (2): still legacy.
        let k2 = TermModes {
            kitty_keyboard: KittyKeyboardFlags(2),
            ..TermModes::default()
        };
        assert_eq!(enc(Key::Char('i'), C, &k2), b"\x09");
    }

    /// The same key encodes per pane.
    #[test]
    fn t06_per_pane() {
        let up = KeyInput::plain(Key::Up);
        let a = encode_key(up, &normal(), &EncodeOpts::default()).unwrap();
        let b = encode_key(up, &decckm(), &EncodeOpts::default()).unwrap();
        assert_eq!(&a[..], b"\x1b[A");
        assert_eq!(&b[..], b"\x1bOA");
    }

    #[test]
    fn line_feed_new_line_mode() {
        let lnm = TermModes {
            line_feed_new_line: true,
            ..TermModes::default()
        };
        assert_eq!(enc(Key::Enter, N, &lnm), b"\r\n");
    }

    fn any_key() -> impl Strategy<Value = Key> {
        prop_oneof![
            any::<char>().prop_map(Key::Char),
            Just(Key::Enter),
            Just(Key::Tab),
            Just(Key::Backspace),
            Just(Key::Esc),
            Just(Key::Up),
            Just(Key::Down),
            Just(Key::Left),
            Just(Key::Right),
            Just(Key::Home),
            Just(Key::End),
            Just(Key::Insert),
            Just(Key::Delete),
            Just(Key::PageUp),
            Just(Key::PageDown),
            any::<u8>().prop_map(Key::F),
            any::<u8>().prop_map(|d| Key::Keypad(KeypadKey::Digit(d))),
            Just(Key::Keypad(KeypadKey::Enter)),
            Just(Key::Keypad(KeypadKey::Equal)),
        ]
    }

    proptest! {
        /// T-16 (in-crate twin of the fuzz target): never panics; text keys always encode.
        #[test]
        fn t16_never_panics(
            key in any_key(),
            mods in 0_u8..16,
            app_cursor: bool,
            app_keypad: bool,
            lnm: bool,
            mok in 0_u8..4,
            kitty in 0_u8..32,
            ctrl_h: bool,
        ) {
            let modes = TermModes {
                app_cursor,
                app_keypad,
                line_feed_new_line: lnm,
                modify_other_keys: mok,
                kitty_keyboard: KittyKeyboardFlags(kitty),
                ..TermModes::default()
            };
            let opts = EncodeOpts {
                backspace: if ctrl_h { BackspaceMode::CtrlH } else { BackspaceMode::Del },
            };
            let out = encode_key(KeyInput::new(key, KeyMods::from_bits(mods)), &modes, &opts);
            if matches!(key, Key::Char(_)) {
                prop_assert!(out.is_some_and(|b| !b.is_empty()));
            }
        }
    }
}
