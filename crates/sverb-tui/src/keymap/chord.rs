//! Key chords: parse `"ctrl-\\"`, `"q"`, `"shift-tab"`, `"f5"` and match key events.
//!
//! [`KeyChord`] is sverb's own key type. Crossterm events are converted with
//! [`KeyChord::from_key_event`], which normalizes terminal quirks so lookups never
//! depend on how a terminal encodes a key (M0-10, `tasks/03-KEYBINDINGS.md`):
//!
//! - a shifted ASCII letter is stored as the uppercase letter **without** SHIFT
//!   (`L` means shift-l; terminals differ in whether they report SHIFT),
//! - SHIFT is dropped from other printable characters (`?` arrives with or without it),
//!   except `space`,
//! - `ctrl-space` is `Char(' ')+CONTROL`, `Null`, `Char('@')+CONTROL` or a raw NUL,
//! - `BackTab` is `Tab+SHIFT`,
//! - the legacy control bytes `0x1C`–`0x1F` (reported by crossterm as `Char('4')`…`Char('7')`
//!   with CONTROL, or as raw control characters) are `ctrl-\`, `ctrl-]`, `ctrl-^` and
//!   `ctrl-_`; `ctrl-/` is `ctrl-_` too. With the kitty protocol the real characters arrive,
//!   and both forms compare equal.
//!
//! # Grammar
//! `[ctrl-][alt-][shift-][super-]<key>`, modifiers case-insensitive and in any order,
//! where `<key>` is a single printable character (including `-`, `|`, `\`, `[`, `,`,
//! `<`, `>`, `?`, `!`, `/`) or one of `space enter esc tab backspace delete insert home
//! end pageup pagedown up down left right f1…f24`. A lone `-` is the minus key and
//! `ctrl--` is ctrl + minus. With `ctrl`, a letter's case is ignored (`CTRL-A` is
//! `ctrl-a`); write `ctrl-shift-a` for the shifted chord. Without `ctrl`, an uppercase
//! letter means shift (`L`, `alt-L`).
//!
//! [`KeyChord`]'s `Display` is the canonical form (modifier order ctrl, alt, shift,
//! super) and round-trips through `FromStr`.

use std::{fmt, ops::BitOr, str::FromStr};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
// M1-11
use sverb_term::modes::input::{Key, KeyInput, KeyMods};

/// Key modifiers sverb distinguishes. Other crossterm modifiers (hyper, meta) are dropped.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Mods(u8);

impl Mods {
    /// No modifier.
    pub const NONE: Self = Self(0);
    /// Control.
    pub const CTRL: Self = Self(1);
    /// Alt / Option / Meta (ESC prefix in legacy encodings).
    pub const ALT: Self = Self(1 << 1);
    /// Shift.
    pub const SHIFT: Self = Self(1 << 2);
    /// Super / Windows / Command (kitty keyboard protocol only).
    pub const SUPER: Self = Self(1 << 3);
    /// Every modifier, for iteration in tests.
    pub const ALL: Self = Self(0b1111);

    /// Whether every modifier in `other` is set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether any modifier in `other` is set.
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// Both sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Set `other`.
    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }

    /// Clear `other`.
    pub fn remove(&mut self, other: Self) {
        self.0 &= !other.0;
    }

    /// No modifier set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The raw bits (0..=15), for exhaustive iteration in tests.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// From raw bits; unknown bits are dropped.
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits & Self::ALL.0)
    }

    /// From crossterm modifiers.
    pub fn from_crossterm(m: KeyModifiers) -> Self {
        let mut out = Self::NONE;
        for (ct, ours) in [
            (KeyModifiers::CONTROL, Self::CTRL),
            (KeyModifiers::ALT, Self::ALT),
            (KeyModifiers::SHIFT, Self::SHIFT),
            (KeyModifiers::SUPER, Self::SUPER),
        ] {
            if m.contains(ct) {
                out.insert(ours);
            }
        }
        out
    }

    /// To crossterm modifiers.
    pub fn to_crossterm(self) -> KeyModifiers {
        let mut out = KeyModifiers::NONE;
        for (ct, ours) in [
            (KeyModifiers::CONTROL, Self::CTRL),
            (KeyModifiers::ALT, Self::ALT),
            (KeyModifiers::SHIFT, Self::SHIFT),
            (KeyModifiers::SUPER, Self::SUPER),
        ] {
            if self.contains(ours) {
                out.insert(ct);
            }
        }
        out
    }
}

impl BitOr for Mods {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

/// A single key with modifiers, normalized so lookups don't depend on terminal quirks.
///
/// Construct it with [`KeyChord::new`], [`KeyChord::from_key_event`] or `FromStr`; all
/// of them normalize, so two chords for the same physical key compare equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyChord {
    /// The key.
    pub code: KeyCode,
    /// Modifiers.
    pub mods: Mods,
}

/// Why a chord string did not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChordParseError {
    /// The text that failed.
    pub input: String,
    /// What is wrong with it.
    pub reason: String,
}

impl ChordParseError {
    fn new(input: &str, reason: impl Into<String>) -> Self {
        Self {
            input: input.to_owned(),
            reason: reason.into(),
        }
    }
}

impl fmt::Display for ChordParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid key chord `{}`: {}", self.input, self.reason)
    }
}

impl std::error::Error for ChordParseError {}

/// Named keys accepted by the parser, with their canonical spelling first.
const NAMED: &[(&str, KeyCode)] = &[
    ("space", KeyCode::Char(' ')),
    ("enter", KeyCode::Enter),
    ("esc", KeyCode::Esc),
    ("tab", KeyCode::Tab),
    ("backspace", KeyCode::Backspace),
    ("delete", KeyCode::Delete),
    ("insert", KeyCode::Insert),
    ("home", KeyCode::Home),
    ("end", KeyCode::End),
    ("pageup", KeyCode::PageUp),
    ("pagedown", KeyCode::PageDown),
    ("up", KeyCode::Up),
    ("down", KeyCode::Down),
    ("left", KeyCode::Left),
    ("right", KeyCode::Right),
    // Aliases (never displayed).
    ("escape", KeyCode::Esc),
    ("return", KeyCode::Enter),
    ("del", KeyCode::Delete),
];

impl KeyChord {
    /// Build a normalized chord.
    pub fn new(code: KeyCode, mods: Mods) -> Self {
        let (code, mods) = normalize(code, mods);
        Self { code, mods }
    }

    /// A chord for a printable character without modifiers.
    pub fn char(c: char) -> Self {
        Self::new(KeyCode::Char(c), Mods::NONE)
    }

    /// `ctrl-<c>`.
    pub fn ctrl(c: char) -> Self {
        Self::new(KeyCode::Char(c), Mods::CTRL)
    }

    /// The chord for a crossterm key event.
    pub fn from_key_event(key: &KeyEvent) -> Self {
        Self::new(key.code, Mods::from_crossterm(key.modifiers))
    }

    /// A press event for this chord (used by the test harness).
    pub fn to_key_event(self) -> KeyEvent {
        KeyEvent {
            code: self.code,
            modifiers: self.mods.to_crossterm(),
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    /// Parse a whitespace-separated chord sequence such as `"ctrl-\\ q"` or `"g g"`.
    pub fn parse_sequence(s: &str) -> Result<Vec<Self>, ChordParseError> {
        let seq: Vec<Self> = s
            .split_whitespace()
            .map(str::parse)
            .collect::<Result<_, _>>()?;
        if seq.is_empty() {
            return Err(ChordParseError::new(s, "empty key chord"));
        }
        Ok(seq)
    }

    /// Canonical text of a sequence (chords joined by one space).
    pub fn display_sequence(seq: &[Self]) -> String {
        seq.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Short form for hints in the status bar: `^\` for ctrl + a character, else canonical.
    pub fn hint(&self) -> String {
        match self.code {
            KeyCode::Char(c) if self.mods == Mods::CTRL && c != ' ' => {
                format!("^{}", c.to_ascii_uppercase())
            }
            _ => self.to_string(),
        }
    }
}

fn normalize(code: KeyCode, mut mods: Mods) -> (KeyCode, Mods) {
    let code = match code {
        KeyCode::Null => {
            mods.insert(Mods::CTRL);
            KeyCode::Char(' ')
        }
        KeyCode::BackTab => {
            mods.insert(Mods::SHIFT);
            KeyCode::Tab
        }
        KeyCode::Char(c) => return normalize_char(c, mods),
        other => other,
    };
    (code, mods)
}

fn normalize_char(c: char, mut mods: Mods) -> (KeyCode, Mods) {
    // Raw control characters (a terminal or test sending the byte itself).
    let c = match u32::from(c) {
        0x00 => {
            mods.insert(Mods::CTRL);
            ' '
        }
        0x08 | 0x7F => return (KeyCode::Backspace, mods),
        0x09 => return (KeyCode::Tab, mods),
        0x0A | 0x0D => return (KeyCode::Enter, mods),
        0x1B => return (KeyCode::Esc, mods),
        n @ (0x01..=0x1A | 0x1C..=0x1F) => {
            mods.insert(Mods::CTRL);
            // 0x01..=0x1A are ctrl-a..ctrl-z; 0x1C..=0x1F are ctrl-\ ] ^ _.
            match n {
                0x1C => '\\',
                0x1D => ']',
                0x1E => '^',
                0x1F => '_',
                // 0x01..=0x1A: `n + 0x60` is a lowercase letter.
                n => char::from_u32(n + 0x60).unwrap_or('?'),
            }
        }
        _ => c,
    };
    let c = if mods.contains(Mods::CTRL) {
        // Legacy encodings: crossterm reports 0x1C..0x1F as ctrl-4..ctrl-7, NUL as ctrl-@.
        match c {
            '4' => '\\',
            '5' => ']',
            '6' => '^',
            '7' | '/' => '_',
            '@' => ' ',
            c => c,
        }
    } else {
        c
    };
    let c = if c.is_ascii_alphabetic() {
        if mods.contains(Mods::SHIFT) || c.is_ascii_uppercase() {
            mods.remove(Mods::SHIFT);
            c.to_ascii_uppercase()
        } else {
            c
        }
    } else {
        if c != ' ' {
            mods.remove(Mods::SHIFT);
        }
        c
    };
    (KeyCode::Char(c), mods)
}

// M1-11
impl KeyChord {
    /// The key encoder's view of this chord (`sverb-term` never sees crossterm types).
    /// `None` for keys that have no byte encoding (media keys, lone modifiers, caps lock).
    /// The session actor encodes it with its pane's modes (SPEC §7.3, §9.8).
    pub fn to_key_input(&self) -> Option<KeyInput> {
        let key = match self.code {
            KeyCode::Char(c) => Key::Char(c),
            KeyCode::Null => Key::Char(' '),
            KeyCode::Enter => Key::Enter,
            KeyCode::Tab | KeyCode::BackTab => Key::Tab,
            KeyCode::Backspace => Key::Backspace,
            KeyCode::Esc => Key::Esc,
            KeyCode::Up => Key::Up,
            KeyCode::Down => Key::Down,
            KeyCode::Left => Key::Left,
            KeyCode::Right => Key::Right,
            KeyCode::Home => Key::Home,
            KeyCode::End => Key::End,
            KeyCode::Insert => Key::Insert,
            KeyCode::Delete => Key::Delete,
            KeyCode::PageUp => Key::PageUp,
            KeyCode::PageDown => Key::PageDown,
            KeyCode::F(n) => Key::F(n),
            _ => return None,
        };
        let mut mods = KeyMods::NONE;
        for (ours, theirs) in [
            (Mods::SHIFT, KeyMods::SHIFT),
            (Mods::ALT, KeyMods::ALT),
            (Mods::CTRL, KeyMods::CTRL),
            (Mods::SUPER, KeyMods::SUPER),
        ] {
            if self.mods.contains(ours) {
                mods = mods | theirs;
            }
        }
        if matches!(self.code, KeyCode::BackTab | KeyCode::Null) {
            mods = mods
                | if self.code == KeyCode::BackTab {
                    KeyMods::SHIFT
                } else {
                    KeyMods::CTRL
                };
        }
        Some(KeyInput::new(key, mods))
    }
}

impl FromStr for KeyChord {
    type Err = ChordParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(ChordParseError::new(s, "empty key chord"));
        }
        let mut mods = Mods::NONE;
        let mut explicit_shift = false;
        let mut rest = s;
        while let Some((head, tail)) = rest.split_once('-') {
            // A lone `-` (in `ctrl--` or `-`) is the key itself.
            if head.is_empty() {
                break;
            }
            let m = match head.to_ascii_lowercase().as_str() {
                "ctrl" | "control" => Mods::CTRL,
                "alt" | "meta" | "option" => Mods::ALT,
                "shift" => {
                    explicit_shift = true;
                    Mods::SHIFT
                }
                "super" | "cmd" | "win" => Mods::SUPER,
                _ => break,
            };
            if tail.is_empty() {
                return Err(ChordParseError::new(
                    s,
                    format!("missing key after `{head}-`"),
                ));
            }
            mods.insert(m);
            rest = tail;
        }
        let mut chars = rest.chars();
        let code = match (chars.next(), chars.next()) {
            (Some(c), None) if !c.is_control() && !c.is_whitespace() => {
                // With ctrl a letter's case is ignored: `CTRL-A` is `ctrl-a`.
                if mods.contains(Mods::CTRL) && !explicit_shift {
                    KeyCode::Char(c.to_ascii_lowercase())
                } else {
                    KeyCode::Char(c)
                }
            }
            _ => {
                let lower = rest.to_ascii_lowercase();
                if let Some((_, code)) = NAMED.iter().find(|(name, _)| *name == lower) {
                    *code
                } else if let Some(n) = lower.strip_prefix('f').and_then(|n| n.parse::<u8>().ok()) {
                    if !(1..=24).contains(&n) {
                        return Err(ChordParseError::new(s, "function keys go from f1 to f24"));
                    }
                    KeyCode::F(n)
                } else {
                    return Err(ChordParseError::new(
                        s,
                        format!(
                            "unknown key `{rest}` (expected one character, a named key such as `enter` or `pageup`, or f1…f24)"
                        ),
                    ));
                }
            }
        };
        Ok(Self::new(code, mods))
    }
}

impl fmt::Display for KeyChord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // An uppercase letter with ctrl is written `ctrl-shift-x` (the parser folds the
        // case of letters after `ctrl-`); without ctrl it is written as the letter.
        let (shown, shift_letter) = match self.code {
            KeyCode::Char(c) if c.is_ascii_uppercase() && self.mods.contains(Mods::CTRL) => {
                (KeyCode::Char(c.to_ascii_lowercase()), true)
            }
            code => (code, false),
        };
        for (m, name) in [
            (Mods::CTRL, "ctrl-"),
            (Mods::ALT, "alt-"),
            (Mods::SHIFT, "shift-"),
            (Mods::SUPER, "super-"),
        ] {
            if self.mods.contains(m) || (m == Mods::SHIFT && shift_letter) {
                f.write_str(name)?;
            }
        }
        match shown {
            KeyCode::Char(' ') => f.write_str("space"),
            KeyCode::Char(c) => write!(f, "{c}"),
            KeyCode::Enter => f.write_str("enter"),
            KeyCode::Esc => f.write_str("esc"),
            KeyCode::Tab => f.write_str("tab"),
            KeyCode::Backspace => f.write_str("backspace"),
            KeyCode::Delete => f.write_str("delete"),
            KeyCode::Insert => f.write_str("insert"),
            KeyCode::Home => f.write_str("home"),
            KeyCode::End => f.write_str("end"),
            KeyCode::PageUp => f.write_str("pageup"),
            KeyCode::PageDown => f.write_str("pagedown"),
            KeyCode::Up => f.write_str("up"),
            KeyCode::Down => f.write_str("down"),
            KeyCode::Left => f.write_str("left"),
            KeyCode::Right => f.write_str("right"),
            KeyCode::F(n) => write!(f, "f{n}"),
            // Keys outside the grammar (caps lock, media keys, …) can't be bound; they
            // only ever pass through to sessions. Shown for logs, not parseable.
            other => write!(f, "<{}>", format!("{other:?}").to_ascii_lowercase()),
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn p(s: &str) -> KeyChord {
        s.parse().unwrap_or_else(|e| panic!("{s}: {e}"))
    }

    // T-01: parse + canonical display round-trip (≥ 40 chords).
    #[test]
    fn t01_parse_display_table() {
        for (input, canonical) in [
            ("ctrl-\\", "ctrl-\\"),
            ("CTRL-A", "ctrl-a"),
            ("CTRL-a", "ctrl-a"),
            ("Ctrl-Alt-x", "ctrl-alt-x"),
            ("alt-ctrl-x", "ctrl-alt-x"),
            ("alt-enter", "alt-enter"),
            ("AlT-eNtEr", "alt-enter"),
            ("ctrl-alt-shift-x", "ctrl-alt-shift-x"),
            ("shift-ctrl-alt-X", "ctrl-alt-shift-x"),
            ("ctrl-shift-enter", "ctrl-shift-enter"),
            ("shift-esc", "shift-esc"),
            ("super-k", "super-k"),
            ("ctrl-super-k", "ctrl-super-k"),
            ("a", "a"),
            ("q", "q"),
            ("enter", "enter"),
            ("esc", "esc"),
            ("escape", "esc"),
            ("return", "enter"),
            ("f1", "f1"),
            ("f5", "f5"),
            ("F12", "f12"),
            ("f24", "f24"),
            ("-", "-"),
            ("ctrl--", "ctrl--"),
            ("alt--", "alt--"),
            ("|", "|"),
            ("\\", "\\"),
            ("[", "["),
            ("]", "]"),
            ("space", "space"),
            ("ctrl-space", "ctrl-space"),
            ("shift-space", "shift-space"),
            ("ctrl-@", "ctrl-space"),
            ("shift-tab", "shift-tab"),
            ("tab", "tab"),
            ("L", "L"),
            ("shift-l", "L"),
            ("alt-L", "alt-L"),
            ("alt-shift-l", "alt-L"),
            ("ctrl-shift-l", "ctrl-shift-l"),
            ("?", "?"),
            ("shift-/", "/"),
            ("!", "!"),
            (",", ","),
            ("<", "<"),
            (">", ">"),
            ("/", "/"),
            ("ctrl-]", "ctrl-]"),
            ("ctrl-4", "ctrl-\\"),
            ("ctrl-5", "ctrl-]"),
            ("ctrl-6", "ctrl-^"),
            ("ctrl-7", "ctrl-_"),
            ("ctrl-/", "ctrl-_"),
            ("pageup", "pageup"),
            ("PageDown", "pagedown"),
            ("home", "home"),
            ("end", "end"),
            ("insert", "insert"),
            ("delete", "delete"),
            ("del", "delete"),
            ("backspace", "backspace"),
            ("ctrl-left", "ctrl-left"),
            ("é", "é"),
        ] {
            let chord = p(input);
            assert_eq!(chord.to_string(), canonical, "{input}");
            assert_eq!(p(canonical), chord, "{canonical}");
        }
    }

    // T-03: invalid chords are errors with messages.
    #[test]
    fn t03_invalid() {
        for (bad, why) in [
            ("", "empty"),
            ("ctrl-", "missing key"),
            ("foo", "unknown key"),
            ("ctrl-invalid", "unknown key"),
            ("invalid-key", "unknown key"),
            ("ctrl-invalid-key", "unknown key"),
            ("f25", "f1 to f24"),
            ("f0", "f1 to f24"),
            ("hyper-x", "unknown key"),
        ] {
            let Err(err) = bad.parse::<KeyChord>() else {
                panic!("`{bad}` must not parse");
            };
            assert!(err.to_string().contains(why), "{bad}: {err}");
            assert!(err.to_string().contains(&format!("`{bad}`")), "{err}");
        }
        assert!(KeyChord::parse_sequence("  ").is_err());
    }

    // T-04 / K-05: terminal quirks normalize to one chord.
    #[test]
    fn t04_normalization() {
        let ev = |code, m| KeyChord::from_key_event(&KeyEvent::new(code, m));
        let leader = p("ctrl-\\");
        assert_eq!(ev(KeyCode::Char('4'), KeyModifiers::CONTROL), leader);
        assert_eq!(ev(KeyCode::Char('\x1c'), KeyModifiers::NONE), leader);
        assert_eq!(ev(KeyCode::Char('\\'), KeyModifiers::CONTROL), leader);

        let cs = p("ctrl-space");
        assert_eq!(ev(KeyCode::Char(' '), KeyModifiers::CONTROL), cs);
        assert_eq!(ev(KeyCode::Null, KeyModifiers::NONE), cs);
        assert_eq!(ev(KeyCode::Char('@'), KeyModifiers::CONTROL), cs);
        assert_eq!(ev(KeyCode::Char('\0'), KeyModifiers::NONE), cs);

        assert_eq!(ev(KeyCode::BackTab, KeyModifiers::SHIFT), p("shift-tab"));
        assert_eq!(ev(KeyCode::BackTab, KeyModifiers::NONE), p("shift-tab"));
        assert_eq!(ev(KeyCode::Char('L'), KeyModifiers::SHIFT), p("L"));
        assert_eq!(ev(KeyCode::Char('l'), KeyModifiers::SHIFT), p("L"));
        assert_eq!(ev(KeyCode::Char('L'), KeyModifiers::NONE), p("L"));
        assert_eq!(ev(KeyCode::Char('?'), KeyModifiers::SHIFT), p("?"));

        assert_eq!(ev(KeyCode::Char('5'), KeyModifiers::CONTROL), p("ctrl-]"));
        assert_eq!(ev(KeyCode::Char('\x1d'), KeyModifiers::NONE), p("ctrl-]"));
        assert_eq!(ev(KeyCode::Char('6'), KeyModifiers::CONTROL), p("ctrl-^"));
        assert_eq!(ev(KeyCode::Char('7'), KeyModifiers::CONTROL), p("ctrl-_"));
        assert_eq!(ev(KeyCode::Char('/'), KeyModifiers::CONTROL), p("ctrl-_"));
        assert_eq!(ev(KeyCode::Char('\x07'), KeyModifiers::NONE), p("ctrl-g"));
        // Hyper/meta are dropped.
        assert_eq!(ev(KeyCode::Char('x'), KeyModifiers::HYPER), p("x"));
    }

    #[test]
    fn events_round_trip_through_key_events() {
        for s in ["ctrl-\\", "L", "shift-tab", "ctrl-space", "alt-f4", "q"] {
            let c = p(s);
            assert_eq!(KeyChord::from_key_event(&c.to_key_event()), c, "{s}");
        }
    }

    #[test]
    fn sequences_and_hints() {
        let seq = KeyChord::parse_sequence("ctrl-\\  q").unwrap_or_default();
        assert_eq!(seq.len(), 2);
        assert_eq!(KeyChord::display_sequence(&seq), "ctrl-\\ q");
        assert_eq!(p("ctrl-\\").hint(), "^\\");
        assert_eq!(p("ctrl-g").hint(), "^G");
        assert_eq!(p("alt-x").hint(), "alt-x");
    }

    fn any_code() -> impl Strategy<Value = KeyCode> {
        prop_oneof![
            (0x20u8..0x7F).prop_map(|b| KeyCode::Char(char::from(b))),
            prop::sample::select(vec!['é', 'ß', 'Ä', '€', 'ж', '中']).prop_map(KeyCode::Char),
            (1u8..=24).prop_map(KeyCode::F),
            prop::sample::select(vec![
                KeyCode::Enter,
                KeyCode::Esc,
                KeyCode::Tab,
                KeyCode::BackTab,
                KeyCode::Backspace,
                KeyCode::Delete,
                KeyCode::Insert,
                KeyCode::Home,
                KeyCode::End,
                KeyCode::PageUp,
                KeyCode::PageDown,
                KeyCode::Up,
                KeyCode::Down,
                KeyCode::Left,
                KeyCode::Right,
                KeyCode::Null,
            ]),
            (0u8..0x20).prop_map(|b| KeyCode::Char(char::from(b))),
        ]
    }

    proptest! {
        // T-02: parse(display(c)) == c for every chord in the grammar.
        #[test]
        fn t02_display_parse_round_trip(code in any_code(), bits in 0u8..16) {
            let chord = KeyChord::new(code, Mods::from_bits(bits));
            let shown = chord.to_string();
            let back: KeyChord = shown
                .parse()
                .map_err(|e| TestCaseError::fail(format!("{chord:?} → {shown}: {e}")))?;
            prop_assert_eq!(back, chord, "{}", shown);
            // Normalization is idempotent.
            prop_assert_eq!(KeyChord::new(chord.code, chord.mods), chord);
        }
    }
}
