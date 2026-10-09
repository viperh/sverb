//! Paste → bytes (SPEC §7.3).
//!
//! - Remote bracketed paste on (`?2004`): `ESC[200~` + text + `ESC[201~`. Every
//!   `ESC[201~` (and `ESC[200~`) inside the text is removed first — repeatedly, so a
//!   marker split around another one can't be reassembled — so a pasted text can't end
//!   the bracket early and type commands (paste injection).
//! - Off: newlines (`\r\n`, `\n`) become `\r`, what the Enter key sends. A multi-line paste
//!   asks for confirmation first when `terminal.paste_confirm_multiline` is on
//!   ([`needs_confirmation`]); the dialog shows a [`preview`].

use bytes::Bytes;

use crate::modes::TermModes;

/// Bracketed paste start marker.
pub const PASTE_START: &str = "\x1b[200~";
/// Bracketed paste end marker.
pub const PASTE_END: &str = "\x1b[201~";

/// Remove every bracketed-paste marker, until none is left.
#[must_use]
pub fn strip_paste_markers(text: &str) -> String {
    let mut s = text.to_owned();
    while s.contains(PASTE_END) || s.contains(PASTE_START) {
        s = s.replace(PASTE_END, "").replace(PASTE_START, "");
    }
    s
}

/// `\r\n` and `\n` → `\r`.
#[must_use]
pub fn normalize_newlines(text: &str) -> String {
    text.replace("\r\n", "\r").replace('\n', "\r")
}

/// Encode a paste for a pane with `modes`.
#[must_use]
pub fn encode_paste(text: &str, modes: &TermModes) -> Bytes {
    if modes.bracketed_paste {
        let body = strip_paste_markers(text);
        Bytes::from(format!("{PASTE_START}{body}{PASTE_END}"))
    } else {
        Bytes::from(normalize_newlines(text))
    }
}

/// Whether pasting `text` must be confirmed first: bracketed paste off, the text has a
/// line break, and `terminal.paste_confirm_multiline` is on.
#[must_use]
pub fn needs_confirmation(text: &str, modes: &TermModes, confirm_multiline: bool) -> bool {
    confirm_multiline && !modes.bracketed_paste && text.contains(['\n', '\r'])
}

/// What the confirmation dialog shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PastePreview {
    /// Number of lines (a trailing newline doesn't start a new one).
    pub lines: usize,
    /// The first lines, control characters removed.
    pub head: Vec<String>,
}

/// The line count and the first `max_lines` lines of `text`.
#[must_use]
pub fn preview(text: &str, max_lines: usize) -> PastePreview {
    let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    let lines: Vec<&str> = normalized.lines().collect();
    PastePreview {
        lines: lines.len(),
        head: lines
            .iter()
            .take(max_lines)
            .map(|l| l.chars().filter(|c| !c.is_control()).collect())
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bracketed() -> TermModes {
        TermModes {
            bracketed_paste: true,
            ..TermModes::default()
        }
    }

    /// Wrapped, and an embedded end marker is stripped.
    #[test]
    fn t11_bracketed() {
        assert_eq!(
            &encode_paste("ls\nrm -rf /", &bracketed())[..],
            b"\x1b[200~ls\nrm -rf /\x1b[201~"
        );
        assert_eq!(
            &encode_paste("a\x1b[201~echo pwned\n", &bracketed())[..],
            b"\x1b[200~aecho pwned\n\x1b[201~"
        );
        // A marker hidden around another one is gone too.
        assert_eq!(
            &encode_paste("x\x1b[20\x1b[201~1~y", &bracketed())[..],
            b"\x1b[200~xy\x1b[201~"
        );
    }

    #[test]
    fn unbracketed_newlines_become_cr() {
        let m = TermModes::default();
        assert_eq!(&encode_paste("a\nb\r\nc", &m)[..], b"a\rb\rc");
        assert_eq!(&encode_paste("one line", &m)[..], b"one line");
    }

    #[test]
    fn confirmation_rules() {
        let m = TermModes::default();
        assert!(needs_confirmation("a\nb", &m, true));
        assert!(!needs_confirmation("a\nb", &m, false));
        assert!(!needs_confirmation("a\nb", &bracketed(), true));
        assert!(!needs_confirmation("ab", &m, true));
    }

    #[test]
    fn previews() {
        let p = preview("1\n2\r\n3\n4\n5\n6\x07\n7\n", 5);
        assert_eq!(p.lines, 7);
        assert_eq!(p.head, ["1", "2", "3", "4", "5"]);
        assert_eq!(preview("a\x1bb", 5).head, ["ab"]);
    }
}
