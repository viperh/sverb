//! A tiny side scanner for the few sequences `alacritty_terminal` ignores but sverb needs:
//!
//! - OSC 7 (working directory) and OSC 133 (semantic prompt marks),
//! - `CSI > 4 ; n m` / `CSI > 4 n` (xterm modifyOtherKeys level),
//! - `CSI ? 1015 h/l` (urxvt mouse encoding),
//! - `ESC c` (RIS) to reset the above.
//!
//! It runs over the same bytes as the main parser and reports the byte offset just past each
//! recognized sequence, so the emulator can feed the main parser up to that point first and
//! attach the right cursor position to prompt marks. Ground-state text is skipped with a fast
//! search for ESC, so the overhead on plain output is small.

use crate::emulator::PromptMarkKind;
use crate::policy::{MAX_CWD_CHARS, sanitize_text};

/// Longest OSC payload we buffer (enough for a `MAX_CWD_CHARS` path, percent-encoded).
const MAX_OSC: usize = MAX_CWD_CHARS * 3 + 64;
/// Longest CSI parameter string we buffer.
const MAX_CSI: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SideEvent {
    Cwd { host: Option<String>, path: String },
    PromptMark(PromptMarkKind),
    ModifyOtherKeys(u8),
    UrxvtMouse(bool),
    Reset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Ground,
    Esc,
    /// Collecting an OSC we may care about.
    Osc,
    /// Inside an OSC we don't care about (or that overflowed); waiting for its terminator.
    OscSkip,
    /// ESC seen inside an OSC (possible ST).
    OscEsc {
        skip: bool,
    },
    Csi,
    CsiSkip,
}

#[derive(Debug)]
pub(crate) struct SideScanner {
    state: State,
    buf: Vec<u8>,
}

impl Default for SideScanner {
    fn default() -> Self {
        Self {
            state: State::Ground,
            buf: Vec::with_capacity(64),
        }
    }
}

impl SideScanner {
    /// Scan `bytes`; returns `(end_offset, event)` pairs in order.
    pub(crate) fn scan(&mut self, bytes: &[u8]) -> Vec<(usize, SideEvent)> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if self.state == State::Ground {
                match bytes[i..].iter().position(|&b| b == 0x1b) {
                    Some(p) => {
                        i += p + 1;
                        self.state = State::Esc;
                        continue;
                    }
                    None => break,
                }
            }
            let b = bytes[i];
            i += 1;
            if let Some(ev) = self.step(b) {
                out.push((i, ev));
            }
        }
        out
    }

    fn step(&mut self, b: u8) -> Option<SideEvent> {
        match self.state {
            State::Ground => {
                if b == 0x1b {
                    self.state = State::Esc;
                }
                None
            }
            State::Esc => {
                self.buf.clear();
                self.state = match b {
                    b']' => State::Osc,
                    b'[' => State::Csi,
                    0x1b => State::Esc,
                    b'c' => {
                        self.state = State::Ground;
                        return Some(SideEvent::Reset);
                    }
                    _ => State::Ground,
                };
                None
            }
            State::Osc | State::OscSkip => {
                let skip = self.state == State::OscSkip;
                match b {
                    0x07 => {
                        self.state = State::Ground;
                        if skip { None } else { self.dispatch_osc() }
                    }
                    0x1b => {
                        self.state = State::OscEsc { skip };
                        None
                    }
                    0x18 | 0x1a => {
                        self.state = State::Ground;
                        None
                    }
                    _ => {
                        if !skip {
                            self.buf.push(b);
                            if self.buf.len() > MAX_OSC || !self.osc_prefix_interesting() {
                                self.state = State::OscSkip;
                            }
                        }
                        None
                    }
                }
            }
            State::OscEsc { skip } => {
                if b == b'\\' {
                    self.state = State::Ground;
                    if skip { None } else { self.dispatch_osc() }
                } else {
                    // Not ST: the OSC is aborted and this byte starts a new escape.
                    self.state = State::Esc;
                    self.step(b)
                }
            }
            State::Csi | State::CsiSkip => match b {
                0x40..=0x7e => {
                    let skip = self.state == State::CsiSkip;
                    self.state = State::Ground;
                    if skip { None } else { self.dispatch_csi(b) }
                }
                0x1b => {
                    self.state = State::Esc;
                    None
                }
                0x18 | 0x1a => {
                    self.state = State::Ground;
                    None
                }
                0x20..=0x3f => {
                    if self.state == State::Csi {
                        self.buf.push(b);
                        if self.buf.len() > MAX_CSI {
                            self.state = State::CsiSkip;
                        }
                    }
                    None
                }
                // C0 controls inside CSI are executed by the main parser; ignore here.
                _ => None,
            },
        }
    }

    /// Whether the OSC collected so far can still be OSC 7 or OSC 133.
    fn osc_prefix_interesting(&self) -> bool {
        let b = &self.buf[..];
        let compatible = |p: &[u8]| p.starts_with(b) || b.starts_with(p);
        compatible(b"7;") || compatible(b"133;")
    }

    fn dispatch_osc(&mut self) -> Option<SideEvent> {
        let buf = std::mem::take(&mut self.buf);
        let ev = if let Some(rest) = buf.strip_prefix(b"7;") {
            parse_osc7(rest)
        } else if let Some(rest) = buf.strip_prefix(b"133;") {
            parse_osc133(rest)
        } else {
            None
        };
        self.buf = buf;
        self.buf.clear();
        ev
    }

    fn dispatch_csi(&mut self, fin: u8) -> Option<SideEvent> {
        let params = &self.buf[..];
        match (params.first(), fin) {
            (Some(b'?'), b'h' | b'l') => {
                let on = fin == b'h';
                params[1..]
                    .split(|&c| c == b';')
                    .any(|p| p == b"1015")
                    .then_some(SideEvent::UrxvtMouse(on))
            }
            (Some(b'>'), b'm') => {
                let mut it = params[1..].split(|&c| c == b';');
                if it.next()? != b"4" {
                    return None;
                }
                let level = it.next().and_then(parse_u32).unwrap_or(0);
                Some(SideEvent::ModifyOtherKeys(level.min(2) as u8))
            }
            (Some(b'>'), b'n') => (params[1..].split(|&c| c == b';').next()? == b"4")
                .then_some(SideEvent::ModifyOtherKeys(0)),
            _ => None,
        }
    }
}

fn parse_u32(p: &[u8]) -> Option<u32> {
    if p.is_empty() || p.len() > 9 {
        return None;
    }
    std::str::from_utf8(p).ok()?.parse().ok()
}

fn parse_osc133(rest: &[u8]) -> Option<SideEvent> {
    let mut parts = rest.split(|&c| c == b';');
    let kind = match parts.next()? {
        b"A" => PromptMarkKind::PromptStart,
        b"B" => PromptMarkKind::CommandStart,
        b"C" => PromptMarkKind::OutputStart,
        b"D" => {
            let exit_code = parts
                .next()
                .and_then(|p| std::str::from_utf8(p).ok())
                .and_then(|s| s.parse::<i32>().ok());
            PromptMarkKind::CommandFinished { exit_code }
        }
        _ => return None,
    };
    Some(SideEvent::PromptMark(kind))
}

fn parse_osc7(rest: &[u8]) -> Option<SideEvent> {
    let decoded = percent_decode(rest);
    let text = String::from_utf8_lossy(&decoded);
    let (host, path) = match text.find("://") {
        Some(idx) => {
            let after = &text[idx + 3..];
            match after.find('/') {
                Some(slash) => (&after[..slash], &after[slash..]),
                None => (after, "/"),
            }
        }
        None => ("", &text[..]),
    };
    if path.is_empty() {
        return None;
    }
    let host = sanitize_text(host, 255);
    let path = sanitize_text(path, MAX_CWD_CHARS);
    Some(SideEvent::Cwd {
        host: (!host.is_empty()).then_some(host),
        path,
    })
}

fn percent_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' && i + 2 < input.len() {
            let hex = |c: u8| (c as char).to_digit(16);
            if let (Some(h), Some(l)) = (hex(input[i + 1]), hex(input[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(input[i]);
        i += 1;
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn events(chunks: &[&[u8]]) -> Vec<SideEvent> {
        let mut s = SideScanner::default();
        chunks
            .iter()
            .flat_map(|c| s.scan(c))
            .map(|(_, e)| e)
            .collect()
    }

    #[test]
    fn osc7_split_across_chunks() {
        let ev = events(&[b"abc\x1b]7;file://box/ho", b"me/a%20b\x1b", b"\\tail"]);
        assert_eq!(
            ev,
            vec![SideEvent::Cwd {
                host: Some("box".into()),
                path: "/home/a b".into()
            }]
        );
    }

    #[test]
    fn osc133_marks() {
        let ev =
            events(&[b"\x1b]133;A\x07$ \x1b]133;B\x07ls\r\n\x1b]133;C\x07out\x1b]133;D;2\x07"]);
        assert_eq!(
            ev,
            vec![
                SideEvent::PromptMark(PromptMarkKind::PromptStart),
                SideEvent::PromptMark(PromptMarkKind::CommandStart),
                SideEvent::PromptMark(PromptMarkKind::OutputStart),
                SideEvent::PromptMark(PromptMarkKind::CommandFinished { exit_code: Some(2) }),
            ]
        );
    }

    #[test]
    fn offsets_point_past_the_sequence() {
        let mut s = SideScanner::default();
        let input = b"ab\x1b]133;A\x07cd";
        let ev = s.scan(input);
        assert_eq!(ev[0].0, 10);
    }

    #[test]
    fn csi_modes() {
        let ev = events(&[b"\x1b[>4;2m\x1b[?1000;1015h\x1b[?1015l\x1b[>4n\x1bc\x1b[1;31m"]);
        assert_eq!(
            ev,
            vec![
                SideEvent::ModifyOtherKeys(2),
                SideEvent::UrxvtMouse(true),
                SideEvent::UrxvtMouse(false),
                SideEvent::ModifyOtherKeys(0),
                SideEvent::Reset,
            ]
        );
    }

    #[test]
    fn other_osc_ignored_and_bounded() {
        let mut big = b"\x1b]2;".to_vec();
        big.extend(std::iter::repeat_n(b'x', 100_000));
        big.extend_from_slice(b"\x07\x1b]7;/tmp\x07");
        let ev = events(&[&big]);
        assert_eq!(
            ev,
            vec![SideEvent::Cwd {
                host: None,
                path: "/tmp".into()
            }]
        );
    }
}
