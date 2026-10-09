//! M7-04: terminal capability detection shared by the TUI startup and `sverb doctor`.
//!
//! - [`TermEnv`]: what the environment says (`TERM`, `COLORTERM`, `NO_COLOR`,
//!   `TERM_PROGRAM`, tmux / screen, SSH). Pure: built from a lookup function, so tests
//!   never touch the process environment. The theme ([`crate::theme::ThemeEnv`]) and
//!   the clipboard service read it.
//! - [`probe_terminal`] (unix): asks the controlling terminal about the kitty keyboard
//!   protocol (the same query as startup, [`super::terminal::kitty_probe`]) and the
//!   width it gives a wide character (a cursor-position report). It writes escape
//!   sequences, so callers must only use it when stdout **is** a terminal.

use std::io;
use std::time::Duration;

/// A terminal multiplexer sverb runs inside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Multiplexer {
    /// tmux (`TMUX` set, or `TERM=tmux*`).
    Tmux,
    /// GNU screen (`STY` set, or `TERM=screen*` without tmux).
    Screen,
}

impl Multiplexer {
    /// The program name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Tmux => "tmux",
            Self::Screen => "screen",
        }
    }
}

/// How likely OSC 52 clipboard writes reach the system clipboard. Terminals don't
/// report it, so this is a guess from `TERM_PROGRAM` / `TERM`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Osc52Guess {
    /// The terminal is known to support it (by default).
    Likely,
    /// The terminal is known not to support it.
    Unlikely,
    /// Unknown terminal.
    Unknown,
}

/// The terminal-related environment, read once.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TermEnv {
    /// `TERM`.
    pub term: Option<String>,
    /// `COLORTERM`.
    pub colorterm: Option<String>,
    /// `TERM_PROGRAM`.
    pub term_program: Option<String>,
    /// `NO_COLOR` is set to a non-empty value.
    pub no_color: bool,
    /// `TMUX` is set.
    pub tmux: bool,
    /// `STY` is set (GNU screen).
    pub screen: bool,
    /// `SSH_CONNECTION` or `SSH_TTY` is set.
    pub ssh: bool,
    // M7-07
    /// The locale: the first non-empty of `LC_ALL`, `LC_CTYPE`, `LANG`.
    pub locale: Option<String>,
}

/// The variables [`TermEnv`] reads.
pub const TERM_ENV_VARS: &[&str] = &[
    "TERM",
    "COLORTERM",
    "TERM_PROGRAM",
    "NO_COLOR",
    "TMUX",
    "STY",
    "SSH_CONNECTION",
    "SSH_TTY",
    // M7-07
    "LC_ALL",
    "LC_CTYPE",
    "LANG",
];

impl TermEnv {
    /// From a lookup (`name → value`); empty values count as unset except for
    /// `NO_COLOR`, where only a non-empty value counts.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Self {
        let set = |name: &str| get(name).filter(|v| !v.is_empty());
        Self {
            term: set("TERM"),
            colorterm: set("COLORTERM"),
            term_program: set("TERM_PROGRAM"),
            no_color: set("NO_COLOR").is_some(),
            tmux: set("TMUX").is_some(),
            screen: set("STY").is_some(),
            ssh: set("SSH_CONNECTION").is_some() || set("SSH_TTY").is_some(),
            // M7-07
            locale: set("LC_ALL")
                .or_else(|| set("LC_CTYPE"))
                .or_else(|| set("LANG")),
        }
    }

    /// The process environment.
    pub fn from_process() -> Self {
        Self::from_lookup(|name| std::env::var_os(name).map(|v| v.to_string_lossy().into_owned()))
    }

    /// `COLORTERM` says `truecolor` / `24bit`.
    pub fn truecolor(&self) -> bool {
        self.colorterm.as_deref().is_some_and(|v| {
            let v = v.trim();
            v.eq_ignore_ascii_case("truecolor") || v.eq_ignore_ascii_case("24bit")
        })
    }

    /// At least 256 colors: truecolor, or a `TERM` naming `256color` / `direct`.
    pub fn colors_256(&self) -> bool {
        self.truecolor()
            || self
                .term
                .as_deref()
                .is_some_and(|t| t.contains("256color") || t.contains("direct"))
    }

    // M7-07
    /// The locale names UTF-8 (always true on Windows, which has no `LANG`). An unset
    /// locale is POSIX `C`, so it doesn't (the same rule as `sverb doctor`).
    pub fn utf8_locale(&self) -> bool {
        cfg!(windows)
            || self.locale.as_deref().is_some_and(|v| {
                let v = v.to_ascii_lowercase();
                v.contains("utf-8") || v.contains("utf8")
            })
    }

    /// `ui.ascii = "auto"` picks ASCII glyphs: the locale isn't UTF-8, or this is the
    /// Linux console (`TERM=linux`, whose font lacks most symbols).
    pub fn wants_ascii(&self) -> bool {
        !self.utf8_locale() || self.term.as_deref() == Some("linux")
    }

    /// sverb itself runs over SSH.
    pub fn over_ssh(&self) -> bool {
        self.ssh
    }

    /// The multiplexer sverb runs inside, if any.
    pub fn multiplexer(&self) -> Option<Multiplexer> {
        let term = self.term.as_deref().unwrap_or("");
        if self.tmux || term.starts_with("tmux") {
            Some(Multiplexer::Tmux)
        } else if self.screen || term.starts_with("screen") {
            Some(Multiplexer::Screen)
        } else {
            None
        }
    }

    /// The terminal's name for messages: `TERM_PROGRAM`, else `TERM`.
    pub fn terminal_name(&self) -> Option<&str> {
        self.term_program.as_deref().or(self.term.as_deref())
    }

    /// Whether OSC 52 likely works with this terminal (a heuristic; inside tmux
    /// `TERM_PROGRAM` names tmux, so the outer terminal is unknown).
    pub fn osc52(&self) -> Osc52Guess {
        const LIKELY_PROGRAMS: &[&str] = &[
            "iterm.app",
            "wezterm",
            "ghostty",
            "vscode",
            "kitty",
            "alacritty",
            "foot",
            "rio",
            "tabby",
            "warpterminal",
            "contour",
            "windows_terminal",
        ];
        const LIKELY_TERMS: &[&str] = &[
            "xterm-kitty",
            "alacritty",
            "foot",
            "xterm-ghostty",
            "wezterm",
            "contour",
            "rio",
        ];
        let program = self
            .term_program
            .as_deref()
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();
        let term = self.term.as_deref().unwrap_or("");
        if program == "apple_terminal" {
            return Osc52Guess::Unlikely;
        }
        if LIKELY_PROGRAMS.contains(&program.as_str())
            || LIKELY_TERMS.iter().any(|t| term.starts_with(t))
        {
            return Osc52Guess::Likely;
        }
        if term == "linux" {
            return Osc52Guess::Unlikely;
        }
        Osc52Guess::Unknown
    }
}

/// What [`probe_terminal`] found.
#[derive(Debug)]
pub struct TerminalProbe {
    /// The kitty keyboard protocol answered.
    pub kitty: io::Result<bool>,
    /// The columns the terminal advanced for [`WIDE_PROBE_CHAR`]; `Ok(None)` when it
    /// sent no cursor position report in time.
    pub wide_char_width: io::Result<Option<u16>>,
}

/// The character used for the width probe (East Asian Wide: 2 columns).
pub const WIDE_PROBE_CHAR: &str = "\u{754c}";

/// Ask the controlling terminal (raw mode for the duration) about the kitty keyboard
/// protocol and wide-character width, waiting at most `timeout` for each answer.
/// The probe line is cleared afterwards. Only call it when stdout is a terminal.
#[cfg(unix)]
pub fn probe_terminal(timeout: Duration) -> TerminalProbe {
    let was_raw = crossterm::terminal::is_raw_mode_enabled().unwrap_or(false);
    if !was_raw && let Err(e) = crossterm::terminal::enable_raw_mode() {
        let msg = e.to_string();
        return TerminalProbe {
            kitty: Err(io::Error::other(msg.clone())),
            wide_char_width: Err(io::Error::other(msg)),
        };
    }
    let kitty = super::terminal::kitty_probe::probe(timeout);
    let wide_char_width = cursor_probe::wide_char_width(timeout);
    if !was_raw {
        let _ = crossterm::terminal::disable_raw_mode();
    }
    TerminalProbe {
        kitty,
        wide_char_width,
    }
}

/// Not implemented outside unix: both answers are errors.
#[cfg(not(unix))]
pub fn probe_terminal(_timeout: Duration) -> TerminalProbe {
    TerminalProbe {
        kitty: Err(io::Error::other("not probed on this platform")),
        wide_char_width: Err(io::Error::other("not probed on this platform")),
    }
}

/// The cursor-position probe (unix).
#[cfg(unix)]
pub mod cursor_probe {
    use std::fs::OpenOptions;
    use std::io::{self, Read, Write};
    use std::time::{Duration, Instant};

    use rustix::event::{PollFd, PollFlags, Timespec, poll};

    use super::WIDE_PROBE_CHAR;

    /// The column of a cursor position report (`ESC [ row ; col R`) in `reply`,
    /// `None` while it is incomplete.
    pub fn parse_cpr(reply: &[u8]) -> Option<u16> {
        let start = reply.windows(2).position(|w| w == b"\x1b[")?;
        let body = &reply[start + 2..];
        let end = body.iter().position(|b| *b == b'R')?;
        let text = std::str::from_utf8(&body[..end]).ok()?;
        let (_, col) = text.split_once(';')?;
        col.parse().ok()
    }

    /// Print [`WIDE_PROBE_CHAR`] at column 1, ask where the cursor is, then clear
    /// the line. Needs raw mode.
    ///
    /// # Errors
    /// The terminal can't be opened, written or read.
    pub fn wide_char_width(timeout: Duration) -> io::Result<Option<u16>> {
        let mut tty = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
        let mut query = Vec::new();
        query.extend_from_slice(b"\r");
        query.extend_from_slice(WIDE_PROBE_CHAR.as_bytes());
        query.extend_from_slice(b"\x1b[6n");
        tty.write_all(&query)?;
        tty.flush()?;
        let deadline = Instant::now() + timeout;
        let mut reply = Vec::new();
        let col = loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break None;
            }
            let ts = Timespec::try_from(left).unwrap_or(Timespec {
                tv_sec: 0,
                tv_nsec: 50_000_000,
            });
            let ready = {
                let mut fds = [PollFd::new(&tty, PollFlags::IN)];
                match poll(&mut fds, Some(&ts)) {
                    Ok(n) => n > 0,
                    Err(rustix::io::Errno::INTR) => continue,
                    Err(e) => return Err(e.into()),
                }
            };
            if !ready {
                break None;
            }
            let mut chunk = [0u8; 64];
            let n = tty.read(&mut chunk)?;
            if n == 0 {
                break None;
            }
            reply.extend_from_slice(&chunk[..n]);
            if let Some(col) = parse_cpr(&reply) {
                break Some(col);
            }
        };
        tty.write_all(b"\r\x1b[2K")?;
        tty.flush()?;
        Ok(col.map(|c| c.saturating_sub(1)))
    }

    #[cfg(test)]
    mod tests {
        use super::parse_cpr;

        #[test]
        fn cursor_position_reports() {
            assert_eq!(parse_cpr(b"\x1b[12;3R"), Some(3));
            assert_eq!(parse_cpr(b"junk\x1b[1;80R"), Some(80));
            assert_eq!(parse_cpr(b"\x1b[12;3"), None);
            assert_eq!(parse_cpr(b""), None);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn env(vars: &[(&str, &str)]) -> TermEnv {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        TermEnv::from_lookup(|k| map.get(k).cloned())
    }

    #[test]
    fn colors() {
        assert!(env(&[("COLORTERM", "truecolor")]).truecolor());
        assert!(env(&[("COLORTERM", "24BIT")]).truecolor());
        assert!(!env(&[("COLORTERM", "yes")]).truecolor());
        assert!(env(&[("TERM", "xterm-256color")]).colors_256());
        assert!(!env(&[("TERM", "xterm")]).colors_256());
        assert!(env(&[("NO_COLOR", "1")]).no_color);
        assert!(!env(&[("NO_COLOR", "")]).no_color);
    }

    // M7-07: `ui.ascii = "auto"`.
    #[test]
    fn ascii_fallback_from_locale_and_term() {
        let utf8 = [("LANG", "en_US.UTF-8"), ("TERM", "xterm-256color")];
        assert!(!env(&utf8).wants_ascii());
        assert!(!env(&[("LC_ALL", "C.utf8")]).wants_ascii());
        // LC_ALL wins over LANG.
        assert_eq!(
            env(&[("LC_ALL", "C"), ("LANG", "en_US.UTF-8")]).wants_ascii(),
            !cfg!(windows)
        );
        assert_eq!(
            env(&[("LANG", "de_DE.ISO-8859-1")]).wants_ascii(),
            !cfg!(windows)
        );
        assert_eq!(env(&[]).wants_ascii(), !cfg!(windows));
        // The Linux console, even with a UTF-8 locale.
        assert!(env(&[("LANG", "en_US.UTF-8"), ("TERM", "linux")]).wants_ascii());
    }

    #[test]
    fn ssh_and_multiplexers() {
        assert!(env(&[("SSH_CONNECTION", "1.2.3.4 5 6.7.8.9 22")]).over_ssh());
        assert!(env(&[("SSH_TTY", "/dev/pts/1")]).over_ssh());
        assert!(!env(&[]).over_ssh());
        assert_eq!(
            env(&[("TMUX", "/tmp/tmux-1/default,1,0")]).multiplexer(),
            Some(Multiplexer::Tmux)
        );
        assert_eq!(
            env(&[("TERM", "screen-256color"), ("STY", "1.pts")]).multiplexer(),
            Some(Multiplexer::Screen)
        );
        assert_eq!(
            env(&[("TERM", "screen-256color"), ("TMUX", "x")]).multiplexer(),
            Some(Multiplexer::Tmux)
        );
        assert_eq!(env(&[("TERM", "xterm")]).multiplexer(), None);
    }

    #[test]
    fn osc52_guess() {
        assert_eq!(
            env(&[("TERM_PROGRAM", "WezTerm")]).osc52(),
            Osc52Guess::Likely
        );
        assert_eq!(env(&[("TERM", "xterm-kitty")]).osc52(), Osc52Guess::Likely);
        assert_eq!(
            env(&[("TERM_PROGRAM", "Apple_Terminal")]).osc52(),
            Osc52Guess::Unlikely
        );
        assert_eq!(env(&[("TERM", "xterm")]).osc52(), Osc52Guess::Unknown);
        assert_eq!(
            env(&[("TERM", "xterm-ghostty")]).terminal_name(),
            Some("xterm-ghostty")
        );
    }
}
