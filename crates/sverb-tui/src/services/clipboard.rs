//! M1-11: the clipboard service (`Effect::CopyToClipboard`, SPEC §7.3).
//!
//! Strategy:
//! - sverb itself runs over SSH (`SSH_CONNECTION` or `SSH_TTY` set): **OSC 52 only** — the
//!   local machine's clipboard is the wrong one, and the outer terminal is on the user's
//!   machine.
//! - Otherwise: the local clipboard, **plus** OSC 52 when `clipboard.osc52 = true`. A text
//!   over the OSC 52 cap skips OSC 52 when a local clipboard exists (a truncated OSC 52
//!   copy would overwrite the full local one).
//!
//! OSC 52 is `ESC ] 52 ; c ; <base64> BEL`, written to the outer terminal (stdout). Many
//! terminals reject large payloads, so the base64 payload is capped at
//! [`OSC52_MAX_PAYLOAD`] (100 KB): the text is cut at a character boundary and the reducer
//! shows a toast (`App::copy_to_clipboard`).
//!
//! The local clipboard: `arboard` is the spec's choice, but it isn't available to this
//! build (offline registry), so [`CommandClipboard`] pipes the text into the platform's
//! clipboard tool (`wl-copy`, `xclip`/`xsel`, `pbcopy`, `clip.exe`) on a background
//! thread. A missing tool or a failure is logged, never fatal. [`LocalClipboard`] is the
//! seam for swapping in `arboard` later.

use std::{
    fmt,
    io::{self, Write},
    process::{Command, Stdio},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use tracing::{debug, warn};

/// Maximum OSC 52 payload (base64 bytes).
pub const OSC52_MAX_PAYLOAD: usize = 100 * 1024;
/// Maximum text (UTF-8 bytes) whose base64 fits in [`OSC52_MAX_PAYLOAD`].
pub const OSC52_MAX_TEXT_BYTES: usize = OSC52_MAX_PAYLOAD / 4 * 3;

/// `ESC ] 52 ; c ; <base64> BEL` for `text`, cut to [`OSC52_MAX_TEXT_BYTES`] at a char
/// boundary. The flag says whether it was cut.
pub fn osc52_sequence(text: &str) -> (Vec<u8>, bool) {
    let mut end = text.len().min(OSC52_MAX_TEXT_BYTES);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = b"\x1b]52;c;".to_vec();
    out.extend_from_slice(STANDARD.encode(&text.as_bytes()[..end]).as_bytes());
    out.push(0x07);
    (out, end < text.len())
}

/// A local clipboard.
pub trait LocalClipboard: Send + fmt::Debug {
    /// Start setting the clipboard to `text` (may finish in the background).
    fn set_text(&mut self, text: &str) -> io::Result<()>;
}

/// The platform's clipboard command.
#[derive(Debug, Clone)]
pub struct CommandClipboard {
    program: &'static str,
    args: &'static [&'static str],
}

impl CommandClipboard {
    /// The first clipboard tool found for this platform and session, if any.
    pub fn detect() -> Option<Self> {
        let candidates: &[(&'static str, &'static [&'static str], bool)] =
            if cfg!(target_os = "macos") {
                &[("pbcopy", &[], true)]
            } else if cfg!(windows) {
                &[("clip.exe", &[], true)]
            } else {
                let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some();
                let x11 = std::env::var_os("DISPLAY").is_some();
                &[
                    ("wl-copy", &[], wayland),
                    ("xclip", &["-selection", "clipboard"], x11),
                    ("xsel", &["--clipboard", "--input"], x11),
                ]
            };
        candidates
            .iter()
            .find(|(program, _, usable)| *usable && in_path(program))
            .map(|&(program, args, _)| Self { program, args })
    }
}

fn in_path(program: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|dir| dir.join(program).is_file()))
}

impl LocalClipboard for CommandClipboard {
    fn set_text(&mut self, text: &str) -> io::Result<()> {
        let mut child = Command::new(self.program)
            .args(self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let text = text.to_owned();
        let program = self.program;
        // The tool may keep running to own the selection (xclip): never wait on the UI
        // thread.
        std::thread::spawn(move || {
            if let Some(mut stdin) = child.stdin.take()
                && let Err(err) = stdin.write_all(text.as_bytes())
            {
                debug!(program, %err, "clipboard tool rejected input");
            }
            match child.wait() {
                Ok(status) if !status.success() => {
                    debug!(program, %status, "clipboard tool failed")
                }
                Err(err) => debug!(program, %err, "clipboard tool failed"),
                Ok(_) => {}
            }
        });
        Ok(())
    }
}

/// What a copy did (for logs and tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CopyReport {
    /// An OSC 52 sequence was written.
    pub osc52: bool,
    /// The OSC 52 payload was cut at the cap.
    pub truncated: bool,
    /// The local clipboard was asked.
    pub local: bool,
}

/// Executes `Effect::CopyToClipboard`.
pub struct ClipboardService {
    osc52: bool,
    over_ssh: bool,
    local: Option<Box<dyn LocalClipboard>>,
    out: Box<dyn Write + Send>,
}

impl fmt::Debug for ClipboardService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClipboardService")
            .field("osc52", &self.osc52)
            .field("over_ssh", &self.over_ssh)
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

impl ClipboardService {
    /// A service with explicit parts (tests).
    pub fn new(
        osc52: bool,
        over_ssh: bool,
        local: Option<Box<dyn LocalClipboard>>,
        out: Box<dyn Write + Send>,
    ) -> Self {
        Self {
            osc52,
            over_ssh,
            local,
            out,
        }
    }

    /// The real service: OSC 52 to stdout, the platform's clipboard tool, and SSH
    /// detection from `SSH_CONNECTION` / `SSH_TTY`.
    pub fn from_env(osc52: bool) -> Self {
        // M7-04: the shared detection (`runtime::capabilities`, also used by `sverb doctor`).
        let over_ssh = crate::runtime::capabilities::TermEnv::from_process().over_ssh();
        let local = if over_ssh {
            None
        } else {
            CommandClipboard::detect().map(|c| Box::new(c) as Box<dyn LocalClipboard>)
        };
        Self::new(osc52, over_ssh, local, Box::new(io::stdout()))
    }

    /// `clipboard.osc52` changed (hot reload).
    pub fn set_osc52(&mut self, on: bool) {
        self.osc52 = on;
    }

    /// Copy `text`. Failures are logged; nothing here is fatal.
    pub fn copy(&mut self, text: &str) -> CopyReport {
        let mut report = CopyReport::default();
        if !self.over_ssh
            && let Some(local) = &mut self.local
        {
            match local.set_text(text) {
                Ok(()) => report.local = true,
                Err(err) => debug!(%err, "local clipboard unavailable"),
            }
        }
        let too_big = text.len() > OSC52_MAX_TEXT_BYTES;
        if self.osc52 && !(report.local && too_big) {
            let (seq, truncated) = osc52_sequence(text);
            match self.out.write_all(&seq).and_then(|()| self.out.flush()) {
                Ok(()) => {
                    report.osc52 = true;
                    report.truncated = truncated;
                }
                Err(err) => warn!(%err, "cannot write OSC 52"),
            }
        }
        if !report.osc52 && !report.local {
            warn!("nothing was copied: no local clipboard and OSC 52 is off or failed");
        }
        report
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::sync::{Arc, Mutex};

    use super::*;

    /// T-13: the OSC 52 format and the 100 KB cap.
    #[test]
    fn t13_osc52_format_and_cap() {
        let (seq, cut) = osc52_sequence("hello");
        assert_eq!(seq, b"\x1b]52;c;aGVsbG8=\x07");
        assert!(!cut);

        let big = "é".repeat(OSC52_MAX_TEXT_BYTES); // 2 bytes each
        let (seq, cut) = osc52_sequence(&big);
        assert!(cut);
        let payload = &seq[7..seq.len() - 1];
        assert!(payload.len() <= OSC52_MAX_PAYLOAD, "{}", payload.len());
        let decoded = STANDARD.decode(payload).unwrap();
        // Cut at a char boundary.
        let text = String::from_utf8(decoded).unwrap();
        assert!(text.len() <= OSC52_MAX_TEXT_BYTES);
        assert!(text.chars().all(|c| c == 'é'));

        let exact = "a".repeat(OSC52_MAX_TEXT_BYTES);
        let (seq, cut) = osc52_sequence(&exact);
        assert!(!cut);
        assert_eq!(seq.len() - 8, OSC52_MAX_PAYLOAD);
    }

    #[derive(Debug, Default, Clone)]
    struct FakeLocal(Arc<Mutex<Vec<String>>>);

    impl LocalClipboard for FakeLocal {
        fn set_text(&mut self, text: &str) -> io::Result<()> {
            self.0.lock().unwrap().push(text.to_owned());
            Ok(())
        }
    }

    #[derive(Debug, Default, Clone)]
    struct Out(Arc<Mutex<Vec<u8>>>);

    impl Write for Out {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn service(osc52: bool, over_ssh: bool) -> (ClipboardService, FakeLocal, Out) {
        let local = FakeLocal::default();
        let out = Out::default();
        let svc = ClipboardService::new(
            osc52,
            over_ssh,
            Some(Box::new(local.clone())),
            Box::new(out.clone()),
        );
        (svc, local, out)
    }

    #[test]
    fn strategy() {
        // Over SSH: OSC 52 only.
        let (mut svc, local, out) = service(true, true);
        let r = svc.copy("hi");
        assert_eq!(
            r,
            CopyReport {
                osc52: true,
                truncated: false,
                local: false
            }
        );
        assert!(local.0.lock().unwrap().is_empty());
        assert_eq!(*out.0.lock().unwrap(), b"\x1b]52;c;aGk=\x07");

        // Locally: both.
        let (mut svc, local, out) = service(true, false);
        let r = svc.copy("hi");
        assert!(r.osc52 && r.local);
        assert_eq!(*local.0.lock().unwrap(), ["hi"]);
        assert!(!out.0.lock().unwrap().is_empty());

        // OSC 52 off: local only.
        let (mut svc, local, out) = service(false, false);
        svc.copy("hi");
        assert_eq!(*local.0.lock().unwrap(), ["hi"]);
        assert!(out.0.lock().unwrap().is_empty());

        // Too big with a local clipboard: no truncated OSC 52 on top of it.
        let (mut svc, _, out) = service(true, false);
        let r = svc.copy(&"x".repeat(OSC52_MAX_TEXT_BYTES + 1));
        assert!(r.local && !r.osc52);
        assert!(out.0.lock().unwrap().is_empty());

        // Too big over SSH: truncated OSC 52.
        let (mut svc, _, _) = service(true, true);
        let r = svc.copy(&"x".repeat(OSC52_MAX_TEXT_BYTES + 1));
        assert!(r.osc52 && r.truncated);
    }
}
