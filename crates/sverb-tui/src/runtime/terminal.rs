//! Terminal mode bookkeeping, best-effort restore and the RAII guard (SPEC §18).
//!
//! [`TerminalModes`] is the single source of truth for which terminal modes sverb has
//! turned on. It is a lock-free bitset, so the panic hook can read it from any thread,
//! with or without a tokio runtime, without allocating:
//!
//! - every enable operation sets its bit **after** it succeeded,
//! - every disable operation clears its bit,
//! - [`restore_terminal`] undoes exactly the enabled modes, in this order: pop kitty
//!   keyboard flags → bracketed paste off → mouse capture off → focus events off →
//!   show cursor → leave the alternate screen → raw mode off.
//!
//! [`restore_terminal`] never panics and never blocks on a lock another thread may hold:
//! it writes to a freshly duplicated stdout file descriptor (handle on Windows) instead
//! of going through `std::io::Stdout`'s lock. Each step is best effort.
//!
//! [`TerminalGuard`] enters TUI mode through the tracked wrappers and calls
//! `runtime::TerminalControl` (mouse capture live toggle, suspend/resume; kitty flags

use std::{
    fs::File,
    io::{self, Write},
    sync::atomic::{AtomicU8, Ordering},
};

use crossterm::{
    cursor,
    event::{
        DisableBracketedPaste, DisableFocusChange, DisableMouseCapture, EnableBracketedPaste,
        EnableFocusChange, EnableMouseCapture, KeyboardEnhancementFlags,
        PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
    },
    queue,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen},
};

/// One terminal mode that sverb may turn on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Mode {
    /// Raw (non-canonical, no echo) input mode.
    Raw = 1 << 0,
    /// The alternate screen.
    AltScreen = 1 << 1,
    /// Mouse capture (`ESC[?1000h` and friends).
    Mouse = 1 << 2,
    /// Bracketed paste (`ESC[?2004h`).
    BracketedPaste = 1 << 3,
    /// Kitty progressive keyboard enhancement flags (pushed).
    KittyFlags = 1 << 4,
    /// The cursor is hidden.
    CursorHidden = 1 << 5,
    /// Focus in/out events (`ESC[?1004h`).
    FocusEvents = 1 << 6,
}

impl Mode {
    /// The order [`restore_terminal`] undoes modes in.
    pub const RESTORE_ORDER: [Mode; 7] = [
        Mode::KittyFlags,
        Mode::BracketedPaste,
        Mode::Mouse,
        Mode::FocusEvents,
        Mode::CursorHidden,
        Mode::AltScreen,
        Mode::Raw,
    ];

    /// The order modes are (re-)enabled in: the reverse of [`Mode::RESTORE_ORDER`].
    pub const ENABLE_ORDER: [Mode; 7] = [
        Mode::Raw,
        Mode::AltScreen,
        Mode::CursorHidden,
        Mode::FocusEvents,
        Mode::Mouse,
        Mode::BracketedPaste,
        Mode::KittyFlags,
    ];

    const fn bit(self) -> u8 {
        self as u8
    }
}

/// A set of [`Mode`]s (a copy of the bitset at one point in time).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct ModeSet(u8);

impl ModeSet {
    /// No modes.
    pub const EMPTY: Self = Self(0);

    /// Whether `mode` is in the set.
    pub const fn contains(self, mode: Mode) -> bool {
        self.0 & mode.bit() != 0
    }

    /// Whether the set is empty.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The set with `mode` added.
    #[must_use]
    pub const fn with(self, mode: Mode) -> Self {
        Self(self.0 | mode.bit())
    }

    /// The raw bits.
    pub const fn bits(self) -> u8 {
        self.0
    }
}

/// Switches the terminal's raw mode. Abstracted so mode bookkeeping is testable
/// without a TTY; [`CrosstermRaw`] is the real implementation.
pub trait RawSwitch {
    /// Turn raw mode on.
    fn enable_raw(&mut self) -> io::Result<()>;
    /// Turn raw mode off.
    fn disable_raw(&mut self) -> io::Result<()>;
}

/// [`RawSwitch`] backed by `crossterm::terminal::{enable,disable}_raw_mode`.
#[derive(Debug, Clone, Copy, Default)]
pub struct CrosstermRaw;

impl RawSwitch for CrosstermRaw {
    fn enable_raw(&mut self) -> io::Result<()> {
        crossterm::terminal::enable_raw_mode()
    }

    fn disable_raw(&mut self) -> io::Result<()> {
        crossterm::terminal::disable_raw_mode()
    }
}

/// Process-global record of the terminal modes sverb has enabled.
///
/// Use [`TerminalModes::global`] in the app; tests create their own instance with
/// [`TerminalModes::new`] and a fake writer and [`RawSwitch`].
#[derive(Debug)]
pub struct TerminalModes {
    bits: AtomicU8,
    /// The kitty flags last pushed, so suspend/resume can push them again.
    kitty: AtomicU8,
}

static GLOBAL: TerminalModes = TerminalModes::new();

impl Default for TerminalModes {
    fn default() -> Self {
        Self::new()
    }
}

impl TerminalModes {
    /// A record with nothing enabled.
    pub const fn new() -> Self {
        Self {
            bits: AtomicU8::new(0),
            kitty: AtomicU8::new(0),
        }
    }

    /// The process-wide record used by [`TerminalGuard`] and [`restore_terminal`].
    pub fn global() -> &'static Self {
        &GLOBAL
    }

    /// The modes currently enabled.
    pub fn enabled(&self) -> ModeSet {
        ModeSet(self.bits.load(Ordering::SeqCst))
    }

    /// Whether `mode` is currently enabled.
    pub fn is_enabled(&self, mode: Mode) -> bool {
        self.enabled().contains(mode)
    }

    /// The kitty keyboard flags pushed by [`TerminalModes::push_kitty_flags`].
    pub fn kitty_flags(&self) -> KeyboardEnhancementFlags {
        KeyboardEnhancementFlags::from_bits_truncate(self.kitty.load(Ordering::SeqCst))
    }

    pub fn push_kitty_flags(
        &self,
        flags: KeyboardEnhancementFlags,
        out: &mut dyn Write,
    ) -> io::Result<()> {
        if self.is_enabled(Mode::KittyFlags) {
            return Ok(());
        }
        self.kitty.store(flags.bits(), Ordering::SeqCst);
        self.enable(Mode::KittyFlags, out, &mut NoRaw)
    }

    /// Push [`SVERB_KITTY_FLAGS`] when `probe` says the terminal supports the kitty
    /// keyboard protocol. Returns whether the flags are pushed now; a failed probe or push
    /// degrades to legacy key parsing (where `ctrl-i` == `tab`), never to an error.
    pub fn negotiate_kitty(
        &self,
        out: &mut dyn Write,
        probe: impl FnOnce() -> io::Result<bool>,
    ) -> bool {
        if self.is_enabled(Mode::KittyFlags) {
            return true;
        }
        match probe() {
            Ok(true) => self.push_kitty_flags(SVERB_KITTY_FLAGS, out).is_ok(),
            Ok(false) | Err(_) => false,
        }
    }

    /// Turn `mode` on. A no-op if it is already on. The bit is set only on success.
    ///
    /// Escape sequences go to `out` (flushed); raw mode goes through `raw`.
    pub fn enable(
        &self,
        mode: Mode,
        out: &mut dyn Write,
        raw: &mut dyn RawSwitch,
    ) -> io::Result<()> {
        if self.is_enabled(mode) {
            return Ok(());
        }
        match mode {
            Mode::Raw => raw.enable_raw()?,
            other => {
                let mut buf = Vec::new();
                self.queue_enable(other, &mut buf)?;
                out.write_all(&buf)?;
                out.flush()?;
            }
        }
        self.bits.fetch_or(mode.bit(), Ordering::SeqCst);
        Ok(())
    }

    /// Turn `mode` off. A no-op if it is not on. The bit is cleared even on error,
    /// so a later [`restore_terminal`] doesn't repeat a failing step.
    pub fn disable(
        &self,
        mode: Mode,
        out: &mut dyn Write,
        raw: &mut dyn RawSwitch,
    ) -> io::Result<()> {
        let was = self.bits.fetch_and(!mode.bit(), Ordering::SeqCst);
        if was & mode.bit() == 0 {
            return Ok(());
        }
        match mode {
            Mode::Raw => raw.disable_raw(),
            other => {
                let mut buf = Vec::new();
                queue_disable(other, &mut buf)?;
                out.write_all(&buf)?;
                out.flush()
            }
        }
    }

    /// Undo every enabled mode in [`Mode::RESTORE_ORDER`], best effort, and return
    /// the set that was enabled (for re-enabling after a suspend).
    ///
    /// Each bit is claimed atomically before its mode is undone, so concurrent
    /// restores (panic hook + guard drop) never emit a sequence twice. With nothing
    /// enabled, nothing is written to `out`.
    pub fn restore(&self, out: &mut dyn Write, raw: &mut dyn RawSwitch) -> ModeSet {
        let mut restored = ModeSet::EMPTY;
        let mut buf = Vec::new();
        for mode in Mode::RESTORE_ORDER {
            let was = self.bits.fetch_and(!mode.bit(), Ordering::SeqCst);
            if was & mode.bit() == 0 {
                continue;
            }
            restored = restored.with(mode);
            if mode == Mode::Raw {
                // All escape sequences must reach the terminal before cooked mode.
                if !buf.is_empty() {
                    let _ = out.write_all(&buf);
                    let _ = out.flush();
                    buf.clear();
                }
                let _ = raw.disable_raw();
            } else {
                let _ = queue_disable(mode, &mut buf);
            }
        }
        if !buf.is_empty() {
            let _ = out.write_all(&buf);
            let _ = out.flush();
        }
        restored
    }

    /// Re-enable `set` in [`Mode::ENABLE_ORDER`] (resume after `SIGTSTP`).
    pub fn reapply(
        &self,
        set: ModeSet,
        out: &mut dyn Write,
        raw: &mut dyn RawSwitch,
    ) -> io::Result<()> {
        for mode in Mode::ENABLE_ORDER {
            if set.contains(mode) {
                self.enable(mode, out, raw)?;
            }
        }
        Ok(())
    }

    fn queue_enable(&self, mode: Mode, buf: &mut Vec<u8>) -> io::Result<()> {
        match mode {
            Mode::Raw => Ok(()),
            Mode::AltScreen => queue!(buf, EnterAlternateScreen),
            Mode::Mouse => queue!(buf, EnableMouseCapture),
            Mode::BracketedPaste => queue!(buf, EnableBracketedPaste),
            Mode::KittyFlags => queue!(buf, PushKeyboardEnhancementFlags(self.kitty_flags())),
            Mode::CursorHidden => queue!(buf, cursor::Hide),
            Mode::FocusEvents => queue!(buf, EnableFocusChange),
        }
    }
}

fn queue_disable(mode: Mode, buf: &mut Vec<u8>) -> io::Result<()> {
    match mode {
        Mode::Raw => Ok(()),
        Mode::AltScreen => queue!(buf, LeaveAlternateScreen),
        Mode::Mouse => queue!(buf, DisableMouseCapture),
        Mode::BracketedPaste => queue!(buf, DisableBracketedPaste),
        Mode::KittyFlags => queue!(buf, PopKeyboardEnhancementFlags),
        Mode::CursorHidden => queue!(buf, cursor::Show),
        Mode::FocusEvents => queue!(buf, DisableFocusChange),
    }
}

/// A [`RawSwitch`] for calls that never touch raw mode.
struct NoRaw;

impl RawSwitch for NoRaw {
    fn enable_raw(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn disable_raw(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A private duplicate of the process's stdout, so writing never takes
/// `std::io::Stdout`'s lock (which a panicking or stuck thread may hold).
///
/// `std` has no `try_lock` for `Stdout`, so the panic-safe path always uses the dup.
fn dup_stdout() -> Option<File> {
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        io::stdout()
            .as_fd()
            .try_clone_to_owned()
            .ok()
            .map(File::from)
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle;
        io::stdout()
            .as_handle()
            .try_clone_to_owned()
            .ok()
            .map(File::from)
    }
    #[cfg(not(any(unix, windows)))]
    {
        None
    }
}

/// Undo every terminal mode sverb enabled (see the module docs for the order).
///
/// Safe to call from any thread, inside or outside a tokio runtime, from a panic hook,
/// and repeatedly (a second call writes nothing). Never panics; errors are ignored.
pub fn restore_terminal() -> ModeSet {
    let modes = TerminalModes::global();
    if modes.enabled().is_empty() {
        return ModeSet::EMPTY;
    }
    match dup_stdout() {
        Some(mut out) => modes.restore(&mut out, &mut CrosstermRaw),
        None => modes.restore(&mut io::sink(), &mut CrosstermRaw),
    }
}

/// The kitty keyboard flags sverb pushes on the outer terminal (SPEC §7.3):
/// disambiguate escape codes (so `ctrl-i` ≠ `tab`, `ctrl-[` ≠ `esc`) and report alternate
/// keys. Release events and "all keys as escape codes" stay off: sverb doesn't need them.
pub const SVERB_KITTY_FLAGS: KeyboardEnhancementFlags =
    KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES
        .union(KeyboardEnhancementFlags::REPORT_ALTERNATE_KEYS);

/// What [`TerminalGuard::enter`] turns on (raw mode, the alternate screen and a hidden
/// cursor are always on).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalSetup {
    /// Mouse capture (`ui.mouse`).
    pub mouse: bool,
    /// Bracketed paste (on by default, SPEC §2.1).
    pub bracketed_paste: bool,
    /// Focus in/out events.
    pub focus_events: bool,
}

impl Default for TerminalSetup {
    fn default() -> Self {
        Self {
            mouse: true,
            bracketed_paste: true,
            focus_events: true,
        }
    }
}

/// Puts the terminal into TUI mode through the tracked wrappers and restores it on drop.
///
/// `Drop` calls [`restore_terminal`], which never panics, so dropping the guard during
/// unwinding (or with stdout closed) is safe.
#[derive(Debug)]
pub struct TerminalGuard {
    _private: (),
}

impl TerminalGuard {
    /// Enable raw mode, the alternate screen, a hidden cursor and the modes in `setup`.
    /// On error, whatever was already enabled is restored.
    pub fn enter(setup: TerminalSetup) -> io::Result<Self> {
        let guard = Self { _private: () };
        let modes = TerminalModes::global();
        let mut out = io::stdout();
        let mut raw = CrosstermRaw;
        let mut wanted = ModeSet::EMPTY
            .with(Mode::Raw)
            .with(Mode::AltScreen)
            .with(Mode::CursorHidden);
        if setup.focus_events {
            wanted = wanted.with(Mode::FocusEvents);
        }
        if setup.mouse {
            wanted = wanted.with(Mode::Mouse);
        }
        if setup.bracketed_paste {
            wanted = wanted.with(Mode::BracketedPaste);
        }
        // On error `guard` drops here and restores the partial setup.
        modes.reapply(wanted, &mut out, &mut raw)?;
        Ok(guard)
    }

    /// The modes currently enabled.
    pub fn modes(&self) -> ModeSet {
        TerminalModes::global().enabled()
    }

    /// Toggle mouse capture live (config hot reload of `ui.mouse`).
    pub fn set_mouse(&mut self, on: bool) -> io::Result<()> {
        let modes = TerminalModes::global();
        if on {
            modes.enable(Mode::Mouse, &mut io::stdout(), &mut CrosstermRaw)
        } else {
            modes.disable(Mode::Mouse, &mut io::stdout(), &mut CrosstermRaw)
        }
    }

    pub fn push_kitty_flags(&mut self, flags: KeyboardEnhancementFlags) -> io::Result<()> {
        TerminalModes::global().push_kitty_flags(flags, &mut io::stdout())
    }

    /// Use the kitty keyboard protocol when the outer terminal supports it: query with
    /// `CSI ? u` followed by DA1 and push [`SVERB_KITTY_FLAGS`]; the restore path pops
    /// them. Call it in raw mode, **before** the input reader starts, so the reply isn't
    /// read as keys. Returns whether the protocol is on.
    ///
    /// On unix the reply is awaited for at most [`KITTY_PROBE_TIMEOUT`] (50 ms)
    /// instead of crossterm's 2 s, so a terminal that answers neither query does not
    /// delay the first frame (SPEC §1: < 100 ms to the host list). A late reply is
    /// harmless: crossterm's reader parses both answers as internal events, not keys.
    /// Keys typed during the probe window itself (before the first frame) are
    /// dropped; with a terminal that answers, the window is about a millisecond.
    pub fn enable_kitty_keyboard(&mut self) -> bool {
        TerminalModes::global().negotiate_kitty(&mut io::stdout(), || {
            #[cfg(unix)]
            {
                kitty_probe::probe(KITTY_PROBE_TIMEOUT)
            }
            #[cfg(not(unix))]
            {
                crossterm::terminal::supports_keyboard_enhancement()
            }
        })
    }

    /// Restore the terminal now (idempotent; `Drop` does it too).
    pub fn restore(&mut self) -> ModeSet {
        restore_terminal()
    }

    /// Re-enable a set returned by [`TerminalGuard::restore`].
    pub fn reapply(&mut self, set: ModeSet) -> io::Result<()> {
        TerminalModes::global().reapply(set, &mut io::stdout(), &mut CrosstermRaw)
    }

    /// `Ctrl-z`: restore the terminal, stop the process with `SIGTSTP`, and re-enable the
    /// recorded modes once it is continued (`SIGCONT`). The caller redraws everything.
    #[cfg(unix)]
    pub fn suspend(&mut self) -> io::Result<()> {
        let set = self.restore();
        let raised = signal_hook::low_level::raise(signal_hook::consts::signal::SIGTSTP);
        // Execution resumes here after SIGCONT. Re-enter TUI mode even if the
        // raise failed, so the loop never keeps running on a cooked terminal.
        let reapplied = self.reapply(set);
        raised?;
        reapplied
    }

    /// Suspend is not available on this platform; the caller shows a toast.
    #[cfg(not(unix))]
    pub fn suspend(&mut self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "suspend is not supported on this platform",
        ))
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Default)]
    struct FakeRaw {
        log: Vec<&'static str>,
    }

    impl RawSwitch for FakeRaw {
        fn enable_raw(&mut self) -> io::Result<()> {
            self.log.push("raw on");
            Ok(())
        }
        fn disable_raw(&mut self) -> io::Result<()> {
            self.log.push("raw off");
            Ok(())
        }
    }

    /// Records each write as one chunk, plus a marker when raw mode changes.
    #[derive(Debug, Default)]
    struct Recorder {
        bytes: Vec<u8>,
    }

    impl Write for Recorder {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.bytes.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }

    #[test]
    fn restore_with_nothing_enabled_writes_nothing() {
        let modes = TerminalModes::new();
        let mut out = Recorder::default();
        let mut raw = FakeRaw::default();
        let restored = modes.restore(&mut out, &mut raw);
        assert!(restored.is_empty());
        assert!(out.bytes.is_empty());
        assert!(raw.log.is_empty());
    }

    #[test]
    fn restore_undoes_exactly_the_enabled_modes_in_reverse() -> io::Result<()> {
        let modes = TerminalModes::new();
        let mut out = Recorder::default();
        let mut raw = FakeRaw::default();
        modes.enable(Mode::Raw, &mut out, &mut raw)?;
        modes.enable(Mode::AltScreen, &mut out, &mut raw)?;
        modes.enable(Mode::BracketedPaste, &mut out, &mut raw)?;
        assert_eq!(out.bytes, b"\x1b[?1049h\x1b[?2004h");
        assert_eq!(raw.log, ["raw on"]);

        let mut out = Recorder::default();
        let restored = modes.restore(&mut out, &mut raw);
        assert_eq!(
            restored,
            ModeSet::EMPTY
                .with(Mode::Raw)
                .with(Mode::AltScreen)
                .with(Mode::BracketedPaste)
        );
        // Paste off, then leave the alt screen; nothing else (no cursor, mouse, kitty).
        assert_eq!(
            String::from_utf8_lossy(&out.bytes),
            "\x1b[?2004l\x1b[?1049l"
        );
        assert_eq!(raw.log, ["raw on", "raw off"]);
        assert!(modes.enabled().is_empty());

        // A second restore is a no-op.
        let mut out = Recorder::default();
        assert!(modes.restore(&mut out, &mut raw).is_empty());
        assert!(out.bytes.is_empty());
        Ok(())
    }

    #[test]
    fn full_restore_order() -> io::Result<()> {
        let modes = TerminalModes::new();
        let mut raw = FakeRaw::default();
        let mut out = Recorder::default();
        modes.reapply(
            ModeSet::EMPTY
                .with(Mode::Raw)
                .with(Mode::AltScreen)
                .with(Mode::CursorHidden)
                .with(Mode::FocusEvents)
                .with(Mode::Mouse)
                .with(Mode::BracketedPaste),
            &mut out,
            &mut raw,
        )?;
        modes.push_kitty_flags(
            KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES,
            &mut out,
        )?;
        let mut out = Recorder::default();
        modes.restore(&mut out, &mut raw);
        let text = String::from_utf8_lossy(&out.bytes).into_owned();
        let pos = |needle: &str| text.find(needle).unwrap_or(usize::MAX);
        let order = [
            pos("\x1b[<1u"),
            pos("\x1b[?2004l"),
            pos("\x1b[?1000l"),
            pos("\x1b[?1004l"),
            pos("\x1b[?25h"),
            pos("\x1b[?1049l"),
        ];
        assert!(order.iter().all(|&p| p != usize::MAX), "{text:?}");
        assert!(order.windows(2).all(|w| w[0] < w[1]), "{text:?}");
        assert_eq!(raw.log.last(), Some(&"raw off"));
        Ok(())
    }

    #[test]
    fn failed_enable_leaves_bit_clear_and_restore_ignores_errors() {
        let modes = TerminalModes::new();
        let mut raw = FakeRaw::default();
        assert!(
            modes
                .enable(Mode::AltScreen, &mut FailingWriter, &mut raw)
                .is_err()
        );
        assert!(!modes.is_enabled(Mode::AltScreen));

        let mut out = Recorder::default();
        let _ = modes.enable(Mode::Mouse, &mut out, &mut raw);
        // Restoring into a closed pipe must not panic and still clears the bits.
        modes.restore(&mut FailingWriter, &mut raw);
        assert!(modes.enabled().is_empty());
    }

    // A terminal that answers the kitty query gets `CSI > 5 u` (disambiguate
    // + alternate keys), popped on restore; one that doesn't gets nothing.
    #[test]
    fn t15_kitty_negotiation() {
        let modes = TerminalModes::new();
        let mut raw = FakeRaw::default();
        let mut out = Recorder::default();
        assert!(modes.negotiate_kitty(&mut out, || Ok(true)));
        assert_eq!(out.bytes, b"\x1b[>5u");
        assert!(modes.is_enabled(Mode::KittyFlags));
        assert_eq!(modes.kitty_flags(), SVERB_KITTY_FLAGS);
        // Idempotent: no second push.
        assert!(modes.negotiate_kitty(&mut out, || Ok(true)));
        assert_eq!(out.bytes, b"\x1b[>5u");
        let mut out = Recorder::default();
        modes.restore(&mut out, &mut raw);
        assert_eq!(out.bytes, b"\x1b[<1u");

        for answer in [Ok(false), Err(io::Error::from(io::ErrorKind::TimedOut))] {
            let modes = TerminalModes::new();
            let mut out = Recorder::default();
            assert!(!modes.negotiate_kitty(&mut out, || answer));
            assert!(out.bytes.is_empty());
            assert!(!modes.is_enabled(Mode::KittyFlags));
        }
        // A failed push degrades too.
        let modes = TerminalModes::new();
        assert!(!modes.negotiate_kitty(&mut FailingWriter, || Ok(true)));
        assert!(!modes.is_enabled(Mode::KittyFlags));
    }

    #[test]
    fn mouse_toggle_is_idempotent() -> io::Result<()> {
        let modes = TerminalModes::new();
        let mut raw = FakeRaw::default();
        let mut out = Recorder::default();
        modes.enable(Mode::Mouse, &mut out, &mut raw)?;
        let first = out.bytes.len();
        modes.enable(Mode::Mouse, &mut out, &mut raw)?;
        assert_eq!(out.bytes.len(), first);
        modes.disable(Mode::Mouse, &mut out, &mut raw)?;
        let second = out.bytes.len();
        modes.disable(Mode::Mouse, &mut out, &mut raw)?;
        assert_eq!(out.bytes.len(), second);
        Ok(())
    }
}

/// How long startup waits for the terminal to answer the kitty keyboard query.
pub const KITTY_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(50);

/// The kitty keyboard probe with a short timeout (unix).
#[cfg(unix)]
pub mod kitty_probe {
    use std::fs::OpenOptions;
    use std::io::{self, IsTerminal, Write};
    use std::os::fd::{AsFd, BorrowedFd};
    use std::time::{Duration, Instant};

    use rustix::event::{PollFd, PollFlags, Timespec, poll};

    /// `CSI ? u` (kitty flags) then DA1, the detection the kitty docs recommend.
    pub const QUERY: &[u8] = b"\x1b[?u\x1b[c";

    /// What the bytes read so far say: `Some(supported)` once the DA1 reply is in
    /// (a kitty flags reply `CSI ? <n> u` before it means supported), `None` while
    /// it is still missing.
    pub fn parse(reply: &[u8]) -> Option<bool> {
        let mut kitty = false;
        let mut i = 0;
        while let Some(start) = find(&reply[i..], b"\x1b[?") {
            let body = &reply[i + start + 3..];
            let end = body
                .iter()
                .position(|b| !(b.is_ascii_digit() || *b == b';'))?;
            match body[end] {
                b'u' => kitty = true,
                b'c' => return Some(kitty),
                _ => {}
            }
            i += start + 3 + end + 1;
        }
        None
    }

    fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
        hay.windows(needle.len()).position(|w| w == needle)
    }

    /// Sends [`QUERY`] to the controlling terminal and waits up to `timeout` for the
    /// DA1 reply. No reply in time: not supported.
    ///
    /// The reply is read from stdin when stdin is the terminal: on macOS `poll()` doesn't
    /// work on `/dev/tty` (it reports `POLLNVAL` at once, and a `read` would then block
    /// forever). Anything but readable input ends the probe as "not supported".
    ///
    /// # Errors
    /// The terminal can't be opened or written.
    pub fn probe(timeout: Duration) -> io::Result<bool> {
        let mut tty = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
        tty.write_all(QUERY)?;
        tty.flush()?;
        let stdin = io::stdin();
        if stdin.is_terminal() {
            read_reply(stdin.as_fd(), timeout)
        } else {
            read_reply(tty.as_fd(), timeout)
        }
    }

    fn read_reply(fd: BorrowedFd<'_>, timeout: Duration) -> io::Result<bool> {
        let deadline = Instant::now() + timeout;
        let mut reply = Vec::new();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(false);
            }
            let readable = {
                let mut fds = [PollFd::new(&fd, PollFlags::IN)];
                let ts = Timespec::try_from(left).unwrap_or(Timespec {
                    tv_sec: 0,
                    tv_nsec: 50_000_000,
                });
                match poll(&mut fds, Some(&ts)) {
                    Ok(0) => false,
                    // Only real input counts: POLLNVAL / POLLERR / POLLHUP must not lead
                    // to a blocking read.
                    Ok(_) => fds[0].revents().contains(PollFlags::IN),
                    Err(rustix::io::Errno::INTR) => continue,
                    Err(e) => return Err(e.into()),
                }
            };
            if !readable {
                return Ok(false);
            }
            let mut chunk = [0u8; 256];
            let n = match rustix::io::read(fd, &mut chunk) {
                Ok(n) => n,
                Err(rustix::io::Errno::INTR) => continue,
                Err(e) => return Err(e.into()),
            };
            if n == 0 {
                return Ok(false);
            }
            reply.extend_from_slice(&chunk[..n]);
            if let Some(supported) = parse(&reply) {
                return Ok(supported);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::parse;

        #[test]
        fn replies() {
            assert_eq!(parse(b""), None);
            assert_eq!(parse(b"\x1b[?62;22c"), Some(false));
            assert_eq!(parse(b"\x1b[?1u\x1b[?62;22c"), Some(true));
            assert_eq!(parse(b"\x1b[?0u"), None, "flags alone: wait for DA1");
            assert_eq!(parse(b"\x1b[?0u\x1b[?6"), None);
            assert_eq!(parse(b"x\x1b[?0u\x1b[?64;1;2c"), Some(true));
        }
    }
}
