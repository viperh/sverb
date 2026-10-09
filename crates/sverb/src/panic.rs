//! The panic hook (SPEC §17, §18). Replaces the template's `errors.rs`
//! (color-eyre + human-panic + better-panic).
//!
//! [`install`] runs first in `main`, before paths and logging, so even a panic during
//! startup restores the terminal. For every panic, on any thread, with or without a
//! tokio runtime, the hook:
//! 1. restores the terminal ([`restore_terminal`]: lock-free, no tokio, never panics),
//! 2. builds color-eyre's panic report (with the "This is a bug" section),
//! 3. writes a private crash report (`0600`) to `<state>/crash/`, with the last
//!    [`RING_LINES`] lines of the `info`+ crash ring (never `debug`, so no hostnames),
//! 4. prints a short message to stderr (the full report only in debug builds or
//!    with `SVERB_LOG` at `debug`/`trace`),
//! 5. flushes the log file ([`sverb_core::logging::shutdown`]),
//! 6. returns, so the panic unwinds normally: destructors run, and a panicked UI task
//!    ends `main` with exit code 101.
//!
//! A panic *inside* the hook (same thread) prints one line and aborts instead of
//! recursing. A panic on another thread while a report is being written only prints
//! its short message.
//!
//! A panic inside a **session actor** is contained: the session manager catches
//! it through the task's `JoinHandle`, the pane shows "session crashed (see log)" and
//! the UI keeps running. The actor is polled inside
//! `sverb_conn::panic_scope::Contained`, so [`in_contained_task`] is true while the
//! hook runs for such a panic. The hook then only logs the panic and writes the crash
//! report: it does not restore the terminal, print to stderr or shut logging down,
//! which would leave the still-running UI broken.

use std::{
    backtrace::Backtrace,
    cell::Cell,
    fmt::Write as _,
    fs::{self, File, OpenOptions},
    io::{self, Write as _},
    panic::PanicHookInfo,
    path::{Path, PathBuf},
    sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use color_eyre::config::PanicHook;
use sverb_core::{
    logging::{self, LogLine},
    paths::{Paths, SystemEnv},
};
use sverb_tui::runtime::terminal::restore_terminal;
use sverb_tui::services::sessions::in_contained_task;
use tracing::Level;

/// Lines of the crash ring included in a crash report.
pub(crate) const RING_LINES: usize = 200;

/// How long the hook waits for the crash ring's lock before giving up on it.
const RING_TIMEOUT: Duration = Duration::from_millis(100);

/// Set while a panic hook runs (on any thread).
static IN_PANIC_HOOK: AtomicBool = AtomicBool::new(false);

thread_local! {
    /// Set while the panic hook runs on *this* thread: a panic now is nested.
    static IN_HOOK_ON_THIS_THREAD: Cell<bool> = const { Cell::new(false) };
}

/// Where crash reports go, set by [`set_crash_dir`] once paths are resolved.
static CRASH_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Installs color-eyre's error hook and sverb's panic hook. Call first in `main`.
pub(crate) fn install() -> color_eyre::Result<()> {
    let (panic_hook, eyre_hook) = color_eyre::config::HookBuilder::default()
        .panic_section(format!(
            "This is a bug. Please report it at {}/issues",
            env!("CARGO_PKG_REPOSITORY")
        ))
        .capture_span_trace_by_default(false)
        .display_location_section(true)
        .display_env_section(false)
        .into_hooks();
    eyre_hook.install()?;
    std::panic::set_hook(Box::new(move |info| hook(&panic_hook, info)));
    Ok(())
}

/// Tells the hook where to write crash reports (`paths.crash_dir()`). Before this is
/// called, the hook resolves the paths itself.
pub(crate) fn set_crash_dir(paths: &Paths) {
    let _ = CRASH_DIR.set(paths.crash_dir());
}

/// What the hook does on entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HookEntry {
    /// The normal path: restore, report, flush.
    Report,
    /// A panic inside the hook on this thread: one line to stderr, then abort.
    Abort,
    /// Another thread is already reporting a crash: only print the short message.
    Concurrent,
}

/// The re-entrancy decision. Marks the hook as running when it returns
/// [`HookEntry::Report`].
fn enter_hook(running: &AtomicBool, nested_on_this_thread: bool) -> HookEntry {
    if nested_on_this_thread {
        return HookEntry::Abort;
    }
    if running
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return HookEntry::Concurrent;
    }
    HookEntry::Report
}

fn hook(panic_hook: &PanicHook, info: &PanicHookInfo<'_>) {
    let nested = IN_HOOK_ON_THIS_THREAD.with(|flag| flag.replace(true));
    match enter_hook(&IN_PANIC_HOOK, nested) {
        HookEntry::Abort => {
            let _ = writeln!(
                io::stderr(),
                "sverb: panicked inside the panic hook; aborting"
            );
            std::process::abort();
        }
        // Contained session panic while another report is being written.
        HookEntry::Concurrent if in_contained_task() => {
            tracing::error!(target: "sverb::panic", "contained session panic: {}", message(info));
        }
        HookEntry::Concurrent => {
            restore_terminal();
            let _ = writeln!(io::stderr(), "sverb crashed: {}", message(info));
        }
        // The UI keeps running; log and write the crash report only.
        HookEntry::Report if in_contained_task() => {
            report_contained(panic_hook, info);
            IN_PANIC_HOOK.store(false, Ordering::SeqCst);
        }
        HookEntry::Report => {
            report(panic_hook, info);
            IN_PANIC_HOOK.store(false, Ordering::SeqCst);
        }
    }
    IN_HOOK_ON_THIS_THREAD.with(|flag| flag.set(false));
}

fn report(panic_hook: &PanicHook, info: &PanicHookInfo<'_>) {
    // 1. The terminal first: everything below may fail, this must not.
    restore_terminal();

    let msg = message(info);
    let location = location(info);
    tracing::error!(target: "sverb::panic", %location, "panic: {msg}");

    // 2. color-eyre's report (colored when stderr is a terminal).
    let colored = panic_hook.panic_report(info).to_string();

    // 3. The crash report.
    let ring = logging::crash_ring()
        .and_then(|ring| ring.try_tail(RING_LINES, RING_TIMEOUT))
        .unwrap_or_default();
    let ctx = CrashContext {
        version: version(),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        term: std::env::var("TERM").ok(),
        term_program: std::env::var("TERM_PROGRAM").ok(),
        message: msg,
        location,
        thread: std::thread::current()
            .name()
            .unwrap_or("<unnamed>")
            .to_owned(),
        backtrace: Backtrace::force_capture().to_string(),
        report: strip_ansi_escapes::strip_str(&colored),
    };
    let text = crash_report_text(&ctx, &ring);
    let written = crash_dir()
        .ok_or_else(|| io::Error::other("the state directory could not be resolved"))
        .and_then(|dir| write_crash_report(&dir, SystemTime::now(), std::process::id(), &text));

    // 4. stderr: short by default.
    let mut err = io::stderr().lock();
    let full = show_full_report();
    if full {
        let _ = writeln!(err, "{colored}");
    }
    let _ = writeln!(err, "sverb crashed: {}", ctx.message);
    let _ = match &written {
        Ok(path) => writeln!(err, "A crash report was written to {}", path.display()),
        Err(e) => writeln!(err, "The crash report could not be written: {e}"),
    };
    if !full {
        // The full report already has this section.
        let _ = writeln!(
            err,
            "This is a bug. Please report it at {}/issues",
            env!("CARGO_PKG_REPOSITORY")
        );
    }
    drop(err);

    // 5. Flush the log file (the WorkerGuard lives in sverb_core::logging).
    logging::shutdown();
}

// A contained session panic (see the module docs): log it and write the crash
// report, but leave the terminal, stderr and the log file alone.
fn report_contained(panic_hook: &PanicHook, info: &PanicHookInfo<'_>) {
    let msg = message(info);
    let location = location(info);
    tracing::error!(target: "sverb::panic", %location, "contained session panic: {msg}");
    let colored = panic_hook.panic_report(info).to_string();
    let ring = logging::crash_ring()
        .and_then(|ring| ring.try_tail(RING_LINES, RING_TIMEOUT))
        .unwrap_or_default();
    let ctx = CrashContext {
        version: version(),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        term: std::env::var("TERM").ok(),
        term_program: std::env::var("TERM_PROGRAM").ok(),
        message: msg,
        location,
        thread: std::thread::current()
            .name()
            .unwrap_or("<unnamed>")
            .to_owned(),
        backtrace: Backtrace::force_capture().to_string(),
        report: strip_ansi_escapes::strip_str(&colored),
    };
    let text = crash_report_text(&ctx, &ring);
    match crash_dir()
        .ok_or_else(|| io::Error::other("the state directory could not be resolved"))
        .and_then(|dir| write_crash_report(&dir, SystemTime::now(), std::process::id(), &text))
    {
        Ok(path) => tracing::error!(
            target: "sverb::panic",
            "crash report written to {}",
            path.display()
        ),
        Err(e) => tracing::error!(target: "sverb::panic", "crash report not written: {e}"),
    }
}

fn location(info: &PanicHookInfo<'_>) -> String {
    info.location()
        .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
        .unwrap_or_else(|| "<unknown>".to_owned())
}

fn message(info: &PanicHookInfo<'_>) -> String {
    info.payload_as_str()
        .unwrap_or("Box<dyn Any> (non-string panic payload)")
        .to_owned()
}

/// `0.1.0 (<git describe>)`, from vergen.
fn version() -> String {
    format!(
        "{} ({})",
        env!("CARGO_PKG_VERSION"),
        env!("VERGEN_GIT_DESCRIBE")
    )
}

fn show_full_report() -> bool {
    if cfg!(debug_assertions) {
        return true;
    }
    std::env::var(logging::LOG_ENV).is_ok_and(|v| {
        let v = v.to_ascii_lowercase();
        v.contains("debug") || v.contains("trace")
    })
}

fn crash_dir() -> Option<PathBuf> {
    if let Some(dir) = CRASH_DIR.get() {
        return Some(dir.clone());
    }
    Paths::resolve(&SystemEnv).ok().map(|p| p.crash_dir())
}

/// Everything a crash report contains besides the log lines.
#[derive(Debug)]
struct CrashContext {
    version: String,
    os: &'static str,
    arch: &'static str,
    term: Option<String>,
    term_program: Option<String>,
    message: String,
    location: String,
    thread: String,
    backtrace: String,
    /// color-eyre's report without ANSI escapes.
    report: String,
}

/// The crash report text. Only `info`+ ring lines are included (the crash ring holds
/// nothing else; the filter here is a second line of defence against hostnames).
fn crash_report_text(ctx: &CrashContext, ring: &[LogLine]) -> String {
    let none = "<unset>";
    let mut out = String::new();
    let _ = writeln!(out, "sverb crash report");
    let _ = writeln!(out, "==================");
    let _ = writeln!(out, "version:      {}", ctx.version);
    let _ = writeln!(out, "os/arch:      {}/{}", ctx.os, ctx.arch);
    let _ = writeln!(out, "TERM:         {}", ctx.term.as_deref().unwrap_or(none));
    let _ = writeln!(
        out,
        "TERM_PROGRAM: {}",
        ctx.term_program.as_deref().unwrap_or(none)
    );
    let _ = writeln!(out, "thread:       {}", ctx.thread);
    let _ = writeln!(out, "location:     {}", ctx.location);
    let _ = writeln!(out, "message:      {}", ctx.message);
    let _ = writeln!(out, "\n--- report ---\n{}", ctx.report.trim_end());
    let _ = writeln!(out, "\n--- backtrace ---\n{}", ctx.backtrace.trim_end());
    let _ = writeln!(out, "\n--- last log lines (info and above) ---");
    // `Level` orders TRACE > DEBUG > INFO > WARN > ERROR.
    for line in ring.iter().filter(|l| l.level <= Level::INFO) {
        let _ = writeln!(out, "{line}");
    }
    out
}

/// Writes `text` to `<dir>/crash-<UTC yyyymmddThhmmssZ>-<pid>.txt` (mode `0600` on
/// Unix, never overwriting: a `-N` suffix is added on collision).
fn write_crash_report(dir: &Path, now: SystemTime, pid: u32, text: &str) -> io::Result<PathBuf> {
    create_private_dir(dir)?;
    let stem = format!("crash-{}-{pid}", utc_stamp(now));
    for n in 0..100u32 {
        let name = if n == 0 {
            format!("{stem}.txt")
        } else {
            format!("{stem}-{n}.txt")
        };
        let path = dir.join(name);
        match open_private(&path) {
            Ok(mut file) => {
                file.write_all(text.as_bytes())?;
                file.sync_all()?;
                return Ok(path);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "too many crash reports with the same name",
    ))
}

fn create_private_dir(dir: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

fn open_private(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// `yyyymmddThhmmssZ` in UTC.
fn utc_stamp(at: SystemTime) -> String {
    let secs = at
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let days = i64::try_from(secs / 86_400).unwrap_or_default();
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Days since 1970-01-01 → (year, month, day) (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (
        y,
        u32::try_from(m).unwrap_or_default(),
        u32::try_from(d).unwrap_or_default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    // A panic while the hook runs on the same thread takes the abort path;
    // the decision function is tested, not the abort itself.
    #[test]
    fn nested_panic_takes_the_abort_path() {
        let running = AtomicBool::new(false);
        assert_eq!(enter_hook(&running, false), HookEntry::Report);
        assert!(running.load(Ordering::SeqCst));
        assert_eq!(enter_hook(&running, true), HookEntry::Abort);
        // Another thread panicking meanwhile does not abort the process.
        assert_eq!(enter_hook(&running, false), HookEntry::Concurrent);
        running.store(false, Ordering::SeqCst);
        assert_eq!(enter_hook(&running, false), HookEntry::Report);
    }

    #[test]
    fn utc_stamps() {
        assert_eq!(utc_stamp(UNIX_EPOCH), "19700101T000000Z");
        // 2026-10-07T21:30:05Z
        let t = UNIX_EPOCH + Duration::from_secs(1_791_408_605);
        assert_eq!(utc_stamp(t), "20261007T213005Z");
        // Leap day.
        let t = UNIX_EPOCH + Duration::from_secs(951_782_400);
        assert_eq!(utc_stamp(t), "20000229T000000Z");
    }

    fn ctx() -> CrashContext {
        CrashContext {
            version: "0.1.0 (test)".to_owned(),
            os: "linux",
            arch: "x86_64",
            term: Some("xterm-256color".to_owned()),
            term_program: None,
            message: "boom".to_owned(),
            location: "src/x.rs:1:2".to_owned(),
            thread: "main".to_owned(),
            backtrace: "0: frame".to_owned(),
            report: "The application panicked".to_owned(),
        }
    }

    fn line(level: Level, message: &str) -> LogLine {
        LogLine {
            at: UNIX_EPOCH,
            level,
            target: "sverb".to_owned(),
            message: message.to_owned(),
        }
    }

    #[test]
    fn report_text_has_the_fields_and_no_debug_lines() {
        let ring = [
            line(Level::DEBUG, "host=secret.example"),
            line(Level::INFO, "last words"),
            line(Level::ERROR, "panic: boom"),
            line(Level::TRACE, "trace detail"),
        ];
        let text = crash_report_text(&ctx(), &ring);
        for needle in [
            "version:      0.1.0 (test)",
            "os/arch:      linux/x86_64",
            "TERM:         xterm-256color",
            "TERM_PROGRAM: <unset>",
            "thread:       main",
            "location:     src/x.rs:1:2",
            "message:      boom",
            "The application panicked",
            "0: frame",
            "last words",
            "panic: boom",
        ] {
            assert!(text.contains(needle), "missing {needle:?} in\n{text}");
        }
        assert!(!text.contains("secret.example"), "{text}");
        assert!(!text.contains("DEBUG"), "{text}");
        assert!(!text.contains("trace detail"), "{text}");
    }

    #[test]
    fn crash_file_is_private_and_never_overwritten() -> TestResult {
        let dir = std::env::temp_dir().join(format!(
            "sverb-m0-05-crash-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        let crash = dir.join("state").join("crash");
        let t = UNIX_EPOCH + Duration::from_secs(1_791_408_605);
        let first = write_crash_report(&crash, t, 42, "one")?;
        let second = write_crash_report(&crash, t, 42, "two")?;
        assert_eq!(
            first.file_name().and_then(|n| n.to_str()),
            Some("crash-20261007T213005Z-42.txt")
        );
        assert_eq!(
            second.file_name().and_then(|n| n.to_str()),
            Some("crash-20261007T213005Z-42-1.txt")
        );
        assert_eq!(fs::read_to_string(&first)?, "one");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&first)?.permissions().mode() & 0o777, 0o600);
            assert_eq!(fs::metadata(&crash)?.permissions().mode() & 0o777, 0o700);
        }
        fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
