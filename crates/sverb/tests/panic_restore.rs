//! Terminal restore, crash reports and log flushing after a panic.
//!
//! The binary runs inside a PTY (`portable-pty`) with the `test-hooks` feature; the
//! `SVERB_TEST_HOOK` environment variable selects where it panics right after the
//! terminal entered TUI mode (see `sverb-tui/src/runtime/test_hooks.rs`).
//!
//! Run with `cargo test -p sverb --features test-hooks --test panic_restore`.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::mpsc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use portable_pty::{CommandBuilder, ExitStatus, PtySize, native_pty_system};

// `assert_restored` is shared with the event-loop tests.
mod common;
use common::assert_restored;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TIMEOUT: Duration = Duration::from_secs(30);

struct Run {
    output: String,
    status: ExitStatus,
    /// The PTY's local flags after the child exited (`ICANON`, `ECHO`, …).
    local_flags: Vec<String>,
    home: PathBuf,
}

fn unique_home(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("m0-05-{tag}-{}-{nanos}", std::process::id()))
}

fn command(hook: &str, home: &Path, ignore_sighup: bool) -> CommandBuilder {
    let bin = env!("CARGO_BIN_EXE_sverb");
    let mut cmd = if ignore_sighup {
        // Ignored signals stay ignored across exec.
        let mut cmd = CommandBuilder::new("sh");
        cmd.args(["-c", "trap '' HUP; exec \"$0\"", bin]);
        cmd
    } else {
        CommandBuilder::new(bin)
    };
    cmd.env("SVERB_HOME", home);
    cmd.env("SVERB_TEST_HOOK", hook);
    cmd.env("SVERB_LOG", "debug");
    cmd.env("TERM", "xterm-256color");
    cmd.env_remove("RUST_BACKTRACE");
    cmd
}

fn run_in_pty(tag: &str, hook: &str) -> Result<Run, Box<dyn std::error::Error>> {
    let home = unique_home(tag);
    let pair = native_pty_system().openpty(PtySize {
        rows: 24,
        cols: 80,
        pixel_width: 0,
        pixel_height: 0,
    })?;
    let mut child = pair.slave.spawn_command(command(hook, &home, false))?;
    // `pair.slave` stays open until the end, so the PTY keeps the termios the child
    // left behind (the pty driver resets it once every slave fd is closed).
    let mut reader = pair.master.try_clone_reader()?;
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = reader.read(&mut buf) {
            if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    });

    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > TIMEOUT {
            child.kill()?;
            return Err("sverb did not exit in time".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut output = Vec::new();
    while let Ok(chunk) = rx.recv_timeout(Duration::from_millis(300)) {
        output.extend(chunk);
    }
    let local_flags = pair
        .master
        .get_termios()
        .map(|t| {
            // `LocalFlags(ECHOKE | ECHOE | ECHOK | ECHO | ICANON | …)`: split into names
            // (portable-pty's termios type comes from its own `nix`).
            format!("{:?}", t.local_flags)
                .split(|c: char| !c.is_ascii_alphanumeric())
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    drop(pair.slave);
    Ok(Run {
        output: String::from_utf8_lossy(&output).into_owned(),
        status,
        local_flags,
        home,
    })
}

fn assert_cooked(run: &Run) {
    for flag in ["ICANON", "ECHO"] {
        assert!(
            run.local_flags.iter().any(|f| f == flag),
            "{flag} not restored: {:?}",
            run.local_flags
        );
    }
}

/// A panic exits with 101 (unwound), not with a signal (no double panic / abort).
fn assert_unwound(run: &Run) {
    assert_eq!(
        run.status.signal(),
        None,
        "killed by a signal: {:?}",
        run.status
    );
    assert_eq!(
        run.status.exit_code(),
        101,
        "{:?}\n{}",
        run.status,
        run.output
    );
    assert!(
        !run.output.contains("panicked while processing panic")
            && !run.output.contains("panicked while panicking")
            && !run.output.contains("panicked inside the panic hook"),
        "{}",
        run.output
    );
}

fn crash_reports(home: &Path) -> Vec<PathBuf> {
    let dir = home.join("state").join("crash");
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("crash-") && n.ends_with(".txt"))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn log_text(home: &Path) -> String {
    let mut text = String::new();
    if let Ok(entries) = std::fs::read_dir(home.join("state")) {
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            let is_log = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("sverb.") && n.ends_with(".log"));
            if is_log {
                text.push_str(&std::fs::read_to_string(&path).unwrap_or_default());
            }
        }
    }
    text
}

#[test]
fn panic_in_ui_task_restores_terminal_and_writes_a_crash_report() -> TestResult {
    let run = run_in_pty("ui", "panic-ui")?;
    assert_unwound(&run);
    assert_restored(&run.output);
    assert_cooked(&run);
    assert!(
        run.output
            .contains("sverb crashed: sverb test hook: panic on the UI task")
    );
    assert!(
        run.output.contains("A crash report was written to"),
        "{}",
        run.output
    );

    // Exactly one private crash report, without debug lines.
    let reports = crash_reports(&run.home);
    assert_eq!(reports.len(), 1, "{reports:?}");
    let report = std::fs::read_to_string(&reports[0])?;
    assert!(report.contains("panic on the UI task"), "{report}");
    assert!(
        report.contains(&format!("version:      {}", env!("CARGO_PKG_VERSION"))),
        "{report}"
    );
    assert!(report.contains("last words"), "{report}");
    assert!(!report.contains(" DEBUG "), "{report}");
    assert!(!report.contains("debug-only.example"), "{report}");
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&reports[0])?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    // The line logged right before the panic reached the file; the debug line
    // was emitted too (so its absence from the report is meaningful).
    let log = log_text(&run.home);
    assert!(log.contains("last words"), "{log}");
    assert!(log.contains("debug-only.example"), "{log}");

    let _ = std::fs::remove_dir_all(&run.home);
    Ok(())
}

#[test]
fn panic_on_a_plain_thread_restores_terminal() -> TestResult {
    let run = run_in_pty("thread", "panic-thread")?;
    assert_unwound(&run);
    assert_restored(&run.output);
    assert_cooked(&run);
    assert!(
        run.output.contains("panic on a plain thread"),
        "{}",
        run.output
    );
    assert_eq!(crash_reports(&run.home).len(), 1);
    let _ = std::fs::remove_dir_all(&run.home);
    Ok(())
}

#[test]
fn panic_in_spawn_blocking_restores_terminal() -> TestResult {
    let run = run_in_pty("blocking", "panic-blocking")?;
    assert_unwound(&run);
    assert_restored(&run.output);
    assert_cooked(&run);
    assert!(
        run.output.contains("panic in spawn_blocking"),
        "{}",
        run.output
    );
    assert_eq!(crash_reports(&run.home).len(), 1);
    let _ = std::fs::remove_dir_all(&run.home);
    Ok(())
}

// The terminal goes away (stdout writes fail) before a normal exit; the
// guard's `Drop` must not panic. SIGHUP is ignored so the hangup doesn't kill sverb.
#[test]
fn drop_with_closed_terminal_never_panics() -> TestResult {
    let home = unique_home("closed");
    let pair = native_pty_system().openpty(PtySize::default())?;
    let mut child = pair.slave.spawn_command(command("exit:500", &home, true))?;
    drop(pair.slave);
    let mut reader = pair.master.try_clone_reader()?;
    // Wait until sverb is in TUI mode, then close the terminal.
    let mut seen = Vec::new();
    let mut buf = [0u8; 1024];
    let started = Instant::now();
    while !String::from_utf8_lossy(&seen).contains("\x1b[?1049h") {
        let n = reader.read(&mut buf)?;
        if n == 0 || started.elapsed() > TIMEOUT {
            return Err(format!(
                "never entered TUI mode: {:?}",
                String::from_utf8_lossy(&seen)
            )
            .into());
        }
        seen.extend_from_slice(&buf[..n]);
    }
    drop(reader);
    drop(pair.master);

    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > TIMEOUT {
            child.kill()?;
            return Err("sverb did not exit in time".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status.signal(), None, "{status:?}");
    // 0 normally; 1 when the terminal was already gone while sverb set it up (the
    // setup error is reported, still without a panic: no exit 101, no crash report).
    assert!(matches!(status.exit_code(), 0 | 1), "{status:?}");
    assert!(
        crash_reports(&home).is_empty(),
        "{:?}",
        crash_reports(&home)
    );
    let log = log_text(&home);
    assert!(!log.contains("panicked"), "{log}");
    let _ = std::fs::remove_dir_all(&home);
    Ok(())
}
