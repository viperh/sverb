//! M0-09: event loop exits and terminal modes, end to end in a PTY (T-09..T-12).
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;

use common::{PtyRun, TestResult, assert_restored, init_vault, unique_home, unlock};
use portable_pty::CommandBuilder;

/// The status bar of the first frame (proves the loop drew).
const DRAWN: &str = "NORMAL";

fn sverb(home: &Path) -> CommandBuilder {
    let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_sverb"));
    sverb_env(&mut cmd, home);
    cmd
}

fn sverb_env(cmd: &mut CommandBuilder, home: &Path) {
    cmd.env("SVERB_HOME", home);
    cmd.env("TERM", "xterm-256color");
    // M1-04: never the real OS keyring in tests.
    cmd.env("SVERB_KEYRING", "off");
    cmd.env_remove("SVERB_TEST_HOOK");
    cmd.env_remove("RUST_BACKTRACE");
}

fn signal(pid: u32, sig: &str) -> TestResult {
    let status = std::process::Command::new("kill")
        .args([format!("-{sig}"), pid.to_string()])
        .status()?;
    assert!(status.success(), "kill -{sig} {pid}: {status:?}");
    Ok(())
}

// T-09
#[test]
fn quit_restores_the_terminal() -> TestResult {
    let home = unique_home("m0-09-quit");
    // M1-04: start from an initialized vault and unlock it.
    init_vault(&home);
    let mut run = PtyRun::spawn(sverb(&home))?;
    let entered = run.wait_for("\x1b[?1049h", 0)?;
    run.wait_for(DRAWN, entered)?;
    unlock(&mut run, entered)?;
    run.send(b"q")?;
    let status = run.wait_exit()?;
    let output = run.output();
    assert_eq!(status.exit_code(), 0, "{status:?} {output:?}");
    assert_restored(&output);
    // Bracketed paste and (default `ui.mouse = true`) mouse capture were on.
    assert!(output.contains("\x1b[?2004h"), "{output:?}");
    assert!(output.contains("\x1b[?1000h"), "{output:?}");
    let _ = std::fs::remove_dir_all(&home);
    Ok(())
}

// T-10
#[test]
fn sigterm_exits_cleanly_without_confirmation() -> TestResult {
    let home = unique_home("m0-09-term");
    let mut run = PtyRun::spawn(sverb(&home))?;
    let entered = run.wait_for("\x1b[?1049h", 0)?;
    run.wait_for(DRAWN, entered)?;
    let pid = run.child.process_id().ok_or("no pid")?;
    signal(pid, "TERM")?;
    let status = run.wait_exit()?;
    let output = run.output();
    assert_eq!(status.signal(), None, "{status:?}");
    assert_eq!(status.exit_code(), 0, "{status:?} {output:?}");
    assert_restored(&output);
    assert!(!output.contains("Quit?"), "{output:?}");
    let _ = std::fs::remove_dir_all(&home);
    Ok(())
}

// T-11: `ctrl-z` stops the process with the terminal restored; `SIGCONT` re-enters
// TUI mode and redraws. A job-control shell (`set -m`) runs sverb in the foreground:
// a process in an orphaned process group would ignore SIGTSTP. The shell's
// `waitpid(WUNTRACED)` reports the stop (`$? = 128 + SIGTSTP`), then `fg` continues it.
#[test]
fn suspend_and_resume() -> TestResult {
    let home = unique_home("m0-09-suspend");
    // M1-04: start from an initialized vault and unlock it.
    init_vault(&home);
    let mut cmd = CommandBuilder::new("sh");
    cmd.args([
        "-c",
        "set -m; \"$0\"; st=$?; echo \"SVERB-STOPPED:$(kill -l $((st - 128)))\"; \
         read _; fg >/dev/null",
        env!("CARGO_BIN_EXE_sverb"),
    ]);
    sverb_env(&mut cmd, &home);
    let mut run = PtyRun::spawn(cmd)?;
    let entered = run.wait_for("\x1b[?1049h", 0)?;
    run.wait_for(DRAWN, entered)?;
    unlock(&mut run, entered)?;
    run.send(b"\x1a")?;
    let stopped = run.wait_for("SVERB-STOPPED:TSTP", entered)?;
    let before_stop = run.output()[entered..stopped].to_owned();
    assert!(before_stop.contains("\x1b[?1049l"), "{before_stop:?}");
    assert!(before_stop.contains("\x1b[?25h"), "{before_stop:?}");
    assert!(before_stop.contains("\x1b[?2004l"), "{before_stop:?}");

    // Continue (`fg` sends SIGCONT): TUI mode again, and a full redraw.
    run.send(b"\n")?;
    let reentered = run.wait_for("\x1b[?1049h", stopped)?;
    run.wait_for(DRAWN, reentered)?;
    run.send(b"q")?;
    let status = run.wait_exit()?;
    let output = run.output();
    assert_eq!(status.exit_code(), 0, "{status:?} {output:?}");
    assert_restored(&output[reentered.saturating_sub(8)..]);
    let _ = std::fs::remove_dir_all(&home);
    Ok(())
}

// T-12
#[test]
fn mouse_capture_follows_config() -> TestResult {
    let home = unique_home("m0-09-mouse");
    // M1-04: start from an initialized vault and unlock it.
    init_vault(&home);
    std::fs::create_dir_all(home.join("config"))?;
    std::fs::write(
        home.join("config").join("config.toml"),
        "[ui]\nmouse = false\n",
    )?;
    let mut run = PtyRun::spawn(sverb(&home))?;
    let entered = run.wait_for("\x1b[?1049h", 0)?;
    run.wait_for(DRAWN, entered)?;
    unlock(&mut run, entered)?;
    run.send(b"q")?;
    let status = run.wait_exit()?;
    let output = run.output();
    assert_eq!(status.exit_code(), 0, "{status:?} {output:?}");
    assert!(!output.contains("\x1b[?1000h"), "{output:?}");
    // Bracketed paste is on regardless.
    assert!(output.contains("\x1b[?2004h"), "{output:?}");
    let _ = std::fs::remove_dir_all(&home);
    Ok(())
}
