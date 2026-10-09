//! vault fails fast with exit 3; with a terminal (PTY) the password is prompted
//! without echo. The OS keyring is disabled (`SVERB_KEYRING=off`).
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;
use std::process::{Command, Stdio};

use common::{PtyRun, TEST_PASSWORD, TestResult, init_vault, unique_home};
use portable_pty::CommandBuilder;

fn headless(home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sverb"))
        .args(args)
        .env("SVERB_HOME", home)
        .env("SVERB_KEYRING", "off")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap()
}

fn pty_unlock(home: &Path) -> Result<PtyRun, Box<dyn std::error::Error>> {
    let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_sverb"));
    cmd.arg("unlock");
    cmd.env("SVERB_HOME", home);
    cmd.env("SVERB_KEYRING", "off");
    cmd.env("TERM", "xterm-256color");
    PtyRun::spawn(cmd)
}

// Fresh home, no terminal.
#[test]
fn t16_not_initialized_exits_3() {
    let home = unique_home("m1-04-fresh");
    let out = headless(&home, &["unlock"]);
    assert_eq!(out.status.code(), Some(3), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("sverb is not initialized; run `sverb` once to set a master password"),
        "{stderr}"
    );
    assert!(out.stdout.is_empty());
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn t16_locked_without_a_terminal_exits_3() {
    let home = unique_home("m1-04-notty");
    init_vault(&home);
    let out = headless(&home, &["unlock"]);
    assert_eq!(out.status.code(), Some(3), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr
            .contains("vault is locked and no terminal is available to enter the master password"),
        "{stderr}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

// With a terminal: prompt (no echo), then success.
#[test]
fn t16_terminal_prompt_then_success() -> TestResult {
    let home = unique_home("m1-04-tty");
    init_vault(&home);
    let mut run = pty_unlock(&home)?;
    let at = run.wait_for("Master password: ", 0)?;
    run.send(TEST_PASSWORD.as_bytes())?;
    run.send(b"\r")?;
    run.wait_for("Password OK.", at)?;
    let status = run.wait_exit()?;
    assert_eq!(status.exit_code(), 0, "{:?}", run.output());
    assert!(
        !run.output().contains(TEST_PASSWORD),
        "the password was echoed"
    );
    let _ = std::fs::remove_dir_all(&home);
    Ok(())
}

// Wrong passwords on the terminal: three attempts, then exit 3.
#[test]
fn t16_terminal_wrong_password_exits_3() -> TestResult {
    let home = unique_home("m1-04-tty-wrong");
    init_vault(&home);
    let mut run = pty_unlock(&home)?;
    let mut at = 0;
    for _ in 0..3 {
        at = run.wait_for("Master password: ", at)?;
        run.send(b"wrong\r")?;
        at = run.wait_for("wrong master password", at)?;
    }
    let status = run.wait_exit()?;
    assert_eq!(status.exit_code(), 3, "{:?}", run.output());
    let _ = std::fs::remove_dir_all(&home);
    Ok(())
}

#[test]
fn lock_without_a_running_tui_is_a_no_op() {
    let home = unique_home("m1-04-lock");
    let out = headless(&home, &["lock"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let _ = std::fs::remove_dir_all(&home);
}
