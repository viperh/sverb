//! The kitty keyboard protocol on the outer terminal, end to end in a PTY.
//!
//! The test plays the outer terminal: it answers (or doesn't answer) crossterm's
//! `CSI ? u` query, then checks the push (`CSI > 5 u`: disambiguate + alternate keys)
//! and the pop on exit (`CSI < 1 u`).
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;

use common::{PtyRun, TestResult, assert_restored, init_vault, unique_home, unlock};
use portable_pty::CommandBuilder;

const QUERY: &str = "\x1b[?u";
const PUSH: &str = "\x1b[>5u";
const POP: &str = "\x1b[<1u";
const DRAWN: &str = "NORMAL";

fn sverb(home: &Path) -> CommandBuilder {
    let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_sverb"));
    cmd.env("SVERB_HOME", home);
    cmd.env("TERM", "xterm-256color");
    // Never the real OS keyring in tests.
    cmd.env("SVERB_KEYRING", "off");
    cmd.env_remove("SVERB_TEST_HOOK");
    cmd.env_remove("RUST_BACKTRACE");
    cmd
}

#[test]
fn kitty_flags_pushed_and_popped_when_supported() -> TestResult {
    let home = unique_home("m1-11-kitty");
    // The TUI starts locked; unlock before typing.
    init_vault(&home);
    let mut run = PtyRun::spawn(sverb(&home))?;
    let queried = run.wait_for(QUERY, 0)?;
    // A kitty-capable terminal: current flags (0), then the DA1 reply.
    run.send(b"\x1b[?0u\x1b[?62;22c")?;
    let pushed = run.wait_for(PUSH, queried)?;
    run.wait_for(DRAWN, pushed)?;
    unlock(&mut run, pushed)?;
    run.send(b"q")?;
    let status = run.wait_exit()?;
    let output = run.output();
    assert_eq!(status.exit_code(), 0, "{status:?} {output:?}");
    assert_restored(&output);
    let pop = output.rfind(POP).expect("kitty flags never popped");
    assert!(pop > pushed, "{output:?}");
    let _ = std::fs::remove_dir_all(&home);
    Ok(())
}

#[test]
fn legacy_terminal_gets_no_kitty_flags() -> TestResult {
    let home = unique_home("m1-11-legacy");
    // The TUI starts locked; unlock before typing.
    init_vault(&home);
    let mut run = PtyRun::spawn(sverb(&home))?;
    let queried = run.wait_for(QUERY, 0)?;
    // A legacy terminal answers DA1 only.
    run.send(b"\x1b[?62;22c")?;
    run.wait_for(DRAWN, queried)?;
    unlock(&mut run, queried)?;
    run.send(b"q")?;
    let status = run.wait_exit()?;
    let output = run.output();
    assert_eq!(status.exit_code(), 0, "{status:?} {output:?}");
    assert_restored(&output);
    assert!(!output.contains(PUSH), "{output:?}");
    assert!(!output.contains(POP), "{output:?}");
    let _ = std::fs::remove_dir_all(&home);
    Ok(())
}
