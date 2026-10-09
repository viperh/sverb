//! A local-only run makes **zero** network connections (§1.1: no
//! telemetry, no update checks, no default server).
//!
//! The TUI runs on a PTY under `strace -f -e trace=connect,sendto,sendmsg` for 10 s:
//! it unlocks, opens a local shell (`leader t`), idles, and quits. Every traced
//! call is checked: no `AF_INET` / `AF_INET6` address may appear (Unix-domain
//! sockets, such as the agent's control socket, are fine). Linux only; skipped with
//! a note when `strace` is missing or ptrace is not allowed.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::{Duration, Instant};

use common::{PtyRun, TestResult, init_vault, unique_home, unlock};
use portable_pty::CommandBuilder;

/// Whether `strace` can trace a child here.
fn strace_works() -> bool {
    std::process::Command::new("strace")
        .args([
            "-f",
            "-qq",
            "-e",
            "trace=connect",
            "-o",
            "/dev/null",
            "true",
        ])
        .status()
        .is_ok_and(|s| s.success())
}

#[test]
fn t08_local_only_run_is_network_silent() -> TestResult {
    if !strace_works() {
        eprintln!("SKIPPED (needs strace with ptrace allowed)");
        return Ok(());
    }
    let home = unique_home("m4-09-silence");
    init_vault(&home);
    let trace = home.join("strace.log");
    let mut cmd = CommandBuilder::new("strace");
    cmd.args(["-f", "-qq", "-e", "trace=connect,sendto,sendmsg", "-o"]);
    cmd.arg(&trace);
    cmd.arg(env!("CARGO_BIN_EXE_sverb"));
    cmd.env("SVERB_HOME", &home);
    cmd.env("TERM", "xterm-256color");
    cmd.env("SHELL", "/bin/sh");
    // Never the real OS keyring or agent in tests.
    cmd.env("SVERB_KEYRING", "off");
    cmd.env_remove("SSH_AUTH_SOCK");
    cmd.env_remove("SVERB_TEST_HOOK");
    let started = Instant::now();
    let mut run = PtyRun::spawn(cmd)?;
    let entered = run.wait_for("\x1b[?1049h", 0)?;
    let unlocked = unlock(&mut run, entered)?;
    // A local shell (`leader t`), then idle until 10 s have passed.
    run.send(b"\x1ct")?;
    run.wait_for(" 1 local", unlocked)?;
    while started.elapsed() < Duration::from_secs(10) {
        run.poll(Duration::from_millis(200));
    }
    run.send(b"\x1cq")?;
    // Sessions are open: confirm the quit.
    run.poll(Duration::from_millis(300));
    run.send(b"y")?;
    let status = run.wait_exit()?;
    assert_eq!(status.exit_code(), 0, "{status:?}");
    let log = std::fs::read_to_string(&trace)?;
    let inet: Vec<&str> = log.lines().filter(|l| l.contains("AF_INET")).collect();
    assert!(
        inet.is_empty(),
        "network calls in local-only mode:\n{}",
        inet.join("\n")
    );
    let _ = std::fs::remove_dir_all(&home);
    Ok(())
}
