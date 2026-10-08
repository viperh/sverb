//! M0-11 T-19: `sverb` launches into the shell and `ctrl-\ q` exits 0 with the
//! terminal restored (the M0 exit criterion), end to end in a PTY.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{PtyRun, TestResult, assert_restored, init_vault, unique_home, unlock};
use portable_pty::CommandBuilder;

#[test]
fn t19_shell_opens_and_leader_q_quits() -> TestResult {
    let home = unique_home("m0-11-shell");
    // M1-04: the shell starts locked; unlock first.
    init_vault(&home);
    let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_sverb"));
    cmd.env("SVERB_HOME", &home);
    cmd.env("TERM", "xterm-256color");
    // M1-04: never the real OS keyring in tests.
    cmd.env("SVERB_KEYRING", "off");
    cmd.env_remove("SVERB_TEST_HOOK");
    cmd.env_remove("RUST_BACKTRACE");
    let mut run = PtyRun::spawn(cmd)?;
    let entered = run.wait_for("\x1b[?1049h", 0)?;
    // The status bar is on the first frame; the Hosts section after unlocking (M1-04).
    run.wait_for("NORMAL", entered)?;
    unlock(&mut run, entered)?;
    run.wait_for("Hosts", entered)?;
    // The leader (`ctrl-\`, byte 0x1C) then `q`.
    run.send(b"\x1c")?;
    run.send(b"q")?;
    let status = run.wait_exit()?;
    let output = run.output();
    assert_eq!(status.exit_code(), 0, "{status:?} {output:?}");
    assert_restored(&output);
    let _ = std::fs::remove_dir_all(&home);
    Ok(())
}
