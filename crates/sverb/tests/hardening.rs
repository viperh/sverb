//! M7-05 T-01 (binary level): the running `sverb` is not dumpable and has a core limit
//! of 0. Checked from outside, without ptrace: the kernel makes `/proc/<pid>/*` of a
//! non-dumpable process owned by root, and `/proc/<pid>/limits` shows the core limit.
//! The in-process twin (`PR_GET_DUMPABLE`) is `crates/sverb-core/tests/hardening.rs`.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::os::unix::fs::MetadataExt;

use common::{PtyRun, TestResult, unique_home};
use portable_pty::CommandBuilder;

#[test]
fn t01_running_sverb_is_not_dumpable() -> TestResult {
    let home = unique_home("m7-05-hardening");
    let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_sverb"));
    cmd.env("SVERB_HOME", &home);
    cmd.env("TERM", "xterm-256color");
    cmd.env("SVERB_KEYRING", "off");
    cmd.env_remove("SVERB_TEST_HOOK");
    let mut run = PtyRun::spawn(cmd)?;
    let entered = run.wait_for("\x1b[?1049h", 0)?;
    run.wait_for("NORMAL", entered)?;
    let pid = run.child.process_id().ok_or("no pid")?;

    let me = std::fs::metadata("/proc/self")?.uid();
    let owner = std::fs::metadata(format!("/proc/{pid}/status"))?.uid();
    let limits = std::fs::read_to_string(format!("/proc/{pid}/limits"))?;

    let status = std::process::Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()?;
    assert!(status.success());
    let _ = run.wait_exit()?;
    let _ = std::fs::remove_dir_all(&home);

    if me != 0 {
        assert_eq!(
            owner, 0,
            "/proc/{pid} is owned by uid {owner}: still dumpable"
        );
    }
    let core = limits
        .lines()
        .find(|l| l.starts_with("Max core file size"))
        .ok_or("no core limit line")?;
    let fields: Vec<&str> = core.split_whitespace().collect();
    // "Max core file size  <soft>  <hard>  bytes"
    assert_eq!(fields.get(4), Some(&"0"), "{core}");
    assert_eq!(fields.get(5), Some(&"0"), "{core}");
    Ok(())
}
