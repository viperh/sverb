//! `sverb doctor` without a terminal skips the terminal probes ("not a
//! terminal") and writes no escape sequences. The real binary, with `SVERB_HOME` in a
//! temp dir, `SVERB_KEYRING=off` and no `SSH_AUTH_SOCK` (the user's agent and
//! keyring are never touched).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

fn home(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("sverb-doctor-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn doctor(home: &Path, args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sverb"));
    cmd.arg("doctor")
        .args(args)
        .env("SVERB_HOME", home)
        .env("HOME", home)
        .env("SVERB_KEYRING", "off")
        .env("TERM", "xterm-256color")
        .env("LANG", "C.UTF-8")
        .env_remove("LC_ALL")
        .env_remove("LC_CTYPE")
        .env_remove("SVERB_LOG")
        .env_remove("SSH_AUTH_SOCK")
        .env_remove("TMUX")
        .env_remove("STY")
        .env_remove("COLORTERM")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn t05_not_a_tty_skips_terminal_probes() {
    let home = home("notty");
    let out = doctor(&home, &[]);
    let stdout = text(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{stdout}\n{}",
        text(&out.stderr)
    );
    assert!(
        !out.stdout.contains(&0x1b),
        "escape bytes on stdout: {stdout:?}"
    );
    assert!(!out.stderr.contains(&0x1b), "escape bytes on stderr");
    assert!(
        stdout.contains("kitty keyboard    skipped: not a terminal"),
        "{stdout}"
    );
    assert!(
        stdout.contains("unicode width     skipped: not a terminal"),
        "{stdout}"
    );
    for section in ["Environment", "Terminal", "Agent", "Keyring", "Sync"] {
        assert!(
            stdout.contains(&format!("{section}\n")),
            "{section}: {stdout}"
        );
    }
    assert!(stdout.contains("disabled by SVERB_KEYRING"), "{stdout}");
    assert!(stdout.contains("SSH_AUTH_SOCK is not set"), "{stdout}");

    // --json: one envelope line, also without escape bytes.
    let out = doctor(&home, &["--json"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(!out.stdout.contains(&0x1b));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["version"], 1);
    assert_eq!(v["data"]["ok"], true);
    let term = v["data"]["sections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == "terminal")
        .unwrap();
    let kitty = term["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "term.kitty")
        .unwrap();
    assert_eq!(kitty["detail"], "skipped: not a terminal");

    // Read-only: no database was created.
    assert!(!home.join("data").join("sverb.db").exists());
    let _ = std::fs::remove_dir_all(&home);
}

// `--algos` lists the offered algorithms, exit 0.
#[test]
fn algos_lists_offered_algorithms() {
    let home = home("algos");
    let out = doctor(&home, &["--algos"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}");
    assert!(stdout.contains("Key exchange\n"), "{stdout}");
    assert!(
        stdout.contains("default      curve25519-sha256"),
        "{stdout}"
    );
    assert!(
        stdout.contains("legacy       diffie-hellman-group14-sha1"),
        "{stdout}"
    );
    let _ = std::fs::remove_dir_all(&home);
}
