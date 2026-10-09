//! T-09 (no TUI without a terminal) and T-10 (`sverb config …`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

fn home(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("sverb-cli-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn sverb(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sverb"))
        .args(args)
        .env("SVERB_HOME", home)
        .env_remove("SVERB_LOG")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn tui_without_terminal_exits_1_without_escape_bytes() {
    let home = home("notty");
    for args in [&[][..], &["connect", "db"][..], &["--workspace", "w"][..]] {
        let out = sverb(&home, args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}: {:?}", text(&out.stdout));
        assert!(
            !out.stderr.contains(&0x1b),
            "{args:?}: escape bytes on stderr"
        );
        assert!(
            text(&out.stderr).contains("error: sverb's TUI needs an interactive terminal"),
            "{}",
            text(&out.stderr)
        );
    }
}

#[test]
fn config_path_honors_sverb_home() {
    let home = home("path");
    let out = sverb(&home, &["config", "--path"]);
    assert!(out.status.success());
    let path = text(&out.stdout);
    assert!(path.trim_end().ends_with("config.toml"), "{path}");
    assert!(Path::new(path.trim_end()).starts_with(&home), "{path}");
}

#[test]
fn config_print_default_equals_embedded_file() {
    let home = home("default");
    let out = sverb(&home, &["config", "--print-default"]);
    assert!(out.status.success());
    let embedded = include_str!("../../sverb-core/src/config/default_config.toml");
    assert_eq!(text(&out.stdout), embedded);
}

#[test]
fn config_check_valid_and_invalid() {
    let home = home("check");
    let path = PathBuf::from(text(&sverb(&home, &["config", "--path"]).stdout).trim_end());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();

    // No file yet: the defaults are fine.
    let out = sverb(&home, &["config", "--check"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "OK\n");

    std::fs::write(&path, "[ui]\nmouse = false\n").unwrap();
    let out = sverb(&home, &["config", "--check"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "OK\n");

    std::fs::write(
        &path,
        "[ui]\nmouse = false\n\n[ssh]\nkeepalive_secs = \"often\"\n",
    )
    .unwrap();
    let out = sverb(&home, &["config", "--check"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains(&format!("{}:5:", path.display())),
        "expected path:line:col in {stderr}"
    );

    // --file checks another file; a missing one is "not found".
    let out = sverb(
        &home,
        &["config", "--check", "--file", "/nonexistent/x.toml"],
    );
    assert_eq!(out.status.code(), Some(4));
}

// Headless commands never wait on a non-TTY stdin and never print escape bytes.
#[test]
fn headless_stub_does_not_hang() {
    let home = home("stub");
    let start = Instant::now();
    let out = sverb(&home, &["hosts", "list"]);
    assert!(start.elapsed() < Duration::from_secs(2));
    // `hosts list` needs the vault; a fresh home fails fast (exit 3).
    assert_eq!(out.status.code(), Some(3));
    assert!(out.stdout.is_empty());
    assert!(text(&out.stderr).contains("not initialized"));
}

// The template's knobs are gone.
#[test]
fn tick_rate_is_rejected() {
    let home = home("tick");
    let out = sverb(&home, &["--tick-rate", "4"]);
    assert_eq!(out.status.code(), Some(2));
}
