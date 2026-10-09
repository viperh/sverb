//! `sverb export recording <id> <out.cast>` writes plain asciicast v2 (every
//! line is JSON), and refuses without `--yes` when there is no terminal to confirm on.
//! The OS keyring is disabled (`SVERB_KEYRING=off`); the vault is unlocked on a PTY.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use common::{PtyRun, TEST_PASSWORD, TestResult, init_vault, unique_home};
use portable_pty::CommandBuilder;
use sverb_core::paths::{MapEnv, Paths};
use sverb_term::recording::{
    RecorderMeta, recording_file_name,
    writer::{ChunkWriter, Recorder},
};

const CANARY: &str = "export-canary-\u{1F980}";
const CONN: [u8; 16] = [0x42; 16];

fn paths(home: &Path) -> Paths {
    Paths::resolve(&MapEnv::new().var("SVERB_HOME", home)).unwrap()
}

/// Write an encrypted recording under the vault's recording key; returns its id.
fn make_recording(home: &Path) -> String {
    let paths = paths(home);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let key = rt.block_on(async {
        let store = sverb_store::Store::open(&paths).unwrap();
        let engine = sverb_tui::services::vault::VaultEngine::new(
            store,
            std::sync::Arc::new(sverb_core::vault::NoKeyring),
            sverb_core::vault::Argon2Cost::TEST,
        );
        let vault = engine.unlock_with_password(TEST_PASSWORD).await.unwrap();
        sverb_tui::services::recording::recording_key(&vault)
    });
    let dir = paths.recordings_dir();
    let (path, file) = sverb_term::recording::create_recording_file(&dir, &CONN).unwrap();
    let chunks = ChunkWriter::new(file, key, CONN).unwrap();
    let meta = RecorderMeta {
        title: Some("web-1".into()),
        ..RecorderMeta::default()
    };
    let mut rec = Recorder::new(chunks, meta, (80, 24));
    rec.resize(std::time::Duration::ZERO, 80, 24).unwrap();
    rec.output(
        std::time::Duration::from_millis(100),
        format!("$ echo {CANARY}\r\n").as_bytes(),
    )
    .unwrap();
    rec.output(
        std::time::Duration::from_millis(900),
        b"\x1b[1mbold\x1b[0m\r\n",
    )
    .unwrap();
    rec.finish().unwrap();
    assert!(path.ends_with(recording_file_name(&CONN)));
    // The conn id as a UUID.
    "42424242-4242-4242-4242-424242424242".to_owned()
}

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

fn pty(home: &Path, args: &[&str]) -> Result<PtyRun, Box<dyn std::error::Error>> {
    let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_sverb"));
    cmd.args(args);
    cmd.env("SVERB_HOME", home);
    cmd.env("SVERB_KEYRING", "off");
    cmd.env("TERM", "xterm-256color");
    PtyRun::spawn(cmd)
}

/// Every line is JSON: a v2 header, then `[t, code, data]` events.
fn assert_valid_cast(out: &Path) {
    let text = std::fs::read_to_string(out).unwrap();
    let mut lines = text.lines();
    let header: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
    assert_eq!(header["version"], 2);
    assert_eq!(header["width"], 80);
    assert_eq!(header["title"], "web-1");
    let mut data = String::new();
    for line in lines {
        let ev: serde_json::Value = serde_json::from_str(line).unwrap();
        let arr = ev.as_array().unwrap();
        assert_eq!(arr.len(), 3, "{line}");
        assert!(arr[0].as_f64().is_some());
        assert!(arr[1].is_string());
        data.push_str(arr[2].as_str().unwrap());
    }
    assert!(data.contains(CANARY), "{data:?}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(out).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}

fn out_path(home: &Path) -> PathBuf {
    home.join("out.cast")
}

// No terminal and no --yes → refused (usage, exit 2), nothing written.
#[test]
fn t11_refuses_without_yes_and_without_a_terminal() {
    let home = unique_home("m3-05-export-notty");
    init_vault(&home);
    let id = make_recording(&home);
    let out = out_path(&home);
    let res = headless(&home, &["export", "recording", &id, out.to_str().unwrap()]);
    assert_eq!(res.status.code(), Some(2), "{res:?}");
    let stderr = String::from_utf8_lossy(&res.stderr);
    assert!(stderr.contains("--yes"), "{stderr}");
    assert!(stderr.contains("plain text"), "{stderr}");
    assert!(!out.exists());

    // With --yes but no terminal and no keyring the vault stays locked (exit 3).
    let res = headless(
        &home,
        &["export", "recording", &id, out.to_str().unwrap(), "--yes"],
    );
    assert_eq!(res.status.code(), Some(3), "{res:?}");
    assert!(!out.exists());

    // Unknown recording: not found (exit 4).
    let res = headless(
        &home,
        &[
            "export",
            "recording",
            "nope",
            out.to_str().unwrap(),
            "--yes",
        ],
    );
    assert_eq!(res.status.code(), Some(4), "{res:?}");
    let _ = std::fs::remove_dir_all(&home);
}

// --yes on a terminal: unlock, then a valid .cast file.
#[test]
fn t11_exports_valid_asciicast_with_yes() -> TestResult {
    let home = unique_home("m3-05-export-yes");
    init_vault(&home);
    let id = make_recording(&home);
    let out = out_path(&home);
    let mut run = pty(
        &home,
        &["export", "recording", &id, out.to_str().unwrap(), "--yes"],
    )?;
    let at = run.wait_for("Master password: ", 0)?;
    run.send(TEST_PASSWORD.as_bytes())?;
    run.send(b"\r")?;
    run.wait_for("Wrote ", at)?;
    let status = run.wait_exit()?;
    assert_eq!(status.exit_code(), 0, "{:?}", run.output());
    assert_valid_cast(&out);
    let _ = std::fs::remove_dir_all(&home);
    Ok(())
}

// Without --yes on a terminal: the confirmation is asked first.
#[test]
fn t11_confirms_on_a_terminal() -> TestResult {
    let home = unique_home("m3-05-export-confirm");
    init_vault(&home);
    let id = make_recording(&home);
    let out = out_path(&home);
    // Declined: nothing written.
    let file_name = recording_file_name(&CONN);
    let mut run = pty(
        &home,
        &["export", "recording", &file_name, out.to_str().unwrap()],
    )?;
    run.wait_for("[y/N] ", 0)?;
    run.send(b"n\r")?;
    let status = run.wait_exit()?;
    assert_eq!(status.exit_code(), 1, "{:?}", run.output());
    assert!(!out.exists());
    // Accepted.
    let mut run = pty(&home, &["export", "recording", &id, out.to_str().unwrap()])?;
    let at = run.wait_for("[y/N] ", 0)?;
    assert!(run.output().contains("plain text"));
    run.send(b"y\r")?;
    let at = run.wait_for("Master password: ", at)?;
    run.send(TEST_PASSWORD.as_bytes())?;
    run.send(b"\r")?;
    run.wait_for("Wrote ", at)?;
    let status = run.wait_exit()?;
    assert_eq!(status.exit_code(), 0, "{:?}", run.output());
    assert_valid_cast(&out);
    let _ = std::fs::remove_dir_all(&home);
    Ok(())
}
