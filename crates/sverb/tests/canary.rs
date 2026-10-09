//! M7-05 T-03 (fixture half): the canary convention end to end through the real binary.
//!
//! With `SVERB_LOG=trace`, a backup that holds planted canaries (a host password
//! `CANARY-PW-…`, a hostname `canary-host-….example`, the export password
//! `CANARY-PASS-…`) is imported, the hosts are listed, and the TUI starts and quits.
//! Then `scripts/canary-scan.sh` must find no secret anywhere in the logs, the SQLite
//! files or the backup, and no hostname in `info`+ log lines.
//!
//! The `SVERB_HOME` is kept in `target/tmp/m7-05-canary/` after the run, so the CI
//! canary job (`.github/workflows/ci.yml`, job `canary`) scans it again together with
//! everything else the suite leaves behind.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::{path::Path, process::Command, time::Duration};

use common::{PtyRun, TEST_PASSWORD, TestResult, init_vault};
use portable_pty::CommandBuilder;
use sverb_core::{
    exporters::backup,
    importers::backup::{BackupItem, BackupPayload, BackupVault},
    model::{
        DeviceId, HlcClock, Host, ItemBody, ItemId, ItemKind, ManualClock, UnixMillis, VaultId,
        current_schema,
    },
    secret::SecretString,
};

const HOST: &str = "canary-host-7f3a.example";
const HOST_PASSWORD: &str = "CANARY-PW-7f3a-host-password";
const EXPORT_PASSWORD: &str = "CANARY-PASS-7f3a export horse battery staple";

fn sverb(home: &Path, args: &[&str]) -> CommandBuilder {
    let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_sverb"));
    cmd.args(args);
    cmd.env("SVERB_HOME", home);
    cmd.env("TERM", "xterm-256color");
    cmd.env("SVERB_KEYRING", "off");
    cmd.env("SVERB_LOG", "trace");
    cmd.env("SVERB_EXPORT_PASSWORD", EXPORT_PASSWORD);
    cmd.env_remove("SVERB_TEST_HOOK");
    cmd
}

fn write_backup(path: &Path) {
    let mut clock = HlcClock::new(ManualClock::new(Duration::from_secs(1_800_000_000)));
    let device = DeviceId::from_bytes([5; 16]);
    let vault = VaultId::from_bytes([7; 16]);
    let mut body = ItemBody::new(ItemKind::Host, current_schema(ItemKind::Host));
    Host {
        label: "canary".to_owned(),
        address: HOST.to_owned(),
        username: Some("canary-user".to_owned()),
        password: Some(SecretString::from(HOST_PASSWORD)),
        ..Host::default()
    }
    .apply_to(&mut body, &mut clock, device);
    let payload = BackupPayload {
        vaults: vec![BackupVault {
            id: vault,
            name: "Personal".to_owned(),
            kind: "personal".to_owned(),
            defaults: None,
        }],
        items: vec![BackupItem {
            id: ItemId::from_bytes([0x7f; 16]),
            vault,
            body,
        }],
    };
    let text = backup::encrypt(
        &payload,
        EXPORT_PASSWORD,
        sverb_crypto::kdf::Argon2Params::MIN_M_KIB,
        1,
        1,
        UnixMillis(0),
    )
    .unwrap();
    std::fs::write(path, text).unwrap();
}

/// Run a headless command that asks for the master password on the PTY.
fn run_unlocked(home: &Path, args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let mut run = PtyRun::spawn(sverb(home, args))?;
    let at = run.wait_for("Master password: ", 0)?;
    run.send(TEST_PASSWORD.as_bytes())?;
    run.send(b"\r")?;
    let status = run.wait_exit()?;
    let output = run.output()[at..].to_owned();
    assert_eq!(status.exit_code(), 0, "{args:?}: {output}");
    Ok(output)
}

#[test]
fn t03_planted_canaries_never_reach_logs_or_disk() -> TestResult {
    let home = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m7-05-canary");
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home)?;
    init_vault(&home);
    let file = home.join("canary.sverb-backup");
    write_backup(&file);

    let imported = run_unlocked(
        &home,
        &["import", "backup", file.to_str().unwrap(), "--yes"],
    )?;
    assert!(!imported.contains(HOST_PASSWORD), "{imported}");
    let listed = run_unlocked(&home, &["hosts", "list"])?;
    assert!(
        listed.contains("canary"),
        "the import did not land: {listed}"
    );
    assert!(!listed.contains(HOST_PASSWORD), "{listed}");

    // The TUI: unlock (the vault, the index and the Hosts view load), then quit.
    let mut run = PtyRun::spawn(sverb(&home, &[]))?;
    let entered = run.wait_for("\x1b[?1049h", 0)?;
    let prompt = run.wait_for("Unlock sverb", entered)?;
    run.send(TEST_PASSWORD.as_bytes())?;
    run.send(b"\r")?;
    run.wait_for(" Hosts ", prompt)?;
    run.send(b"q")?;
    run.wait_exit()?;

    // The scan over this home: clean, and it did look at logs and the database.
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/canary-scan.sh");
    let Ok(out) = Command::new("bash")
        .arg(&script)
        .arg("--require-files")
        .arg(&home)
        .output()
    else {
        eprintln!("SKIP: bash not available for the scan");
        return Ok(());
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(
        !stdout.contains(" log=0 "),
        "no log file was scanned: {stdout}"
    );
    assert!(
        !stdout.contains(" db=0 "),
        "no database was scanned: {stdout}"
    );

    // Debug/trace lines may name the host (SPEC §17); prove the scan looked at a log
    // that really has trace output.
    let logs = std::fs::read_dir(home.join("state"))?
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().ends_with(".log"))
        .map(|e| std::fs::read_to_string(e.path()).unwrap_or_default())
        .collect::<String>();
    assert!(
        logs.contains("TRACE") || logs.contains("DEBUG"),
        "no debug output: {logs}"
    );
    Ok(())
}
