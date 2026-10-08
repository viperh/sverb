//! M2-11 T-15: `sverb import …` with injected terminal I/O.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use sverb_core::vault::{Argon2Cost, MemKeyring};
use sverb_store::Store;
use sverb_tui::services::vault::VaultEngine;

use super::*;

const PW: &str = "correct horse battery staple 42";

struct Home(PathBuf);

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn svc(tag: &str) -> (ImportService, Home) {
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "sverb-m2-11-cli-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
    let store = Store::open_at(dir.join("sverb.db"), Arc::new(sverb_store::SystemClock))
        .unwrap_or_else(|e| panic!("{e}"));
    let engine = VaultEngine::new(store, Arc::new(MemKeyring::new()), Argon2Cost::TEST);
    let vault = engine
        .initialize(PW, false)
        .await
        .unwrap_or_else(|e| panic!("{e}"))
        .vault;
    (ImportService::new(engine, Arc::new(vault)), Home(dir))
}

fn fixture(rel: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(rel)
        .display()
        .to_string()
}

fn parse(args: &str) -> ImportArgs {
    let paths = sverb_core::paths::Paths::resolve(
        &sverb_core::paths::MapEnv::new().var("SVERB_HOME", "/nonexistent"),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let cli = super::super::Cli::try_parse_with(
        &paths,
        std::iter::once("sverb").chain(args.split_whitespace()),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    match cli.command {
        Some(super::super::Command::Import(a)) => a,
        other => panic!("not an import: {other:?}"),
    }
}

async fn run(
    svc: &ImportService,
    args: &str,
    tty: bool,
    answer: bool,
) -> (Result<u8, CliError>, String) {
    let mut yes = move || answer;
    let mut secret = |_: &str| None;
    let mut io = ImportIo {
        tty,
        read_yes: &mut yes,
        read_secret: &mut secret,
        env_password: None,
    };
    let mut out = Vec::new();
    let res = run_with(parse(args), svc, &mut io, &mut out).await;
    (res, String::from_utf8(out).unwrap_or_default())
}

// T-15
#[tokio::test]
async fn t15_dry_run_prints_the_preview() {
    let (svc, _home) = svc("dry").await;
    let args = format!(
        "import ssh-config {} --dry-run",
        fixture("ssh_config/wildcard")
    );
    let (res, out) = run(&svc, &args, false, false).await;
    assert_eq!(res, Ok(0));
    insta::assert_snapshot!("import_ssh_config_dry_run", out);
    let (res, _) = run(&svc, &args, false, false).await;
    assert_eq!(res, Ok(0));
    // Nothing was written.
    let plan = svc
        .preview(
            &SourceSpec::SshConfig(Some(fixture("ssh_config/wildcard").into())),
            None,
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(plan.counts().duplicate + plan.counts().conflict, 0);
}

// T-15
#[tokio::test]
async fn t15_csv_yes_imports() {
    let (svc, _home) = svc("csv").await;
    let args = format!("import csv {} --yes", fixture("csv/hosts.csv"));
    let (res, out) = run(&svc, &args, false, false).await;
    assert_eq!(res, Ok(0), "{out}");
    assert!(out.contains("Imported 9 new"), "{out}");
    // Again: duplicates only.
    let (res, out) = run(&svc, &args, false, false).await;
    assert_eq!(res, Ok(0));
    assert!(out.contains("0 new, 0 updated, 9 duplicate"), "{out}");
}

#[tokio::test]
async fn no_tty_without_yes_is_a_usage_error() {
    let (svc, _home) = svc("notty").await;
    let args = format!("import csv {}", fixture("csv/hosts.csv"));
    let (res, out) = run(&svc, &args, false, false).await;
    assert_eq!(res.map_err(|e| e.exit_code()), Err(2));
    assert!(
        out.contains("Import preview (csv)"),
        "the preview is printed: {out}"
    );
    // On a terminal, "n" cancels.
    let (res, _) = run(&svc, &args, true, false).await;
    assert_eq!(res, Ok(1));
    let (res, out) = run(&svc, &args, true, true).await;
    assert_eq!(res, Ok(0), "{out}");
}

#[tokio::test]
async fn unknown_group_and_vault() {
    let (svc, _home) = svc("target").await;
    let args = format!("import csv {} --group Nope --yes", fixture("csv/hosts.csv"));
    let (res, _) = run(&svc, &args, false, false).await;
    assert_eq!(res.map_err(|e| e.exit_code()), Err(4));
    let args = format!("import csv {} --vault Nope --yes", fixture("csv/hosts.csv"));
    let (res, _) = run(&svc, &args, false, false).await;
    assert_eq!(res.map_err(|e| e.exit_code()), Err(4));
    // An existing group (created by the first import) is a valid target.
    let (res, _) = run(
        &svc,
        &format!("import csv {} --yes", fixture("csv/hosts.csv")),
        false,
        false,
    )
    .await;
    assert_eq!(res, Ok(0));
    let args = format!(
        "import ssh-config {} --group prod/web --vault personal --yes",
        fixture("ssh_config/basic")
    );
    let (res, out) = run(&svc, &args, false, false).await;
    assert_eq!(res, Ok(0), "{out}");
}

#[tokio::test]
async fn backup_needs_a_password_without_a_terminal() {
    let (svc, _home) = svc("bk").await;
    let (res, _) = run(
        &svc,
        "import backup /nonexistent.sverb-backup --dry-run",
        false,
        false,
    )
    .await;
    assert_eq!(res.map_err(|e| e.exit_code()), Err(2));
}

// M7-03 T-08: `sverb import putty <dir> --dry-run` prints the preview; nothing is written.
#[tokio::test]
async fn t08_putty_dry_run_prints_the_preview() {
    let (svc, _home) = svc("putty").await;
    let dir = fixture("putty/sessions");
    let args = format!("import putty {dir} --dry-run");
    assert_eq!(
        parse(&args).source,
        ImportSource::Putty {
            path: Some(PathBuf::from(&dir))
        }
    );
    let (res, out) = run(&svc, &args, false, false).await;
    assert_eq!(res, Ok(0), "{out}");
    assert!(
        out.starts_with("Import preview (putty): 9 new, 0 duplicate, 0 conflict, 7 skipped"),
        "{out}"
    );
    for needle in [
        "prod web",
        "proxy=socks5://jump@bastion.example.com:1080",
        "non-SSH protocol not supported (telnet)",
        "SOCKS4 proxy not supported",
        "prod web D1080",
        "Identity files (imported as keys only when confirmed):",
        "/nonexistent/putty/prod.ppk (cannot read",
    ] {
        assert!(out.contains(needle), "{needle}: {out}");
    }
    assert!(!out.contains("hunter2"));
    // Still all new: the dry run wrote nothing.
    let (_, again) = run(&svc, &args, false, false).await;
    assert!(again.contains("9 new"), "{again}");
    // Importing for real, then again: duplicates only.
    let args = format!("import putty {dir} --yes");
    let (res, out) = run(&svc, &args, false, false).await;
    assert_eq!(res, Ok(0), "{out}");
    assert!(out.contains("Imported 9 new"), "{out}");
    let (_, out) = run(&svc, &args, false, false).await;
    assert!(out.contains("0 new, 0 updated, 9 duplicate"), "{out}");
}
