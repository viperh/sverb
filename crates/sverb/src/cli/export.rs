//! M0-07: `sverb export …`. M2-11 implements backup, ssh-config and csv; M3-05
//! implements `recording`.
//!
//! M2-11: files are written with mode 0600 and an existing file is replaced only with
//! `--force`. `ssh-config` and `csv` print the secrets warning first. The backup's
//! export password (zxcvbn score ≥ 3) is asked twice on a terminal, or read from
//! `SVERB_EXPORT_PASSWORD`.

use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use clap::Subcommand;
use sverb_core::error_report::ErrorReport;
use sverb_tui::services::recording::{export_recording, recording_key, resolve_recording};

use super::{CliError, Ctx, write_out};
// M2-11
use std::sync::Arc;
use sverb_tui::services::import::{BackupKdf, ImportService};
use zeroize::Zeroizing;

/// `sverb export …`
#[derive(Subcommand, Debug, PartialEq, Eq)]
pub(crate) enum ExportCmd {
    /// Write an encrypted backup of the vault
    Backup {
        /// Output file
        file: PathBuf,
        // M2-11
        /// Replace an existing file
        #[arg(long)]
        force: bool,
        /// Also include shared vaults (they belong to their organization)
        #[arg(long)]
        include_shared: bool,
    },
    /// Write hosts as an OpenSSH config (no secrets)
    SshConfig {
        /// Output file
        file: PathBuf,
        // M2-11
        /// Replace an existing file
        #[arg(long)]
        force: bool,
    },
    /// Write hosts as CSV (no secrets)
    Csv {
        /// Output file
        file: PathBuf,
        // M2-11
        /// Replace an existing file
        #[arg(long)]
        force: bool,
    },
    /// Export a session recording as asciicast
    Recording {
        /// Recording id (connection id, or the `.cast.sv` file name or path)
        id: String,
        /// Output `.cast` file
        out: PathBuf,
        // M3-05
        /// Skip the plain-text confirmation (required without a terminal)
        #[arg(long)]
        yes: bool,
    },
}

pub(crate) async fn run(cmd: ExportCmd, ctx: &Ctx, out: &mut dyn Write) -> Result<u8, CliError> {
    match cmd {
        // M2-11
        ExportCmd::Backup {
            file,
            force,
            include_shared,
        } => backup(&file, force, include_shared, ctx, out).await,
        ExportCmd::SshConfig { file, force } => plain(&file, force, false, ctx, out).await,
        ExportCmd::Csv { file, force } => plain(&file, force, true, ctx, out).await,
        // M3-05
        ExportCmd::Recording { id, out: file, yes } => recording(&id, &file, yes, ctx, out).await,
    }
}

// M2-11
async fn service(ctx: &Ctx) -> Result<ImportService, CliError> {
    let unlocked = super::vault::require_unlocked(ctx).await?;
    Ok(ImportService::new(
        unlocked.engine,
        Arc::new(unlocked.vault),
    ))
}

// M2-11
fn refuse_existing(file: &Path, force: bool) -> Result<(), CliError> {
    if !force && file.exists() {
        return Err(CliError::Usage(format!(
            "{} already exists; pass --force to replace it",
            file.display()
        )));
    }
    Ok(())
}

// M2-11
/// `sverb export ssh-config|csv <file> [--force]`
async fn plain(
    file: &Path,
    force: bool,
    csv: bool,
    ctx: &Ctx,
    out: &mut dyn Write,
) -> Result<u8, CliError> {
    refuse_existing(file, force)?;
    eprintln!("warning: {}", sverb_core::exporters::SECRETS_WARNING);
    let svc = service(ctx).await?;
    let n = if csv {
        svc.export_csv(file, force).await
    } else {
        svc.export_ssh_config(file, force).await
    }
    .map_err(|e| CliError::Failure(ErrorReport::msg(e.0)))?;
    write_out(out, &format!("Exported {n} hosts to {}\n", file.display()))?;
    Ok(super::exit::OK)
}

// M2-11
/// `sverb export backup <file> [--force] [--include-shared]`
async fn backup(
    file: &Path,
    force: bool,
    include_shared: bool,
    ctx: &Ctx,
    out: &mut dyn Write,
) -> Result<u8, CliError> {
    refuse_existing(file, force)?;
    let password = match std::env::var(super::import::PASSWORD_ENV).ok() {
        Some(p) => Zeroizing::new(p),
        None if ctx.tty.stdin && ctx.tty.stderr => {
            let a = super::vault::read_secret("Export password: ")
                .map_err(|e| CliError::failure(&e))?;
            let b = super::vault::read_secret("Repeat the export password: ")
                .map_err(|e| CliError::failure(&e))?;
            if a != b {
                return Err(CliError::Usage("the passwords do not match".to_owned()));
            }
            a
        }
        None => {
            return Err(CliError::Usage(format!(
                "an export password is needed: run on a terminal or set {}",
                super::import::PASSWORD_ENV
            )));
        }
    };
    if include_shared {
        eprintln!("warning: shared vaults belong to their organization; keep this backup safe");
    }
    let svc = service(ctx).await?;
    let n = svc
        .export_backup(
            file,
            sverb_core::secret::SecretString::from(password.as_str()),
            include_shared,
            force,
            BackupKdf::default(),
        )
        .await
        .map_err(|e| CliError::Failure(ErrorReport::msg(e.0)))?;
    write_out(out, &format!("Backed up {n} items to {}\n", file.display()))?;
    Ok(super::exit::OK)
}

// M3-05
/// The confirmation shown before writing a recording in plain text.
pub(crate) const PLAIN_TEXT_WARNING: &str = "This writes the terminal output in plain text. \
Recordings can contain secrets (anything that was displayed).";

// M3-05
/// `sverb export recording <id> <out.cast> [--yes]`: decrypt a recording into plain
/// asciicast v2 (for `asciinema play`). Without `--yes` it asks on the terminal, and
/// refuses when there is none.
async fn recording(
    id: &str,
    file: &Path,
    yes: bool,
    ctx: &Ctx,
    out: &mut dyn Write,
) -> Result<u8, CliError> {
    let dir = ctx.paths.recordings_dir();
    let Some(src) = resolve_recording(&dir, id) else {
        return Err(CliError::NotFound(format!(
            "no recording `{id}` in {}",
            dir.display()
        )));
    };
    if !yes {
        if !(ctx.tty.stdin && ctx.tty.stderr) {
            return Err(CliError::Usage(format!(
                "{PLAIN_TEXT_WARNING} Pass --yes to confirm (no terminal to ask on)"
            )));
        }
        if !confirm(file)? {
            eprintln!("Cancelled.");
            return Ok(super::exit::FAILURE);
        }
    }
    let unlocked = super::vault::require_unlocked(ctx).await?;
    let key = recording_key(&unlocked.vault);
    drop(unlocked);

    let file_owned = file.to_path_buf();
    let incomplete = tokio::task::spawn_blocking(move || export_recording(&src, &file_owned, key))
        .await
        .map_err(|e| CliError::failure(&e))?
        .map_err(|e| CliError::Failure(ErrorReport::from_error(&e)))?;
    if incomplete {
        eprintln!("warning: recording incomplete (truncated); exported up to the last valid chunk");
    }
    write_out(out, &format!("Wrote {}\n", file.display()))?;
    Ok(super::exit::OK)
}

/// Ask `Continue? [y/N]` on stderr, read the answer from stdin.
fn confirm(file: &Path) -> Result<bool, CliError> {
    eprint!("{PLAIN_TEXT_WARNING}\nWrite {}? [y/N] ", file.display());
    let _ = io::stderr().flush();
    let mut answer = String::new();
    io::stdin()
        .lock()
        .read_line(&mut answer)
        .map_err(|e| CliError::failure(&e))?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "Yes" | "YES"))
}
