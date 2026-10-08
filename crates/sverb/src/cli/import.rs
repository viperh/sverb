//! `sverb import …` (SPEC §9.13, §16). M2-11 implements ssh-config, known-hosts, csv
//! and backup; M7-03 adds `putty` (`~/.putty/sessions`, the registry on Windows, or a
//! sessions directory).
//!
//! Every import is a dry run first: the preview table (new / duplicate / conflict,
//! skipped entries, warnings) is printed on stdout. Then:
//! - `--dry-run`: stop (exit 0);
//! - `--yes`: import;
//! - otherwise, on a terminal: ask `Import? [y/N]`; without a terminal: exit 2.
//!
//! IdentityFiles of an ssh_config (PuTTY: `PublicKeyFile`, `.ppk` included) are listed and imported as keys only after their
//! own confirmation (`--identity-files`, or `y` on a terminal); encrypted non-OpenSSH
//! files ask for their passphrase on a terminal, else they are skipped.
//!
//! A backup's export password is asked on the terminal, or read from the environment
//! variable `SVERB_EXPORT_PASSWORD` (scripts).

use std::collections::BTreeMap;
use std::io::{BufRead as _, Write};
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Args, Subcommand, ValueEnum};
use sverb_core::error_report::ErrorReport;
use sverb_core::importers::ConflictPolicy;
use sverb_core::model::{ItemId, VaultId};
use sverb_core::secret::SecretString;
use sverb_tui::services::import::{
    IdentityFileState, ImportFailure, ImportService, KeyChoice, SourceSpec,
};
use zeroize::Zeroizing;

use super::{CliError, Ctx, write_out};

/// The environment variable a script can pass a backup's export password in.
pub(crate) const PASSWORD_ENV: &str = "SVERB_EXPORT_PASSWORD";

/// `sverb import <source> [--dry-run] [--vault V] [--group G] [--on-conflict P] [--yes]`
#[derive(Args, Debug, PartialEq, Eq)]
pub(crate) struct ImportArgs {
    /// Show what would be imported without changing anything
    #[arg(long, global = true)]
    pub dry_run: bool,
    // M2-11
    /// Vault to import into (default: Personal)
    #[arg(long, global = true, value_name = "VAULT")]
    pub vault: Option<String>,
    /// Group to import into (a name or a path like a/b; default: the top level)
    #[arg(long, global = true, value_name = "GROUP")]
    pub group: Option<String>,
    /// What to do with items that already exist with other values
    #[arg(long, global = true, value_enum, default_value_t = OnConflict::Skip)]
    pub on_conflict: OnConflict,
    /// Import without asking (required without a terminal)
    #[arg(long, short = 'y', global = true)]
    pub yes: bool,
    /// Also import the IdentityFiles of an ssh_config as keys
    #[arg(long, global = true)]
    pub identity_files: bool,
    #[command(subcommand)]
    pub source: ImportSource,
}

// M2-11
/// `--on-conflict`
#[derive(ValueEnum, Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum OnConflict {
    /// Keep the existing item
    #[default]
    Skip,
    /// Write the imported values over it (backups: merge by timestamp)
    Overwrite,
    /// Import it next to the existing one
    KeepBoth,
}

impl From<OnConflict> for ConflictPolicy {
    fn from(o: OnConflict) -> Self {
        match o {
            OnConflict::Skip => Self::Skip,
            OnConflict::Overwrite => Self::Overwrite,
            OnConflict::KeepBoth => Self::KeepBoth,
        }
    }
}

/// What to import.
#[derive(Subcommand, Debug, PartialEq, Eq)]
pub(crate) enum ImportSource {
    /// Hosts from an OpenSSH config (default ~/.ssh/config)
    SshConfig {
        /// Path to the config file
        path: Option<PathBuf>,
    },
    /// Host keys from a known_hosts file (default ~/.ssh/known_hosts)
    KnownHosts {
        /// Path to the known_hosts file
        path: Option<PathBuf>,
    },
    /// Sessions from PuTTY (default ~/.putty/sessions; the registry on Windows)
    Putty {
        /// A PuTTY sessions directory (one file per session)
        path: Option<PathBuf>,
    },
    /// Hosts from a CSV file (label,address,port,username,group,tags; tags split on ; or |)
    Csv {
        /// CSV file
        file: PathBuf,
    },
    /// A sverb backup
    Backup {
        /// Backup file
        file: PathBuf,
    },
}

/// Terminal I/O of an import (injectable for tests).
pub(crate) struct ImportIo<'a> {
    /// stdin and stderr are terminals.
    pub tty: bool,
    /// Ask y/N (the question is already printed).
    pub read_yes: &'a mut dyn FnMut() -> bool,
    /// Ask for a secret.
    pub read_secret: &'a mut dyn FnMut(&str) -> Option<Zeroizing<String>>,
    /// The backup password from the environment.
    pub env_password: Option<Zeroizing<String>>,
}

pub(crate) async fn run(args: ImportArgs, ctx: &Ctx, out: &mut dyn Write) -> Result<u8, CliError> {
    let unlocked = super::vault::require_unlocked(ctx).await?;
    let svc = ImportService::new(unlocked.engine, Arc::new(unlocked.vault));
    let mut yes = read_yes;
    let mut secret = |p: &str| super::vault::read_secret(p).ok();
    let mut io = ImportIo {
        tty: ctx.tty.stdin && ctx.tty.stderr,
        read_yes: &mut yes,
        read_secret: &mut secret,
        env_password: std::env::var(PASSWORD_ENV).ok().map(Zeroizing::new),
    };
    run_with(args, &svc, &mut io, out).await
}

/// `y`/`yes` on stdin.
fn read_yes() -> bool {
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).is_ok()
        && matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
}

fn failure(e: ImportFailure) -> CliError {
    CliError::Failure(ErrorReport::msg(e.0))
}

/// `--vault`: a display name (`Personal`, `Shared 0190a5f2`), an id or its prefix.
async fn resolve_vault(
    svc: &ImportService,
    arg: Option<&str>,
) -> Result<Option<VaultId>, CliError> {
    let Some(arg) = arg else {
        return Ok(None);
    };
    let vaults = svc.vaults().await.map_err(failure)?;
    let lower = arg.to_lowercase();
    vaults
        .iter()
        .find(|(id, name, _)| {
            name.to_lowercase() == lower || id.to_string() == lower || id.short() == lower
        })
        .map(|(id, _, _)| Some(*id))
        .ok_or_else(|| {
            let names: Vec<&str> = vaults.iter().map(|(_, n, _)| n.as_str()).collect();
            CliError::NotFound(format!("no vault {arg:?} (vaults: {})", names.join(", ")))
        })
}

/// `--group`: a path `a/b` (case-insensitive) or a unique group name.
async fn resolve_group(
    svc: &ImportService,
    vault: Option<VaultId>,
    arg: Option<&str>,
) -> Result<Option<ItemId>, CliError> {
    let Some(arg) = arg else {
        return Ok(None);
    };
    let Some(vault) = vault.or_else(|| svc.default_vault()) else {
        return Err(CliError::VaultLocked);
    };
    let groups = svc.group_paths(vault).await.map_err(failure)?;
    let want = arg.trim_matches('/').to_lowercase();
    if let Some((id, _)) = groups.iter().find(|(_, p)| p.to_lowercase() == want) {
        return Ok(Some(*id));
    }
    let by_name: Vec<&(ItemId, String)> = groups
        .iter()
        .filter(|(_, p)| {
            p.rsplit('/')
                .next()
                .is_some_and(|n| n.to_lowercase() == want)
        })
        .collect();
    match by_name.as_slice() {
        [(id, _)] => Ok(Some(*id)),
        [] => Err(CliError::NotFound(format!(
            "no group {arg:?}; create it first (sverb hosts add --group {arg} --create-group …) or omit --group"
        ))),
        _ => Err(CliError::Usage(format!(
            "group {arg:?} is ambiguous; give its path ({})",
            by_name
                .iter()
                .map(|(_, p)| p.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

fn spec(source: ImportSource, io: &mut ImportIo<'_>) -> Result<SourceSpec, CliError> {
    Ok(match source {
        ImportSource::SshConfig { path } => SourceSpec::SshConfig(path),
        ImportSource::KnownHosts { path } => SourceSpec::KnownHosts(path),
        ImportSource::Csv { file } => SourceSpec::Csv(file),
        ImportSource::Backup { file } => {
            let password = match io.env_password.take() {
                Some(p) => p,
                None if io.tty => (io.read_secret)("Backup export password: ")
                    .ok_or_else(|| CliError::Usage("cancelled".to_owned()))?,
                None => {
                    return Err(CliError::Usage(format!(
                        "the backup's export password is needed: run on a terminal or set {PASSWORD_ENV}"
                    )));
                }
            };
            SourceSpec::Backup {
                path: file,
                password: SecretString::from(password.as_str()),
            }
        }
        // M7-03
        ImportSource::Putty { path } => SourceSpec::Putty(path),
    })
}

/// The import with injectable terminal I/O.
pub(crate) async fn run_with(
    args: ImportArgs,
    svc: &ImportService,
    io: &mut ImportIo<'_>,
    out: &mut dyn Write,
) -> Result<u8, CliError> {
    let ImportArgs {
        dry_run,
        vault,
        group,
        on_conflict,
        yes,
        identity_files,
        source,
    } = args;
    let spec = spec(source, io)?;
    let vault = resolve_vault(svc, vault.as_deref()).await?;
    let group = resolve_group(svc, vault, group.as_deref()).await?;
    let plan = svc.preview(&spec, vault, group).await.map_err(failure)?;
    write_out(out, &plan.render_table())?;
    let files = svc.identity_files(&plan);
    if !files.is_empty() {
        let mut list = String::from("Identity files (imported as keys only when confirmed):\n");
        for f in &files {
            let state = match &f.state {
                IdentityFileState::Ready => String::new(),
                IdentityFileState::NeedsPassphrase => " (encrypted)".to_owned(),
                IdentityFileState::Unreadable(e) => format!(" (cannot read: {e})"),
            };
            list.push_str(&format!("  {}{state}\n", f.path));
        }
        write_out(out, &list)?;
    }
    if dry_run {
        return Ok(super::exit::OK);
    }
    let counts = plan.counts();
    if !yes {
        if !io.tty {
            return Err(CliError::Usage(
                "nothing imported: pass --yes to import (or --dry-run to only preview)".to_owned(),
            ));
        }
        eprint!(
            "Import {} new items ({} conflicts: {})? [y/N] ",
            counts.new,
            counts.conflict,
            ConflictPolicy::from(on_conflict).as_str()
        );
        let _ = std::io::stderr().flush();
        if !(io.read_yes)() {
            eprintln!("Cancelled.");
            return Ok(super::exit::FAILURE);
        }
    }
    let importable = files
        .iter()
        .any(|f| !matches!(f.state, IdentityFileState::Unreadable(_)));
    let mut keys = KeyChoice::default();
    if importable {
        keys.import = identity_files
            || (io.tty && !yes && {
                eprint!("Import the identity files listed above as keys? [y/N] ");
                let _ = std::io::stderr().flush();
                (io.read_yes)()
            });
        if keys.import && io.tty {
            let mut passphrases = BTreeMap::new();
            for f in files
                .iter()
                .filter(|f| f.state == IdentityFileState::NeedsPassphrase)
            {
                if let Some(p) =
                    (io.read_secret)(&format!("Passphrase for {} (empty: skip): ", f.path))
                    && !p.is_empty()
                {
                    passphrases.insert(f.path.clone(), SecretString::from(p.as_str()));
                }
            }
            keys.passphrases = passphrases;
        }
    }
    let report = svc
        .apply(plan, vault, group, on_conflict.into(), keys, None)
        .await
        .map_err(failure)?;
    let mut text = format!("{}\n", report.summary());
    for (path, why) in &report.keys_skipped {
        text.push_str(&format!("  identity file {path} skipped: {why}\n"));
    }
    for a in &report.approvals {
        text.push_str(&format!(
            "  approved on this device: {} = {}\n",
            a.field, a.value
        ));
    }
    write_out(out, &text)?;
    Ok(super::exit::OK)
}

#[cfg(test)]
#[path = "import_tests.rs"]
mod tests;
