//! M0-07: the command line (SPEC §16).
//!
//! [`Cli`] is the clap tree; [`dispatch`] runs a parsed command and returns the exit
//! code. One module per command group holds its arguments and body. Bodies whose
//! feature task has not landed return [`CliError::NotImplemented`] naming that task.
//!
//! Conventions (see `tasks/M0-07-cli-surface.md` §2.3):
//! - exit codes are the constants in [`exit`], listed in `sverb --help`,
//! - errors print as `error: …` / `  caused by: …` ([`sverb_core::error_report`]),
//! - `--json` output is wrapped as `{"version":1,"data":…}` ([`output`], `docs/cli-json.md`),
//! - headless commands never touch terminal modes and never read a non-TTY stdin
//!   ([`vault::require_unlocked`]),
//! - `<host>` arguments resolve through [`sverb_core::resolve_host_arg`].

pub(crate) mod account;
pub(crate) mod agent;
pub(crate) mod approve;
pub(crate) mod config;
pub(crate) mod devices;
pub(crate) mod doctor;
pub(crate) mod exit;
pub(crate) mod export;
pub(crate) mod forward;
pub(crate) mod hosts;
pub(crate) mod import;
pub(crate) mod keys;
pub(crate) mod output;
pub(crate) mod snippet;
pub(crate) mod team;
pub(crate) mod vault;

#[cfg(test)]
mod tests;

#[cfg(not(feature = "sync"))]
use std::ffi::OsString;
use std::io::{IsTerminal, Write};

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand, error::ErrorKind};
use sverb_core::{
    config::{Config, Validators},
    paths::{DirKind, Paths},
};
use sverb_tui::{LaunchCtx, LaunchIntent, keymap::Keymap};

pub(crate) use exit::CliError;

/// `sverb`: an SSH client for the terminal.
#[derive(Parser, Debug, PartialEq, Eq)]
#[command(
    name = "sverb",
    author,
    version,
    about,
    after_long_help = exit::HELP
)]
pub(crate) struct Cli {
    // M0-04
    /// Log at debug level and keep recent log lines for the log pane
    /// (log files may then contain hostnames)
    #[arg(long, global = true)]
    pub debug: bool,

    /// Launch the TUI and open this workspace
    #[arg(long, value_name = "NAME")]
    pub workspace: Option<String>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

/// The subcommands. With no subcommand, `sverb` launches the TUI.
#[derive(Subcommand, Debug, PartialEq, Eq)]
pub(crate) enum Command {
    /// Launch the TUI with a session open (fuzzy host match or user@host:port)
    Connect {
        /// A host label, address or fuzzy match, or `user@host:port`
        target: String,
    },
    /// Join a shared terminal
    #[cfg(feature = "sync")]
    Join {
        /// The share link
        link: String,
    },
    /// List, add and remove hosts
    #[command(subcommand)]
    Hosts(hosts::HostsCmd),
    /// Manage SSH keys, or print the effective keymap with --dump
    Keys(keys::KeysArgs),
    /// Print the effective keymap (alias of `sverb keys --dump`)
    #[command(hide = true)]
    Keymap(keys::KeymapArgs),
    /// Run a port-forward rule headless
    Forward(forward::ForwardArgs),
    /// Run snippets on hosts
    #[command(subcommand)]
    Snippet(snippet::SnippetCmd),
    /// Import hosts, keys and settings
    Import(import::ImportArgs),
    /// Export hosts, backups and recordings
    #[command(subcommand)]
    Export(export::ExportCmd),
    /// Review and approve locally-acting fields from sync
    Approve(approve::ApproveArgs),
    /// Run the built-in agent exposing forwardable vault keys
    Agent(agent::AgentArgs),
    /// Lock the vault
    Lock,
    /// Unlock the vault
    Unlock,
    /// Log in to a sync server
    #[cfg(feature = "sync")]
    Login(account::LoginArgs),
    /// Log out of the sync server
    #[cfg(feature = "sync")]
    Logout(account::LogoutArgs),
    /// Create an account on a sync server
    #[cfg(feature = "sync")]
    Register(account::RegisterArgs),
    /// Sync now or show the sync status
    #[cfg(feature = "sync")]
    Sync(account::SyncArgs),
    /// List or revoke devices
    #[cfg(feature = "sync")]
    #[command(subcommand)]
    Devices(devices::DevicesCmd),
    /// Manage the team vault
    #[cfg(feature = "sync")]
    #[command(subcommand)]
    Team(team::TeamCmd),
    /// Check, print or locate config.toml
    Config(config::ConfigArgs),
    /// Diagnose terminal capabilities, agent and sync; list SSH algorithms
    Doctor(doctor::DoctorArgs),
    /// Sync-only commands in a local-only build (and unknown commands).
    #[cfg(not(feature = "sync"))]
    #[command(external_subcommand)]
    External(Vec<OsString>),
}

/// Command names that exist only with the `sync` feature.
#[cfg_attr(feature = "sync", allow(dead_code))] // used by tests in sync builds
pub(crate) const SYNC_COMMANDS: &[&str] = &[
    "join", "login", "logout", "register", "sync", "devices", "team",
];

/// Enabled cargo features, for `--version`.
pub(crate) const FEATURES: &str = if cfg!(feature = "sync") {
    "sync"
} else {
    "none"
};

impl Cli {
    // M0-03: parse argv with a `--version` text that lists the resolved paths.
    /// Parse `std::env::args`, exiting with clap's message (code 2) on bad input.
    pub(crate) fn parse_with(paths: &Paths) -> Self {
        Self::try_parse_with(paths, std::env::args_os()).unwrap_or_else(|e| e.exit())
    }

    /// Parse `args` (including the binary name).
    pub(crate) fn try_parse_with<I, T>(paths: &Paths, args: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        let mut cmd = Self::command().version(version(paths));
        let matches = cmd.try_get_matches_from_mut(args)?;
        let cli = Self::from_arg_matches(&matches).map_err(|e| e.format(&mut cmd))?;
        if cli.workspace.is_some() && cli.command.is_some() {
            return Err(cmd.error(
                ErrorKind::ArgumentConflict,
                "--workspace only applies when launching the TUI without a subcommand",
            ));
        }
        Ok(cli)
    }

    /// Whether this invocation runs without the TUI (logging uses this, M0-04).
    pub(crate) fn is_headless(&self) -> bool {
        match &self.command {
            None | Some(Command::Connect { .. }) => false,
            #[cfg(feature = "sync")]
            Some(Command::Join { .. }) => false,
            Some(_) => true,
        }
    }
}

const VERSION_MESSAGE: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "-",
    env!("VERGEN_GIT_DESCRIBE"),
    " (",
    env!("VERGEN_BUILD_DATE"),
    ")"
);

// M0-03: prints all four roots and whether SVERB_HOME is in effect.
/// The `--version` text: version, git describe, build date, features and paths.
pub(crate) fn version(paths: &Paths) -> String {
    let author = clap::crate_authors!();
    let dirs = paths.describe();

    format!(
        "\
{VERSION_MESSAGE} features: {FEATURES}

Authors: {author}

{dirs}"
    )
}

/// Which standard streams are terminals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tty {
    pub stdin: bool,
    pub stdout: bool,
    pub stderr: bool,
}

impl Tty {
    /// The real streams.
    pub(crate) fn detect() -> Self {
        Self {
            stdin: std::io::stdin().is_terminal(),
            stdout: std::io::stdout().is_terminal(),
            stderr: std::io::stderr().is_terminal(),
        }
    }
}

/// What every command may need. Built once in `main`.
#[derive(Debug)]
pub(crate) struct Ctx {
    pub paths: Paths,
    /// The config loaded at startup (defaults if the file was rejected).
    pub config: Config,
    /// Validators for config.toml (stubs until M0-10/M0-11).
    pub validators: Validators,
    pub tty: Tty,
}

/// Run `cli` and print any error. Returns the process exit code.
pub(crate) async fn dispatch(cli: Cli, ctx: &Ctx, out: &mut dyn Write) -> u8 {
    match run(cli, ctx, out).await {
        Ok(code) => code,
        Err(err) => {
            tracing::debug!(code = err.exit_code(), "command failed");
            eprintln!("{}", err.report());
            err.exit_code()
        }
    }
}

/// Run `cli`; `Ok` carries the exit code (non-zero only when the TUI asks for it).
pub(crate) async fn run(cli: Cli, ctx: &Ctx, out: &mut dyn Write) -> Result<u8, CliError> {
    let Some(command) = cli.command else {
        let intent = match cli.workspace {
            Some(name) => LaunchIntent::Workspace(name),
            None => LaunchIntent::Plain,
        };
        return launch_tui(intent, ctx).await;
    };
    match command {
        Command::Connect { target } => launch_tui(LaunchIntent::Connect(target), ctx).await,
        #[cfg(feature = "sync")]
        Command::Join { link } => launch_tui(LaunchIntent::Join(link), ctx).await,
        // M1-07: unlocks the vault (async).
        Command::Hosts(cmd) => hosts::run(cmd, ctx, out).await,
        // M2-03: `keys list | generate | import | export` unlock the vault (async).
        Command::Keys(args) => keys::run(args, ctx, out).await,
        Command::Keymap(args) => keys::run_dump(args.json, ctx, out),
        // M2-08: unlocks the vault and runs the tunnel (async).
        Command::Forward(args) => forward::run(args, ctx, out).await,
        // M2-09: unlocks the vault and runs on the hosts (async).
        Command::Snippet(cmd) => snippet::run(cmd, ctx, out).await,
        // M2-11: imports unlock the vault (async).
        Command::Import(args) => import::run(args, ctx, out).await,
        // M3-05: `export recording` unlocks the vault (async).
        Command::Export(cmd) => export::run(cmd, ctx, out).await,
        // M2-10: unlocks the vault and asks on the TTY (async).
        Command::Approve(args) => {
            let opts = approve::ApproveOptions {
                all: args.all,
                yes: args.yes,
            };
            approve::run_async(&args.host, opts, ctx, out).await
        }
        // M2-07: serves until Ctrl-C; `lock` reaches the TUI's control socket (async).
        Command::Agent(args) => agent::run(args, ctx, out).await,
        Command::Lock => vault::lock(ctx).await,
        // M1-04
        Command::Unlock => vault::unlock(ctx).await,
        #[cfg(feature = "sync")]
        // M4-08: the account flows (async, TTY prompts).
        Command::Login(args) => account::login(args, ctx).await,
        #[cfg(feature = "sync")]
        Command::Logout(args) => account::logout(args, ctx).await,
        #[cfg(feature = "sync")]
        Command::Register(args) => account::register(args, ctx).await,
        #[cfg(feature = "sync")]
        // M4-07: one headless engine cycle (async).
        Command::Sync(args) => account::sync(args, ctx, out).await,
        #[cfg(feature = "sync")]
        Command::Devices(cmd) => devices::run(cmd, ctx, out),
        #[cfg(feature = "sync")]
        // M5-03: `team verify` opens the store (async).
        Command::Team(cmd) => team::run_async(cmd, ctx, out).await,
        Command::Config(args) => config::run(args, ctx, out),
        Command::Doctor(args) => doctor::run(args, ctx, out),
        #[cfg(not(feature = "sync"))]
        Command::External(args) => external(&args),
    }
}

// M0-07: local-only builds catch the sync command names here (T-04).
#[cfg(not(feature = "sync"))]
fn external(args: &[OsString]) -> Result<u8, CliError> {
    let name = args
        .first()
        .map(|a| a.to_string_lossy().into_owned())
        .unwrap_or_default();
    if SYNC_COMMANDS.contains(&name.as_str()) {
        return Err(CliError::NoSync { command: name });
    }
    Err(CliError::Usage(format!(
        "unrecognized subcommand '{name}' (see `sverb --help`)"
    )))
}

/// `sverb`, `connect`, `--workspace`, `join`: hand over to the TUI.
async fn launch_tui(intent: LaunchIntent, ctx: &Ctx) -> Result<u8, CliError> {
    // Before touching the terminal: no escape bytes may reach a pipe or file (T-09).
    if !ctx.tty.stdout {
        return Err(CliError::NoTty);
    }
    // Best effort: the watcher needs the directory; without it there is no hot reload.
    if let Err(err) = ctx.paths.ensure(DirKind::Config) {
        tracing::warn!(%err, "cannot create the config directory");
    }
    let launch = LaunchCtx {
        config: ctx.config.clone(),
        // M0-10: built-ins merged with `general.leader` and `[keys.*]`.
        keymap: Keymap::from_config(&ctx.config),
        config_file: Some(ctx.paths.config_file()),
        validators: ctx.validators.clone(),
        // M1-04: the TUI opens the store and starts locked.
        paths: Some(ctx.paths.clone()),
    };
    let code = sverb_tui::run(intent, launch)
        .await
        .map_err(|e| CliError::failure(&e))?;
    Ok(u8::try_from(code).unwrap_or(exit::FAILURE))
}

/// Shorthand for a stub body.
pub(crate) fn not_implemented<T>(
    command: &'static str,
    milestone: &'static str,
) -> Result<T, CliError> {
    Err(CliError::NotImplemented { command, milestone })
}

/// Map a write error on stdout to a failure.
pub(crate) fn write_out(out: &mut dyn Write, text: &str) -> Result<(), CliError> {
    out.write_all(text.as_bytes())
        .and_then(|()| out.flush())
        .map_err(|e| CliError::failure(&e))
}
