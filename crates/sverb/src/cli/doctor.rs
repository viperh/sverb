//! `sverb doctor [--algos] [--json] [--ascii]` (SPEC §16, §6.1.8).
//!
//! A headless, read-only diagnosis in sections (environment, terminal, agent,
//! keyring, sync). Every line is marked `✓` ok, `·` info, `!` warning or `✗`
//! problem (`[ok]`/`[info]`/`[warn]`/`[fail]` with `--ascii` or a non-UTF-8 locale),
//! with a hint where something can be done. Exit code 0 without `✗`, 1 otherwise.
//!
//! The command works in three steps, so tests can inject every probe:
//! 1. [`gather`] collects [`Facts`] (the only step that looks at the system:
//!    files, sockets, the keyring, the terminal, the sync server),
//! 2. [`build_report`] turns them into a [`Report`] (pure),
//! 3. [`render_text`] / `--json` print it (pure).
//!
//! Terminal probes (kitty keyboard query, wide-character width) write escape
//! sequences, so they only run when stdout is a terminal; otherwise those lines say
//! "not a terminal" and nothing is written to the terminal.
//!
//! `--algos` prints the SSH algorithms this build offers instead
//! ([`sverb_conn::ssh::algorithms::supported`]).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use clap::Args;
use serde::Serialize;
use sverb_conn::agent_client::{AgentConnector, SystemAgent};
use sverb_conn::ssh::algorithms::{self, AlgoKind, SupportedAlgos};
use sverb_core::config::Config;
use sverb_core::paths::AgentEndpoint;
use sverb_core::vault::{Argon2Cost, KeyringStore};
use sverb_store::health::DbHealth;
use sverb_tui::runtime::capabilities::{Multiplexer, Osc52Guess, TermEnv, WIDE_PROBE_CHAR};
use sverb_tui::services::vault::{KEYRING_ENV, VaultEngine, keyring_from_env};

use super::output::write_json;
use super::{CliError, Ctx, exit, write_out};

#[cfg(test)]
#[path = "doctor_tests.rs"]
mod tests;

/// `sverb doctor …`
#[derive(Args, Debug, PartialEq, Eq)]
pub(crate) struct DoctorArgs {
    /// List the supported SSH algorithms
    #[arg(long)]
    pub algos: bool,
    /// Machine-readable output
    #[arg(long)]
    pub json: bool,
    // In `help` (not a doc comment), so rustdoc doesn't read `[ok]` as a link.
    #[arg(long, help = "Mark lines with [ok] [warn] [fail] instead of symbols")]
    pub ascii: bool,
}

/// How long one terminal answer, agent or keyring call may take.
const PROBE_TIMEOUT: Duration = Duration::from_millis(500);
const AGENT_TIMEOUT: Duration = Duration::from_secs(3);
const KEYRING_TIMEOUT: Duration = Duration::from_secs(5);

// ------------------------------------------------------------------ the report

/// A line's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Status {
    Ok,
    Info,
    Warn,
    Fail,
}

impl Status {
    fn mark(self, glyphs: bool) -> &'static str {
        match (self, glyphs) {
            (Self::Ok, true) => "✓",
            (Self::Info, true) => "·",
            (Self::Warn, true) => "!",
            (Self::Fail, true) => "✗",
            (Self::Ok, false) => "[ok]  ",
            (Self::Info, false) => "[info]",
            (Self::Warn, false) => "[warn]",
            (Self::Fail, false) => "[fail]",
        }
    }
}

/// One line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Check {
    pub id: String,
    pub status: Status,
    pub label: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

fn check(id: &str, status: Status, label: &str, detail: impl Into<String>) -> Check {
    Check {
        id: id.to_owned(),
        status,
        label: label.to_owned(),
        detail: detail.into(),
        hint: None,
    }
}

impl Check {
    fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
}

/// One section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Section {
    pub id: &'static str,
    pub title: &'static str,
    pub checks: Vec<Check>,
}

/// The whole report (`--json` data).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Report {
    /// No `fail` line.
    pub ok: bool,
    pub problems: usize,
    pub warnings: usize,
    pub sections: Vec<Section>,
}

impl Report {
    fn new(sections: Vec<Section>) -> Self {
        let count = |s: Status| {
            sections
                .iter()
                .flat_map(|sec| &sec.checks)
                .filter(|c| c.status == s)
                .count()
        };
        let problems = count(Status::Fail);
        let warnings = count(Status::Warn);
        Self {
            ok: problems == 0,
            problems,
            warnings,
            sections,
        }
    }

    pub(crate) fn exit_code(&self) -> u8 {
        if self.ok { exit::OK } else { exit::FAILURE }
    }
}

// ------------------------------------------------------------------- the facts

/// A directory or file sverb uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PathFact {
    pub label: &'static str,
    pub path: PathBuf,
    pub state: PathState,
    /// The expected mode (`0o700` for directories, `0o600` for the database).
    pub private_mode: u32,
}

/// What is at a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PathState {
    Missing,
    /// Exists; `Some(mode)` (permission bits) on unix.
    Exists(Option<u32>),
    /// Exists, but is the wrong kind (a file where a directory belongs, …).
    WrongKind,
    Error(String),
}

/// config.toml.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConfigFact {
    Missing,
    Valid { warnings: Vec<String> },
    Invalid { errors: Vec<String> },
}

/// The database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DbFact {
    Missing,
    Health(DbHealth),
    Error(String),
}

/// Environment facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EnvFacts {
    pub version: String,
    pub features: &'static str,
    pub os: &'static str,
    pub arch: &'static str,
    pub sverb_home: Option<PathBuf>,
    pub paths: Vec<PathFact>,
    pub config: ConfigFact,
    pub db: DbFact,
    /// The log directory is writable (`None`: it doesn't exist yet).
    pub log_writable: Option<bool>,
}

/// What the terminal answered (only asked when stdout is a terminal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TerminalAnswers {
    pub kitty: Result<bool, String>,
    /// Columns advanced for [`WIDE_PROBE_CHAR`]; `Ok(None)`: no report in time.
    pub wide_char_width: Result<Option<u16>, String>,
}

/// Terminal facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TermFacts {
    pub env: TermEnv,
    /// `None` when stdout is not a terminal (nothing was probed).
    pub answers: Option<TerminalAnswers>,
    /// `ui.mouse`.
    pub mouse: bool,
    /// `clipboard.osc52`.
    pub osc52: bool,
}

/// An agent's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AgentState {
    /// Not configured (`SSH_AUTH_SOCK` unset / no socket file).
    Absent,
    /// Answered with this many identities.
    Identities(usize),
    Error(String),
}

/// Agent facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentFacts {
    /// `SSH_AUTH_SOCK` (unix) or the pipe / Pageant (Windows).
    pub system_source: Option<String>,
    pub system: AgentState,
    /// The built-in agent's endpoint.
    pub builtin_endpoint: String,
    pub builtin: AgentState,
}

/// Keyring facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyringFacts {
    /// `SVERB_KEYRING=off`.
    pub disabled: bool,
    /// The probe entry could be written and deleted (`None`: not probed).
    pub available: Option<bool>,
    /// Keyring unlock is enabled for this database (`None`: no database).
    pub unlock_enabled: Option<bool>,
}

/// Sync facts.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // which variants are built depends on the `sync` feature
pub(crate) enum SyncFacts {
    /// A local-only build.
    NotCompiled,
    /// No database yet.
    NoDatabase,
    /// No server configured.
    LocalOnly,
    /// The database could not be read.
    Error(String),
    /// The server checks.
    Checked { server: String, checks: Vec<Check> },
}

/// Everything [`build_report`] needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Facts {
    pub env: EnvFacts,
    pub term: TermFacts,
    pub agent: AgentFacts,
    pub keyring: KeyringFacts,
    pub sync: SyncFacts,
}

// ------------------------------------------------------------- facts → report

fn mode_text(mode: u32) -> String {
    format!("{:04o}", mode & 0o7777)
}

/// The permission line for a path.
pub(crate) fn path_check(fact: &PathFact) -> Check {
    let id = format!("env.path.{}", fact.label.replace(' ', "_"));
    let shown = fact.path.display().to_string();
    match &fact.state {
        PathState::Missing => check(
            &id,
            Status::Info,
            fact.label,
            format!("{shown} (not created yet)"),
        ),
        PathState::WrongKind => check(
            &id,
            Status::Fail,
            fact.label,
            format!("{shown} is not the expected kind of file"),
        )
        .hint("move it away; sverb recreates it"),
        PathState::Error(e) => check(&id, Status::Fail, fact.label, format!("{shown}: {e}")),
        PathState::Exists(None) => check(&id, Status::Ok, fact.label, shown),
        PathState::Exists(Some(mode)) if mode & 0o077 == 0 => check(
            &id,
            Status::Ok,
            fact.label,
            format!("{shown} ({})", mode_text(*mode)),
        ),
        PathState::Exists(Some(mode)) => check(
            &id,
            Status::Warn,
            fact.label,
            format!(
                "{shown} is {} (expected {})",
                mode_text(*mode),
                mode_text(fact.private_mode)
            ),
        )
        .hint(format!(
            "chmod {:o} {}",
            fact.private_mode,
            shell_quote(&shown)
        )),
    }
}

fn shell_quote(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || "/._-~+,:@".contains(c))
    {
        s.to_owned()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

fn env_section(f: &EnvFacts) -> Section {
    let mut checks = vec![
        check(
            "env.version",
            Status::Info,
            "version",
            format!("sverb {} (features: {})", f.version, f.features),
        ),
        check(
            "env.platform",
            Status::Info,
            "platform",
            format!("{} {}", f.os, f.arch),
        ),
        check(
            "env.sverb_home",
            Status::Info,
            "SVERB_HOME",
            f.sverb_home
                .as_ref()
                .map_or_else(|| "not set".to_owned(), |p| p.display().to_string()),
        ),
    ];
    checks.extend(f.paths.iter().map(path_check));
    checks.push(match &f.config {
        ConfigFact::Missing => check(
            "env.config",
            Status::Ok,
            "config",
            "no config.toml; the defaults are in effect",
        ),
        ConfigFact::Valid { warnings } if warnings.is_empty() => {
            check("env.config", Status::Ok, "config", "config.toml is valid")
        }
        ConfigFact::Valid { warnings } => check(
            "env.config",
            Status::Warn,
            "config",
            format!(
                "config.toml is valid with {} warning(s): {}",
                warnings.len(),
                warnings[0]
            ),
        )
        .hint("see `sverb config --check`"),
        ConfigFact::Invalid { errors } => check(
            "env.config",
            Status::Fail,
            "config",
            format!(
                "config.toml has {} error(s); the defaults are in effect: {}",
                errors.len(),
                errors.first().map_or("", String::as_str)
            ),
        )
        .hint("see `sverb config --check`"),
    });
    checks.push(match &f.db {
        DbFact::Missing => check(
            "env.database",
            Status::Info,
            "database",
            "not created yet (run `sverb` once to set a master password)",
        ),
        DbFact::Error(e) => check("env.database", Status::Fail, "database", e.clone())
            .hint("restore sverb.db from a backup, or move it away to start fresh"),
        DbFact::Health(h) if h.is_newer() => check(
            "env.database",
            Status::Fail,
            "database",
            format!(
                "schema {} is newer than this sverb ({})",
                h.schema_version, h.supported_version
            ),
        )
        .hint("update sverb"),
        DbFact::Health(h) if !h.is_intact() => check(
            "env.database",
            Status::Fail,
            "database",
            format!("integrity check failed: {}", h.problems.join("; ")),
        )
        .hint("restore sverb.db from a backup (`sverb import backup`)"),
        DbFact::Health(h) if h.needs_migration() => check(
            "env.database",
            Status::Info,
            "database",
            format!(
                "schema {} (migrates to {} on the next start), integrity ok",
                h.schema_version, h.supported_version
            ),
        ),
        DbFact::Health(h) => check(
            "env.database",
            Status::Ok,
            "database",
            format!("schema {}, integrity ok", h.schema_version),
        ),
    });
    checks.push(match f.log_writable {
        None => check(
            "env.logs",
            Status::Info,
            "logs",
            "the log directory does not exist yet",
        ),
        Some(true) => check(
            "env.logs",
            Status::Ok,
            "logs",
            "the log directory is writable",
        ),
        Some(false) => check(
            "env.logs",
            Status::Fail,
            "logs",
            "the log directory is not writable",
        )
        .hint("fix the permissions of the state directory"),
    });
    Section {
        id: "environment",
        title: "Environment",
        checks,
    }
}

fn term_section(f: &TermFacts) -> Section {
    let env = &f.env;
    let not_tty = "skipped: not a terminal";
    let mut checks = Vec::new();
    checks.push(match env.term.as_deref() {
        None => check("term.term", Status::Warn, "TERM", "not set")
            .hint("run sverb from a terminal emulator"),
        Some("dumb") => check("term.term", Status::Warn, "TERM", "dumb")
            .hint("the TUI needs a full-featured terminal"),
        Some(t) => check("term.term", Status::Ok, "TERM", t),
    });
    let colorterm = env.colorterm.as_deref().unwrap_or("unset");
    checks.push(if env.no_color {
        check(
            "term.colors",
            Status::Info,
            "colors",
            "NO_COLOR is set: monochrome UI",
        )
    } else if env.truecolor() {
        check(
            "term.colors",
            Status::Ok,
            "colors",
            format!("truecolor (COLORTERM={colorterm})"),
        )
    } else if env.colors_256() {
        check(
            "term.colors",
            Status::Warn,
            "colors",
            format!("256 colors (COLORTERM={colorterm}); RGB colors are downsampled"),
        )
        .hint("if the terminal supports 24-bit color, set COLORTERM=truecolor or ui.truecolor = \"on\"")
    } else {
        check(
            "term.colors",
            Status::Warn,
            "colors",
            format!("no truecolor or 256-color support advertised (COLORTERM={colorterm})"),
        )
        .hint("use a TERM with 256 colors (e.g. xterm-256color)")
    });
    checks.push(match &f.answers {
        None => check("term.kitty", Status::Info, "kitty keyboard", not_tty),
        Some(a) => match &a.kitty {
            Ok(true) => check(
                "term.kitty",
                Status::Ok,
                "kitty keyboard",
                "supported (ctrl-i and tab are told apart)",
            ),
            Ok(false) => check(
                "term.kitty",
                Status::Warn,
                "kitty keyboard",
                "not supported: some chords (ctrl-i/tab, ctrl-m/enter) look the same",
            )
            .hint("bind actions to chords that work everywhere, or use a terminal with the kitty protocol"),
            Err(e) => check(
                "term.kitty",
                Status::Warn,
                "kitty keyboard",
                format!("query failed: {e}"),
            ),
        },
    });
    checks.push(check(
        "term.mouse",
        Status::Info,
        "mouse",
        if f.mouse {
            "captured by sverb (ui.mouse = true); support can't be detected"
        } else {
            "not captured (ui.mouse = false)"
        },
    ));
    checks.push(check(
        "term.paste",
        Status::Info,
        "bracketed paste",
        "enabled by sverb; support can't be detected",
    ));
    let name = env.terminal_name().unwrap_or("this terminal");
    checks.push(if !f.osc52 {
        check(
            "term.osc52",
            Status::Info,
            "OSC 52 clipboard",
            "disabled (clipboard.osc52 = false)",
        )
    } else {
        match env.osc52() {
            Osc52Guess::Likely => check(
                "term.osc52",
                Status::Ok,
                "OSC 52 clipboard",
                format!("likely supported by {name} (a guess: it can't be detected)"),
            ),
            Osc52Guess::Unknown => check(
                "term.osc52",
                Status::Info,
                "OSC 52 clipboard",
                format!("unknown for {name} (it can't be detected)"),
            ),
            Osc52Guess::Unlikely => check(
                "term.osc52",
                Status::Warn,
                "OSC 52 clipboard",
                format!("probably not supported by {name}"),
            )
            .hint("copies from sverb may not reach the system clipboard over SSH"),
        }
    });
    let expected = ratatui::text::Span::raw(WIDE_PROBE_CHAR).width();
    checks.push(match &f.answers {
        None => check("term.width", Status::Info, "unicode width", not_tty),
        Some(a) => match &a.wide_char_width {
            Ok(Some(w)) if usize::from(*w) == expected => check(
                "term.width",
                Status::Ok,
                "unicode width",
                format!("wide characters take {w} columns, as expected"),
            ),
            Ok(Some(w)) => check(
                "term.width",
                Status::Warn,
                "unicode width",
                format!("the terminal advanced {w} column(s) for U+754C; sverb expects {expected}"),
            )
            .hint("CJK and emoji may misalign; check the terminal's font and width settings"),
            Ok(None) => check(
                "term.width",
                Status::Info,
                "unicode width",
                "the terminal sent no cursor position report",
            ),
            Err(e) => check(
                "term.width",
                Status::Warn,
                "unicode width",
                format!("probe failed: {e}"),
            ),
        },
    });
    checks.push(if env.over_ssh() {
        check(
            "term.ssh",
            Status::Info,
            "over SSH",
            "yes: copies go through OSC 52 only",
        )
    } else {
        check("term.ssh", Status::Info, "over SSH", "no")
    });
    checks.push(match env.multiplexer() {
        None => check("term.multiplexer", Status::Info, "multiplexer", "none"),
        Some(Multiplexer::Tmux) => check(
            "term.multiplexer",
            Status::Warn,
            "multiplexer",
            "tmux: OSC 52 and passthrough sequences need tmux settings",
        )
        .hint("in tmux.conf: `set -g set-clipboard on` and `set -g allow-passthrough on`"),
        Some(Multiplexer::Screen) => check(
            "term.multiplexer",
            Status::Warn,
            "multiplexer",
            "GNU screen: OSC 52 and the kitty keyboard protocol don't pass through",
        )
        .hint("run sverb outside screen, or use tmux with set-clipboard on"),
    });
    Section {
        id: "terminal",
        title: "Terminal",
        checks,
    }
}

fn agent_section(f: &AgentFacts) -> Section {
    let source = f.system_source.as_deref().unwrap_or("SSH_AUTH_SOCK");
    let system = match &f.system {
        AgentState::Absent => check(
            "agent.system",
            Status::Info,
            "system agent",
            "SSH_AUTH_SOCK is not set; agent authentication is skipped",
        )
        .hint("start ssh-agent, or use keys from the vault"),
        AgentState::Identities(0) => check(
            "agent.system",
            Status::Warn,
            "system agent",
            format!("{source} is reachable but holds no keys"),
        )
        .hint("add keys with `ssh-add`"),
        AgentState::Identities(n) => check(
            "agent.system",
            Status::Ok,
            "system agent",
            format!("{source}: {n} identit{}", if *n == 1 { "y" } else { "ies" }),
        ),
        AgentState::Error(e) => check(
            "agent.system",
            Status::Warn,
            "system agent",
            format!("{source} is not reachable: {e}"),
        )
        .hint("restart ssh-agent or unset a stale SSH_AUTH_SOCK"),
    };
    let ep = &f.builtin_endpoint;
    let builtin = match &f.builtin {
        AgentState::Absent => check(
            "agent.builtin",
            Status::Info,
            "built-in agent",
            "not running (`sverb agent` starts it)",
        ),
        AgentState::Identities(n) => check(
            "agent.builtin",
            Status::Ok,
            "built-in agent",
            format!("running at {ep}: {n} key(s)"),
        ),
        AgentState::Error(e) => check(
            "agent.builtin",
            Status::Warn,
            "built-in agent",
            format!("{ep} does not answer: {e}"),
        )
        .hint("a stale socket from a crashed `sverb agent`; it is replaced on the next start"),
    };
    Section {
        id: "agent",
        title: "Agent",
        checks: vec![system, builtin],
    }
}

fn keyring_section(f: &KeyringFacts) -> Section {
    let available = if f.disabled {
        check(
            "keyring.available",
            Status::Info,
            "OS keyring",
            format!("disabled by {KEYRING_ENV}"),
        )
    } else {
        match f.available {
            Some(true) => check("keyring.available", Status::Ok, "OS keyring", "available"),
            Some(false) => check(
                "keyring.available",
                Status::Warn,
                "OS keyring",
                "not available: keyring unlock can't be used",
            )
            .hint("on Linux, run a Secret Service provider (gnome-keyring, KeePassXC)"),
            None => check(
                "keyring.available",
                Status::Info,
                "OS keyring",
                "not probed",
            ),
        }
    };
    let unlock = match f.unlock_enabled {
        None => check(
            "keyring.unlock",
            Status::Info,
            "keyring unlock",
            "no database yet",
        ),
        Some(true) => check("keyring.unlock", Status::Info, "keyring unlock", "enabled"),
        Some(false) => check(
            "keyring.unlock",
            Status::Info,
            "keyring unlock",
            "disabled (the master password is asked at every start)",
        ),
    };
    Section {
        id: "keyring",
        title: "Keyring",
        checks: vec![available, unlock],
    }
}

fn sync_section(f: &SyncFacts) -> Section {
    let checks = match f {
        SyncFacts::NotCompiled => vec![check(
            "sync.build",
            Status::Info,
            "sync",
            "not compiled in (local-only build)",
        )],
        SyncFacts::NoDatabase | SyncFacts::LocalOnly => vec![check(
            "sync.server",
            Status::Info,
            "server",
            "local-only: not connected to a sync server",
        )],
        SyncFacts::Error(e) => vec![check(
            "sync.server",
            Status::Fail,
            "server",
            format!("the sync state can't be read: {e}"),
        )],
        SyncFacts::Checked { checks, .. } => checks.clone(),
    };
    Section {
        id: "sync",
        title: "Sync",
        checks,
    }
}

/// Facts → report (pure).
pub(crate) fn build_report(f: &Facts) -> Report {
    Report::new(vec![
        env_section(&f.env),
        term_section(&f.term),
        agent_section(&f.agent),
        keyring_section(&f.keyring),
        sync_section(&f.sync),
    ])
}

const LABEL_WIDTH: usize = 17;

/// The text form.
pub(crate) fn render_text(r: &Report, glyphs: bool) -> String {
    use std::fmt::Write as _;
    let mut t = String::new();
    for (i, s) in r.sections.iter().enumerate() {
        if i > 0 {
            t.push('\n');
        }
        let _ = writeln!(t, "{}", s.title);
        for c in &s.checks {
            let _ = writeln!(
                t,
                "  {} {:<LABEL_WIDTH$} {}",
                c.status.mark(glyphs),
                c.label,
                c.detail
            );
            if let Some(hint) = &c.hint {
                let pad = if glyphs { 4 } else { 9 };
                let arrow = if glyphs { "→" } else { "->" };
                let _ = writeln!(t, "{:pad$}{arrow} {hint}", "");
            }
        }
    }
    t.push('\n');
    let plural =
        |n: usize, one: &str, many: &str| format!("{n} {}", if n == 1 { one } else { many });
    if r.ok && r.warnings == 0 {
        t.push_str("No problems found.\n");
    } else {
        let _ = writeln!(
            t,
            "{}, {}.",
            plural(r.problems, "problem", "problems"),
            plural(r.warnings, "warning", "warnings")
        );
    }
    t
}

// ------------------------------------------------------------------ --algos

/// One algorithm in `--algos`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct AlgoLine {
    pub name: String,
    /// `default` (offered, in order), `certificate` (host-key certificates, offered
    /// ahead of the plain keys), `legacy` (per-host opt-in) or `unavailable`
    /// (in the spec's list, not in this build's russh).
    pub status: &'static str,
}

/// One category in `--algos`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct AlgoCategory {
    pub kind: &'static str,
    pub title: &'static str,
    pub algorithms: Vec<AlgoLine>,
}

fn kind_id(kind: AlgoKind) -> (&'static str, &'static str) {
    match kind {
        AlgoKind::Kex => ("kex", "Key exchange"),
        AlgoKind::HostKey => ("host_key", "Host key"),
        AlgoKind::Cipher => ("cipher", "Cipher"),
        AlgoKind::Mac => ("mac", "MAC"),
        AlgoKind::Compression => ("compression", "Compression"),
    }
}

/// The `--algos` data for `supported` (pure).
pub(crate) fn algo_categories(supported: &[SupportedAlgos]) -> Vec<AlgoCategory> {
    supported
        .iter()
        .map(|s| {
            let (kind, title) = kind_id(s.kind);
            let line = |status: &'static str| {
                move |name: &String| AlgoLine {
                    name: name.clone(),
                    status,
                }
            };
            let mut algorithms: Vec<AlgoLine> = Vec::new();
            if s.kind == AlgoKind::HostKey {
                algorithms.extend(
                    s.default
                        .iter()
                        .filter_map(|n| algorithms::certificate_name(n))
                        .map(|name| AlgoLine {
                            name,
                            status: "certificate",
                        }),
                );
            }
            algorithms.extend(s.default.iter().map(line("default")));
            algorithms.extend(s.legacy.iter().map(line("legacy")));
            algorithms.extend(s.unavailable.iter().map(line("unavailable")));
            algorithms.extend(s.legacy_unavailable.iter().map(line("unavailable")));
            AlgoCategory {
                kind,
                title,
                algorithms,
            }
        })
        .collect()
}

/// The `--algos` text.
pub(crate) fn render_algos(categories: &[AlgoCategory]) -> String {
    use std::fmt::Write as _;
    let mut t = String::from(
        "SSH algorithms offered by this build, most preferred first\n\
         (legacy: only for hosts that opt in; unavailable: in sverb's list but not\n\
         implemented by this build's russh)\n",
    );
    for c in categories {
        let _ = writeln!(t, "\n{}", c.title);
        for a in &c.algorithms {
            let _ = writeln!(t, "  {:<12} {}", a.status, a.name);
        }
    }
    t
}

// ------------------------------------------------------------------ gathering

/// The probes [`gather`] uses (injected by tests).
pub(crate) struct Probes {
    pub term_env: TermEnv,
    pub stdout_tty: bool,
    /// Asked only when `stdout_tty`.
    pub terminal: Box<dyn Fn() -> TerminalAnswers + Send + Sync>,
    pub system_agent: Arc<dyn AgentConnector>,
    /// Where the system agent is (for messages); `None` when not configured.
    pub system_agent_source: Option<String>,
    pub keyring: Arc<dyn KeyringStore>,
    pub keyring_disabled: bool,
    /// Sync request timeout.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub sync_timeout: Duration,
}

fn keyring_disabled_by_env() -> bool {
    std::env::var(KEYRING_ENV).is_ok_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "off" | "0" | "none" | "disabled" | "false"
        )
    })
}

fn system_agent_source() -> Option<String> {
    if cfg!(windows) {
        Some(
            std::env::var("SSH_AUTH_SOCK")
                .ok()
                .filter(|p| p.starts_with(r"\\.\pipe\"))
                .unwrap_or_else(|| "the OpenSSH agent pipe or Pageant".to_owned()),
        )
    } else {
        std::env::var("SSH_AUTH_SOCK")
            .ok()
            .filter(|p| !p.is_empty())
    }
}

impl Probes {
    /// The real system.
    pub(crate) fn system(ctx: &Ctx) -> Self {
        Self {
            term_env: TermEnv::from_process(),
            stdout_tty: ctx.tty.stdout,
            terminal: Box::new(|| {
                let p = sverb_tui::runtime::capabilities::probe_terminal(PROBE_TIMEOUT);
                TerminalAnswers {
                    kitty: p.kitty.map_err(|e| e.to_string()),
                    wide_char_width: p.wide_char_width.map_err(|e| e.to_string()),
                }
            }),
            system_agent: Arc::new(SystemAgent),
            system_agent_source: system_agent_source(),
            keyring: keyring_from_env(),
            keyring_disabled: keyring_disabled_by_env(),
            sync_timeout: Duration::from_secs(10),
        }
    }
}

/// What is at `path` (`dir`: a directory is expected).
pub(crate) fn inspect_path(path: &Path, dir: bool) -> PathState {
    match std::fs::metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => PathState::Missing,
        Err(e) => PathState::Error(e.to_string()),
        Ok(m) if m.is_dir() != dir => PathState::WrongKind,
        Ok(m) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                PathState::Exists(Some(m.permissions().mode() & 0o7777))
            }
            #[cfg(not(unix))]
            {
                let _ = m;
                PathState::Exists(None)
            }
        }
    }
}

fn path_facts(ctx: &Ctx) -> Vec<PathFact> {
    let p = &ctx.paths;
    let mut out = vec![
        ("config dir", p.config_dir().to_path_buf(), true),
        ("data dir", p.data_dir().to_path_buf(), true),
        ("state dir", p.state_dir().to_path_buf(), true),
    ];
    if let Some(run) = p.runtime_dir() {
        out.push(("runtime dir", run.to_path_buf(), true));
    }
    out.push(("database file", p.db_file(), false));
    out.into_iter()
        .map(|(label, path, dir)| PathFact {
            label,
            state: inspect_path(&path, dir),
            path,
            private_mode: if dir { 0o700 } else { 0o600 },
        })
        .collect()
}

fn config_fact(ctx: &Ctx) -> ConfigFact {
    let file = ctx.paths.config_file();
    if !file.exists() {
        return ConfigFact::Missing;
    }
    let outcome = Config::load_file(&file, &ctx.validators, None);
    let located = |e| super::config::located(&file, e);
    if outcome.is_ok() {
        ConfigFact::Valid {
            warnings: outcome.warnings.iter().map(located).collect(),
        }
    } else {
        ConfigFact::Invalid {
            errors: outcome.errors.iter().map(located).collect(),
        }
    }
}

fn log_writable(dir: &Path) -> Option<bool> {
    let m = std::fs::metadata(dir).ok()?;
    if !m.is_dir() {
        return Some(false);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Owner-write is what matters for the user's own state directory.
        Some(m.permissions().mode() & 0o200 != 0)
    }
    #[cfg(not(unix))]
    {
        Some(!m.permissions().readonly())
    }
}

async fn agent_state(connector: &dyn AgentConnector) -> AgentState {
    let ask = async {
        let mut agent = connector.connect().await?;
        agent.identities().await
    };
    match tokio::time::timeout(AGENT_TIMEOUT, ask).await {
        Ok(Ok(ids)) => AgentState::Identities(ids.len()),
        Ok(Err(e)) => AgentState::Error(e.0),
        Err(_) => AgentState::Error("no answer in time".to_owned()),
    }
}

async fn agent_facts(ctx: &Ctx, probes: &Probes) -> AgentFacts {
    let system = if probes.system_agent_source.is_none() && !cfg!(windows) {
        AgentState::Absent
    } else {
        agent_state(probes.system_agent.as_ref()).await
    };
    let endpoint = ctx.paths.agent_endpoint();
    let builtin = match endpoint {
        #[cfg(unix)]
        AgentEndpoint::UnixSocket(path) => {
            if path.exists() {
                let connector = sverb_conn::agent_client::SocketAgent { path: path.clone() };
                agent_state(&connector).await
            } else {
                AgentState::Absent
            }
        }
        #[cfg(not(unix))]
        AgentEndpoint::UnixSocket(_) => AgentState::Absent,
        // The named pipe can't be checked without connecting to it as a client,
        // which the built-in agent would log as a connection; report it as unknown.
        AgentEndpoint::NamedPipe(_) => AgentState::Absent,
    };
    AgentFacts {
        system_source: probes.system_agent_source.clone(),
        system,
        builtin_endpoint: endpoint.to_string(),
        builtin,
    }
}

/// The database, opened only when its schema is current (so opening it migrates
/// nothing).
async fn open_store(ctx: &Ctx, db: &DbFact) -> Option<sverb_store::Store> {
    let DbFact::Health(h) = db else {
        return None;
    };
    if h.is_newer() || h.needs_migration() {
        return None;
    }
    let paths = ctx.paths.clone();
    tokio::task::spawn_blocking(move || sverb_store::Store::open(&paths).ok())
        .await
        .ok()
        .flatten()
}

async fn keyring_facts(probes: &Probes, engine: Option<&VaultEngine>) -> KeyringFacts {
    let available = if probes.keyring_disabled {
        None
    } else {
        let keyring = Arc::clone(&probes.keyring);
        let probe = tokio::task::spawn_blocking(move || keyring.probe());
        match tokio::time::timeout(KEYRING_TIMEOUT, probe).await {
            Ok(Ok(ok)) => Some(ok),
            _ => Some(false),
        }
    };
    let unlock_enabled = match engine {
        Some(e) => e.status().await.ok().map(|s| s.keyring_enabled),
        None => None,
    };
    KeyringFacts {
        disabled: probes.keyring_disabled,
        available,
        unlock_enabled,
    }
}

#[cfg(feature = "sync")]
async fn sync_facts(engine: Option<&VaultEngine>, probes: &Probes) -> SyncFacts {
    use sverb_sync::doctor::{ProbeLevel, ProbeOptions, probe};

    let Some(engine) = engine else {
        return SyncFacts::NoDatabase;
    };
    let store = engine.store();
    let info = match sverb_sync::local_info(store).await {
        Ok(i) => i,
        Err(e) => return SyncFacts::Error(e.to_string()),
    };
    let Some(server) = info.server_url.clone() else {
        return SyncFacts::LocalOnly;
    };
    // The token: only with keyring unlock (doctor never prompts), never refreshed.
    let token: Result<zeroize::Zeroizing<String>, String> = if !info.signed_in {
        Err("skipped: not signed in (`sverb login`)".to_owned())
    } else {
        match engine.status().await {
            Ok(s) if s.keyring_enabled => match engine.unlock_with_keyring().await {
                Ok(vault) => match sverb_sync::tokens::peek_access(store, vault.lmk()).await {
                    Ok(Some((t, expires))) if expires > store.now() => Ok(t),
                    Ok(Some(_)) => Err(
                        "skipped: the access token expired; the next sync refreshes it".to_owned(),
                    ),
                    Ok(None) => Err("skipped: not signed in (`sverb login`)".to_owned()),
                    Err(e) => Err(format!("skipped: {e}")),
                },
                Err(e) => Err(format!("skipped: keyring unlock failed ({e})")),
            },
            _ => Err("skipped: the vault is locked (token checks need keyring unlock)".to_owned()),
        }
    };
    let opts = ProbeOptions {
        timeout: probes.sync_timeout,
        tls: None,
    };
    let results = probe(
        &server,
        token.as_ref().map(|t| t.as_str()).map_err(Clone::clone),
        &opts,
    )
    .await;
    let checks = results
        .into_iter()
        .map(|c| Check {
            id: format!("sync.{}", c.id),
            status: match c.level {
                ProbeLevel::Ok => Status::Ok,
                ProbeLevel::Warn => Status::Warn,
                ProbeLevel::Fail => Status::Fail,
                ProbeLevel::Skip => Status::Info,
            },
            label: c.id.to_owned(),
            detail: c.detail,
            hint: c.hint,
        })
        .collect();
    SyncFacts::Checked { server, checks }
}

#[cfg(not(feature = "sync"))]
async fn sync_facts(_engine: Option<&VaultEngine>, _probes: &Probes) -> SyncFacts {
    SyncFacts::NotCompiled
}

/// Collect the facts. Read-only: nothing is created, migrated or rotated.
pub(crate) async fn gather(ctx: &Ctx, probes: &Probes) -> Facts {
    let db_file = ctx.paths.db_file();
    let db = if db_file.exists() {
        let path = db_file.clone();
        match tokio::task::spawn_blocking(move || sverb_store::health::inspect(&path)).await {
            Ok(Ok(h)) => DbFact::Health(h),
            Ok(Err(e)) => DbFact::Error(e.to_string()),
            Err(e) => DbFact::Error(e.to_string()),
        }
    } else {
        DbFact::Missing
    };
    let env = EnvFacts {
        version: super::VERSION_MESSAGE.to_owned(),
        features: super::FEATURES,
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        sverb_home: ctx.paths.sverb_home().map(Path::to_path_buf),
        paths: path_facts(ctx),
        config: config_fact(ctx),
        log_writable: log_writable(ctx.paths.log_dir()),
        db: db.clone(),
    };
    let term = TermFacts {
        env: probes.term_env.clone(),
        answers: probes.stdout_tty.then(|| (probes.terminal)()),
        mouse: ctx.config.ui.mouse,
        osc52: ctx.config.clipboard.osc52,
    };
    let agent = agent_facts(ctx, probes).await;
    let engine = open_store(ctx, &db)
        .await
        .map(|store| VaultEngine::new(store, Arc::clone(&probes.keyring), Argon2Cost::PRODUCTION));
    let keyring = keyring_facts(probes, engine.as_ref()).await;
    let sync = sync_facts(engine.as_ref(), probes).await;
    Facts {
        env,
        term,
        agent,
        keyring,
        sync,
    }
}

/// Whether the locale can show the status symbols.
fn utf8_locale() -> bool {
    if cfg!(windows) {
        return true;
    }
    ["LC_ALL", "LC_CTYPE", "LANG"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
        .is_some_and(|v| {
            let v = v.to_ascii_lowercase();
            v.contains("utf-8") || v.contains("utf8")
        })
}

// ------------------------------------------------------------------ the command

pub(crate) async fn run(args: DoctorArgs, ctx: &Ctx, out: &mut dyn Write) -> Result<u8, CliError> {
    run_with(args, ctx, &Probes::system(ctx), utf8_locale(), out).await
}

/// [`run`] with explicit probes and locale (tests).
pub(crate) async fn run_with(
    args: DoctorArgs,
    ctx: &Ctx,
    probes: &Probes,
    utf8: bool,
    out: &mut dyn Write,
) -> Result<u8, CliError> {
    if args.algos {
        let categories = algo_categories(&algorithms::supported());
        if args.json {
            write_json(out, &categories)?;
        } else {
            write_out(out, &render_algos(&categories))?;
        }
        return Ok(exit::OK);
    }
    let facts = gather(ctx, probes).await;
    let report = build_report(&facts);
    if args.json {
        write_json(out, &report)?;
    } else {
        write_out(out, &render_text(&report, utf8 && !args.ascii))?;
    }
    Ok(report.exit_code())
}
