//! `sverb agent [--socket <path>]` and `sverb lock` (SPEC §6.1.6, §16).
//!
//! `sverb agent` runs the built-in agent in the foreground so plain `ssh`, `ssh-add`
//! and `git` can use vault keys:
//! 1. binds the socket first (default `Paths::agent_endpoint()`: `agent.sock` in the
//!    `0700` runtime dir; the socket is `0600`; a stale socket is replaced, a live one
//!    is "agent already running (pid N)"),
//! 2. unlocks the vault (`require_unlocked`: keyring, else the master password on the
//!    TTY) and keeps **only** the decrypted `agent_forwardable` keys and their
//!    certificates (the vault keys are dropped right away),
//! 3. prints `SSH_AUTH_SOCK=<path>; export SSH_AUTH_SOCK;` on stdout (fish / csh syntax
//!    when `$SHELL` is fish / csh, like `ssh-agent`),
//! 4. serves until Ctrl-C / SIGTERM, then removes the socket.
//!
//! Peers with another uid are refused. `confirm_on_use` keys are confirmed on the
//! terminal (`[a]llow once / [d]eny`, 60 s, then deny; without a terminal: deny).
//! **Auto-lock:** after `general.auto_lock_minutes` without agent requests the keys
//! are dropped; signing is then refused (and logged) until the agent is restarted.
//!
//! `sverb_conn::agent::pipe_windows`).
//!
//! `sverb lock` ([`lock`]) asks a running TUI to lock over its control socket.

use std::{io::Write, path::PathBuf, sync::Arc, time::Duration};

use async_trait::async_trait;
use clap::Args;
use sverb_conn::agent::{
    AgentServer, BuiltinAgent, ConfirmRequest, Confirmer, DenyConfirm, StaticKeys,
    builtin::agent_keys,
    control::{self, ControlCommand, ControlError},
    forward::SystemRawAgent,
};
use sverb_core::{model::AgentSource, paths::AgentEndpoint};
use sverb_tui::services::vault::items::ItemOps;

use super::{CliError, Ctx, exit, vault::require_unlocked, write_out};

/// `sverb agent …`
#[derive(Args, Debug, PartialEq, Eq)]
pub(crate) struct AgentArgs {
    /// Listen on this socket instead of the default in the runtime directory
    #[arg(long, value_name = "PATH")]
    pub socket: Option<PathBuf>,
}

/// How often the auto-lock check runs.
const AUTO_LOCK_CHECK: Duration = Duration::from_secs(15);

/// The shell syntax for the `SSH_AUTH_SOCK` line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShellSyntax {
    Sh,
    Fish,
    Csh,
}

impl ShellSyntax {
    /// From `$SHELL` (like `ssh-agent`: `*csh` → csh; fish → fish; else sh).
    pub(crate) fn from_shell(shell: Option<&str>) -> Self {
        let name = shell.and_then(|s| s.rsplit('/').next()).unwrap_or_default();
        if name == "fish" {
            Self::Fish
        } else if name.ends_with("csh") {
            Self::Csh
        } else {
            Self::Sh
        }
    }

    /// The line exporting `SSH_AUTH_SOCK`.
    pub(crate) fn export(self, sock: &str) -> String {
        match self {
            Self::Sh => format!("SSH_AUTH_SOCK={sock}; export SSH_AUTH_SOCK;\n"),
            Self::Fish => format!("set -x SSH_AUTH_SOCK {sock};\n"),
            Self::Csh => format!("setenv SSH_AUTH_SOCK {sock};\n"),
        }
    }
}

/// Confirms `confirm_on_use` keys on the terminal (one prompt at a time).
#[derive(Debug, Default)]
struct TtyConfirmer {
    turn: tokio::sync::Mutex<()>,
}

#[async_trait]
impl Confirmer for TtyConfirmer {
    async fn confirm(&self, request: ConfirmRequest) -> bool {
        let _turn = self.turn.lock().await;
        eprintln!(
            "{} requests a signature with key {} ({}). [a]llow once / [d]eny (denied in {}s)",
            request.requester,
            request.key_label,
            request.fingerprint,
            sverb_conn::agent::CONFIRM_TIMEOUT.as_secs()
        );
        tokio::task::spawn_blocking(|| ask_key(sverb_conn::agent::CONFIRM_TIMEOUT))
            .await
            .unwrap_or(false)
    }
}

/// Wait for `a` (allow) or `d` / Esc / Ctrl-C (deny) in raw mode; deny on timeout.
fn ask_key(timeout: Duration) -> bool {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    if crossterm::terminal::enable_raw_mode().is_err() {
        return false;
    }
    let deadline = std::time::Instant::now() + timeout;
    let allowed = loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() || !event::poll(left).unwrap_or(false) {
            break false;
        }
        let Ok(Event::Key(key)) = event::read() else {
            continue;
        };
        if key.kind == KeyEventKind::Release {
            continue;
        }
        match key.code {
            KeyCode::Char('a' | 'A') => break true,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break false,
            KeyCode::Char('d' | 'D') | KeyCode::Esc => break false,
            _ => {}
        }
    };
    let _ = crossterm::terminal::disable_raw_mode();
    eprintln!("{}\r", if allowed { "allowed" } else { "denied" });
    allowed
}

/// Ctrl-C, or SIGTERM on Unix.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// The vault's forwardable keys (the unlocked vault is dropped on return).
async fn load_keys(ctx: &Ctx) -> Result<StaticKeys, CliError> {
    let unlocked = require_unlocked(ctx).await?;
    let ops = ItemOps::new(unlocked.engine.clone(), Arc::new(unlocked.vault));
    let keys = ops.keys().await.map_err(|e| CliError::failure(&e))?;
    let certs = ops
        .certificates()
        .await
        .map_err(|e| CliError::failure(&e))?;
    let keys: Vec<_> = keys.into_iter().map(|(l, k)| (l.id, k)).collect();
    let certs: Vec<_> = certs.into_iter().map(|(l, c)| (l.id, c)).collect();
    Ok(StaticKeys::new(agent_keys(&keys, &certs)))
}

/// Drop the keys after `minutes` without requests (0: never).
fn spawn_auto_lock(keys: Arc<StaticKeys>, minutes: u32) -> Option<tokio::task::JoinHandle<()>> {
    if minutes == 0 {
        return None;
    }
    let idle = Duration::from_secs(u64::from(minutes) * 60);
    Some(tokio::spawn(async move {
        let mut tick = tokio::time::interval(AUTO_LOCK_CHECK);
        loop {
            tick.tick().await;
            if !keys.is_locked() && keys.idle() >= idle {
                keys.lock();
                tracing::info!(
                    "agent auto-locked after {minutes} idle minutes; signing is refused"
                );
                eprintln!(
                    "sverb agent: locked after {minutes} idle minutes; signing is refused until \
                     `sverb agent` is restarted"
                );
            }
        }
    }))
}

/// `sverb agent`.
pub(crate) async fn run(args: AgentArgs, ctx: &Ctx, out: &mut dyn Write) -> Result<u8, CliError> {
    let endpoint = match args.socket {
        Some(path) => AgentEndpoint::UnixSocket(path),
        None => ctx.paths.agent_endpoint().clone(),
    };
    match endpoint {
        AgentEndpoint::UnixSocket(path) => run_unix(path, ctx, out).await,
        AgentEndpoint::NamedPipe(name) => run_pipe(name, ctx, out).await,
    }
}

fn server(ctx: &Ctx, keys: Arc<StaticKeys>) -> AgentServer {
    let confirmer: Arc<dyn Confirmer> = if ctx.tty.stdin && ctx.tty.stderr {
        Arc::new(TtyConfirmer::default())
    } else {
        Arc::new(DenyConfirm)
    };
    AgentServer::new(
        Arc::new(BuiltinAgent::new(keys, confirmer)),
        Arc::new(SystemRawAgent),
        AgentSource::Builtin,
        sverb_conn::agent::Requester::Local {
            pid: None,
            exe: None,
        },
    )
}

#[cfg(unix)]
async fn run_unix(path: PathBuf, ctx: &Ctx, out: &mut dyn Write) -> Result<u8, CliError> {
    use sverb_conn::agent::socket::{DirPolicy, PrivateSocket};
    let default = matches!(ctx.paths.agent_endpoint(), AgentEndpoint::UnixSocket(p) if *p == path);
    let policy = if default {
        ctx.paths
            .ensure(sverb_core::paths::DirKind::Run)
            .map_err(|e| CliError::failure(&e))?;
        DirPolicy::Private
    } else {
        DirPolicy::Lenient
    };
    let socket = PrivateSocket::bind(&path, policy, "agent")
        .await
        .map_err(|e| CliError::failure(&e))?;
    let keys = Arc::new(load_keys(ctx).await?);
    let count = sverb_conn::agent::KeySource::keys(&*keys)
        .await
        .map_or(0, |k| k.len());
    let shell = std::env::var("SHELL").ok();
    write_out(
        out,
        &ShellSyntax::from_shell(shell.as_deref()).export(&path.display().to_string()),
    )?;
    eprintln!(
        "sverb agent: serving {count} forwardable key{} on {} (Ctrl-C to stop)",
        if count == 1 { "" } else { "s" },
        path.display()
    );
    let auto_lock = spawn_auto_lock(Arc::clone(&keys), ctx.config.general.auto_lock_minutes);
    let server = server(ctx, keys);
    let result = tokio::select! {
        res = sverb_conn::agent::serve_local(&socket, server) => res.map(|()| exit::OK).map_err(|e| CliError::failure(&e)),
        () = shutdown_signal() => Ok(exit::OK),
    };
    if let Some(task) = auto_lock {
        task.abort();
    }
    drop(socket);
    result
}

#[cfg(not(unix))]
async fn run_unix(_path: PathBuf, _ctx: &Ctx, _out: &mut dyn Write) -> Result<u8, CliError> {
    Err(CliError::Usage(
        "--socket is not supported on this platform (the agent uses a named pipe)".to_owned(),
    ))
}

#[cfg(windows)]
async fn run_pipe(name: String, ctx: &Ctx, out: &mut dyn Write) -> Result<u8, CliError> {
    let keys = Arc::new(load_keys(ctx).await?);
    write_out(out, &ShellSyntax::Sh.export(&name))?;
    eprintln!("sverb agent: serving on {name} (Ctrl-C to stop)");
    let auto_lock = spawn_auto_lock(Arc::clone(&keys), ctx.config.general.auto_lock_minutes);
    let server = server(ctx, keys);
    let result = tokio::select! {
        res = sverb_conn::agent::pipe_windows::serve(&name, server) => res.map(|()| exit::OK).map_err(|e| CliError::failure(&e)),
        () = shutdown_signal() => Ok(exit::OK),
    };
    if let Some(task) = auto_lock {
        task.abort();
    }
    result
}

#[cfg(not(windows))]
async fn run_pipe(name: String, _ctx: &Ctx, _out: &mut dyn Write) -> Result<u8, CliError> {
    Err(CliError::Usage(format!(
        "named pipe {name} is only supported on Windows"
    )))
}

/// `sverb lock`: lock the running TUI through its control socket. No running TUI is
/// not an error (exit 0, a note on stderr): headless commands never keep the vault
/// unlocked.
pub(crate) async fn lock(ctx: &Ctx) -> Result<u8, CliError> {
    let Some(path) = control::control_path(&ctx.paths) else {
        eprintln!("no running sverb TUI to lock; nothing to do");
        return Ok(exit::OK);
    };
    match control::send(&path, ControlCommand::Lock).await {
        Ok(pid) => {
            match pid {
                Some(pid) => eprintln!("locked the running sverb (pid {pid})"),
                None => eprintln!("locked the running sverb"),
            }
            Ok(exit::OK)
        }
        Err(ControlError::NotRunning) => {
            eprintln!("no running sverb TUI to lock; nothing to do");
            Ok(exit::OK)
        }
        Err(err) => Err(CliError::failure(&err)),
    }
}

#[cfg(test)]
mod tests {
    use super::ShellSyntax;

    #[test]
    fn export_line_follows_the_shell() {
        let sh = ShellSyntax::from_shell(Some("/bin/bash"));
        assert_eq!(
            sh.export("/run/a.sock"),
            "SSH_AUTH_SOCK=/run/a.sock; export SSH_AUTH_SOCK;\n"
        );
        assert_eq!(ShellSyntax::from_shell(None), ShellSyntax::Sh);
        assert_eq!(
            ShellSyntax::from_shell(Some("/usr/bin/fish")).export("/s"),
            "set -x SSH_AUTH_SOCK /s;\n"
        );
        assert_eq!(
            ShellSyntax::from_shell(Some("/bin/tcsh")).export("/s"),
            "setenv SSH_AUTH_SOCK /s;\n"
        );
    }
}
