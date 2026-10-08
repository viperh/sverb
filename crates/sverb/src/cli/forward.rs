//! M0-07 / M2-08: `sverb forward <rule> [--detach]` (SPEC §16, §9.6).
//!
//! Resolves the rule by label (exact, else a unique case-insensitive match; an id
//! works too), unlocks the vault (keyring, else the master password on the TTY),
//! checks the values that act locally against this device's `local_approvals` (M2-10,
//! §17.1: the host's unapproved ProxyCommand or system-agent forwarding, or a synced
//! non-loopback bind or remote destination → exit 5 pointing to `sverb approve
//! <host>`; §9.6: a non-loopback bind typed on this device is confirmed on the TTY and
//! stored, else exit 5), connects a
//! **standalone** tunnel (no shell channel), starts the rule and prints
//! `listening on 127.0.0.1:5432 → db:5432`. Host-key and authentication prompts are
//! answered on the TTY; without one they are refused. Ctrl-C (or SIGTERM) stops it.
//! A dropped connection is retried with a growing delay (1 s … 30 s).
//!
//! `--detach`: everything above happens in the foreground first (so prompts are
//! possible), then the tunnel is handed to a background `sverb` process in its own
//! process group (Unix; Windows: `CREATE_NO_WINDOW | DETACHED_PROCESS`) with null
//! stdin/stdout and stderr appended to `forward-<rule>.log` in the log directory. A
//! typed master password reaches it over a pipe, never the command line. Once the
//! background process reports `listening on …`, its pid is written to
//! `forward-<rule>.pid` in the runtime directory (the state directory when there is
//! none) and the command returns. SSH logins that need typing (password prompts,
//! OTP) cannot be detached: store the credential or use a key or agent.

use std::{
    io::{BufRead, Write},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use clap::Args;
use sverb_conn::{
    AuthAnswer, Decision, OpenError, SessionCmd, SessionEvent, SessionHandle, SessionId,
    SessionManager, SessionState, SshSpec, TransportKind,
    forward::{self as fwd, ForwardManager, ForwardRule, ForwardState, RiskyValue},
};
use sverb_core::{
    error_report::ErrorReport,
    model::{Host, ItemId, ItemKind, PortForward},
    paths::DirKind,
    secret::SecretString,
};
use sverb_tui::services::vault::VaultService;
// M2-10
use sverb_conn::forward::ApprovalStore;
use sverb_core::resolve::approval::{ActionKind, DeviceApprovals, LocalAction};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt},
    sync::mpsc,
};
use zeroize::Zeroizing;

use super::{
    CliError, Ctx, exit,
    vault::{read_secret, require_unlocked, require_unlocked_with_password, unlock_with_handoff},
    write_out,
};

/// `sverb forward …`
#[derive(Args, Debug, PartialEq, Eq)]
pub(crate) struct ForwardArgs {
    /// Port-forward rule name or id
    pub rule: String,
    /// Keep running in the background
    #[arg(long)]
    pub detach: bool,
    // M2-08
    /// Internal: the background half of `--detach` (reads a handed-over password on
    /// stdin, reports `listening on …` on stdout).
    #[arg(long, hide = true)]
    pub detached_child: bool,
}

/// How long the background process may take to report that it listens.
const DETACH_READY_TIMEOUT: Duration = Duration::from_secs(60);
/// The longest delay between reconnect attempts.
const MAX_RETRY: Duration = Duration::from_secs(30);

/// What the command found in the vault.
#[derive(Debug, Clone)]
struct Found {
    rule: ForwardRule,
    host_label: String,
    spec: SshSpec,
}

fn item_err(e: impl std::fmt::Display) -> CliError {
    CliError::Failure(ErrorReport::msg(e.to_string()))
}

/// Load the rules and pick the one `arg` names.
async fn load_rule(vault: &VaultService, arg: &str) -> Result<Found, CliError> {
    let ops = vault.item_ops().ok_or(CliError::VaultLocked)?;
    let device = ops.vault().device_id();
    let items = ops
        .list(&[ItemKind::PortForward, ItemKind::Host])
        .await
        .map_err(item_err)?;
    let mut rules = Vec::new();
    for item in &items {
        if item.body.kind != ItemKind::PortForward {
            continue;
        }
        if let Ok(pf) = PortForward::try_from(&item.body) {
            rules.push(ForwardRule::from_body(item.id, &pf, &item.body, device));
        }
    }
    let rule = pick(&rules, arg)?.clone();
    let host_item = items
        .iter()
        .find(|i| i.id == rule.host_id && i.body.kind == ItemKind::Host)
        .ok_or_else(|| {
            CliError::NotFound(format!(
                "the host of forward `{}` no longer exists",
                rule.label
            ))
        })?;
    let host = Host::try_from(&host_item.body).map_err(item_err)?;
    let host_label = host.display_label().to_owned();
    let spec = SshSpec {
        host: host.address.clone(),
        port: host.port.unwrap_or(22),
        user: host.username.clone(),
        host_id: Some(rule.host_id),
        label: Some(host_label.clone()),
        ..SshSpec::default()
    };
    Ok(Found {
        rule,
        host_label,
        spec,
    })
}

/// The rule `arg` names: an id (or its prefix), an exact label, else a unique
/// case-insensitive substring of a label.
fn pick<'a>(rules: &'a [ForwardRule], arg: &str) -> Result<&'a ForwardRule, CliError> {
    let needle = arg.trim().to_lowercase();
    if needle.is_empty() {
        return Err(CliError::Usage("name a port-forward rule".to_owned()));
    }
    let one = |found: Vec<&'a ForwardRule>| -> Option<Result<&'a ForwardRule, CliError>> {
        match found.as_slice() {
            [] => None,
            [rule] => Some(Ok(rule)),
            several => Some(Err(CliError::NotFound(format!(
                "`{arg}` matches several forwards: {}",
                several
                    .iter()
                    .map(|r| r.label.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )))),
        }
    };
    let by_id = rules
        .iter()
        .filter(|r| r.id.to_string().starts_with(&needle) && needle.len() >= 8)
        .collect();
    let exact = rules
        .iter()
        .filter(|r| r.label.to_lowercase() == needle)
        .collect();
    let fuzzy = rules
        .iter()
        .filter(|r| r.label.to_lowercase().contains(&needle))
        .collect();
    one(by_id)
        .or_else(|| one(exact))
        .or_else(|| one(fuzzy))
        .unwrap_or_else(|| {
            Err(CliError::NotFound(format!(
                "no port forward matches `{arg}`"
            )))
        })
}

/// `y`/`yes` on the terminal.
fn ask_yes(question: &str) -> bool {
    eprint!("{question} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).is_ok()
        && matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
}

// M2-10
/// The §17.1 headless error for `v` of the forward's host.
fn needs_approval(found: &Found, action: &LocalAction) -> CliError {
    CliError::NeedsApproval(action.headless_message(&found.host_label))
}

// M2-10
/// The host's own values that act locally (ProxyCommand, system agent) must be
/// approved before the tunnel connects (headless: exit 5, §17.1).
async fn check_host_values(
    vault: &VaultService,
    found: &Found,
    approvals: &DeviceApprovals,
) -> Result<(), CliError> {
    let ops = vault.item_ops().ok_or(CliError::VaultLocked)?;
    let (_, actions) = ops
        .host_local_actions(found.rule.host_id)
        .await
        .map_err(|e| CliError::Failure(e.report()))?;
    match actions
        .iter()
        .filter(|a| matches!(a.kind, ActionKind::ProxyCommand | ActionKind::SystemAgent))
        .find(|a| !approvals.is_approved(a.item_id, a.field(), &a.value))
    {
        Some(a) => Err(needs_approval(found, a)),
        None => Ok(()),
    }
}

/// Check the values that act locally. Returns the values confirmed now (not yet
/// approved on this device). M2-10: a value is approved when it has its
/// `local_approvals` row; otherwise a value not written on this device must be
/// approved with `sverb approve` (exit 5), and a non-loopback bind typed here is
/// confirmed on the terminal (§9.6), else exit 5.
fn confirm_values(
    found: &Found,
    ctx: &Ctx,
    assume: bool,
    approvals: &DeviceApprovals,
) -> Result<Vec<RiskyValue>, CliError> {
    let values: Vec<RiskyValue> = fwd::risky_values(&found.rule)
        .into_iter()
        .filter(|v| !ApprovalStore::is_approved(approvals, v))
        .collect();
    if values.is_empty() || assume {
        return Ok(values);
    }
    let action = |v: &RiskyValue| LocalAction::new(v.rule, v.kind(), v.value.clone());
    // §17.1: synced values are approved with `sverb approve`, never here.
    if let Some(v) = values.iter().find(|v| v.synced) {
        return Err(needs_approval(found, &action(v)));
    }
    // §9.6: a non-loopback bind typed here is confirmed on the terminal.
    if !(ctx.tty.stdin && ctx.tty.stderr) {
        return Err(needs_approval(found, &action(&values[0])));
    }
    for v in &values {
        if !ask_yes(&v.question()) {
            return Err(CliError::Failure(ErrorReport::msg(
                "the forward was not started (not confirmed)",
            )));
        }
    }
    Ok(values)
}

/// A running standalone tunnel.
struct Tunnel {
    sessions: SessionManager,
    forwards: ForwardManager,
    events: mpsc::UnboundedReceiver<(SessionId, SessionEvent)>,
    handle: Option<SessionHandle>,
    rule: ItemId,
    interactive: bool,
}

impl Tunnel {
    /// Connect and start the rule; returns once it listens.
    async fn start(
        ctx: &Ctx,
        vault: VaultService,
        found: &Found,
        approved: &[RiskyValue],
        interactive: bool,
    ) -> Result<(Self, String), CliError> {
        let (tx, events) = mpsc::unbounded_channel();
        let sessions = SessionManager::new(tx);
        // M2-10: the device's `local_approvals` for the connector and the manager.
        let approvals = vault.store().device_approvals();
        sessions.register_connector(
            TransportKind::Ssh,
            Arc::new(
                sverb_tui::services::ssh::ssh_connector(Some(vault), Arc::new(ctx.config.clone()))
                    .with_local_approvals(approvals.clone()),
            ),
        );
        let forwards = ForwardManager::with_approvals(approvals);
        sessions.set_forward_hook(Arc::new(forwards.clone()));
        forwards.set_rules([found.rule.clone()]);
        forwards.approve(approved);
        let handle = fwd::open_standalone(
            &sessions,
            &forwards,
            found.rule.id,
            found.spec.clone(),
            None,
        )
        .map_err(|e| match e {
            // M2-10
            fwd::StandaloneError::Start(fwd::StartError::NeedsApproval(values)) => {
                match values.first() {
                    Some(v) => {
                        needs_approval(found, &LocalAction::new(v.rule, v.kind(), v.value.clone()))
                    }
                    None => CliError::ApprovalRequired {
                        host: found.host_label.clone(),
                    },
                }
            }
            fwd::StandaloneError::Open(OpenError::NoRuntime) | fwd::StandaloneError::Start(_) => {
                item_err(e)
            }
            fwd::StandaloneError::Open(other) => item_err(other),
        })?;
        let mut tunnel = Self {
            sessions,
            forwards,
            events,
            handle,
            rule: found.rule.id,
            interactive,
        };
        let line = tunnel.until_listening().await?;
        Ok((tunnel, line))
    }

    /// Answer prompts until the rule listens (or fails).
    async fn until_listening(&mut self) -> Result<String, CliError> {
        let mut last_error: Option<ErrorReport> = None;
        let mut tick = tokio::time::interval(Duration::from_millis(50));
        loop {
            tokio::select! {
                ev = self.events.recv() => {
                    let Some((_, ev)) = ev else {
                        return Err(item_err("the connection ended"));
                    };
                    match ev {
                        SessionEvent::Error(report) => last_error = Some(report),
                        SessionEvent::State(SessionState::Disconnected { .. } | SessionState::Closed) => {
                            let report = last_error
                                .take()
                                .unwrap_or_else(|| ErrorReport::msg("the connection failed"));
                            return Err(CliError::Network(report));
                        }
                        other => self.answer(other).await,
                    }
                }
                _ = tick.tick() => {
                    let Some(status) = self.forwards.status(self.rule) else {
                        return Err(item_err("the rule disappeared"));
                    };
                    match status.state {
                        ForwardState::Listening => return Ok(status.listening_line()),
                        ForwardState::Error(msg) => {
                            return Err(CliError::Failure(ErrorReport::msg(format!(
                                "the forward could not start: {msg}"
                            ))));
                        }
                        ForwardState::NeedsApproval => {
                            return Err(item_err("the forward needs approval"));
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    /// Answer a host-key or authentication prompt (on the TTY; refused without one).
    async fn answer(&self, ev: SessionEvent) {
        let Some(handle) = &self.handle else {
            return;
        };
        let cmd = match ev {
            SessionEvent::HostKey(v) => {
                let trusted = self.interactive && {
                    eprintln!(
                        "{} host key for {}: {}",
                        if v.changed { "CHANGED" } else { "Unknown" },
                        v.host,
                        v.fingerprint
                    );
                    ask_yes("Trust this host key and save it?")
                };
                SessionCmd::HostKeyDecision(if trusted {
                    Decision::AcceptAndSave
                } else {
                    Decision::Reject
                })
            }
            SessionEvent::Prompt(prompt) => {
                if !self.interactive {
                    SessionCmd::AuthAnswer(AuthAnswer::Cancel)
                } else {
                    let mut answers = Vec::new();
                    for line in &prompt.prompts {
                        match read_secret(&line.text) {
                            Ok(text) => answers.push(SecretString::from(text.as_str())),
                            Err(_) => break,
                        }
                    }
                    if answers.len() == prompt.prompts.len() {
                        SessionCmd::AuthAnswer(AuthAnswer::Responses(answers))
                    } else {
                        SessionCmd::AuthAnswer(AuthAnswer::Cancel)
                    }
                }
            }
            _ => return,
        };
        let _ = handle.cmd_tx.send(cmd).await;
    }

    /// Keep the tunnel up until Ctrl-C / SIGTERM; reconnect when the connection drops.
    async fn run_until_signal(mut self) -> Result<u8, CliError> {
        let mut retry = Duration::from_secs(1);
        let reconnect = tokio::time::sleep(Duration::MAX);
        tokio::pin!(reconnect);
        let mut waiting = false;
        loop {
            tokio::select! {
                () = shutdown_signal() => break,
                ev = self.events.recv() => {
                    let Some((_, ev)) = ev else { break };
                    match ev {
                        SessionEvent::State(SessionState::Disconnected { .. }) => {
                            eprintln!("connection lost; reconnecting in {} s", retry.as_secs());
                            reconnect.as_mut().reset(tokio::time::Instant::now() + retry);
                            waiting = true;
                            retry = (retry * 2).min(MAX_RETRY);
                        }
                        SessionEvent::State(SessionState::Connected { .. }) => {
                            retry = Duration::from_secs(1);
                            eprintln!("reconnected");
                        }
                        SessionEvent::State(SessionState::Closed) => break,
                        SessionEvent::Error(report) => {
                            tracing::info!(error = %report.short, "forward connection error");
                        }
                        other => self.answer(other).await,
                    }
                }
                () = &mut reconnect, if waiting => {
                    waiting = false;
                    if let Some(handle) = &self.handle {
                        let _ = handle.cmd_tx.send(SessionCmd::Reconnect).await;
                    }
                }
            }
        }
        self.stop().await;
        Ok(exit::OK)
    }

    async fn stop(self) {
        self.forwards.stop(self.rule);
        self.sessions.shutdown(Duration::from_secs(2)).await;
    }
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

/// A file-name-safe form of `label`.
fn file_stem(label: &str) -> String {
    let stem: String = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if stem.is_empty() {
        "rule".to_owned()
    } else {
        stem
    }
}

/// Where `--detach` writes the pid.
pub(crate) fn pid_file(ctx: &Ctx, label: &str) -> PathBuf {
    let dir = ctx
        .paths
        .runtime_dir()
        .unwrap_or_else(|| ctx.paths.state_dir());
    dir.join(format!("forward-{}.pid", file_stem(label)))
}

/// Start the background process and wait for its `listening on …` line.
async fn spawn_detached(
    ctx: &Ctx,
    args: &ForwardArgs,
    label: &str,
    password: Option<Zeroizing<String>>,
) -> Result<String, CliError> {
    let fail = |msg: String| CliError::Failure(ErrorReport::msg(msg));
    let exe = std::env::current_exe().map_err(|e| CliError::failure(&e))?;
    let _ = ctx.paths.ensure(DirKind::State);
    let log_dir = ctx.paths.log_dir().to_path_buf();
    let _ = std::fs::create_dir_all(&log_dir);
    let log_path = log_dir.join(format!("forward-{}.log", file_stem(label)));
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|e| fail(format!("cannot open {}: {e}", log_path.display())))?;
    let mut cmd = tokio::process::Command::new(exe);
    cmd.arg("forward")
        .arg(&args.rule)
        .arg("--detached-child")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(log);
    #[cfg(unix)]
    cmd.process_group(0);
    #[cfg(windows)]
    {
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
    }
    let mut child = cmd.spawn().map_err(|e| CliError::failure(&e))?;
    if let Some(mut stdin) = child.stdin.take() {
        let line = password.map(|p| Zeroizing::new(format!("{}\n", p.as_str())));
        let bytes: &[u8] = line.as_ref().map_or(b"\n", |l| l.as_bytes());
        let _ = stdin.write_all(bytes).await;
        drop(stdin);
    }
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| fail("no pipe to the background process".to_owned()))?;
    let mut lines = tokio::io::BufReader::new(stdout).lines();
    let ready = tokio::time::timeout(DETACH_READY_TIMEOUT, lines.next_line()).await;
    match ready {
        Ok(Ok(Some(line))) if line.starts_with("listening on") => {
            let pid = child.id().unwrap_or_default();
            let pid_path = pid_file(ctx, label);
            if let Some(dir) = pid_path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            std::fs::write(&pid_path, format!("{pid}\n"))
                .map_err(|e| fail(format!("cannot write {}: {e}", pid_path.display())))?;
            Ok(format!("{line} (pid {pid}, {})", pid_path.display()))
        }
        Ok(_) => {
            let status = child.wait().await.ok().and_then(|s| s.code());
            Err(fail(format!(
                "the background forward stopped (exit {}); see {}",
                status.map_or_else(|| "?".to_owned(), |c| c.to_string()),
                log_path.display()
            )))
        }
        Err(_) => {
            let _ = child.start_kill();
            Err(fail(format!(
                "the background forward did not start within {} s; see {}",
                DETACH_READY_TIMEOUT.as_secs(),
                log_path.display()
            )))
        }
    }
}

/// The background half of `--detach`.
async fn run_child(args: &ForwardArgs, ctx: &Ctx) -> Result<u8, CliError> {
    let mut line = String::new();
    let _ = tokio::io::BufReader::new(tokio::io::stdin())
        .read_line(&mut line)
        .await;
    let line = Zeroizing::new(line);
    let password = line.trim_end_matches(['\r', '\n']);
    let password = (!password.is_empty()).then(|| Zeroizing::new(password.to_owned()));
    let unlocked = unlock_with_handoff(ctx, password).await?;
    let vault = VaultService::from_unlocked(unlocked.engine, unlocked.vault);
    let found = load_rule(&vault, &args.rule).await?;
    // The foreground process checked and confirmed the values (and stored them).
    let approved = confirm_values(&found, ctx, true, &vault.store().device_approvals())?;
    let (tunnel, ready) = Tunnel::start(ctx, vault, &found, &approved, false).await?;
    let mut stdout = tokio::io::stdout();
    let _ = stdout.write_all(format!("{ready}\n").as_bytes()).await;
    let _ = stdout.flush().await;
    tracing::info!(rule = %found.rule.id.short(), "detached forward listening");
    tunnel.run_until_signal().await
}

pub(crate) async fn run(args: ForwardArgs, ctx: &Ctx, out: &mut dyn Write) -> Result<u8, CliError> {
    if args.detached_child {
        return run_child(&args, ctx).await;
    }
    let (unlocked, password) = if args.detach {
        require_unlocked_with_password(ctx).await?
    } else {
        (require_unlocked(ctx).await?, None)
    };
    let vault = VaultService::from_unlocked(unlocked.engine, unlocked.vault);
    let found = load_rule(&vault, &args.rule).await?;
    // M2-10: §17.1 checks against this device's `local_approvals`.
    let approvals = vault.store().device_approvals();
    check_host_values(&vault, &found, &approvals).await?;
    let approved = confirm_values(&found, ctx, false, &approvals)?;
    let confirmed: Vec<LocalAction> = approved
        .iter()
        .map(|v| LocalAction::new(v.rule, v.kind(), v.value.clone()))
        .collect();
    vault
        .store()
        .approve_all_local(&confirmed)
        .await
        .map_err(|e| CliError::failure(&e))?;
    let interactive = ctx.tty.stdin && ctx.tty.stderr;
    let (tunnel, line) = Tunnel::start(ctx, vault, &found, &approved, interactive).await?;
    if args.detach {
        // Prompts were answered here; the background process takes over.
        tunnel.stop().await;
        let line = spawn_detached(ctx, &args, &found.rule.label, password).await?;
        write_out(out, &format!("{line}\n"))?;
        return Ok(exit::OK);
    }
    write_out(out, &format!("{line}\n"))?;
    tunnel.run_until_signal().await
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use sverb_core::model::ForwardKind;

    use super::*;

    fn rule(label: &str) -> ForwardRule {
        ForwardRule {
            id: ItemId::new(),
            label: label.into(),
            kind: ForwardKind::Local,
            host_id: ItemId::new(),
            bind_addr: "127.0.0.1".into(),
            bind_port: 5432,
            dest_host: Some("db".into()),
            dest_port: Some(5432),
            auto_start: false,
            typed_here: true,
        }
    }

    #[test]
    fn picks_rules_by_label() {
        let rules = vec![rule("db"), rule("db-replica"), rule("Web proxy")];
        assert_eq!(pick(&rules, "DB").unwrap().label, "db");
        assert_eq!(pick(&rules, "replica").unwrap().label, "db-replica");
        assert_eq!(pick(&rules, "web").unwrap().label, "Web proxy");
        let id = rules[2].id.to_string();
        assert_eq!(pick(&rules, &id).unwrap().label, "Web proxy");
        let Err(CliError::NotFound(msg)) = pick(&rules, "d") else {
            panic!()
        };
        assert!(msg.contains("several"), "{msg}");
        assert!(matches!(pick(&rules, "nope"), Err(CliError::NotFound(_))));
        assert_eq!(
            pick(&rules, "nope").unwrap_err().exit_code(),
            exit::NOT_FOUND
        );
    }

    #[test]
    fn file_stems() {
        assert_eq!(file_stem("db tunnel/1"), "db_tunnel_1");
        assert_eq!(file_stem(""), "rule");
    }
}
