//! [`Headless`]: a session driven through the real `SessionManager`, SSH connector and
//! authentication chain, without a TUI. The emulator grid is read with
//! [`Headless::grid_text`] and polled with [`Headless::wait_for_text`].

use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use parking_lot::Mutex;
use sverb_conn::{
    AuthAnswer, Bytes, OpenOptions, SessionCmd, SessionEvent, SessionHandle, SessionId,
    SessionManager, SessionSpec, SessionState, SshSpec, TransportKind,
    ssh::{
        Authenticator, ChainAuthenticator, HostKeyTarget, HostKeyVerdict, HostKeyVerifier,
        HostResolver, KeyMaterial, ServerKey, SshConnector, SshError, SshTarget, resolve,
    },
};
use sverb_core::{
    config::Config,
    model::{AlgoOverrides, Host},
    secret::SecretString,
};
use sverb_term::GridPoint;
use tokio::sync::mpsc;

use crate::{diag, keys, sshd::Sshd};

/// Where and how to log in.
#[derive(Debug, Clone)]
pub struct Login {
    /// Host name or IP.
    pub host: String,
    /// Port.
    pub port: u16,
    /// User name.
    pub user: String,
    /// The stored password, if any.
    pub password: Option<String>,
    /// The configured key: OpenSSH private key text.
    pub key: Option<String>,
    /// The key's stored passphrase.
    pub passphrase: Option<String>,
    /// Certificates attached to the key.
    pub certificates: Vec<String>,
    /// Environment sent with `env` requests.
    pub env: Vec<(String, String)>,
    /// Legacy algorithm opt-ins.
    pub algorithms: Option<AlgoOverrides>,
    /// `ssh.max_auth_attempts` override.
    pub max_auth_attempts: Option<u32>,
    /// Keepalive interval in seconds (0 disables).
    pub keepalive_secs: Option<u32>,
    /// Typed once the shell is up (the startup snippet's text).
    pub startup_input: Option<String>,
}

impl Login {
    /// Password login to `host:port`.
    pub fn password(host: impl Into<String>, port: u16, user: &str, password: &str) -> Self {
        Self {
            host: host.into(),
            port,
            user: user.to_owned(),
            password: Some(password.to_owned()),
            key: None,
            passphrase: None,
            certificates: Vec::new(),
            env: Vec::new(),
            algorithms: None,
            max_auth_attempts: None,
            keepalive_secs: None,
            startup_input: None,
        }
    }

    /// `test`/`test` on a fixture container.
    pub fn sshd_password(sshd: &Sshd) -> Self {
        Self::password(sshd.host(), sshd.port(), keys::USER, keys::PASSWORD)
    }

    /// User `test` with fixture key `key` (its passphrase and certificate included).
    pub fn sshd_key(sshd: &Sshd, key: keys::FixtureKey) -> Self {
        Self {
            password: None,
            key: Some(key.private()),
            passphrase: key.passphrase().map(str::to_owned),
            certificates: key.certificate().into_iter().collect(),
            ..Self::password(sshd.host(), sshd.port(), keys::USER, "")
        }
    }

    /// The resolved target (what a vault-backed resolver would produce).
    pub fn target(&self) -> SshTarget {
        let host = Host {
            label: format!("e2e {}", self.host),
            address: self.host.clone(),
            port: Some(self.port),
            username: Some(self.user.clone()),
            password: self.password.clone().map(SecretString::from),
            env: self.env.clone(),
            algorithms: self.algorithms.clone(),
            keepalive_secs: self.keepalive_secs,
            ..Host::default()
        };
        let mut config = Config::default();
        config.ssh.connect_timeout_secs = 10;
        // `ssh.use_system_agent` stays on, but the default authenticator has no
        // agent: only one attached through `HeadlessOptions::authenticator` (a test's
        // own `ssh-agent`) is ever asked, never the developer's.
        let mut target = resolve(&host, None, None, &config, || None);
        if let Some(key) = &self.key {
            target.auth.key = Some(KeyMaterial {
                key_id: None,
                label: "e2e key".into(),
                private_key: SecretString::from(key.clone()),
                passphrase: self.passphrase.clone().map(SecretString::from),
                certificates: self.certificates.clone(),
            });
        }
        target.startup_input.clone_from(&self.startup_input);
        if let Some(n) = self.max_auth_attempts {
            target.auth.max_attempts = n;
        }
        target
    }
}

#[derive(Debug)]
struct LoginResolver(Login, Option<sverb_core::model::AgentSource>);

#[async_trait]
impl HostResolver for LoginResolver {
    async fn resolve(&self, _spec: &SshSpec) -> Result<SshTarget, SshError> {
        let mut target = self.0.target();
        // M2-07
        if let Some(source) = self.1 {
            target.agent_forwarding = true;
            target.agent_source = source;
        }
        Ok(target)
    }
}

/// Accepts every host key (like `InsecureAcceptAnyHostKey`) and records them, so tests
/// can compare fingerprints.
#[derive(Debug, Default, Clone)]
pub struct RecordingVerifier {
    seen: Arc<Mutex<Vec<(HostKeyTarget, ServerKey)>>>,
}

impl RecordingVerifier {
    /// Every key presented so far, in order.
    pub fn seen(&self) -> Vec<(HostKeyTarget, ServerKey)> {
        self.seen.lock().clone()
    }
}

impl HostKeyVerifier for RecordingVerifier {
    fn verify(&self, target: &HostKeyTarget, key: &ServerKey) -> HostKeyVerdict {
        self.seen.lock().push((target.clone(), key.clone()));
        HostKeyVerdict::Accept
    }
}

/// How to open a [`Headless`] session.
#[derive(Debug, Clone)]
pub struct HeadlessOptions {
    /// Terminal size.
    pub cols: u16,
    /// Terminal size.
    pub rows: u16,
    /// Host-key verifier (default: a [`RecordingVerifier`] that accepts everything).
    pub verifier: Option<Arc<dyn HostKeyVerifier>>,
    /// Authenticator (default: the full chain without any system agent).
    pub authenticator: Option<Arc<dyn Authenticator>>,
    // M2-07
    /// Agent forwarding: the agents answering forwarded channels and the source; the
    /// host gets `agent_forwarding = true` with that source.
    pub agent: Option<(
        sverb_conn::agent::AgentForwarding,
        sverb_core::model::AgentSource,
    )>,
}

impl Default for HeadlessOptions {
    fn default() -> Self {
        Self {
            cols: 80,
            rows: 24,
            verifier: None,
            authenticator: None,
            // M2-07
            agent: None,
        }
    }
}

/// A [`Headless`] wait that timed out. Its `Debug` (what `unwrap` prints) contains
/// the screen and the events seen.
#[derive(Clone, PartialEq, Eq)]
pub struct WaitError(pub String);

impl fmt::Debug for WaitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for WaitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for WaitError {}

/// One SSH session without a TUI. Must be created inside a Tokio runtime. Dumps the
/// screen and the events when dropped during a failing test.
pub struct Headless {
    mgr: SessionManager,
    events: mpsc::UnboundedReceiver<(SessionId, SessionEvent)>,
    /// The session (its emulator is `handle.term`).
    pub handle: SessionHandle,
    log: Vec<SessionEvent>,
    recorder: RecordingVerifier,
    timeout: Duration,
}

impl fmt::Debug for Headless {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Headless")
            .field("id", &self.handle.id)
            .field("events", &self.log.len())
            .finish_non_exhaustive()
    }
}

impl Headless {
    /// Open a session to `login` (80×24). Connecting continues in the background; use
    /// [`Headless::wait_connected`] or [`Headless::wait_for_text`].
    pub fn connect(login: Login) -> Self {
        Self::connect_with(login, HeadlessOptions::default())
    }

    /// Open a session with `opts`.
    pub fn connect_with(login: Login, opts: HeadlessOptions) -> Self {
        let recorder = RecordingVerifier::default();
        let verifier = opts
            .verifier
            .unwrap_or_else(|| Arc::new(recorder.clone()) as Arc<dyn HostKeyVerifier>);
        let auth = opts
            .authenticator
            .unwrap_or_else(|| Arc::new(ChainAuthenticator::new()) as Arc<dyn Authenticator>);
        let label = login.host.clone();
        let port = login.port;
        let user = login.user.clone();
        // M2-07
        let source = opts.agent.as_ref().map(|(_, s)| *s);
        let mut connector = SshConnector::new(Arc::new(LoginResolver(login, source)))
            .with_verifier(verifier)
            .with_authenticator(auth);
        if let Some((forwarding, _)) = opts.agent {
            connector = connector.with_agent_forwarding(forwarding);
        }
        let (tx, events) = mpsc::unbounded_channel();
        let mgr = SessionManager::new(tx);
        mgr.register_connector(TransportKind::Ssh, Arc::new(connector));
        #[allow(clippy::expect_used)]
        let handle = mgr
            .open_with(
                SessionSpec::Ssh(SshSpec {
                    host: label,
                    port,
                    user: Some(user),
                    ..SshSpec::default()
                }),
                OpenOptions {
                    cols: opts.cols,
                    rows: opts.rows,
                    ..OpenOptions::default()
                },
            )
            .expect("open a headless session");
        Self {
            mgr,
            events,
            handle,
            log: Vec::new(),
            recorder,
            timeout: crate::timeout(),
        }
    }

    /// Use `timeout` instead of [`crate::timeout`] for the waits without one.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The whole emulator grid (scrollback and screen) as text.
    pub fn grid_text(&self) -> String {
        let term = self.handle.term.lock();
        let (cols, rows) = term.size();
        let top = -i32::try_from(term.scrollback_len()).unwrap_or(i32::MAX);
        term.grid_text(
            GridPoint::new(top, 0),
            GridPoint::new(i32::from(rows) - 1, usize::from(cols).saturating_sub(1)),
        )
    }

    /// Every event received so far.
    pub fn events(&self) -> &[SessionEvent] {
        &self.log
    }

    /// Host keys presented to the default [`RecordingVerifier`].
    pub fn host_keys(&self) -> Vec<ServerKey> {
        self.recorder.seen().into_iter().map(|(_, k)| k).collect()
    }

    /// The latest state reported, if any.
    pub fn state(&self) -> Option<&SessionState> {
        self.log.iter().rev().find_map(|e| match e {
            SessionEvent::State(s) => Some(s),
            _ => None,
        })
    }

    fn drain(&mut self) {
        while let Ok((_, ev)) = self.events.try_recv() {
            self.log.push(ev);
        }
    }

    fn failure(&self, what: &str, waited: Duration) -> WaitError {
        WaitError(format!(
            "{what} (waited {waited:?})\n--- screen ---\n{}\n--- events ---\n{}",
            self.grid_text().trim_end(),
            self.event_summary()
        ))
    }

    fn event_summary(&self) -> String {
        let lines: Vec<String> = self
            .log
            .iter()
            .filter(|e| !matches!(e, SessionEvent::Dirty))
            .map(|e| format!("{e:?}"))
            .collect();
        diag::tail(&lines.join("\n"), 60)
    }

    /// Poll the grid until it contains `needle` (plain text, not a regex). Returns the
    /// grid.
    ///
    /// # Errors
    /// Not seen within `timeout`; the error shows the screen and the events.
    pub async fn wait_for_text(
        &mut self,
        needle: &str,
        timeout: Duration,
    ) -> Result<String, WaitError> {
        self.wait_for_grid(&format!("text {needle:?}"), timeout, |g| g.contains(needle))
            .await
    }

    /// Poll the grid until `pred` holds. Returns the grid.
    ///
    /// # Errors
    /// Not satisfied within `timeout`.
    pub async fn wait_for_grid(
        &mut self,
        what: &str,
        timeout: Duration,
        pred: impl Fn(&str) -> bool,
    ) -> Result<String, WaitError> {
        let started = Instant::now();
        loop {
            self.drain();
            let grid = self.grid_text();
            if pred(&grid) {
                return Ok(grid);
            }
            if started.elapsed() > timeout {
                return Err(self.failure(&format!("{what} not on screen"), started.elapsed()));
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Wait for the next event matching `pred` (earlier events stay in
    /// [`Headless::events`]). Returns it.
    ///
    /// # Errors
    /// None within the harness timeout, or the session's event channel closed.
    pub async fn wait_event(
        &mut self,
        what: &str,
        pred: impl Fn(&SessionEvent) -> bool,
    ) -> Result<SessionEvent, WaitError> {
        let started = Instant::now();
        let deadline = tokio::time::Instant::now() + self.timeout;
        loop {
            match tokio::time::timeout_at(deadline, self.events.recv()).await {
                Ok(Some((_, ev))) => {
                    self.log.push(ev.clone());
                    if pred(&ev) {
                        return Ok(ev);
                    }
                }
                Ok(None) => {
                    return Err(
                        self.failure(&format!("{what}: event channel closed"), started.elapsed())
                    );
                }
                Err(_) => {
                    return Err(self.failure(&format!("{what}: no such event"), started.elapsed()));
                }
            }
        }
    }

    /// Wait for a state matching `pred`.
    ///
    /// # Errors
    /// As [`Headless::wait_event`].
    pub async fn wait_state(
        &mut self,
        what: &str,
        pred: impl Fn(&SessionState) -> bool,
    ) -> Result<SessionState, WaitError> {
        match self
            .wait_event(what, |e| matches!(e, SessionEvent::State(s) if pred(s)))
            .await?
        {
            SessionEvent::State(s) => Ok(s),
            _ => unreachable!("filtered on State"),
        }
    }

    /// Wait until the session is `Connected`; fails early if it disconnects.
    ///
    /// # Errors
    /// Disconnected or closed first, or the timeout.
    pub async fn wait_connected(&mut self) -> Result<(), WaitError> {
        let state = self
            .wait_state("Connected", |s| {
                matches!(
                    s,
                    SessionState::Connected { .. }
                        | SessionState::Disconnected { .. }
                        | SessionState::Closed
                )
            })
            .await?;
        match state {
            SessionState::Connected { .. } => Ok(()),
            other => Err(self.failure(
                &format!("expected Connected, got {other:?}"),
                Duration::ZERO,
            )),
        }
    }

    /// Type `text` into the session.
    pub async fn send(&self, text: &str) {
        let _ = self
            .handle
            .cmd_tx
            .send(SessionCmd::Input(Bytes::copy_from_slice(text.as_bytes())))
            .await;
    }

    /// Answer the pending authentication prompt.
    pub async fn answer(&self, responses: &[&str]) {
        let answers = responses.iter().map(|r| SecretString::from(*r)).collect();
        let _ = self
            .handle
            .cmd_tx
            .send(SessionCmd::AuthAnswer(AuthAnswer::Responses(answers)))
            .await;
    }

    /// Resize the session.
    pub async fn resize(&self, cols: u16, rows: u16) {
        let _ = self
            .handle
            .cmd_tx
            .send(SessionCmd::Resize {
                cols,
                rows,
                px_w: 0,
                px_h: 0,
            })
            .await;
    }

    /// Send any command.
    pub async fn cmd(&self, cmd: SessionCmd) {
        let _ = self.handle.cmd_tx.send(cmd).await;
    }

    /// The manager (for more sessions or a shutdown report).
    pub fn manager(&self) -> &SessionManager {
        &self.mgr
    }

    /// Close the session and shut the manager down.
    pub async fn close(self) {
        self.cmd(SessionCmd::Close).await;
        self.mgr.shutdown(Duration::from_secs(2)).await;
    }

    /// Dump the screen and events now ([`diag::dump`]).
    pub fn dump(&self) {
        diag::dump(
            &format!("headless session {:?} screen", self.handle.id),
            &self.grid_text(),
        );
        diag::dump(
            &format!("headless session {:?} events", self.handle.id),
            &self.event_summary(),
        );
    }
}

impl Drop for Headless {
    fn drop(&mut self) {
        if diag::failing() {
            self.drain();
            self.dump();
        }
    }
}
