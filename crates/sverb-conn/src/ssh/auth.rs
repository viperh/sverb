//! The authentication chain (SPEC §6.1.1 step 4).
//!
//! After `none` (which learns the server's method list), methods are tried in this order,
//! skipping any the server's latest `USERAUTH_FAILURE` continuation doesn't list:
//!
//! 1. `publickey` with each valid (not expired) certificate attached to the configured key,
//! 2. `publickey` with the configured key: RSA picks `rsa-sha2-512`, then `rsa-sha2-256`
//!    from the server's `server-sig-algs` (RFC 8308); `ssh-rsa` (SHA-1) only with the
//!    host's legacy opt-in, otherwise the key is skipped ([`rsa_hash`]),
//!    An agent / hardware **reference** key (no private part, [`agent_reference`])
//!    is signed by the system agent instead, with that key only,
//! 3. `publickey` through the system agent, one request per identity: **only when no key
//!    is configured** (OpenSSH `IdentitiesOnly`) and `ssh.use_system_agent` is on,
//! 4. `password`: the stored one, then up to [`PASSWORD_PROMPTS`] prompts,
//! 5. `keyboard-interactive`: one dialog per info request. A stored password answers a
//!    request with exactly one non-echo prompt matching `/password/i`, **once** per
//!    connection; everything else is asked.
//!
//! Every request after `none` counts against `ssh.max_auth_attempts` (each key and agent
//! identity is one); at the cap the chain stops with `Permission denied (methods tried:
//! …)`. An encrypted key without a (right) stored passphrase is asked for its passphrase
//! up to [`PASSPHRASE_TRIES`] times, then skipped. Cancelling a prompt skips its method.
//!
//! The chain is written against two seams so unit tests can script both sides:
//! [`AuthBackend`] (the server: russh's auth calls, [`RusshBackend`]) and [`AuthIo`]
//! (the user: state inputs, prompts and answers over the [`ConnectCtx`], [`CtxIo`]).
//! Credentials typed into a prompt are reported with [`AuthIo::accepted`] once the whole
//! authentication succeeded (`SessionEvent::PromptAccepted`), so the UI saves a password
//! or passphrase only when it is known to be right.
//!
//! Server-provided text is untrusted: [`sanitize_server_text`] strips escape sequences
//! and control characters and caps it at [`MAX_SERVER_TEXT`] characters.

use std::{future::Future, sync::Arc};

use async_trait::async_trait;
use russh::{
    client::{AuthResult, KeyboardInteractiveAuthResponse},
    keys::{
        Certificate, HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKey, agent::AgentIdentity,
    },
};
use sverb_core::secret::SecretString;
use tracing::debug;

use super::{
    auth_stub::{AuthOutcome, AuthSession, Authenticator},
    errors::SshError,
    resolved::{KeyMaterial, SshTarget},
};
use crate::{
    agent_client::{Agent, AgentConnector},
    session::{
        AuthAnswer, AuthMethod, AuthPrompt, PromptKind, PromptLine, SessionCmd, SessionEvent,
        SessionState, StateInput,
    },
    transport::ConnectCtx,
};

/// Server-provided prompt text is capped at this many characters.
pub const MAX_SERVER_TEXT: usize = 512;
/// Password prompts after the stored password (OpenSSH `NumberOfPasswordPrompts`).
pub const PASSWORD_PROMPTS: usize = 3;
/// Passphrase prompts for an encrypted key before it is skipped.
pub const PASSPHRASE_TRIES: usize = 3;
/// Keyboard-interactive conversations started per connection.
pub const KBD_ROUNDS: usize = 3;

/// `publickey`.
pub const PUBLICKEY: &str = "publickey";
/// `password`.
pub const PASSWORD: &str = "password";
/// `keyboard-interactive`.
pub const KEYBOARD_INTERACTIVE: &str = "keyboard-interactive";

// ---------------------------------------------------------------- pure helpers

/// Make server-provided text safe to show: ANSI escape sequences (CSI, OSC, DCS, …) and
/// control characters are removed (line breaks are kept as `\n`), and the result is
/// capped at [`MAX_SERVER_TEXT`] characters (`…` marks a cut).
pub fn sanitize_server_text(text: &str) -> String {
    let mut out = String::new();
    let mut count = 0;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        let keep = match c {
            '\u{1b}' => {
                skip_escape(&mut chars);
                None
            }
            // C1 CSI / OSC / DCS / APC / PM / SOS introducers.
            '\u{9b}' => {
                skip_csi(&mut chars);
                None
            }
            '\u{9d}' | '\u{90}' | '\u{9f}' | '\u{9e}' | '\u{98}' => {
                skip_string(&mut chars);
                None
            }
            '\n' => Some('\n'),
            '\t' => Some(' '),
            c if c.is_control() => None,
            // Bidi overrides could reorder what the user reads.
            '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' => None,
            c => Some(c),
        };
        if let Some(c) = keep {
            if count == MAX_SERVER_TEXT {
                out.push('…');
                break;
            }
            out.push(c);
            count += 1;
        }
    }
    out.trim_end().to_owned()
}

fn skip_escape(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    match chars.next() {
        Some('[') => skip_csi(chars),
        Some(']' | 'P' | '_' | '^' | 'X') => skip_string(chars),
        // Two-character sequences (`ESC c`, `ESC 7`, …) and charset selection.
        Some('(' | ')' | '*' | '+' | '#' | '%') => {
            chars.next();
        }
        _ => {}
    }
}

fn skip_csi(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    for c in chars.by_ref() {
        if ('\u{40}'..='\u{7e}').contains(&c) {
            break;
        }
    }
}

fn skip_string(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while let Some(c) = chars.next() {
        match c {
            '\u{7}' | '\u{9c}' => break,
            '\u{1b}' => {
                if chars.peek() == Some(&'\\') {
                    chars.next();
                }
                break;
            }
            _ => {}
        }
    }
}

/// What the server said about RSA signatures (`server-sig-algs`, RFC 8308).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaSigSupport {
    /// `rsa-sha2-512` is offered.
    Sha512,
    /// `rsa-sha2-256` is offered (and not 512).
    Sha256,
    /// Only `ssh-rsa` (SHA-1).
    SshRsaOnly,
    /// No `server-sig-algs`, or it lists no RSA algorithm.
    Unknown,
}

/// The hash for an RSA signature: `Some(Some(h))` → `rsa-sha2-*`, `Some(None)` →
/// `ssh-rsa` (only with `allow_ssh_rsa`), `None` → skip the key.
pub fn rsa_hash(support: RsaSigSupport, allow_ssh_rsa: bool) -> Option<Option<HashAlg>> {
    match support {
        RsaSigSupport::Sha512 => Some(Some(HashAlg::Sha512)),
        RsaSigSupport::Sha256 => Some(Some(HashAlg::Sha256)),
        RsaSigSupport::SshRsaOnly | RsaSigSupport::Unknown if allow_ssh_rsa => Some(None),
        RsaSigSupport::SshRsaOnly | RsaSigSupport::Unknown => None,
    }
}

/// Whether a keyboard-interactive request may be answered with the stored password:
/// exactly one non-echo prompt mentioning "password" (any case).
pub fn is_password_request(prompts: &[PromptLine]) -> bool {
    matches!(prompts, [p] if !p.echo && p.text.to_lowercase().contains("password"))
}

/// Whether `cert` certifies `key` and is valid at `now` (Unix seconds).
pub fn cert_usable(cert: &Certificate, key: &PrivateKey, now: u64) -> bool {
    cert.public_key() == key.public_key().key_data()
        && cert.valid_after() <= now
        && now < cert.valid_before()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// ---------------------------------------------------------------- seams

/// A keyboard-interactive reply from the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KbdReply {
    /// Authenticated.
    Success,
    /// Rejected (see [`AuthOutcome::Failure`]).
    Failure {
        /// Methods that can continue.
        remaining: Vec<&'static str>,
        /// Partial success.
        partial: bool,
    },
    /// An info request (raw server text; the chain sanitizes it).
    Info {
        /// Name.
        name: String,
        /// Instruction.
        instruction: String,
        /// Prompts.
        prompts: Vec<PromptLine>,
    },
}

/// The server side of the chain (russh's auth calls; scripted in unit tests).
#[async_trait]
pub trait AuthBackend: Send {
    /// `none`.
    async fn none(&mut self, user: &str) -> Result<AuthOutcome, SshError>;
    /// `password`.
    async fn password(
        &mut self,
        user: &str,
        password: &SecretString,
    ) -> Result<AuthOutcome, SshError>;
    /// `publickey` with a private key (`hash`: RSA signature hash, `None` = SHA-1).
    async fn publickey(
        &mut self,
        user: &str,
        key: Arc<PrivateKey>,
        hash: Option<HashAlg>,
    ) -> Result<AuthOutcome, SshError>;
    /// `publickey` with an OpenSSH certificate.
    async fn certificate(
        &mut self,
        user: &str,
        key: Arc<PrivateKey>,
        cert: Certificate,
    ) -> Result<AuthOutcome, SshError>;
    /// `publickey` with an agent identity, signed by `agent`.
    async fn agent_identity(
        &mut self,
        user: &str,
        agent: &mut dyn Agent,
        identity: &AgentIdentity,
        hash: Option<HashAlg>,
    ) -> Result<AuthOutcome, SshError>;
    /// Start `keyboard-interactive`.
    async fn kbd_start(&mut self, user: &str) -> Result<KbdReply, SshError>;
    /// Answer an info request.
    async fn kbd_respond(&mut self, answers: &[SecretString]) -> Result<KbdReply, SshError>;
    /// What `server-sig-algs` says about RSA (asked only when an RSA key is used).
    async fn rsa_support(&mut self) -> RsaSigSupport;
}

/// The user side of the chain.
#[async_trait]
pub trait AuthIo: Send {
    /// Trying `method` (`AuthStarted`).
    ///
    /// # Errors
    /// The state machine refused (a bug; the session is already disconnected).
    fn started(&mut self, method: AuthMethod) -> Result<(), SshError>;

    /// Ask the user. `Ok(Some(answers))`: one per prompt line; `Ok(None)`: cancelled.
    ///
    /// # Errors
    /// The session was closed while asking.
    async fn ask(&mut self, prompt: AuthPrompt) -> Result<Option<Vec<SecretString>>, SshError>;

    /// The answer to a prompt of `kind` was part of the successful authentication.
    fn accepted(&mut self, kind: PromptKind);
}

// ---------------------------------------------------------------- answers

#[cfg(test)]
thread_local! {
    /// T-18 hook: answer buffers dropped on this thread.
    pub(crate) static ANSWERS_DROPPED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The user's answers to one prompt. Each is a [`SecretString`] (zeroized on drop); the
/// buffer is dropped as soon as the request using it returns.
struct Answers(Vec<SecretString>);

impl Drop for Answers {
    fn drop(&mut self) {
        #[cfg(test)]
        ANSWERS_DROPPED.with(|c| c.set(c.get() + 1));
    }
}

// ---------------------------------------------------------------- the chain

/// What the chain needs from the target.
#[derive(Debug)]
pub struct ChainTarget<'a> {
    /// Login user.
    pub user: &'a str,
    /// Shown as `Authenticate to <label>`.
    pub label: &'a str,
    /// `user@host` for the password prompt.
    pub user_at_host: String,
    /// The saved host (where a typed password can be saved).
    pub host_id: Option<sverb_core::model::ItemId>,
    /// Credentials and limits.
    pub auth: &'a super::resolved::AuthMaterial,
}

impl<'a> ChainTarget<'a> {
    /// From a resolved target.
    pub fn of(host: &'a SshTarget) -> Self {
        Self {
            user: &host.username,
            label: &host.label,
            user_at_host: format!("{}@{}", host.username, host.address),
            host_id: host.host_id,
            auth: &host.auth,
        }
    }
}

struct Chain<'t, 'x> {
    t: &'t ChainTarget<'t>,
    backend: &'x mut (dyn AuthBackend + 'x),
    io: &'x mut (dyn AuthIo + 'x),
    allowed: Option<Vec<&'static str>>,
    attempts: u32,
    max: u32,
    tried: Vec<&'static str>,
    accepted: Vec<PromptKind>,
    kbd_auto_used: bool,
    rsa: Option<RsaSigSupport>,
    agent: Option<Arc<dyn AgentConnector>>,
}

/// How a step ended.
enum Flow {
    /// Authenticated.
    Done,
    /// Go on with the next step.
    Next,
    /// Stop: the attempt cap is reached, or the server takes nothing more.
    Stop,
}

impl Chain<'_, '_> {
    fn allows(&self, method: &str) -> bool {
        self.allowed.as_ref().is_none_or(|l| l.contains(&method))
    }

    fn exhausted(&self) -> bool {
        self.attempts >= self.max || self.allowed.as_ref().is_some_and(Vec::is_empty)
    }

    /// Count one request for `method`. `false`: the cap is reached (nothing sent).
    fn attempt(&mut self, method: &'static str) -> bool {
        if self.attempts >= self.max {
            debug!(max = self.max, "authentication attempt cap reached");
            return false;
        }
        self.attempts += 1;
        if !self.tried.contains(&method) {
            self.tried.push(method);
        }
        true
    }

    /// Apply an outcome: `true` when authenticated. Partial success means this step
    /// counted; the remaining list decides what follows.
    fn outcome(&mut self, outcome: AuthOutcome) -> (bool, bool) {
        match outcome {
            AuthOutcome::Success => (true, true),
            AuthOutcome::Failure { remaining, partial } => {
                debug!(methods = ?remaining, partial, "authentication continues");
                self.allowed = Some(remaining);
                (false, partial)
            }
        }
    }

    fn title(&self) -> String {
        format!("Authenticate to {}", self.t.label)
    }

    async fn rsa_support(&mut self) -> RsaSigSupport {
        if let Some(s) = self.rsa {
            return s;
        }
        let s = self.backend.rsa_support().await;
        debug!(?s, "server-sig-algs (RSA)");
        self.rsa = Some(s);
        s
    }

    /// The RSA hash for `key`, or `None` to skip it (`Some(None)` for non-RSA keys).
    async fn hash_for(&mut self, is_rsa: bool) -> Option<Option<HashAlg>> {
        if !is_rsa {
            return Some(None);
        }
        let support = self.rsa_support().await;
        let hash = rsa_hash(support, self.t.auth.allow_ssh_rsa);
        if hash.is_none() {
            debug!(
                ?support,
                "RSA key skipped: the server offers no rsa-sha2-* signature and ssh-rsa (SHA-1) is not enabled for this host"
            );
        }
        hash
    }

    async fn run(&mut self) -> Result<(), SshError> {
        self.io.started(AuthMethod::None)?;
        match self.backend.none(self.t.user).await? {
            AuthOutcome::Success => return Ok(()),
            AuthOutcome::Failure { remaining, .. } => {
                debug!(methods = ?remaining, "server auth methods");
                self.allowed = Some(remaining);
            }
        }
        for step in 0..4 {
            if self.exhausted() {
                break;
            }
            let flow = match step {
                0 => self.key_steps().await?,
                1 => self.agent_step().await?,
                2 => self.password_step().await?,
                _ => self.kbd_step().await?,
            };
            match flow {
                Flow::Done => {
                    for kind in std::mem::take(&mut self.accepted) {
                        self.io.accepted(kind);
                    }
                    return Ok(());
                }
                Flow::Next => {}
                Flow::Stop => break,
            }
        }
        Err(SshError::Auth {
            tried: self.tried.clone(),
        })
    }

    // ------------------------------------------------------------ 1–2: cert, key

    async fn key_steps(&mut self) -> Result<Flow, SshError> {
        let Some(km) = self.t.auth.key.as_ref() else {
            if self.t.auth.key_id.is_some() {
                debug!("the configured key could not be read; no key is offered");
            }
            return Ok(Flow::Next);
        };
        if !self.allows(PUBLICKEY) {
            return Ok(Flow::Next);
        }
        // An agent / hardware reference key: the system agent signs with it.
        if let Some(public) = agent_reference(km) {
            return self.agent_ref_step(&public).await;
        }
        self.io.started(AuthMethod::PublicKey)?;
        let Some((key, prompted)) = self.load_key(km).await? else {
            return Ok(Flow::Next);
        };
        let passphrase = prompted.then(|| PromptKind::Passphrase {
            key: km.key_id,
            label: km.label.clone(),
        });
        let now = unix_now();
        // 1. Certificates attached to the key.
        for text in &km.certificates {
            let Ok(cert) = Certificate::from_openssh(text.trim()) else {
                debug!("an attached certificate could not be parsed; skipped");
                continue;
            };
            if !cert_usable(&cert, &key, now) {
                debug!(
                    key_id = cert.key_id(),
                    "certificate skipped: expired, not yet valid, or for another key"
                );
                continue;
            }
            if !self.allows(PUBLICKEY) {
                return Ok(Flow::Next);
            }
            if !self.attempt(PUBLICKEY) {
                return Ok(Flow::Stop);
            }
            let out = self
                .backend
                .certificate(self.t.user, Arc::clone(&key), cert)
                .await?;
            if let Some(flow) = self.after(out, passphrase.as_ref()) {
                return Ok(flow);
            }
        }
        // 2. The key itself.
        if !self.allows(PUBLICKEY) {
            return Ok(Flow::Next);
        }
        let Some(hash) = self.hash_for(key.algorithm().is_rsa()).await else {
            return Ok(Flow::Next);
        };
        if !self.attempt(PUBLICKEY) {
            return Ok(Flow::Stop);
        }
        let out = self.backend.publickey(self.t.user, key, hash).await?;
        Ok(self.after(out, passphrase.as_ref()).unwrap_or(Flow::Next))
    }

    /// `Some(flow)` to leave the step (success); `None` to go on. Records a prompted
    /// credential used by a successful (or partially successful) request.
    fn after(&mut self, out: AuthOutcome, prompted: Option<&PromptKind>) -> Option<Flow> {
        let (done, partial) = self.outcome(out);
        if (done || partial)
            && let Some(kind) = prompted
            && !self.accepted.contains(kind)
        {
            self.accepted.push(kind.clone());
        }
        if done {
            return Some(Flow::Done);
        }
        self.exhausted().then_some(Flow::Stop)
    }

    /// Parse and, when encrypted, decrypt the key (stored passphrase, then prompts).
    /// `None`: skip the key. The flag says the passphrase was typed by the user.
    async fn load_key(
        &mut self,
        km: &KeyMaterial,
    ) -> Result<Option<(Arc<PrivateKey>, bool)>, SshError> {
        let key = match PrivateKey::from_openssh(km.private_key.expose().trim()) {
            Ok(key) => key,
            Err(err) => {
                debug!(%err, "the configured key could not be parsed; skipped");
                return Ok(None);
            }
        };
        if !key.is_encrypted() {
            return Ok(Some((Arc::new(key), false)));
        }
        if let Some(stored) = &km.passphrase {
            match key.decrypt(stored.expose().as_bytes()) {
                Ok(k) => return Ok(Some((Arc::new(k), false))),
                Err(_) => debug!("the stored passphrase does not decrypt the key"),
            }
        }
        let kind = PromptKind::Passphrase {
            key: km.key_id,
            label: km.label.clone(),
        };
        for n in 0..PASSPHRASE_TRIES {
            let mut prompt = AuthPrompt::new(
                kind.clone(),
                self.title(),
                vec![PromptLine {
                    text: "Passphrase:".to_owned(),
                    echo: false,
                }],
            );
            prompt.instruction = format!("Passphrase for key \"{}\"", km.label);
            if n > 0 {
                prompt
                    .instruction
                    .push_str("\nWrong passphrase, try again.");
            }
            let Some(answers) = self.io.ask(prompt).await?.map(Answers) else {
                debug!("passphrase prompt cancelled; key skipped");
                return Ok(None);
            };
            let pass = answers.0.first().map_or("", |a| a.expose());
            if let Ok(k) = key.decrypt(pass.as_bytes()) {
                return Ok(Some((Arc::new(k), true)));
            }
            debug!(try_ = n + 1, "wrong passphrase");
        }
        debug!("no right passphrase after {PASSPHRASE_TRIES} tries; key skipped");
        Ok(None)
    }

    /// The configured key is an agent / hardware reference (SPEC §9.4): ask the system
    /// agent to sign with **that** key only (IdentitiesOnly still holds). Skipped when
    /// the agent is unavailable or doesn't hold the key. Independent of
    /// `ssh.use_system_agent`, which governs offering every agent identity.
    async fn agent_ref_step(&mut self, public: &PublicKey) -> Result<Flow, SshError> {
        let Some(connector) = self.agent.clone() else {
            debug!("agent reference key: no system agent; skipped");
            return Ok(Flow::Next);
        };
        let mut agent = match connector.connect().await {
            Ok(agent) => agent,
            Err(err) => {
                debug!(%err, "agent reference key: system agent unavailable; skipped");
                return Ok(Flow::Next);
            }
        };
        let identities = match agent.identities().await {
            Ok(ids) => ids,
            Err(err) => {
                debug!(%err, "agent reference key: listing identities failed; skipped");
                return Ok(Flow::Next);
            }
        };
        let Some(identity) = identities
            .iter()
            .find(|i| i.public_key().key_data() == public.key_data())
        else {
            debug!("agent reference key: the system agent does not hold it; skipped");
            return Ok(Flow::Next);
        };
        self.io.started(AuthMethod::Agent)?;
        let Some(hash) = self.hash_for(public.algorithm().is_rsa()).await else {
            return Ok(Flow::Next);
        };
        if !self.attempt(PUBLICKEY) {
            return Ok(Flow::Stop);
        }
        let out = self
            .backend
            .agent_identity(self.t.user, agent.as_mut(), identity, hash)
            .await?;
        Ok(self.after(out, None).unwrap_or(Flow::Next))
    }

    // ------------------------------------------------------------ 3: system agent

    async fn agent_step(&mut self) -> Result<Flow, SshError> {
        // IdentitiesOnly: a configured key (even one we couldn't read) turns the agent off.
        if self.t.auth.key_id.is_some() || self.t.auth.key.is_some() {
            return Ok(Flow::Next);
        }
        if !self.t.auth.use_system_agent || !self.allows(PUBLICKEY) {
            return Ok(Flow::Next);
        }
        let Some(connector) = self.agent.clone() else {
            return Ok(Flow::Next);
        };
        let mut agent = match connector.connect().await {
            Ok(agent) => agent,
            Err(err) => {
                debug!(%err, "system agent unavailable; skipped");
                return Ok(Flow::Next);
            }
        };
        let identities = match agent.identities().await {
            Ok(ids) => ids,
            Err(err) => {
                debug!(%err, "system agent: listing identities failed; skipped");
                return Ok(Flow::Next);
            }
        };
        debug!(count = identities.len(), "system agent identities");
        self.io.started(AuthMethod::Agent)?;
        for identity in &identities {
            if !self.allows(PUBLICKEY) {
                return Ok(Flow::Next);
            }
            let is_rsa = identity.public_key().algorithm().is_rsa();
            let Some(hash) = self.hash_for(is_rsa).await else {
                continue;
            };
            if !self.attempt(PUBLICKEY) {
                return Ok(Flow::Stop);
            }
            let out = self
                .backend
                .agent_identity(self.t.user, agent.as_mut(), identity, hash)
                .await?;
            if let Some(flow) = self.after(out, None) {
                return Ok(flow);
            }
        }
        Ok(Flow::Next)
    }

    // ------------------------------------------------------------ 4: password

    async fn password_step(&mut self) -> Result<Flow, SshError> {
        if !self.allows(PASSWORD) {
            return Ok(Flow::Next);
        }
        self.io.started(AuthMethod::Password)?;
        if let Some(stored) = self.t.auth.password.as_ref() {
            if !self.attempt(PASSWORD) {
                return Ok(Flow::Stop);
            }
            let out = self.backend.password(self.t.user, stored).await?;
            if let Some(flow) = self.after(out, None) {
                return Ok(flow);
            }
        }
        let kind = PromptKind::Password {
            host: self.t.host_id,
        };
        let mut retry = self.t.auth.password.is_some();
        for _ in 0..PASSWORD_PROMPTS {
            if !self.allows(PASSWORD) {
                return Ok(Flow::Next);
            }
            if self.attempts >= self.max {
                return Ok(Flow::Stop);
            }
            let mut prompt = AuthPrompt::new(
                kind.clone(),
                self.title(),
                vec![PromptLine {
                    text: "Password:".to_owned(),
                    echo: false,
                }],
            );
            prompt.instruction = format!("Password for {}", self.t.user_at_host);
            if retry {
                prompt
                    .instruction
                    .push_str("\nPermission denied, please try again.");
            }
            let Some(answers) = self.io.ask(prompt).await?.map(Answers) else {
                debug!("password prompt cancelled");
                return Ok(Flow::Next);
            };
            if !self.attempt(PASSWORD) {
                return Ok(Flow::Stop);
            }
            let empty = SecretString::from("");
            let password = answers.0.first().unwrap_or(&empty);
            let out = self.backend.password(self.t.user, password).await?;
            drop(answers);
            if let Some(flow) = self.after(out, Some(&kind)) {
                return Ok(flow);
            }
            retry = true;
        }
        Ok(Flow::Next)
    }

    // ------------------------------------------------------------ 5: keyboard-interactive

    async fn kbd_step(&mut self) -> Result<Flow, SshError> {
        for _ in 0..KBD_ROUNDS {
            if !self.allows(KEYBOARD_INTERACTIVE) {
                return Ok(Flow::Next);
            }
            self.io.started(AuthMethod::KeyboardInteractive)?;
            if !self.attempt(KEYBOARD_INTERACTIVE) {
                return Ok(Flow::Stop);
            }
            let mut reply = self.backend.kbd_start(self.t.user).await?;
            loop {
                match reply {
                    KbdReply::Success => return Ok(Flow::Done),
                    KbdReply::Failure { remaining, partial } => {
                        if let Some(flow) =
                            self.after(AuthOutcome::Failure { remaining, partial }, None)
                        {
                            return Ok(flow);
                        }
                        break;
                    }
                    KbdReply::Info {
                        name,
                        instruction,
                        prompts,
                    } => {
                        let Some(answers) = self.kbd_answers(&name, &instruction, prompts).await?
                        else {
                            debug!("keyboard-interactive prompt cancelled");
                            return Ok(Flow::Next);
                        };
                        reply = self.backend.kbd_respond(&answers.0).await?;
                    }
                }
            }
        }
        Ok(Flow::Next)
    }

    /// Answers for one info request: none needed, the stored password once, or a dialog.
    async fn kbd_answers(
        &mut self,
        name: &str,
        instruction: &str,
        prompts: Vec<PromptLine>,
    ) -> Result<Option<Answers>, SshError> {
        if prompts.is_empty() {
            return Ok(Some(Answers(Vec::new())));
        }
        if !self.kbd_auto_used
            && is_password_request(&prompts)
            && let Some(stored) = self.t.auth.password.as_ref()
        {
            debug!("keyboard-interactive: answered with the stored password (once)");
            self.kbd_auto_used = true;
            return Ok(Some(Answers(vec![SecretString::from(stored.expose())])));
        }
        let n = prompts.len();
        let mut prompt = AuthPrompt::new(
            PromptKind::KeyboardInteractive,
            self.title(),
            prompts
                .into_iter()
                .map(|p| PromptLine {
                    text: sanitize_server_text(&p.text),
                    echo: p.echo,
                })
                .collect(),
        );
        prompt.name = sanitize_server_text(name);
        prompt.instruction = sanitize_server_text(instruction);
        Ok(self.io.ask(prompt).await?.map(|mut a| {
            a.resize_with(n, || SecretString::from(""));
            Answers(a)
        }))
    }
}

/// The public key of an agent / hardware reference key (SPEC §9.4). Such a Key item has
/// no private key; the resolver (`sverb-tui` `services::ssh::key_material`) hands its
/// OpenSSH **public** line in [`KeyMaterial::private_key`], which never parses as a
/// private key. `None` for a real private key (PEM armor) or anything unparseable.
pub fn agent_reference(km: &KeyMaterial) -> Option<PublicKey> {
    let text = km.private_key.expose().trim();
    if text.is_empty() || text.starts_with("-----") {
        return None;
    }
    PublicKey::from_openssh(text).ok()
}

/// Run the chain for `target` against `backend`, asking through `io`; `agent` is the
/// system agent (`None`: no agent step).
///
/// # Errors
/// [`SshError::Auth`] with the methods tried when nothing worked; connection errors.
pub async fn run_chain(
    target: &ChainTarget<'_>,
    backend: &mut (dyn AuthBackend + '_),
    io: &mut (dyn AuthIo + '_),
    agent: Option<Arc<dyn AgentConnector>>,
) -> Result<(), SshError> {
    let max = target.auth.max_attempts.max(1);
    let mut chain = Chain {
        t: target,
        backend,
        io,
        allowed: None,
        attempts: 0,
        max,
        tried: Vec::new(),
        accepted: Vec::new(),
        kbd_auto_used: false,
        rsa: None,
        agent,
    };
    chain.run().await
}

// ---------------------------------------------------------------- russh backend

/// [`AuthBackend`] over the russh connection.
pub struct RusshBackend<'s, 'h> {
    session: &'s mut AuthSession<'h>,
    keepalive_secs: u32,
    addr: String,
}

impl std::fmt::Debug for RusshBackend<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RusshBackend").finish_non_exhaustive()
    }
}

impl<'s, 'h> RusshBackend<'s, 'h> {
    /// A backend for `session` connected to `host`.
    pub fn new(session: &'s mut AuthSession<'h>, host: &SshTarget) -> Self {
        Self {
            session,
            keepalive_secs: host.keepalive_secs,
            addr: host.display_addr(),
        }
    }

    fn err(&self, err: &russh::Error) -> SshError {
        super::errors::from_russh(err, self.keepalive_secs, &self.addr)
    }
}

fn outcome(result: AuthResult) -> AuthOutcome {
    match result {
        AuthResult::Success => AuthOutcome::Success,
        AuthResult::Failure {
            remaining_methods,
            partial_success,
        } => AuthOutcome::Failure {
            remaining: remaining_methods.iter().map(<&'static str>::from).collect(),
            partial: partial_success,
        },
    }
}

fn kbd(reply: KeyboardInteractiveAuthResponse) -> KbdReply {
    match reply {
        KeyboardInteractiveAuthResponse::Success => KbdReply::Success,
        KeyboardInteractiveAuthResponse::Failure {
            remaining_methods,
            partial_success,
        } => KbdReply::Failure {
            remaining: remaining_methods.iter().map(<&'static str>::from).collect(),
            partial: partial_success,
        },
        KeyboardInteractiveAuthResponse::InfoRequest {
            name,
            instructions,
            prompts,
        } => KbdReply::Info {
            name,
            instruction: instructions,
            prompts: prompts
                .into_iter()
                .map(|p| PromptLine {
                    text: p.prompt,
                    echo: p.echo,
                })
                .collect(),
        },
    }
}

/// Signs auth requests through an [`Agent`] for russh.
struct AgentSigner<'a> {
    agent: &'a mut dyn Agent,
}

/// An agent signing failure, for russh.
#[derive(Debug)]
struct SignError(String);

impl From<russh::SendError> for SignError {
    fn from(err: russh::SendError) -> Self {
        Self(err.to_string())
    }
}

impl russh::Signer for AgentSigner<'_> {
    type Error = SignError;

    #[allow(clippy::manual_async_fn)]
    fn auth_sign(
        &mut self,
        key: &AgentIdentity,
        hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + Send {
        async move {
            self.agent
                .sign(key, hash_alg, to_sign)
                .await
                .map_err(|e| SignError(e.0))
        }
    }
}

#[async_trait]
impl AuthBackend for RusshBackend<'_, '_> {
    async fn none(&mut self, user: &str) -> Result<AuthOutcome, SshError> {
        let r = self.session.handle.authenticate_none(user).await;
        r.map(outcome).map_err(|e| self.err(&e))
    }

    async fn password(
        &mut self,
        user: &str,
        password: &SecretString,
    ) -> Result<AuthOutcome, SshError> {
        // russh takes an owned `String`; it lives only for the request.
        let r = self
            .session
            .handle
            .authenticate_password(user, password.expose())
            .await;
        r.map(outcome).map_err(|e| self.err(&e))
    }

    async fn publickey(
        &mut self,
        user: &str,
        key: Arc<PrivateKey>,
        hash: Option<HashAlg>,
    ) -> Result<AuthOutcome, SshError> {
        let key = PrivateKeyWithHashAlg::new(key, hash);
        debug!(algorithm = %key.algorithm(), "publickey");
        let r = self.session.handle.authenticate_publickey(user, key).await;
        r.map(outcome).map_err(|e| self.err(&e))
    }

    async fn certificate(
        &mut self,
        user: &str,
        key: Arc<PrivateKey>,
        cert: Certificate,
    ) -> Result<AuthOutcome, SshError> {
        let r = self
            .session
            .handle
            .authenticate_openssh_cert(user, key, cert)
            .await;
        r.map(outcome).map_err(|e| self.err(&e))
    }

    async fn agent_identity(
        &mut self,
        user: &str,
        agent: &mut dyn Agent,
        identity: &AgentIdentity,
        hash: Option<HashAlg>,
    ) -> Result<AuthOutcome, SshError> {
        let mut signer = AgentSigner { agent };
        let r = match identity {
            AgentIdentity::PublicKey { key, .. } => {
                self.session
                    .handle
                    .authenticate_publickey_with(user, key.clone(), hash, &mut signer)
                    .await
            }
            AgentIdentity::Certificate { certificate, .. } => {
                self.session
                    .handle
                    .authenticate_certificate_with(user, certificate.clone(), hash, &mut signer)
                    .await
            }
        };
        r.map(outcome)
            .map_err(|e| SshError::Protocol(format!("the ssh agent could not sign: {}", e.0)))
    }

    async fn kbd_start(&mut self, user: &str) -> Result<KbdReply, SshError> {
        let r = self
            .session
            .handle
            .authenticate_keyboard_interactive_start(user, None::<String>)
            .await;
        r.map(kbd).map_err(|e| self.err(&e))
    }

    async fn kbd_respond(&mut self, answers: &[SecretString]) -> Result<KbdReply, SshError> {
        // russh takes owned `String`s; they live only for the request.
        let responses = answers.iter().map(|a| a.expose().to_owned()).collect();
        let r = self
            .session
            .handle
            .authenticate_keyboard_interactive_respond(responses)
            .await;
        r.map(kbd).map_err(|e| self.err(&e))
    }

    async fn rsa_support(&mut self) -> RsaSigSupport {
        match self.session.handle.best_supported_rsa_hash().await {
            Ok(Some(Some(HashAlg::Sha512))) => RsaSigSupport::Sha512,
            Ok(Some(Some(HashAlg::Sha256))) => RsaSigSupport::Sha256,
            Ok(Some(None)) => RsaSigSupport::SshRsaOnly,
            _ => RsaSigSupport::Unknown,
        }
    }
}

// ---------------------------------------------------------------- ConnectCtx io

/// [`AuthIo`] over the connect context: state inputs, `SessionEvent::Prompt`, and
/// `SessionCmd::AuthAnswer` back. No timeout: the user may be fetching a 2FA token.
pub struct CtxIo<'c, 'a> {
    ctx: &'c mut ConnectCtx<'a>,
}

impl std::fmt::Debug for CtxIo<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CtxIo").finish_non_exhaustive()
    }
}

impl<'c, 'a> CtxIo<'c, 'a> {
    /// Prompts over `ctx`.
    pub fn new(ctx: &'c mut ConnectCtx<'a>) -> Self {
        Self { ctx }
    }
}

fn state_err() -> SshError {
    SshError::Protocol("illegal session state".to_owned())
}

#[async_trait]
impl AuthIo for CtxIo<'_, '_> {
    fn started(&mut self, method: AuthMethod) -> Result<(), SshError> {
        if let SessionState::Authenticating { method: m, .. } = self.ctx.state()
            && *m == method
        {
            return Ok(());
        }
        self.ctx
            .input(StateInput::AuthStarted(method))
            .map_err(|_| state_err())
    }

    async fn ask(&mut self, prompt: AuthPrompt) -> Result<Option<Vec<SecretString>>, SshError> {
        self.ctx
            .input(StateInput::PromptNeeded(prompt.clone()))
            .map_err(|_| state_err())?;
        let shown = match self.ctx.state() {
            SessionState::AwaitingUser(p) => p.clone(),
            _ => prompt,
        };
        self.ctx.emit(SessionEvent::Prompt(shown));
        let answer = loop {
            match self.ctx.next_cmd().await {
                Some(SessionCmd::AuthAnswer(AuthAnswer::Responses(answers))) => {
                    break Some(answers);
                }
                Some(SessionCmd::AuthAnswer(AuthAnswer::Cancel)) => break None,
                Some(other) => debug!(cmd = other.name(), "ignored while asking to authenticate"),
                // Closed by the user: the actor sees the `Close` and ends in `Closed`.
                None => return Err(SshError::Protocol("closed while authenticating".to_owned())),
            }
        };
        self.ctx
            .input(StateInput::PromptAnswered)
            .map_err(|_| state_err())?;
        Ok(answer)
    }

    fn accepted(&mut self, kind: PromptKind) {
        self.ctx.emit(SessionEvent::PromptAccepted(kind));
    }
}

// ---------------------------------------------------------------- the authenticator

/// The full chain (see the module docs). Without an agent connector (the default) the
/// agent step is skipped; the TUI sets the system agent ([`crate::agent_client::SystemAgent`]).
#[derive(Debug, Clone, Default)]
pub struct ChainAuthenticator {
    agent: Option<Arc<dyn AgentConnector>>,
}

impl ChainAuthenticator {
    /// The chain without an agent.
    pub fn new() -> Self {
        Self::default()
    }

    /// Offer `agent`'s identities (when no key is configured and
    /// `ssh.use_system_agent` is on).
    #[must_use]
    pub fn with_agent(mut self, agent: Arc<dyn AgentConnector>) -> Self {
        self.agent = Some(agent);
        self
    }
}

#[async_trait]
impl Authenticator for ChainAuthenticator {
    async fn authenticate(
        &self,
        session: &mut AuthSession<'_>,
        host: &SshTarget,
        ctx: &mut ConnectCtx<'_>,
    ) -> Result<(), SshError> {
        let target = ChainTarget::of(host);
        let mut backend = RusshBackend::new(session, host);
        let mut io = CtxIo::new(ctx);
        let result = run_chain(&target, &mut backend, &mut io, self.agent.clone()).await;
        if let Err(SshError::Auth { tried }) = &result {
            debug!(?tried, "authentication failed");
        }
        result
    }
}
