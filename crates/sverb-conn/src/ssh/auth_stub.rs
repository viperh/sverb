//! The authentication step (SPEC §6.1.1 step 4) behind a seam.
//!
//! [`Authenticator`] runs after the handshake with an [`AuthSession`] (the russh handle,
//! wrapped so russh types stay in this module) and the [`ConnectCtx`] (state inputs,
//! (certificate, key, agent, password with prompt, keyboard-interactive) and adds the
//! matching methods to [`AuthSession`].
//!
//! The stub tries `none`, then `password` with the host's stored password when the
//! server allows it. It never prompts.

use async_trait::async_trait;
use russh::{
    MethodKind,
    client::{AuthResult, Handle},
};
use sverb_core::secret::SecretString;
use tracing::debug;

use super::{errors::SshError, handler::ClientHandler, resolved::SshTarget};
use crate::{session::AuthMethod, session::StateInput, transport::ConnectCtx};

/// The outcome of one authentication request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    /// Authenticated.
    Success,
    /// Rejected. `remaining` is the server's list of methods that can continue
    /// (`publickey`, `password`, …); `partial` means this method succeeded but more are
    /// required.
    Failure {
        /// Methods that can continue.
        remaining: Vec<&'static str>,
        /// Partial success.
        partial: bool,
    },
}

/// The connection being authenticated.
pub struct AuthSession<'a> {
    pub(crate) handle: &'a mut Handle<ClientHandler>,
}

impl std::fmt::Debug for AuthSession<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthSession").finish_non_exhaustive()
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

impl AuthSession<'_> {
    /// `none` (learns the server's method list).
    ///
    /// # Errors
    /// The connection failed.
    pub async fn none(&mut self, user: &str) -> Result<AuthOutcome, russh::Error> {
        self.handle.authenticate_none(user).await.map(outcome)
    }

    /// `password`.
    ///
    /// # Errors
    /// The connection failed.
    pub async fn password(
        &mut self,
        user: &str,
        password: &SecretString,
    ) -> Result<AuthOutcome, russh::Error> {
        // russh takes an owned `String`; it lives only for the request.
        let result = self
            .handle
            .authenticate_password(user, password.expose())
            .await;
        result.map(outcome)
    }
}

/// Runs the authentication step.
#[async_trait]
pub trait Authenticator: Send + Sync + std::fmt::Debug {
    /// Authenticate `host` on `session`, reporting `AuthStarted` per method through
    /// `ctx`. Return `Ok` once authenticated (the connector then sends
    /// `AuthSucceeded`).
    ///
    /// # Errors
    /// [`SshError::Auth`] when every method failed; connection errors otherwise.
    async fn authenticate(
        &self,
        session: &mut AuthSession<'_>,
        host: &SshTarget,
        ctx: &mut ConnectCtx<'_>,
    ) -> Result<(), SshError>;
}

/// The M1 stub: `none`, then the stored password. No prompts, no keys.
#[derive(Debug, Clone, Copy, Default)]
pub struct StubAuthenticator;

fn input(ctx: &mut ConnectCtx<'_>, method: AuthMethod) -> Result<(), SshError> {
    ctx.input(StateInput::AuthStarted(method))
        .map_err(|_| SshError::Protocol("illegal session state".to_owned()))
}

#[async_trait]
impl Authenticator for StubAuthenticator {
    async fn authenticate(
        &self,
        session: &mut AuthSession<'_>,
        host: &SshTarget,
        ctx: &mut ConnectCtx<'_>,
    ) -> Result<(), SshError> {
        let user = host.username.as_str();
        let mut tried = vec!["none"];
        input(ctx, AuthMethod::None)?;
        let remaining = match session.none(user).await.map_err(|e| russh_err(&e, host))? {
            AuthOutcome::Success => return Ok(()),
            AuthOutcome::Failure { remaining, .. } => remaining,
        };
        debug!(session = %ctx.id(), methods = ?remaining, "server auth methods");
        let password_allowed = remaining.contains(&<&'static str>::from(&MethodKind::Password));
        if let (true, Some(password)) = (password_allowed, host.auth.password.as_ref()) {
            tried.push("password");
            input(ctx, AuthMethod::Password)?;
            if session
                .password(user, password)
                .await
                .map_err(|e| russh_err(&e, host))?
                == AuthOutcome::Success
            {
                return Ok(());
            }
        }
        Err(SshError::Auth { tried })
    }
}

fn russh_err(err: &russh::Error, host: &SshTarget) -> SshError {
    super::errors::from_russh(err, host.keepalive_secs, &host.display_addr())
}
