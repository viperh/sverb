//! M1-14 test support (`test-util`): the in-process russh server with configurable
//! authentication: `publickey` (authorized keys, a trusted user CA for certificates),
//! `password`, a scripted `keyboard-interactive` conversation, the method list it
//! advertises (kept on every rejection, as OpenSSH does), `server-sig-algs` (RFC 8308;
//! russh advertises its host-key preference list) and `MaxAuthTries`.
//!
//! Sessions behave like [`TestServer`](super::testing::TestServer)'s (the channel
//! handlers delegate to it), so a successful login gets the same shell.

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::{borrow::Cow, net::SocketAddr, sync::Arc, time::Duration};

use parking_lot::Mutex;
use russh::{
    Channel, ChannelId, MethodKind, MethodSet, Preferred, Pty,
    keys::{
        Algorithm, Certificate, HashAlg, PrivateKey, PublicKey, ssh_key::private::Ed25519Keypair,
    },
    server::{self, Auth, ChannelOpenHandle, Msg, Response, Session},
};
use tokio::net::TcpListener;

use super::testing::{Seen, TestServer};

/// One keyboard-interactive info request and the answers it expects.
#[derive(Debug, Clone)]
pub struct KbdRound {
    pub name: &'static str,
    pub instructions: String,
    /// `(prompt, echo)`.
    pub prompts: Vec<(&'static str, bool)>,
    pub expect: Vec<&'static str>,
}

/// How the server authenticates.
#[derive(Debug, Clone)]
pub struct AuthPolicy {
    /// Advertised methods (returned with every rejection).
    pub methods: MethodSet,
    /// The accepted password.
    pub password: Option<&'static str>,
    /// Accepted public keys.
    pub authorized: Vec<PublicKey>,
    /// Certificates signed by this CA are accepted (`TrustedUserCAKeys`).
    pub trusted_ca: Option<PublicKey>,
    /// The keyboard-interactive conversation (every round must be answered right).
    pub kbd: Vec<KbdRound>,
    /// `MaxAuthTries` (russh counts every rejection, `none` included). 0: unlimited.
    pub max_auth_attempts: usize,
    /// Signature algorithms advertised in `server-sig-algs` (and accepted as host keys).
    pub sig_algs: Option<Vec<Algorithm>>,
}

impl Default for AuthPolicy {
    fn default() -> Self {
        Self {
            methods: MethodSet::from(
                &[
                    MethodKind::PublicKey,
                    MethodKind::Password,
                    MethodKind::KeyboardInteractive,
                ][..],
            ),
            password: None,
            authorized: Vec::new(),
            trusted_ca: None,
            kbd: Vec::new(),
            max_auth_attempts: 0,
            sig_algs: None,
        }
    }
}

/// What the server saw during authentication, in order: `none`, `password`,
/// `publickey:<type>` (offered), `cert:<key id>`, `kbd`, `kbd-answer`.
#[derive(Debug, Default)]
pub struct AuthSeen {
    pub requests: Vec<String>,
}

/// The server handler.
#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct AuthServer {
    inner: TestServer,
    policy: Arc<AuthPolicy>,
    pub auth: Arc<Mutex<AuthSeen>>,
    round: usize,
}

impl AuthServer {
    fn reject(&self) -> Auth {
        Auth::Reject {
            proceed_with_methods: Some(self.policy.methods.clone()),
            partial_success: false,
        }
    }

    fn note(&self, what: String) {
        self.auth.lock().requests.push(what);
    }

    fn kbd_round(&self) -> Auth {
        let r = &self.policy.kbd[self.round];
        Auth::Partial {
            name: Cow::Borrowed(r.name),
            instructions: Cow::Owned(r.instructions.clone()),
            prompts: Cow::Owned(
                r.prompts
                    .iter()
                    .map(|(p, e)| (Cow::Borrowed(*p), *e))
                    .collect(),
            ),
        }
    }
}

impl server::Handler for AuthServer {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        self.note("none".into());
        Ok(self.reject())
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        self.note("password".into());
        self.inner.seen.lock().users.push(user.to_owned());
        Ok(if self.policy.password == Some(password) {
            Auth::Accept
        } else {
            self.reject()
        })
    }

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.note(format!("publickey:{}", key.algorithm().as_str()));
        // russh asks this for a certificate's key too; the CA check comes later.
        let known = self.policy.trusted_ca.is_some()
            || self
                .policy
                .authorized
                .iter()
                .any(|k| k.key_data() == key.key_data());
        Ok(if known { Auth::Accept } else { self.reject() })
    }

    async fn auth_publickey(&mut self, _user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        let known = self
            .policy
            .authorized
            .iter()
            .any(|k| k.key_data() == key.key_data());
        Ok(if known { Auth::Accept } else { self.reject() })
    }

    async fn auth_openssh_certificate(
        &mut self,
        user: &str,
        cert: &Certificate,
    ) -> Result<Auth, Self::Error> {
        self.note(format!("cert:{}", cert.key_id()));
        let Some(ca) = &self.policy.trusted_ca else {
            return Ok(self.reject());
        };
        let fp = ca.fingerprint(HashAlg::Sha256);
        let ok = cert.validate([&fp]).is_ok() && cert.valid_principals().iter().any(|p| p == user);
        Ok(if ok { Auth::Accept } else { self.reject() })
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        _user: &str,
        _submethods: &str,
        response: Option<Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        let Some(response) = response else {
            self.note("kbd".into());
            self.round = 0;
            if self.policy.kbd.is_empty() {
                return Ok(self.reject());
            }
            return Ok(self.kbd_round());
        };
        self.note("kbd-answer".into());
        let answers: Vec<String> = response
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .collect();
        let want = &self.policy.kbd[self.round].expect;
        if answers.len() != want.len() || answers.iter().zip(want).any(|(a, w)| a != w) {
            return Ok(self.reject());
        }
        self.round += 1;
        if self.round == self.policy.kbd.len() {
            Ok(Auth::Accept)
        } else {
            Ok(self.kbd_round())
        }
    }

    // ------------------------------------------------------------ the session

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.inner
            .channel_open_session(channel, reply, session)
            .await
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.inner.env_request(channel, name, value, session).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        cols: u32,
        rows: u32,
        px_w: u32,
        px_h: u32,
        modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.inner
            .pty_request(channel, term, cols, rows, px_w, px_h, modes, session)
            .await
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.inner.shell_request(channel, session).await
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.inner.data(channel, data, session).await
    }
}

/// A server on 127.0.0.1 authenticating per `policy`: its address, what the session
/// saw, and the authentication requests.
pub async fn start_auth_server(
    policy: AuthPolicy,
) -> (SocketAddr, Arc<Mutex<Seen>>, Arc<Mutex<AuthSeen>>) {
    let key = PrivateKey::from(Ed25519Keypair::from_seed(&[42; 32]));
    let mut preferred = Preferred::default();
    if let Some(algs) = &policy.sig_algs {
        preferred.key = Cow::Owned(algs.clone());
    }
    let config = Arc::new(server::Config {
        keys: vec![key],
        preferred,
        methods: policy.methods.clone(),
        max_auth_attempts: policy.max_auth_attempts,
        auth_rejection_time: Duration::from_millis(1),
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..server::Config::default()
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let auth = Arc::new(Mutex::new(AuthSeen::default()));
    let handler = AuthServer {
        inner: TestServer {
            seen: Arc::clone(&seen),
        },
        policy: Arc::new(policy),
        auth: Arc::clone(&auth),
        round: 0,
    };
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let config = Arc::clone(&config);
            let handler = handler.clone();
            tokio::spawn(async move {
                if let Ok(running) = server::run_stream(config, stream, handler).await {
                    let _ = running.await;
                }
            });
        }
    });
    (addr, seen, auth)
}
