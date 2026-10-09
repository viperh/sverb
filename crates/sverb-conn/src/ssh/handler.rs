//! algorithms, and why the connection ended.
//!
//! # Host-key verification seam
//! [`HostKeyVerifier`] decides about the server's key ([`HostKeyVerdict`]). For
//! [`HostKeyVerdict::Ask`] the handler (which runs inside russh's session task) sends a
//! `HostKeyRequest` to the connect flow and **awaits** the answer, which suspends the
//! handshake: the connect flow moves the session to `AwaitingHostKey`, emits
//! `SessionEvent::HostKey` and waits for `SessionCmd::HostKeyDecision` (120 s, then
//!
//! with an explanatory message. [`InsecureAcceptAnyHostKey`] accepts every key with a
//! warning; it is for tests and development only and must be chosen explicitly (the TUI
//! enables it only with `SVERB_INSECURE_ACCEPT_ANY_HOST_KEY=1`).

use std::{fmt, sync::Arc};

use parking_lot::Mutex;
use russh::{
    client::{self, Session},
    keys::{HashAlg, PublicKeyOrCertificate},
};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};

use crate::session::{Decision, SshSessionInfo, Verification};

/// The host whose key is checked (`address:port` as seen from the previous hop).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKeyTarget {
    /// Address as configured.
    pub host: String,
    /// Port.
    pub port: u16,
}

/// The key the server presented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerKey {
    /// Key type (`ssh-ed25519`, `ssh-rsa`, …; for a certificate, the certified key's
    /// type).
    pub key_type: String,
    /// `SHA256:…` fingerprint (base64, no padding) of the (certified) key.
    pub fingerprint: String,
    /// The key in OpenSSH public-key format (`ssh-ed25519 AAAA…`).
    pub openssh: String,
    /// The server presented a certificate.
    pub certificate: bool,
}

/// What the verifier decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyVerdict {
    /// Trusted.
    Accept,
    /// Rejected, with the reason for the detail view.
    Reject(String),
    /// Ask the user (unknown or changed key).
    Ask(Verification),
}

/// `ssh::verify::KnownHostsVerifier`).
// `async_trait` for `prepare`; implementations without it need no attribute.
#[async_trait::async_trait]
pub trait HostKeyVerifier: Send + Sync + fmt::Debug {
    /// Check `key` for `target`.
    fn verify(&self, target: &HostKeyTarget, key: &ServerKey) -> HostKeyVerdict;

    /// The user chose "accept and save".
    fn remember(&self, target: &HostKeyTarget, key: &ServerKey) {
        let _ = (target, key);
    }

    /// Key types already known for `target`, to move to the front of the host-key
    /// algorithm list (§9.5).
    fn known_key_types(&self, target: &HostKeyTarget) -> Vec<String> {
        let _ = target;
        Vec::new()
    }

    /// Called once per hop before the handshake (before
    /// [`HostKeyVerifier::known_key_types`]): bring the known hosts up to date (the TUI
    /// reloads them from the vault). The default does nothing.
    async fn prepare(&self, target: &HostKeyTarget) {
        let _ = target;
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct UnverifiedHostKeys;

/// Detail shown when [`UnverifiedHostKeys`] rejects a key.
pub const UNVERIFIED_DETAIL: &str = "host key verification (known_hosts) is not available in this build yet; \
     set SVERB_INSECURE_ACCEPT_ANY_HOST_KEY=1 to connect without verifying (development only)";

impl HostKeyVerifier for UnverifiedHostKeys {
    fn verify(&self, _target: &HostKeyTarget, key: &ServerKey) -> HostKeyVerdict {
        HostKeyVerdict::Reject(format!(
            "{UNVERIFIED_DETAIL} ({} {})",
            key.key_type, key.fingerprint
        ))
    }
}

/// **Tests and development only.** Accepts every host key and logs a warning. Never
/// the default: it disables protection against man-in-the-middle attacks.
#[derive(Debug, Clone, Copy)]
pub struct InsecureAcceptAnyHostKey {
    _private: (),
}

impl InsecureAcceptAnyHostKey {
    /// The insecure verifier. The name is the warning.
    pub fn insecure_for_testing() -> Self {
        Self { _private: () }
    }
}

impl HostKeyVerifier for InsecureAcceptAnyHostKey {
    fn verify(&self, _target: &HostKeyTarget, key: &ServerKey) -> HostKeyVerdict {
        warn!(
            key_type = %key.key_type,
            fingerprint = %key.fingerprint,
            "host key accepted WITHOUT verification (insecure test/dev verifier)"
        );
        HostKeyVerdict::Accept
    }
}

/// keys behaves the same way).
#[derive(Debug, Clone, Copy, Default)]
pub struct AskEveryTime;

impl HostKeyVerifier for AskEveryTime {
    fn verify(&self, target: &HostKeyTarget, key: &ServerKey) -> HostKeyVerdict {
        HostKeyVerdict::Ask(Verification {
            hop: 1,
            of: 1,
            host: format!("{}:{}", target.host, target.port),
            fingerprint: key.fingerprint.clone(),
            changed: false,
            ..Verification::default()
        })
    }
}

/// A host-key question from the handler to the connect flow.
#[derive(Debug)]
pub(crate) struct HostKeyRequest {
    pub(crate) verification: Verification,
    pub(crate) reply: oneshot::Sender<Decision>,
}

/// How the connection ended, as seen by the handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EndCause {
    /// The server sent a disconnect message.
    Remote(String),
    /// russh failed (the error's text; keepalive timeouts are flagged separately).
    Error(String),
    /// No keepalive reply.
    KeepaliveTimeout,
}

/// State shared between the handler (in russh's task) and the connector/transport.
#[derive(Debug, Default)]
pub(crate) struct Shared {
    pub(crate) info: Mutex<SshSessionInfo>,
    pub(crate) host_key_rejection: Mutex<Option<String>>,
    pub(crate) end: Mutex<Option<EndCause>>,
    // Remote (-R) forwards of this connection, for `forwarded-tcpip` channels.
    pub(crate) forwards: Arc<crate::forward::RemoteRoutes>,
    // Serves forwarded agent channels; `None` rejects them (no forwarding).
    pub(crate) agent: Mutex<Option<crate::agent::AgentServer>>,
}

/// The russh handler.
pub(crate) struct ClientHandler {
    pub(crate) verifier: Arc<dyn HostKeyVerifier>,
    pub(crate) target: HostKeyTarget,
    pub(crate) prompts: mpsc::Sender<HostKeyRequest>,
    pub(crate) shared: Arc<Shared>,
}

/// The handler's error: russh's.
#[derive(Debug)]
pub(crate) struct HandlerError(pub(crate) russh::Error);

impl From<russh::Error> for HandlerError {
    fn from(err: russh::Error) -> Self {
        Self(err)
    }
}

pub(crate) fn server_key(key: &PublicKeyOrCertificate) -> ServerKey {
    match key {
        PublicKeyOrCertificate::PublicKey { key, .. } => ServerKey {
            key_type: key.algorithm().as_str().to_owned(),
            fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
            openssh: key.to_openssh().unwrap_or_default(),
            certificate: false,
        },
        PublicKeyOrCertificate::Certificate(cert) => {
            let key = russh::keys::PublicKey::from(cert.public_key().clone());
            ServerKey {
                key_type: cert.algorithm().as_str().to_owned(),
                fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
                openssh: cert.to_openssh().unwrap_or_default(),
                certificate: true,
            }
        }
    }
}

impl ClientHandler {
    fn reject(&self, why: String) -> Result<bool, HandlerError> {
        debug!(reason = %why, "host key rejected");
        *self.shared.host_key_rejection.lock() = Some(why);
        Ok(false)
    }
}

impl client::Handler for ClientHandler {
    type Error = HandlerError;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let key = server_key(key);
        match self.verifier.verify(&self.target, &key) {
            HostKeyVerdict::Accept => Ok(true),
            HostKeyVerdict::Reject(why) => self.reject(why),
            HostKeyVerdict::Ask(verification) => {
                let (reply, answer) = oneshot::channel();
                let request = HostKeyRequest {
                    verification,
                    reply,
                };
                if self.prompts.send(request).await.is_err() {
                    return self.reject("the connection was abandoned".to_owned());
                }
                match answer.await {
                    Ok(Decision::AcceptAndSave) => {
                        self.verifier.remember(&self.target, &key);
                        Ok(true)
                    }
                    Ok(Decision::AcceptOnce) => Ok(true),
                    Ok(_) => self.reject("rejected by the user".to_owned()),
                    Err(_) => self.reject("no decision".to_owned()),
                }
            }
        }
    }

    async fn kex_done(
        &mut self,
        _shared_secret: Option<&[u8]>,
        names: &russh::Names,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let compression = |c: &russh::compression::Compression| match c {
            russh::compression::Compression::None => "none",
            russh::compression::Compression::Zlib => "zlib",
            russh::compression::Compression::ZlibOpenSSH => "zlib@openssh.com",
        };
        let mut info = self.shared.info.lock();
        info.server_version = String::from_utf8_lossy(session.remote_sshid())
            .trim()
            .to_owned();
        info.kex = names.kex.as_ref().to_owned();
        info.host_key = names.key.to_string();
        info.cipher = names.cipher.as_ref().to_owned();
        info.mac = names.client_mac.as_ref().to_owned();
        info.compression = compression(&names.client_compression).to_owned();
        debug!(
            kex = %info.kex,
            host_key = %info.host_key,
            cipher = %info.cipher,
            mac = %info.mac,
            compression = %info.compression,
            "negotiated algorithms"
        );
        Ok(())
    }

    // Hand the channel to the matching remote forward, or reject it.
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<client::Msg>,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let originator = format!("{originator_address}:{originator_port}");
        crate::forward::ssh_glue::on_forwarded(
            &self.shared.forwards,
            channel,
            connected_address,
            connected_port,
            originator,
            reply,
        )
        .await;
        Ok(())
    }

    // A forwarded `auth-agent@openssh.com` channel (SPEC §6.1.6).
    async fn server_channel_open_agent_forward(
        &mut self,
        channel: russh::Channel<client::Msg>,
        reply: client::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let server = self.shared.agent.lock().clone();
        crate::agent::forward::on_channel(server, channel, reply).await;
        Ok(())
    }

    async fn disconnected(
        &mut self,
        reason: client::DisconnectReason<Self::Error>,
    ) -> Result<(), Self::Error> {
        match reason {
            client::DisconnectReason::ReceivedDisconnect(info) => {
                debug!(code = ?info.reason_code, "server disconnected");
                self.shared
                    .end
                    .lock()
                    .get_or_insert(EndCause::Remote(info.message));
                Ok(())
            }
            client::DisconnectReason::Error(err) => {
                let cause = match &err.0 {
                    russh::Error::KeepaliveTimeout => EndCause::KeepaliveTimeout,
                    other => EndCause::Error(other.to_string()),
                };
                self.shared.end.lock().get_or_insert(cause);
                Err(err)
            }
        }
    }
}
