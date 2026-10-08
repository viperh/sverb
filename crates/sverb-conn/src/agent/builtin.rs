//! M2-07: the built-in agent (SPEC §6.1.6): answers from vault keys with
//! `agent_forwardable = true` (the [`KeySource`] only hands those out) and the
//! certificates attached to them.
//!
//! - `REQUEST_IDENTITIES`: each key's public key, then its certificates, commented with
//!   the key's label. Empty while the vault is locked.
//! - `SIGN_REQUEST` for a key or one of its certificates: signs with the key (RSA:
//!   `rsa-sha2-512` / `rsa-sha2-256` per the request flags, else `ssh-rsa`). A locked
//!   vault refuses (§5.3); a `confirm_on_use` key asks the [`Confirmer`] first (60 s,
//!   then deny; [`super::confirm`]).
//! - Each signature is logged at `debug` with the key fingerprint and the requester
//!   (session id or local pid), never the data.

use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use parking_lot::Mutex;
use russh::keys::{
    HashAlg, PrivateKey,
    ssh_encoding::Encode,
    ssh_key::{Certificate, Signature, private::KeypairData},
};
use tracing::debug;

use super::proto::{RSA_SHA2_256, RSA_SHA2_512};

/// Who asks the agent for something.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Requester {
    /// A forwarded agent channel of an SSH session.
    Session {
        /// The host's label (shown in the confirm dialog).
        host: String,
        /// The session id (logs).
        session: String,
    },
    /// A process connected to the local socket (`sverb agent`).
    Local {
        /// Its pid, when the platform reports one.
        pid: Option<i32>,
        /// Its executable name, when known (Linux: `/proc/<pid>/comm`).
        exe: Option<String>,
    },
}

impl fmt::Display for Requester {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session { host, .. } => f.write_str(host),
            Self::Local {
                pid: Some(pid),
                exe: Some(exe),
            } => write!(f, "{exe} (pid {pid})"),
            Self::Local {
                pid: Some(pid),
                exe: None,
            } => write!(f, "pid {pid}"),
            Self::Local { pid: None, .. } => f.write_str("a local process"),
        }
    }
}

impl Requester {
    /// The id logged with each signature (session id or `pid:N`).
    pub fn log_id(&self) -> String {
        match self {
            Self::Session { session, .. } => session.clone(),
            Self::Local { pid: Some(pid), .. } => format!("pid:{pid}"),
            Self::Local { pid: None, .. } => "local".to_owned(),
        }
    }
}

/// A signature with a `confirm_on_use` key waits for this answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmRequest {
    /// Who asks.
    pub requester: Requester,
    /// The key's label.
    pub key_label: String,
    /// The key's `SHA256:…` fingerprint.
    pub fingerprint: String,
}

/// Asks the user whether a `confirm_on_use` key may sign.
#[async_trait]
pub trait Confirmer: Send + Sync + fmt::Debug {
    /// `true` allows this one signature. Implementations time out (deny) on their own.
    async fn confirm(&self, request: ConfirmRequest) -> bool;
}

/// No one to ask (no UI): `confirm_on_use` keys never sign.
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyConfirm;

#[async_trait]
impl Confirmer for DenyConfirm {
    async fn confirm(&self, request: ConfirmRequest) -> bool {
        debug!(
            fingerprint = %request.fingerprint,
            "confirm_on_use key refused: no one to ask"
        );
        false
    }
}

/// A forwardable key with its certificates.
#[derive(Clone)]
pub struct AgentKey {
    /// The key's label (the identity comment).
    pub label: String,
    /// The decrypted private key.
    pub private: Arc<PrivateKey>,
    /// Certificates for this key (served as additional identities).
    pub certificates: Vec<Certificate>,
    /// Ask before each signature.
    pub confirm_on_use: bool,
}

impl fmt::Debug for AgentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentKey")
            .field("label", &self.label)
            .field("fingerprint", &self.fingerprint())
            .field("certificates", &self.certificates.len())
            .field("confirm_on_use", &self.confirm_on_use)
            .finish_non_exhaustive()
    }
}

impl AgentKey {
    /// A key without certificates or confirmation.
    pub fn new(label: impl Into<String>, private: PrivateKey) -> Self {
        Self {
            label: label.into(),
            private: Arc::new(private),
            certificates: Vec::new(),
            confirm_on_use: false,
        }
    }

    /// The `SHA256:…` fingerprint of the public key.
    pub fn fingerprint(&self) -> String {
        self.private
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string()
    }

    /// The public key blob.
    pub fn key_blob(&self) -> Option<Vec<u8>> {
        self.private.public_key().key_data().encode_vec().ok()
    }

    /// `(blob, comment)` for the key, then each certificate.
    pub fn identities(&self) -> Vec<(Vec<u8>, String)> {
        let mut ids = Vec::new();
        if let Some(blob) = self.key_blob() {
            ids.push((blob, self.label.clone()));
        }
        for cert in &self.certificates {
            if let Ok(blob) = cert.to_bytes() {
                ids.push((blob, self.label.clone()));
            }
        }
        ids
    }

    /// Does `blob` name this key or one of its certificates?
    pub fn holds(&self, blob: &[u8]) -> bool {
        self.identities().iter().any(|(b, _)| b == blob)
    }
}

/// The keys the built-in agent serves; `None` while the vault is locked.
pub type KeySet = Arc<Vec<AgentKey>>;

/// Where the built-in agent gets its keys (the TUI's vault, the headless agent's
/// unlocked snapshot, tests). Only `agent_forwardable` keys may be returned.
#[async_trait]
pub trait KeySource: Send + Sync + fmt::Debug {
    /// The forwardable keys, or `None` when the vault is locked.
    async fn keys(&self) -> Option<KeySet>;

    /// An agent request arrived (idle tracking for auto-lock).
    fn touch(&self) {}
}

/// A fixed key set that can be locked (the headless `sverb agent`, tests).
#[derive(Debug)]
pub struct StaticKeys {
    keys: Mutex<Option<KeySet>>,
    last_use: Mutex<Instant>,
}

impl StaticKeys {
    /// Unlocked, holding `keys`.
    pub fn new(keys: Vec<AgentKey>) -> Self {
        Self {
            keys: Mutex::new(Some(Arc::new(keys))),
            last_use: Mutex::new(Instant::now()),
        }
    }

    /// Locked (holds nothing).
    pub fn locked() -> Self {
        Self {
            keys: Mutex::new(None),
            last_use: Mutex::new(Instant::now()),
        }
    }

    /// Drop the keys (they are zeroized when the last signer lets go).
    pub fn lock(&self) {
        *self.keys.lock() = None;
    }

    /// Hold `keys` again.
    pub fn unlock(&self, keys: Vec<AgentKey>) {
        *self.keys.lock() = Some(Arc::new(keys));
        *self.last_use.lock() = Instant::now();
    }

    /// Locked?
    pub fn is_locked(&self) -> bool {
        self.keys.lock().is_none()
    }

    /// Time since the last request (or unlock).
    pub fn idle(&self) -> Duration {
        self.last_use.lock().elapsed()
    }
}

#[async_trait]
impl KeySource for StaticKeys {
    async fn keys(&self) -> Option<KeySet> {
        self.keys.lock().clone()
    }

    fn touch(&self) {
        *self.last_use.lock() = Instant::now();
    }
}

/// What a sign request came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignOutcome {
    /// The encoded signature (algorithm + blob).
    Signed(Vec<u8>),
    /// Refused: the user denied (or didn't answer), or signing failed.
    Refused,
    /// The vault is locked (§5.3: refuse).
    Locked,
    /// No such key here (`both` asks the system agent).
    NotHeld,
}

/// The built-in agent.
#[derive(Debug, Clone)]
pub struct BuiltinAgent {
    keys: Arc<dyn KeySource>,
    confirmer: Arc<dyn Confirmer>,
}

impl BuiltinAgent {
    /// An agent over `keys`, asking `confirmer` for `confirm_on_use` keys.
    pub fn new(keys: Arc<dyn KeySource>, confirmer: Arc<dyn Confirmer>) -> Self {
        Self { keys, confirmer }
    }

    /// The identities (empty while locked).
    pub async fn identities(&self) -> Vec<(Vec<u8>, String)> {
        self.keys.touch();
        match self.keys.keys().await {
            Some(keys) => keys.iter().flat_map(AgentKey::identities).collect(),
            None => {
                debug!("agent: vault locked; no identities");
                Vec::new()
            }
        }
    }

    /// Sign `data` with the key (or certificate) `blob`.
    pub async fn sign(
        &self,
        blob: &[u8],
        data: &[u8],
        flags: u32,
        requester: &Requester,
    ) -> SignOutcome {
        self.keys.touch();
        let Some(keys) = self.keys.keys().await else {
            debug!(requester = %requester.log_id(), "agent: vault locked; signature refused");
            return SignOutcome::Locked;
        };
        let Some(key) = keys.iter().find(|k| k.holds(blob)) else {
            return SignOutcome::NotHeld;
        };
        let fingerprint = key.fingerprint();
        if key.confirm_on_use {
            let request = ConfirmRequest {
                requester: requester.clone(),
                key_label: key.label.clone(),
                fingerprint: fingerprint.clone(),
            };
            if !self.confirmer.confirm(request).await {
                debug!(%fingerprint, requester = %requester.log_id(), "agent: signature denied");
                return SignOutcome::Refused;
            }
        }
        match sign_with(&key.private, data, flags) {
            Ok(sig) => {
                debug!(%fingerprint, requester = %requester.log_id(), "agent: signed");
                SignOutcome::Signed(sig)
            }
            Err(err) => {
                debug!(%fingerprint, %err, "agent: signing failed");
                SignOutcome::Refused
            }
        }
    }
}

/// The RSA hash the request flags ask for (`None`: `ssh-rsa`, SHA-1).
pub fn rsa_hash(flags: u32) -> Option<HashAlg> {
    if flags & RSA_SHA2_512 != 0 {
        Some(HashAlg::Sha512)
    } else if flags & RSA_SHA2_256 != 0 {
        Some(HashAlg::Sha256)
    } else {
        None
    }
}

/// Sign `data` with `key`; the encoded [`Signature`].
///
/// # Errors
/// The key can't sign (unsupported algorithm, hardware key).
pub fn sign_with(key: &PrivateKey, data: &[u8], flags: u32) -> Result<Vec<u8>, String> {
    use russh::keys::signature::Signer;
    let sig: Signature = match key.key_data() {
        KeypairData::Rsa(rsa) => Signer::try_sign(&(rsa, rsa_hash(flags)), data),
        other => Signer::try_sign(other, data),
    }
    .map_err(|e| e.to_string())?;
    sig.encode_vec().map_err(|e| e.to_string())
}

/// The built-in agent's keys from vault items: only keys with
/// `agent_forwardable = true` that can be decrypted (stored passphrase), each with
/// the certificates attached to it (`certificate_ids`, or a certificate naming the
/// key). Agent-reference keys (no private part) and undecryptable keys are skipped
/// (logged at `debug`).
pub fn agent_keys(
    keys: &[(sverb_core::model::ItemId, sverb_core::model::Key)],
    certificates: &[(sverb_core::model::ItemId, sverb_core::model::Certificate)],
) -> Vec<AgentKey> {
    keys.iter()
        .filter(|(_, k)| k.agent_forwardable && !k.is_agent_ref())
        .filter_map(|(id, k)| {
            let passphrase = k.passphrase.as_ref().map(|p| p.expose());
            let private =
                match sverb_core::keychain::decrypt_openssh(k.private_key.expose(), passphrase) {
                    Ok(private) => private,
                    Err(err) => {
                        debug!(key = %id.short(), %err, "agent: forwardable key skipped");
                        return None;
                    }
                };
            let certificates = certificates
                .iter()
                .filter(|(cid, c)| k.certificate_ids.contains(cid) || c.key_id == Some(*id))
                .filter_map(|(_, c)| Certificate::from_openssh(c.cert.trim()).ok())
                .filter(|c| c.public_key() == private.public_key().key_data())
                .collect();
            Some(AgentKey {
                label: k.label.clone(),
                private: Arc::new(private),
                certificates,
                confirm_on_use: k.confirm_on_use,
            })
        })
        .collect()
}
