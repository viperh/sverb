//! Host-key verification over known hosts (SPEC §9.5, §6.1.1 step 3).
//!
//! [`KnownHostsVerifier`] is the real [`HostKeyVerifier`]: it checks the presented key
//! (plain or host certificate) against a [`KnownHostsStore`] with
//! `sverb_core::known_hosts::check` and applies `ssh.host_key_policy`:
//!
//! | result | `strict` | `ask` (default) | `accept-new` |
//! |---|---|---|---|
//! | revoked (key or CA) | reject | reject | reject |
//! | valid CA-signed cert, known key | accept | accept | accept |
//! | changed key | reject | ask (red warning) | reject |
//! | unknown key | reject | ask (modal) | save, accept |
//!
//! Asking goes through the handler's suspended handshake: `SessionEvent::HostKey` with a
//! [`Verification`] whose [`HostKeyDetails`] carry the key type, the `SHA256:`
//! fingerprint, the randomart and, for a changed key, the old fingerprints; the
//! answer is `SessionCmd::HostKeyDecision` within 120 s, else reject. "Accept & save"
//! (also the confirmed replacement of a changed key) calls [`HostKeyVerifier::remember`],
//! which saves a new entry (hashed when `ssh.hash_known_hosts`) and drops the host's
//! old entries of that key type.
//!
//! Jump hops (§6.1.4) are verified under their own `address:port`; the store is shared.

use std::{fmt, sync::Arc};

use async_trait::async_trait;
use parking_lot::RwLock;
use sverb_core::{
    config::HostKeyPolicy,
    known_hosts::{
        CheckResult, KeyInfo, PolicyDecision, PresentedKey, check, decide, key_types_for, lookup,
        lookup_key, new_entry, same_key_type,
    },
    model::{KnownHost, KnownHostMarker, UnixMillis},
};
use tracing::{debug, info, warn};

use super::handler::{HostKeyTarget, HostKeyVerdict, HostKeyVerifier, ServerKey};
use crate::session::{HostKeyDetails, Verification};

/// Where known hosts live: the vault in the TUI, memory in tests.
#[async_trait]
pub trait KnownHostsStore: Send + Sync + fmt::Debug {
    /// The current entries (a snapshot; called during the handshake, so it must not
    /// block on I/O).
    fn entries(&self) -> Vec<KnownHost>;

    /// Trust `entry` for `host` (the lookup key, readable even when the entry is
    /// hashed) and remove `replaces` (the host's previous keys of the same type).
    /// `auto`: saved by `accept-new` without asking. Persisting may happen in the
    /// background, but [`KnownHostsStore::entries`] must include `entry` right away.
    fn save(&self, host: &str, entry: KnownHost, replaces: Vec<KnownHost>, auto: bool);

    /// Bring the snapshot up to date before a connection (the TUI reloads from the
    /// vault). The default does nothing.
    async fn refresh(&self) {}
}

/// An in-memory store (tests, and the CLI until it has a vault).
#[derive(Debug, Default)]
pub struct MemoryKnownHosts {
    entries: RwLock<Vec<KnownHost>>,
    /// `(entry, auto)` for every save, in order.
    saves: RwLock<Vec<(KnownHost, bool)>>,
}

impl MemoryKnownHosts {
    /// A store holding `entries`.
    pub fn new(entries: Vec<KnownHost>) -> Self {
        Self {
            entries: RwLock::new(entries),
            saves: RwLock::default(),
        }
    }

    /// Every save so far: the entry and whether `accept-new` saved it.
    pub fn saves(&self) -> Vec<(KnownHost, bool)> {
        self.saves.read().clone()
    }
}

#[async_trait]
impl KnownHostsStore for MemoryKnownHosts {
    fn entries(&self) -> Vec<KnownHost> {
        self.entries.read().clone()
    }

    fn save(&self, _host: &str, entry: KnownHost, replaces: Vec<KnownHost>, auto: bool) {
        let mut entries = self.entries.write();
        entries.retain(|e| !replaces.contains(e));
        entries.push(entry.clone());
        self.saves.write().push((entry, auto));
    }
}

/// Settings of a [`KnownHostsVerifier`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VerifyOptions {
    /// `ssh.host_key_policy`.
    pub policy: HostKeyPolicy,
    /// `ssh.hash_known_hosts`: new entries are stored hashed.
    pub hash_known_hosts: bool,
}

/// Seconds since the epoch, for certificate validity (replaceable in tests).
pub type Clock = fn() -> u64;

fn system_now() -> u64 {
    u64::try_from(UnixMillis::now().0 / 1000).unwrap_or(0)
}

/// The known-hosts [`HostKeyVerifier`] (see the module docs).
#[derive(Clone)]
pub struct KnownHostsVerifier {
    store: Arc<dyn KnownHostsStore>,
    options: VerifyOptions,
    clock: Clock,
}

impl fmt::Debug for KnownHostsVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KnownHostsVerifier")
            .field("store", &self.store)
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl KnownHostsVerifier {
    /// A verifier over `store`.
    pub fn new(store: Arc<dyn KnownHostsStore>, options: VerifyOptions) -> Self {
        Self {
            store,
            options,
            clock: system_now,
        }
    }

    /// Use `clock` for "now" (certificate validity).
    #[must_use]
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// The store.
    pub fn store(&self) -> &Arc<dyn KnownHostsStore> {
        &self.store
    }

    fn presented(key: &ServerKey) -> Result<PresentedKey, String> {
        PresentedKey::from_openssh(&key.openssh)
            .map_err(|e| format!("the server's host key could not be read: {e}"))
    }

    /// The question for the user.
    fn verification(target: &HostKeyTarget, info: &KeyInfo, result: &CheckResult) -> Verification {
        let (changed, old, note) = match result {
            CheckResult::Changed { old, cert_note } => (
                true,
                old.iter()
                    .filter_map(KeyInfo::of_entry)
                    .map(|i| i.fingerprint)
                    .collect(),
                cert_note.clone(),
            ),
            CheckResult::Unknown { cert_note } => (false, Vec::new(), cert_note.clone()),
            _ => (false, Vec::new(), None),
        };
        Verification {
            hop: 1,
            of: 1,
            host: format!("{}:{}", target.host, target.port),
            fingerprint: info.fingerprint.clone(),
            changed,
            details: HostKeyDetails {
                hostname: target.host.clone(),
                port: target.port,
                key_type: info.key_type.clone(),
                randomart: info.randomart.clone(),
                old_fingerprints: old,
                note,
            },
        }
    }

    /// The host's plain entries of `key_type` (what a new key of that type replaces).
    fn same_type_entries(&self, target: &HostKeyTarget, key_type: &str) -> Vec<KnownHost> {
        lookup(&self.store.entries(), &target.host, target.port)
            .matching
            .into_iter()
            .filter(|e| e.marker == KnownHostMarker::None && same_key_type(&e.key_type, key_type))
            .collect()
    }

    fn save(&self, target: &HostKeyTarget, info: &KeyInfo, auto: bool) {
        let entry = new_entry(
            &target.host,
            target.port,
            info,
            self.options.hash_known_hosts,
            UnixMillis::now(),
        );
        let replaces = self.same_type_entries(target, &info.key_type);
        info!(
            key_type = %info.key_type,
            fingerprint = %info.fingerprint,
            replaced = replaces.len(),
            auto,
            "host key saved"
        );
        self.store.save(
            &lookup_key(&target.host, target.port),
            entry,
            replaces,
            auto,
        );
    }
}

#[async_trait]
impl HostKeyVerifier for KnownHostsVerifier {
    fn verify(&self, target: &HostKeyTarget, key: &ServerKey) -> HostKeyVerdict {
        let presented = match Self::presented(key) {
            Ok(p) => p,
            Err(why) => return HostKeyVerdict::Reject(why),
        };
        let info = presented.info();
        let entries = self.store.entries();
        let result = check(
            &entries,
            &target.host,
            target.port,
            &presented,
            (self.clock)(),
        );
        debug!(
            lookup = %lookup_key(&target.host, target.port),
            key_type = %info.key_type,
            ?result,
            "host key checked"
        );
        match decide(self.options.policy, &result) {
            PolicyDecision::Accept => HostKeyVerdict::Accept,
            PolicyDecision::Reject(why) => {
                warn!(fingerprint = %info.fingerprint, reason = %why, "host key rejected");
                HostKeyVerdict::Reject(format!("{why} ({} {})", info.key_type, info.fingerprint))
            }
            PolicyDecision::AutoSave => {
                self.save(target, &info, true);
                HostKeyVerdict::Accept
            }
            PolicyDecision::AskUnknown | PolicyDecision::AskChanged => {
                HostKeyVerdict::Ask(Self::verification(target, &info, &result))
            }
        }
    }

    fn remember(&self, target: &HostKeyTarget, key: &ServerKey) {
        match Self::presented(key) {
            Ok(presented) => self.save(target, &presented.info(), false),
            Err(why) => warn!(reason = %why, "host key not saved"),
        }
    }

    fn known_key_types(&self, target: &HostKeyTarget) -> Vec<String> {
        key_types_for(&self.store.entries(), &target.host, target.port)
    }

    async fn prepare(&self, _target: &HostKeyTarget) {
        self.store.refresh().await;
    }
}
