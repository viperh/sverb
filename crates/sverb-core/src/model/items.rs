//! Typed views for the other item kinds (SPEC §4.4–§4.12).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ciborium::Value;

use super::body::ItemBody;
use super::fields::{Reader, ViewError, Writer, check_kind, wire_enum};
use super::hlc::HlcClock;
use super::ids::{DeviceId, ItemId};
use super::kinds::ItemKind;
use crate::secret::SecretString;

/// A UTC timestamp in milliseconds since the Unix epoch (stored as a CBOR integer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct UnixMillis(pub i64);

impl UnixMillis {
    /// The current system time.
    pub fn now() -> Self {
        let d = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        Self(i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
    }
}

impl From<UnixMillis> for Value {
    fn from(t: UnixMillis) -> Self {
        Value::from(t.0)
    }
}

fn read_time(r: &Reader<'_>, key: &str) -> Result<Option<UnixMillis>, ViewError> {
    Ok(r.int::<i64>(key)?.map(UnixMillis))
}

// ---------------------------------------------------------------- Identity (§4.4)

/// Reusable credentials (§4.4), referenced by many hosts.
#[derive(Debug, Default)]
pub struct Identity {
    /// `label`
    pub label: String,
    /// `username`
    pub username: String,
    /// `password`
    pub password: Option<SecretString>,
    /// `key_id`
    pub key_id: Option<ItemId>,
    /// The body's schema is newer than this build (§4.1).
    pub read_only: bool,
}

impl Identity {
    /// Writes the fields that differ from `body`.
    pub fn apply_to(&self, body: &mut ItemBody, clock: &mut HlcClock, device: DeviceId) {
        let mut w = Writer::new(body, clock, device);
        w.text("label", &self.label);
        w.text("username", &self.username);
        w.opt_secret("password", self.password.as_ref());
        w.opt("key_id", self.key_id);
    }
}

impl TryFrom<&ItemBody> for Identity {
    type Error = ViewError;

    fn try_from(body: &ItemBody) -> Result<Self, ViewError> {
        let read_only = check_kind(body, ItemKind::Identity)?;
        let r = Reader::new(body);
        Ok(Self {
            label: r.str("label")?,
            username: r.str("username")?,
            password: r.opt_secret("password")?,
            key_id: r.opt_id("key_id")?,
            read_only,
        })
    }
}

// ---------------------------------------------------------------- Key (§4.5)

wire_enum!(
    /// SSH key algorithm (§4.5).
    KeyAlgorithm {
        /// `ed25519`
        Ed25519 => "ed25519",
        /// `ecdsa-p256`
        EcdsaP256 => "ecdsa-p256",
        /// `ecdsa-p384`
        EcdsaP384 => "ecdsa-p384",
        /// `ecdsa-p521`
        EcdsaP521 => "ecdsa-p521",
        /// `rsa-2048`
        Rsa2048 => "rsa-2048",
        /// `rsa-3072`
        Rsa3072 => "rsa-3072",
        /// `rsa-4096`
        Rsa4096 => "rsa-4096",
        /// `sk-ed25519` (FIDO)
        SkEd25519 => "sk-ed25519",
        /// `sk-ecdsa` (FIDO)
        SkEcdsa => "sk-ecdsa",
    }
);

/// An SSH key pair (§4.5).
#[derive(Debug)]
pub struct Key {
    /// `label`
    pub label: String,
    /// `algorithm`
    pub algorithm: KeyAlgorithm,
    /// OpenSSH private key, optionally passphrase-encrypted.
    pub private_key: SecretString,
    /// OpenSSH public key.
    pub public_key: String,
    /// Stored so the user isn't prompted.
    pub passphrase: Option<SecretString>,
    /// Certificates for this key (whole-value LWW list).
    pub certificate_ids: Vec<ItemId>,
    /// Defaults to `false`.
    pub agent_forwardable: bool,
    /// Prompt before the built-in agent signs with this key.
    pub confirm_on_use: bool,
    /// The body's schema is newer than this build (§4.1).
    pub read_only: bool,
}

impl Key {
    // M2-03
    /// A hardware / agent reference key (§9.4): no `private_key`, only `public_key`;
    /// auth asks the system agent to sign with it. Stored as the `agent_ref` flag;
    /// derived from the fields so existing struct literals stay valid.
    pub fn is_agent_ref(&self) -> bool {
        self.private_key.expose().trim().is_empty() && !self.public_key.trim().is_empty()
    }

    /// Writes the fields that differ from `body`.
    pub fn apply_to(&self, body: &mut ItemBody, clock: &mut HlcClock, device: DeviceId) {
        let mut w = Writer::new(body, clock, device);
        w.text("label", &self.label);
        w.opt_enum("algorithm", Some(self.algorithm));
        w.text("private_key", self.private_key.expose_for_envelope());
        w.text("public_key", &self.public_key);
        w.opt_secret("passphrase", self.passphrase.as_ref());
        w.ids("certificate_ids", &self.certificate_ids);
        w.flag("agent_forwardable", self.agent_forwardable);
        w.flag("confirm_on_use", self.confirm_on_use);
        // M2-03: derived from the fields (see `Key::is_agent_ref`), stored for readers.
        w.flag("agent_ref", self.is_agent_ref());
    }
}

impl TryFrom<&ItemBody> for Key {
    type Error = ViewError;

    fn try_from(body: &ItemBody) -> Result<Self, ViewError> {
        let read_only = check_kind(body, ItemKind::Key)?;
        let r = Reader::new(body);
        Ok(Self {
            label: r.str("label")?,
            algorithm: r.req_enum("algorithm")?,
            private_key: r
                .opt_secret("private_key")?
                .unwrap_or_else(|| SecretString::from("")),
            public_key: r.str("public_key")?,
            passphrase: r.opt_secret("passphrase")?,
            certificate_ids: r.ids("certificate_ids")?,
            agent_forwardable: r.bool("agent_forwardable")?,
            confirm_on_use: r.bool("confirm_on_use")?,
            read_only,
        })
    }
}

// ---------------------------------------------------------------- Certificate (§4.6)

/// An OpenSSH certificate (§4.6). Principals, validity and CA are derived, never stored.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Certificate {
    /// `label`
    pub label: String,
    /// The OpenSSH certificate text.
    pub cert: String,
    /// The key this certificate certifies.
    pub key_id: Option<ItemId>,
    /// The body's schema is newer than this build (§4.1).
    pub read_only: bool,
}

impl Certificate {
    /// Writes the fields that differ from `body`.
    pub fn apply_to(&self, body: &mut ItemBody, clock: &mut HlcClock, device: DeviceId) {
        let mut w = Writer::new(body, clock, device);
        w.text("label", &self.label);
        w.text("cert", &self.cert);
        w.opt("key_id", self.key_id);
    }
}

impl TryFrom<&ItemBody> for Certificate {
    type Error = ViewError;

    fn try_from(body: &ItemBody) -> Result<Self, ViewError> {
        let read_only = check_kind(body, ItemKind::Certificate)?;
        let r = Reader::new(body);
        Ok(Self {
            label: r.str("label")?,
            cert: r.str("cert")?,
            key_id: r.opt_id("key_id")?,
            read_only,
        })
    }
}

// ---------------------------------------------------------------- KnownHost (§4.7)

/// Marker of a known-hosts line (§4.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum KnownHostMarker {
    /// A plain host key (stored as a missing / `Null` `marker`).
    #[default]
    None,
    /// `@cert-authority` → `"cert-authority"`
    CertAuthority,
    /// `@revoked` → `"revoked"`
    Revoked,
}

/// A trusted (or revoked) host key (§4.7).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KnownHost {
    /// `host` or `[host]:port`, hashed or not.
    pub host_pattern: String,
    /// e.g. `ssh-ed25519`
    pub key_type: String,
    /// Base64 public key.
    pub public_key: String,
    /// When it was trusted.
    pub added_at: UnixMillis,
    /// `comment`
    pub comment: Option<String>,
    /// `marker`
    pub marker: KnownHostMarker,
    /// The body's schema is newer than this build (§4.1).
    pub read_only: bool,
}

impl KnownHost {
    /// Writes the fields that differ from `body`.
    pub fn apply_to(&self, body: &mut ItemBody, clock: &mut HlcClock, device: DeviceId) {
        let mut w = Writer::new(body, clock, device);
        w.text("host_pattern", &self.host_pattern);
        w.text("key_type", &self.key_type);
        w.text("public_key", &self.public_key);
        w.always("added_at", self.added_at);
        w.opt("comment", self.comment.clone());
        let marker = match self.marker {
            KnownHostMarker::None => None,
            KnownHostMarker::CertAuthority => Some("cert-authority"),
            KnownHostMarker::Revoked => Some("revoked"),
        };
        w.opt("marker", marker);
    }
}

impl TryFrom<&ItemBody> for KnownHost {
    type Error = ViewError;

    fn try_from(body: &ItemBody) -> Result<Self, ViewError> {
        let read_only = check_kind(body, ItemKind::KnownHost)?;
        let r = Reader::new(body);
        let marker = match r.opt_str("marker")?.as_deref() {
            None => KnownHostMarker::None,
            Some("cert-authority") => KnownHostMarker::CertAuthority,
            Some("revoked") => KnownHostMarker::Revoked,
            Some(_) => return Err(r.type_err("marker")),
        };
        Ok(Self {
            host_pattern: r.str("host_pattern")?,
            key_type: r.str("key_type")?,
            public_key: r.str("public_key")?,
            added_at: read_time(&r, "added_at")?.unwrap_or_default(),
            comment: r.opt_str("comment")?,
            marker,
            read_only,
        })
    }
}

// ---------------------------------------------------------------- PortForward (§4.8)

wire_enum!(
    /// Kind of forwarding (§4.8).
    ForwardKind {
        /// `-L`
        Local => "local",
        /// `-R`
        Remote => "remote",
        /// `-D` (SOCKS)
        Dynamic => "dynamic",
    }
);

/// The default `bind_addr`.
pub const DEFAULT_BIND_ADDR: &str = "127.0.0.1";

/// A port-forwarding rule (§4.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortForward {
    /// `label`
    pub label: String,
    /// `kind`
    pub kind: ForwardKind,
    /// The connection that carries the tunnel.
    pub host_id: ItemId,
    /// Default `127.0.0.1` (when the field is missing).
    pub bind_addr: String,
    /// `bind_port`
    pub bind_port: u16,
    /// `None` for `Dynamic`.
    pub dest_host: Option<String>,
    /// `dest_port`
    pub dest_port: Option<u16>,
    /// Start when the host connects.
    pub auto_start: bool,
    /// The body's schema is newer than this build (§4.1).
    pub read_only: bool,
}

impl PortForward {
    /// Writes the fields that differ from `body`.
    pub fn apply_to(&self, body: &mut ItemBody, clock: &mut HlcClock, device: DeviceId) {
        let mut w = Writer::new(body, clock, device);
        w.text("label", &self.label);
        w.opt_enum("kind", Some(self.kind));
        w.always("host_id", self.host_id);
        w.always("bind_addr", self.bind_addr.clone());
        w.always("bind_port", self.bind_port);
        w.opt("dest_host", self.dest_host.clone());
        w.opt("dest_port", self.dest_port);
        w.flag("auto_start", self.auto_start);
    }
}

impl TryFrom<&ItemBody> for PortForward {
    type Error = ViewError;

    fn try_from(body: &ItemBody) -> Result<Self, ViewError> {
        let read_only = check_kind(body, ItemKind::PortForward)?;
        let r = Reader::new(body);
        Ok(Self {
            label: r.str("label")?,
            kind: r.req_enum("kind")?,
            host_id: r.req_id("host_id")?,
            bind_addr: r
                .opt_str("bind_addr")?
                .unwrap_or_else(|| DEFAULT_BIND_ADDR.to_owned()),
            bind_port: r.req_int("bind_port")?,
            dest_host: r.opt_str("dest_host")?,
            dest_port: r.int("dest_port")?,
            auto_start: r.bool("auto_start")?,
            read_only,
        })
    }
}

// ---------------------------------------------------------------- Snippet (§4.9)

wire_enum!(
    /// How a snippet runs (§4.9, §9.7).
    RunMode {
        /// Type into the focused pane, no trailing newline.
        Paste => "paste",
        /// Each line followed by `\r`.
        PasteAndExecute => "paste-and-execute",
        /// Run via an exec channel.
        Exec => "exec",
    }
);

/// A snippet variable definition. Encoded as a CBOR map
/// `{"name": text, "default": text|null, "secret": bool}`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VarDef {
    /// Matches `[A-Za-z_][A-Za-z0-9_.]*`.
    pub name: String,
    /// Prefilled value.
    pub default: Option<String>,
    /// Masked in the form, never saved to history.
    pub secret: bool,
}

impl VarDef {
    fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::from("name"), Value::Text(self.name.clone())),
            (
                Value::from("default"),
                self.default.clone().map_or(Value::Null, Value::Text),
            ),
            (Value::from("secret"), Value::Bool(self.secret)),
        ])
    }

    fn from_value(v: &Value) -> Option<Self> {
        let mut def = VarDef::default();
        for (k, v) in v.as_map()? {
            match k.as_text()? {
                "name" => def.name = v.as_text()?.to_owned(),
                "default" if v.is_null() => def.default = None,
                "default" => def.default = Some(v.as_text()?.to_owned()),
                "secret" => def.secret = v.as_bool()?,
                _ => {} // unknown sub-keys from newer clients are ignored on read
            }
        }
        Some(def)
    }
}

/// A command snippet (§4.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snippet {
    /// `name`
    pub name: String,
    /// Multiline script.
    pub script: String,
    /// `description`
    pub description: Option<String>,
    /// Tag items (whole-value LWW list).
    pub tags: Vec<ItemId>,
    /// Whole-value LWW list.
    pub variables: Vec<VarDef>,
    /// Defaults to `Paste` when missing.
    pub run_mode: RunMode,
    /// The body's schema is newer than this build (§4.1).
    pub read_only: bool,
}

impl Snippet {
    /// Writes the fields that differ from `body`.
    pub fn apply_to(&self, body: &mut ItemBody, clock: &mut HlcClock, device: DeviceId) {
        let mut w = Writer::new(body, clock, device);
        w.text("name", &self.name);
        w.text("script", &self.script);
        w.opt("description", self.description.clone());
        w.ids("tags", &self.tags);
        w.put_or_skip(
            "variables",
            Value::Array(self.variables.iter().map(VarDef::to_value).collect()),
            self.variables.is_empty(),
        );
        w.opt_enum("run_mode", Some(self.run_mode));
    }
}

impl TryFrom<&ItemBody> for Snippet {
    type Error = ViewError;

    fn try_from(body: &ItemBody) -> Result<Self, ViewError> {
        let read_only = check_kind(body, ItemKind::Snippet)?;
        let r = Reader::new(body);
        let variables = match r.value("variables") {
            None => Vec::new(),
            Some(v) => v
                .as_array()
                .and_then(|a| a.iter().map(VarDef::from_value).collect::<Option<Vec<_>>>())
                .ok_or_else(|| r.type_err("variables"))?,
        };
        Ok(Self {
            name: r.str("name")?,
            script: r.str("script")?,
            description: r.opt_str("description")?,
            tags: r.ids("tags")?,
            variables,
            run_mode: r.opt_enum("run_mode")?.unwrap_or(RunMode::Paste),
            read_only,
        })
    }
}

// ---------------------------------------------------------------- Workspace (§4.10)

/// A saved tab/pane layout (§4.10). The layout tree (§8.4) and broadcast groups are
/// kept as opaque CBOR values until M3-03 defines their typed form; both are
/// whole-value LWW fields.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Workspace {
    /// `name`
    pub name: String,
    /// Serialized layout tree whose leaves reference `host_id` (or `local`).
    pub layout: Option<Value>,
    /// Whole-value LWW list.
    pub broadcast_groups: Vec<Value>,
    /// The body's schema is newer than this build (§4.1).
    pub read_only: bool,
}

impl Workspace {
    /// Writes the fields that differ from `body`.
    pub fn apply_to(&self, body: &mut ItemBody, clock: &mut HlcClock, device: DeviceId) {
        let mut w = Writer::new(body, clock, device);
        w.text("name", &self.name);
        w.opt("layout", self.layout.clone());
        w.put_or_skip(
            "broadcast_groups",
            Value::Array(self.broadcast_groups.clone()),
            self.broadcast_groups.is_empty(),
        );
    }
}

impl TryFrom<&ItemBody> for Workspace {
    type Error = ViewError;

    fn try_from(body: &ItemBody) -> Result<Self, ViewError> {
        let read_only = check_kind(body, ItemKind::Workspace)?;
        let r = Reader::new(body);
        let broadcast_groups = match r.value("broadcast_groups") {
            None => Vec::new(),
            Some(v) => v
                .as_array()
                .cloned()
                .ok_or_else(|| r.type_err("broadcast_groups"))?,
        };
        Ok(Self {
            name: r.str("name")?,
            layout: r.value("layout").cloned(),
            broadcast_groups,
            read_only,
        })
    }
}

// ---------------------------------------------------------------- Tag (§4.11)

/// A tag (§4.11).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tag {
    /// `name`
    pub name: String,
    /// Color name or `#rrggbb`.
    pub color: Option<String>,
    /// The body's schema is newer than this build (§4.1).
    pub read_only: bool,
}

impl Tag {
    /// Writes the fields that differ from `body`.
    pub fn apply_to(&self, body: &mut ItemBody, clock: &mut HlcClock, device: DeviceId) {
        let mut w = Writer::new(body, clock, device);
        w.text("name", &self.name);
        w.opt("color", self.color.clone());
    }
}

impl TryFrom<&ItemBody> for Tag {
    type Error = ViewError;

    fn try_from(body: &ItemBody) -> Result<Self, ViewError> {
        let read_only = check_kind(body, ItemKind::Tag)?;
        let r = Reader::new(body);
        Ok(Self {
            name: r.str("name")?,
            color: r.opt_str("color")?,
            read_only,
        })
    }
}

// ---------------------------------------------------------------- HistoryEntry (§4.12)

/// A command history entry (§4.12). Synced only if the user opts in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    /// `command`
    pub command: String,
    /// The host it ran on (`None` for local shells).
    pub host_id: Option<ItemId>,
    /// `executed_at`
    pub executed_at: UnixMillis,
    /// `exit_code`
    pub exit_code: Option<i32>,
    // M7-01 (spec addition)
    /// `verified`: captured exactly (shell integration, snippet runs). `false` for the
    /// heuristic capture without OSC 133 (shown as "unverified"). Stored only when
    /// `false`; a missing field reads as `true`.
    pub verified: bool,
    /// The body's schema is newer than this build (§4.1).
    pub read_only: bool,
}

// M7-01: `verified` defaults to `true`.
impl Default for HistoryEntry {
    fn default() -> Self {
        Self {
            command: String::new(),
            host_id: None,
            executed_at: UnixMillis::default(),
            exit_code: None,
            verified: true,
            read_only: false,
        }
    }
}

impl HistoryEntry {
    /// Writes the fields that differ from `body`.
    pub fn apply_to(&self, body: &mut ItemBody, clock: &mut HlcClock, device: DeviceId) {
        let mut w = Writer::new(body, clock, device);
        w.text("command", &self.command);
        w.opt("host_id", self.host_id);
        w.always("executed_at", self.executed_at);
        w.opt("exit_code", self.exit_code);
        // M7-01
        w.opt("verified", (!self.verified).then_some(false));
    }
}

impl TryFrom<&ItemBody> for HistoryEntry {
    type Error = ViewError;

    fn try_from(body: &ItemBody) -> Result<Self, ViewError> {
        let read_only = check_kind(body, ItemKind::HistoryEntry)?;
        let r = Reader::new(body);
        Ok(Self {
            command: r.str("command")?,
            host_id: r.opt_id("host_id")?,
            executed_at: read_time(&r, "executed_at")?.unwrap_or_default(),
            exit_code: r.int("exit_code")?,
            // M7-01
            verified: r.opt_bool("verified")?.unwrap_or(true),
            read_only,
        })
    }
}

// ---------------------------------------------------------------- ConnLog (§4.12)

/// How a connection ended (§4.12). Flattened into `result.kind` and `result.message`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnResult {
    /// `"ok"`
    Ok,
    /// `"auth-failed"`
    AuthFailed,
    /// `"host-key-rejected"`
    HostKeyRejected,
    /// `"network-error"` with `result.message`
    NetworkError(String),
}

/// A connection log entry (§4.12). Synced only if `logs.sync = true`. The recording
/// path is device-local and not an item field.
///
/// M3-06 spec additions: `host_id` is optional (local shells and ephemeral quick-connect
/// targets have no host item), plus `label`, `target` and `error_detail`
/// (`docs/data-model.md`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnLog {
    /// `host_id` (M3-06: `None` for local shells and ephemeral hosts).
    pub host_id: Option<ItemId>,
    /// `started_at`
    pub started_at: UnixMillis,
    /// `ended_at` (`None` while the connection is open).
    pub ended_at: Option<UnixMillis>,
    /// `result.*` (`None` while the connection is open).
    pub result: Option<ConnResult>,
    /// `bytes_in`
    pub bytes_in: u64,
    /// `bytes_out`
    pub bytes_out: u64,
    /// The body's schema is newer than this build (§4.1).
    pub read_only: bool,
    // M3-06 (spec additions)
    /// `label`: what the attempt was shown as (host label, `local`), kept so the log
    /// still reads well after the host is renamed or deleted.
    pub label: String,
    /// `target`: `user@host:port` for SSH attempts (reconnecting an ephemeral host),
    /// `None` for local shells.
    pub target: Option<String>,
    /// `error_detail`: the `ErrorReport` of a failed attempt, short message first, then
    /// the cause chain.
    pub error_detail: Option<Vec<String>>,
}

impl ConnLog {
    /// Writes the fields that differ from `body`.
    pub fn apply_to(&self, body: &mut ItemBody, clock: &mut HlcClock, device: DeviceId) {
        let mut w = Writer::new(body, clock, device);
        // M3-06: optional (spec addition).
        w.opt("host_id", self.host_id);
        w.always("started_at", self.started_at);
        w.opt("ended_at", self.ended_at);
        let (kind, message) = match &self.result {
            None => (None, None),
            Some(ConnResult::Ok) => (Some("ok"), None),
            Some(ConnResult::AuthFailed) => (Some("auth-failed"), None),
            Some(ConnResult::HostKeyRejected) => (Some("host-key-rejected"), None),
            Some(ConnResult::NetworkError(m)) => (Some("network-error"), Some(m.clone())),
        };
        w.opt("result.kind", kind);
        w.opt("result.message", message);
        w.put_or_skip("bytes_in", Value::from(self.bytes_in), self.bytes_in == 0);
        w.put_or_skip(
            "bytes_out",
            Value::from(self.bytes_out),
            self.bytes_out == 0,
        );
        // M3-06
        w.text("label", &self.label);
        w.opt("target", self.target.clone());
        w.opt_strs("error_detail", self.error_detail.as_deref());
    }

    // M3-06
    /// Whether the attempt ended in a failure (anything but `Ok`; open entries are not).
    pub fn is_failure(&self) -> bool {
        matches!(&self.result, Some(r) if *r != ConnResult::Ok)
    }

    // M3-06
    /// How long the attempt lasted (`None` while open).
    pub fn duration(&self) -> Option<Duration> {
        let end = self.ended_at?;
        u64::try_from(end.0.saturating_sub(self.started_at.0))
            .ok()
            .map(Duration::from_millis)
    }
}

// M3-06
impl ConnResult {
    /// Short label for lists (`ok`, `auth failed`, …).
    pub fn label(&self) -> &str {
        match self {
            Self::Ok => "ok",
            Self::AuthFailed => "auth failed",
            Self::HostKeyRejected => "host key rejected",
            Self::NetworkError(_) => "network error",
        }
    }
}

impl TryFrom<&ItemBody> for ConnLog {
    type Error = ViewError;

    fn try_from(body: &ItemBody) -> Result<Self, ViewError> {
        let read_only = check_kind(body, ItemKind::ConnLog)?;
        let r = Reader::new(body);
        let result = match r.opt_str("result.kind")?.as_deref() {
            None => None,
            Some("ok") => Some(ConnResult::Ok),
            Some("auth-failed") => Some(ConnResult::AuthFailed),
            Some("host-key-rejected") => Some(ConnResult::HostKeyRejected),
            Some("network-error") => Some(ConnResult::NetworkError(r.str("result.message")?)),
            Some(_) => return Err(r.type_err("result.kind")),
        };
        Ok(Self {
            // M3-06: optional (spec addition).
            host_id: r.opt_id("host_id")?,
            started_at: read_time(&r, "started_at")?.unwrap_or_default(),
            ended_at: read_time(&r, "ended_at")?,
            result,
            bytes_in: r.int("bytes_in")?.unwrap_or(0),
            bytes_out: r.int("bytes_out")?.unwrap_or(0),
            read_only,
            // M3-06
            label: r.opt_str("label")?.unwrap_or_default(),
            target: r.opt_str("target")?,
            error_detail: r.opt_strs("error_detail")?,
        })
    }
}
