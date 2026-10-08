//! [`SshTarget`]: a host with every setting resolved **and** its secrets, ready to
//! connect (M1-13 task §2.1).
//!
//! `sverb_core::resolve::ResolvedHost` (M2-01) is the domain resolution: group chain,
//! vault defaults, provenance, and *no secret values* (it says where the password is
//! stored). The UI's [`HostResolver`](super::HostResolver) turns it into an
//! [`SshTarget`] by reading the secrets from the vault. [`resolve`] and
//! [`resolve_spec`] here are the minimal M1 builders (host → identity → config, no
//! groups) used for unsaved targets, tests, and when no vault is available.
//!
//! Username: inline → identity → `$USER`. Keepalive: host → `ssh.keepalive_secs`.

use std::time::Duration;

use sverb_core::{
    config::Config,
    model::{AgentSource, AlgoOverrides, Backspace, DEFAULT_SSH_PORT, Host, Identity, ItemId},
    secret::SecretString,
};

use crate::session::SshSpec;
// M2-06
use crate::proxy::{ProxyConfig, ValueOrigin};

/// Credentials and references for the authentication step (M1-14 uses the refs).
#[derive(Debug)]
pub struct AuthMaterial {
    /// The stored password (inline, else the identity's).
    pub password: Option<SecretString>,
    /// The configured key (inline, else the identity's).
    pub key_id: Option<ItemId>,
    /// The identity the credentials came from.
    pub identity_id: Option<ItemId>,
    // M1-14
    /// The configured key's material, read from the vault by the resolver. `None` with
    /// `key_id` set means the key item could not be read: no key is offered, and the
    /// system agent stays off too (IdentitiesOnly follows the configuration).
    pub key: Option<KeyMaterial>,
    /// `ssh.max_auth_attempts`: requests per connection (each key, agent identity,
    /// password and keyboard-interactive round counts as one).
    pub max_attempts: u32,
    /// `ssh.use_system_agent`.
    pub use_system_agent: bool,
    /// The host opted into `ssh-rsa` (SHA-1) in its legacy algorithms
    /// (`algorithms.host_key` lists `ssh-rsa`): RSA keys may then sign with SHA-1 when
    /// the server offers nothing better.
    pub allow_ssh_rsa: bool,
}

// M1-14
impl Default for AuthMaterial {
    fn default() -> Self {
        let ssh = sverb_core::config::SshConfig::default();
        Self {
            password: None,
            key_id: None,
            identity_id: None,
            key: None,
            max_attempts: ssh.max_auth_attempts,
            use_system_agent: ssh.use_system_agent,
            allow_ssh_rsa: false,
        }
    }
}

// M1-14
/// A configured private key with what belongs to it.
#[derive(Debug)]
pub struct KeyMaterial {
    /// The Key item.
    pub key_id: Option<ItemId>,
    /// Its label (for the passphrase prompt).
    pub label: String,
    /// The OpenSSH private key text (possibly passphrase-encrypted).
    pub private_key: SecretString,
    /// The stored passphrase.
    pub passphrase: Option<SecretString>,
    /// Attached OpenSSH certificates (`ssh-ed25519-cert-v01@openssh.com AAAA…`).
    pub certificates: Vec<String>,
}

// M1-14
/// Whether `overrides` opts into `ssh-rsa` signatures (SHA-1).
pub fn allows_ssh_rsa(overrides: &AlgoOverrides) -> bool {
    overrides
        .host_key
        .as_ref()
        .is_some_and(|l| l.iter().any(|a| a.trim() == "ssh-rsa"))
}

/// A host with every setting resolved and its secrets, ready to connect.
#[derive(Debug)]
pub struct SshTarget {
    /// The host item (`None` for an unsaved target).
    pub host_id: Option<ItemId>,
    /// Display label.
    pub label: String,
    /// Hostname or IP literal.
    pub address: String,
    /// Port (default 22).
    pub port: u16,
    /// User name (inline → identity → `$USER`).
    pub username: String,
    /// Credentials.
    pub auth: AuthMaterial,
    /// Jump hosts (M2-05). Not supported yet: a non-empty chain fails the connection.
    pub jump_chain: Vec<ItemId>,
    /// A proxy is configured (`proxy.is_some()`; kept for callers that only ask).
    pub proxy_configured: bool,
    // M2-06
    /// How the first hop is reached (§6.1.5), with the proxy password; `None`: direct.
    pub proxy: Option<ProxyConfig>,
    /// Environment sent with `env` requests.
    pub env: Vec<(String, String)>,
    /// Keepalive interval (host → `ssh.keepalive_secs`); 0 disables keepalive.
    pub keepalive_secs: u32,
    /// Remote charset; `None` is UTF-8.
    pub charset: Option<String>,
    /// What Backspace sends (and `VERASE`).
    pub backspace: Backspace,
    /// Color scheme.
    pub color_scheme: Option<String>,
    /// Legacy algorithm opt-ins.
    pub algorithms: AlgoOverrides,
    /// Agent forwarding (M2-07).
    pub agent_forwarding: bool,
    /// Which agent answers (M2-07).
    pub agent_source: AgentSource,
    // M2-07
    /// Where the agent settings came from (§17.1: forwarding the system agent for a
    /// synced host needs approval).
    pub agent_origin: crate::proxy::ValueOrigin,
    /// Snippet run after the shell opens (M2-09).
    pub startup_snippet_id: Option<ItemId>,
    /// What to type once the shell is up (the startup snippet's text; a stub until
    /// M2-09 adds variables and run modes).
    pub startup_input: Option<String>,
    /// Request a PTY for exec runs.
    pub request_pty_for_exec: bool,
    /// `TERM` for the PTY (`terminal.term`).
    pub term: String,
    /// TCP and handshake timeout (`ssh.connect_timeout_secs`).
    pub connect_timeout: Duration,
}

impl SshTarget {
    /// Whether the remote charset is UTF-8 (`IUTF8` is set only then).
    pub fn is_utf8(&self) -> bool {
        self.charset.as_deref().is_none_or(|c| {
            let c = c.trim();
            c.eq_ignore_ascii_case("utf-8") || c.eq_ignore_ascii_case("utf8")
        })
    }

    /// `host:port` as shown in messages (`[v6]:port` for IPv6 literals).
    pub fn display_addr(&self) -> String {
        if self.address.contains(':') && !self.address.starts_with('[') {
            format!("[{}]:{}", self.address, self.port)
        } else {
            format!("{}:{}", self.address, self.port)
        }
    }
}

fn copy_secret(s: &SecretString) -> SecretString {
    SecretString::from(s.expose())
}

/// The local user name (`$USER`, `$USERNAME` on Windows).
pub fn local_user() -> Option<String> {
    ["USER", "USERNAME", "LOGNAME"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
}

/// Resolve `host` (with its `identity`, when it has one) against `config`.
/// `local_user` supplies the fallback user name.
pub fn resolve(
    host: &Host,
    host_id: Option<ItemId>,
    identity: Option<&Identity>,
    config: &Config,
    local_user: impl FnOnce() -> Option<String>,
) -> SshTarget {
    let username = host
        .username
        .clone()
        .filter(|u| !u.is_empty())
        .or_else(|| {
            identity
                .map(|i| i.username.clone())
                .filter(|u| !u.is_empty())
        })
        .or_else(local_user)
        .unwrap_or_default();
    let password = host
        .password
        .as_ref()
        .or_else(|| identity.and_then(|i| i.password.as_ref()))
        .map(copy_secret);
    SshTarget {
        host_id,
        label: host.display_label().to_owned(),
        address: host.address.clone(),
        port: host.port.unwrap_or(DEFAULT_SSH_PORT),
        username,
        auth: AuthMaterial {
            password,
            key_id: host.key_id.or_else(|| identity.and_then(|i| i.key_id)),
            identity_id: host.identity_id,
            // M1-14
            key: None,
            max_attempts: config.ssh.max_auth_attempts,
            use_system_agent: config.ssh.use_system_agent,
            allow_ssh_rsa: host.algorithms.as_ref().is_some_and(allows_ssh_rsa),
        },
        jump_chain: host.jump_chain.clone(),
        proxy_configured: host.proxy.is_some(),
        // M2-06: an unsaved host's ProxyCommand counts as typed here (no stamp).
        proxy: host
            .proxy
            .as_ref()
            .map(|p| ProxyConfig::from_model(p, ValueOrigin::default())),
        env: host.env.clone(),
        keepalive_secs: host.keepalive_secs.unwrap_or(config.ssh.keepalive_secs),
        charset: host.charset.clone(),
        backspace: host.backspace.unwrap_or(Backspace::Del),
        color_scheme: host.color_scheme.clone(),
        algorithms: host.algorithms.clone().unwrap_or_default(),
        agent_forwarding: host.agent_forwarding.unwrap_or(false),
        agent_source: host.agent_source.unwrap_or(AgentSource::Builtin),
        // M2-07: an unsaved / test host: typed here.
        agent_origin: crate::proxy::ValueOrigin::default(),
        startup_snippet_id: host.startup_snippet_id,
        startup_input: None,
        request_pty_for_exec: host.request_pty_for_exec.unwrap_or(false),
        term: config.terminal.term.clone(),
        connect_timeout: Duration::from_secs(u64::from(config.ssh.connect_timeout_secs.max(1))),
    }
}

/// Resolve an unsaved target (quick connect, or a saved host when its settings can't be
/// loaded from a vault): the spec's address, port and user, the global config for the
/// rest.
pub fn resolve_spec(
    spec: &SshSpec,
    config: &Config,
    local_user: impl FnOnce() -> Option<String>,
) -> SshTarget {
    let host = Host {
        label: spec.label.clone().unwrap_or_default(),
        address: spec.host.clone(),
        port: (spec.port != 0).then_some(spec.port),
        username: spec.user.clone(),
        backspace: spec.backspace,
        ..Host::default()
    };
    resolve(&host, spec.host_id, None, config, local_user)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn identity(user: &str, password: Option<&str>) -> Identity {
        Identity {
            label: "ops".into(),
            username: user.into(),
            password: password.map(SecretString::from),
            ..Identity::default()
        }
    }

    #[test]
    fn username_inline_then_identity_then_local() {
        let config = Config::default();
        let mut host = Host {
            address: "db".into(),
            ..Host::default()
        };
        let none = || None;
        assert_eq!(
            resolve(&host, None, None, &config, || Some("me".into())).username,
            "me"
        );
        let id = identity("ops", Some("pw"));
        let r = resolve(&host, None, Some(&id), &config, none);
        assert_eq!(r.username, "ops");
        assert_eq!(
            r.auth.password.as_ref().map(|p| p.expose().to_owned()),
            Some("pw".into())
        );
        host.username = Some("root".into());
        host.password = Some(SecretString::from("inline"));
        let r = resolve(&host, None, Some(&id), &config, none);
        assert_eq!(r.username, "root");
        assert_eq!(r.auth.password.unwrap().expose(), "inline");
    }

    #[test]
    fn defaults_come_from_config() {
        let mut config = Config::default();
        config.ssh.keepalive_secs = 7;
        config.ssh.connect_timeout_secs = 3;
        config.terminal.term = "xterm".into();
        let host = Host {
            address: "2001:db8::1".into(),
            ..Host::default()
        };
        let r = resolve(&host, None, None, &config, || None);
        assert_eq!(r.port, 22);
        assert_eq!(r.keepalive_secs, 7);
        assert_eq!(r.connect_timeout, Duration::from_secs(3));
        assert_eq!(r.term, "xterm");
        assert_eq!(r.backspace, Backspace::Del);
        assert!(r.is_utf8());
        assert_eq!(r.display_addr(), "[2001:db8::1]:22");
        let host = Host {
            address: "db".into(),
            keepalive_secs: Some(0),
            charset: Some("ISO-8859-1".into()),
            ..Host::default()
        };
        let r = resolve(&host, None, None, &config, || None);
        assert_eq!(r.keepalive_secs, 0);
        assert!(!r.is_utf8());
    }

    #[test]
    fn specs_resolve_without_a_vault() {
        let spec = SshSpec {
            host: "10.0.0.5".into(),
            port: 2222,
            user: Some("deploy".into()),
            backspace: Some(Backspace::CtrlH),
            ..SshSpec::default()
        };
        let r = resolve_spec(&spec, &Config::default(), || None);
        assert_eq!(
            (r.address.as_str(), r.port, r.username.as_str()),
            ("10.0.0.5", 2222, "deploy")
        );
        assert_eq!(r.backspace, Backspace::CtrlH);
        assert_eq!(r.label, "10.0.0.5");
    }
}
