//! The session state machine (SPEC §2.1.1).
//!
//! [`SessionState::transition`] is a pure function: given the current state, an input
//! ([`StateInput`]) and the current time, it returns the next state or an
//! [`IllegalTransition`]. The session actor applies inputs through it; an illegal
//! transition is a bug, logged at `error`, and the session moves to
//! `Disconnected { reason: Internal }`.
//!
//! # Allowed transitions
//!
//! | From | Input | To |
//! |---|---|---|
//! | Resolving | `Resolved { hops: n }` | `Connecting { 1, n }` |
//! | Resolving | `ChannelOpened` (local PTY / mock subset) | `Connected` |
//! | Resolving | `TransportError(r)` | `Disconnected { r }` |
//! | Connecting { h, n } | `TcpConnected { hop: h }` | `Connecting { h, n }` (progress for the current hop) |
//! | Connecting | `HostKeyNeeded(v)` | `AwaitingHostKey(v)` (same hop) |
//! | Connecting | `AuthStarted(m)` | `Authenticating { m }` (same hop) |
//! | Connecting | `TransportError(r)` | `Disconnected { r }` |
//! | Connecting | `ChannelOpened` (M3-07: the rest of the chain was shared) | `Connected` |
//! | AwaitingHostKey | `HostKeyAccepted` | `Connecting` (same hop) |
//! | AwaitingHostKey | `HostKeyRejected` / `KeepaliveTimeout` (prompt timeout) | `Disconnected { HostKey }` |
//! | AwaitingHostKey | `TransportError(r)` | `Disconnected { r }` |
//! | Authenticating | `PromptNeeded(p)` | `AwaitingUser(p)` |
//! | Authenticating | `AuthStarted(m)` (next method) | `Authenticating { m }` |
//! | Authenticating { h < n } | `AuthSucceeded` (intermediate hop) | `Connecting { h + 1, n }` |
//! | Authenticating { h = n } | `AuthSucceeded` (final hop) | unchanged, waits for the channel |
//! | Authenticating { h = n } | `ChannelOpened` | `Connected` |
//! | Authenticating | `AuthFailed` (no methods left) | `Disconnected { Auth }` |
//! | Authenticating | `TransportError(r)` | `Disconnected { r }` |
//! | AwaitingUser | `PromptAnswered` | `Authenticating` (same method and hop) |
//! | AwaitingUser | `TransportError(r)` | `Disconnected { r }` |
//! | Connected | `RemoteExit(c)` | `Disconnected { Exited(c) }` |
//! | Connected | `TransportError(r)` | `Disconnected { r }` |
//! | Connected | `KeepaliveTimeout` | `Disconnected { Timeout }` |
//! | Disconnected | `ReconnectRequested` | `Resolving` |
//! | any but Closed | `UserClose` | `Closed` |
//! | Closed | anything | **illegal** |
//!
//! Everything else is illegal. Two rows differ from the task table (M1-08) and are
//! documented in the task report: `TcpConnected` does not advance the hop (the hop
//! advances on `AuthSucceeded` of an intermediate hop, otherwise a two-hop chain would
//! skip a hop), and a network error while a host-key or auth prompt is open is a normal
//! `Disconnected { r }`, not a bug.

use std::{fmt, time::Instant};

/// How the user authenticates (SPEC §6.1.1). M1-14 adds the details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuthMethod {
    /// `none` (servers that allow it).
    None,
    /// Password.
    Password,
    /// Public key (vault key or file).
    PublicKey,
    /// An SSH agent (built-in or system).
    Agent,
    /// Keyboard-interactive (OTP, 2FA).
    KeyboardInteractive,
}

/// A host key the user has to confirm (SPEC §9.5).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Verification {
    /// 1-based hop in the jump chain. Set from the state by the transition.
    pub hop: usize,
    /// Number of hops.
    pub of: usize,
    /// `host:port` as the user configured it.
    pub host: String,
    /// `SHA256:…` fingerprint.
    pub fingerprint: String,
    /// The key changed since it was last trusted (a warning, not a first-use prompt).
    pub changed: bool,
    // M1-15
    /// What the prompt shows: key type, randomart, old fingerprints.
    pub details: HostKeyDetails,
}

// M1-15
/// The details of a host-key question (the unknown-key modal, the changed-key screen).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HostKeyDetails {
    /// The host's address as configured (no port): the name to type to replace a
    /// changed key, and the certificate principal.
    pub hostname: String,
    /// The port.
    pub port: u16,
    /// `ssh-ed25519`, `ecdsa-sha2-nistp256`, …
    pub key_type: String,
    /// The OpenSSH randomart of the key (`\n`-separated lines).
    pub randomart: String,
    /// A changed key: the fingerprints of the trusted keys of this type.
    pub old_fingerprints: Vec<String>,
    /// Why a presented host certificate was not accepted, if it was one.
    pub note: Option<String>,
}

/// A prompt the user has to answer during authentication (M1-14: one dialog per
/// request, SPEC §6.1.1 step 4).
///
/// Server-provided text (`name`, `instruction`, keyboard-interactive prompt lines) is
/// untrusted: the connector sanitizes it (`ssh::auth::sanitize_server_text`) before it
/// lands here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthPrompt {
    /// 1-based hop. Set from the state by the transition.
    pub hop: usize,
    /// Number of hops. Set from the state by the transition.
    pub of: usize,
    /// The method asking. Set from the state by the transition.
    pub method: AuthMethod,
    /// Prompt lines (keyboard-interactive may ask several questions).
    pub prompts: Vec<PromptLine>,
    // M1-14
    /// What is asked (decides the "save to vault" checkbox).
    pub kind: PromptKind,
    /// Dialog title: `Authenticate to <label>`.
    pub title: String,
    /// The server's request name (keyboard-interactive), sanitized; else empty.
    pub name: String,
    /// The instruction (server-provided for keyboard-interactive, sanitized), or
    /// sverb's own text (`Password for user@host`, a retry notice).
    pub instruction: String,
}

// M1-14
impl AuthPrompt {
    /// A prompt of `kind` with `prompts`; the hop and method are set by the transition.
    pub fn new(kind: PromptKind, title: String, prompts: Vec<PromptLine>) -> Self {
        Self {
            hop: 1,
            of: 1,
            method: AuthMethod::None,
            prompts,
            kind,
            title,
            name: String::new(),
            instruction: String::new(),
        }
    }
}

// M1-14
/// What an [`AuthPrompt`] asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PromptKind {
    /// The login password. `host` is the saved host it can be stored on (inline), if
    /// any: the dialog offers "save to vault" only then.
    Password {
        /// The saved host.
        host: Option<sverb_core::model::ItemId>,
    },
    /// The passphrase of an encrypted private key. `key` is the Key item it can be
    /// stored on.
    Passphrase {
        /// The Key item.
        key: Option<sverb_core::model::ItemId>,
        /// The key's label (shown in the dialog).
        label: String,
    },
    /// A keyboard-interactive info request (OTP, 2FA, …). Never saved.
    KeyboardInteractive,
}

impl PromptKind {
    /// Where an accepted answer may be saved, if anywhere.
    pub fn save_target(&self) -> Option<sverb_core::model::ItemId> {
        match self {
            Self::Password { host } => *host,
            Self::Passphrase { key, .. } => *key,
            Self::KeyboardInteractive => None,
        }
    }
}

/// One question of an [`AuthPrompt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptLine {
    /// The question text.
    pub text: String,
    /// Whether the answer may be shown while typed.
    pub echo: bool,
}

/// Why a session is disconnected (SPEC §6.1.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisconnectReason {
    /// DNS failure.
    Resolve,
    /// TCP refused or timed out, or the transport failed.
    Connect,
    /// No common algorithms.
    Negotiation,
    /// Host key rejected or changed.
    HostKey,
    /// All authentication methods failed.
    Auth,
    /// Keepalive timeout.
    Timeout,
    /// The remote side exited with this status.
    Exited(i32),
    /// A bug in sverb (illegal transition, session task panic).
    Internal,
    /// The remote closed the connection without an exit status.
    Closed,
}

impl DisconnectReason {
    /// A short user-facing message (SPEC §6.1.9). M1-13 adds host, address and the
    /// algorithm details to the messages it shows.
    pub fn message(self) -> String {
        match self {
            Self::Resolve => "Could not resolve host".to_owned(),
            Self::Connect => "Connection refused or timed out".to_owned(),
            Self::Negotiation => "No common algorithms with the server".to_owned(),
            Self::HostKey => "Host key verification failed".to_owned(),
            Self::Auth => "Permission denied".to_owned(),
            Self::Timeout => "Connection lost (no response)".to_owned(),
            Self::Exited(code) => format!("Session ended (exit {code})"),
            Self::Internal => "session crashed (see log)".to_owned(),
            Self::Closed => "Connection closed by the remote host".to_owned(),
        }
    }

    /// Whether the pane offers the reconnect banner (SPEC §6.1.2). A clean remote exit
    /// does not (§6.1.9).
    pub fn offers_reconnect(self) -> bool {
        !matches!(self, Self::Exited(_))
    }
}

impl fmt::Display for DisconnectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message())
    }
}

/// The lifecycle state of a session (SPEC §2.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    /// Settings resolution, DNS.
    Resolving,
    /// Connecting to hop `hop` (1-based) of `of`.
    Connecting {
        /// Current hop.
        hop: usize,
        /// Number of hops.
        of: usize,
    },
    /// The host-key modal is shown; the handshake is suspended.
    AwaitingHostKey(Verification),
    /// Trying `method` on hop `hop` of `of`.
    Authenticating {
        /// Method being tried.
        method: AuthMethod,
        /// Current hop (M1-08: needed to tell intermediate from final hops).
        hop: usize,
        /// Number of hops.
        of: usize,
    },
    /// A password / keyboard-interactive / passphrase prompt is shown.
    AwaitingUser(AuthPrompt),
    /// The shell channel is open.
    Connected {
        /// When it connected.
        since: Instant,
    },
    /// Not connected; the pane shows the reconnect banner unless the remote exited.
    Disconnected {
        /// Why.
        reason: DisconnectReason,
        /// When.
        at: Instant,
    },
    /// Closed by the user; the actor ends.
    Closed,
}

/// Something that happened to a session, fed to [`SessionState::transition`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateInput {
    /// Settings and DNS resolved; the chain has `hops` hops (1 without jump hosts).
    Resolved {
        /// Number of hops.
        hops: usize,
    },
    /// The TCP (or proxy / direct-tcpip) stream to `hop` is up.
    TcpConnected {
        /// 1-based hop.
        hop: usize,
    },
    /// The server's host key needs a decision.
    HostKeyNeeded(Verification),
    /// The user (or known_hosts) accepted the key.
    HostKeyAccepted,
    /// The user rejected the key.
    HostKeyRejected,
    /// Trying an authentication method.
    AuthStarted(AuthMethod),
    /// The method needs the user to answer a prompt.
    PromptNeeded(AuthPrompt),
    /// The user answered.
    PromptAnswered,
    /// Authentication on the current hop succeeded.
    AuthSucceeded,
    /// All methods failed.
    AuthFailed,
    /// The shell channel (or local PTY) is open.
    ChannelOpened,
    /// The remote process exited with a status.
    RemoteExit(i32),
    /// The transport failed.
    TransportError(DisconnectReason),
    /// No keepalive reply (or a prompt timed out).
    KeepaliveTimeout,
    /// The user closed the session.
    UserClose,
    /// The user asked to reconnect.
    ReconnectRequested,
}

/// An input that is not allowed in the current state (a bug).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
// Only variant names: states and inputs can carry hostnames (SPEC §17 logging rules).
#[error("illegal session transition: {} in state {}", input.name(), from.name())]
pub struct IllegalTransition {
    /// The state the input arrived in.
    pub from: Box<SessionState>,
    /// The input.
    pub input: Box<StateInput>,
}

impl SessionState {
    /// The next state for `input`, or [`IllegalTransition`]. Pure; `now` stamps
    /// `Connected::since` and `Disconnected::at`.
    pub fn transition(
        &self,
        input: StateInput,
        now: Instant,
    ) -> Result<SessionState, IllegalTransition> {
        use SessionState as S;
        use StateInput as I;

        let disc = |reason: DisconnectReason| Some(S::Disconnected { reason, at: now });
        let next = match (self, &input) {
            (S::Closed, _) => None,
            (_, I::UserClose) => Some(S::Closed),

            (S::Resolving, I::Resolved { hops }) => Some(S::Connecting {
                hop: 1,
                of: (*hops).max(1),
            }),
            (S::Resolving, I::ChannelOpened) => Some(S::Connected { since: now }),
            (S::Resolving, I::TransportError(r)) => disc(*r),

            (S::Connecting { hop, of }, I::TcpConnected { hop: h }) if h == hop => {
                Some(S::Connecting { hop: *hop, of: *of })
            }
            (S::Connecting { hop, of }, I::HostKeyNeeded(v)) => {
                Some(S::AwaitingHostKey(Verification {
                    hop: *hop,
                    of: *of,
                    ..v.clone()
                }))
            }
            (S::Connecting { hop, of }, I::AuthStarted(method)) => Some(S::Authenticating {
                method: *method,
                hop: *hop,
                of: *of,
            }),
            (S::Connecting { .. }, I::TransportError(r)) => disc(*r),
            // M3-07: a connection another session dialed meanwhile was shared, so the
            // hops planned after the current one were never dialed.
            (S::Connecting { .. }, I::ChannelOpened) => Some(S::Connected { since: now }),

            (S::AwaitingHostKey(v), I::HostKeyAccepted) => Some(S::Connecting {
                hop: v.hop,
                of: v.of,
            }),
            (S::AwaitingHostKey(_), I::HostKeyRejected | I::KeepaliveTimeout) => {
                disc(DisconnectReason::HostKey)
            }
            (S::AwaitingHostKey(_), I::TransportError(r)) => disc(*r),

            (S::Authenticating { method, hop, of }, I::PromptNeeded(p)) => {
                Some(S::AwaitingUser(AuthPrompt {
                    hop: *hop,
                    of: *of,
                    method: *method,
                    // M1-14
                    ..p.clone()
                }))
            }
            (S::Authenticating { hop, of, .. }, I::AuthStarted(method)) => {
                Some(S::Authenticating {
                    method: *method,
                    hop: *hop,
                    of: *of,
                })
            }
            (S::Authenticating { hop, of, .. }, I::AuthSucceeded) if hop < of => {
                Some(S::Connecting {
                    hop: hop + 1,
                    of: *of,
                })
            }
            (S::Authenticating { .. }, I::AuthSucceeded) => Some(self.clone()),
            (S::Authenticating { hop, of, .. }, I::ChannelOpened) if hop >= of => {
                Some(S::Connected { since: now })
            }
            (S::Authenticating { .. }, I::AuthFailed) => disc(DisconnectReason::Auth),
            (S::Authenticating { .. }, I::TransportError(r)) => disc(*r),

            (S::AwaitingUser(p), I::PromptAnswered) => Some(S::Authenticating {
                method: p.method,
                hop: p.hop,
                of: p.of,
            }),
            (S::AwaitingUser(_), I::TransportError(r)) => disc(*r),

            (S::Connected { .. }, I::RemoteExit(code)) => disc(DisconnectReason::Exited(*code)),
            (S::Connected { .. }, I::TransportError(r)) => disc(*r),
            (S::Connected { .. }, I::KeepaliveTimeout) => disc(DisconnectReason::Timeout),

            (S::Disconnected { .. }, I::ReconnectRequested) => Some(S::Resolving),

            _ => None,
        };
        next.ok_or_else(|| IllegalTransition {
            from: Box::new(self.clone()),
            input: Box::new(input),
        })
    }

    /// The variant name (for logs: never includes hostnames).
    pub fn name(&self) -> &'static str {
        match self {
            SessionState::Resolving => "Resolving",
            SessionState::Connecting { .. } => "Connecting",
            SessionState::AwaitingHostKey(_) => "AwaitingHostKey",
            SessionState::Authenticating { .. } => "Authenticating",
            SessionState::AwaitingUser(_) => "AwaitingUser",
            SessionState::Connected { .. } => "Connected",
            SessionState::Disconnected { .. } => "Disconnected",
            SessionState::Closed => "Closed",
        }
    }

    /// Whether the session is connected.
    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Connected { .. })
    }

    /// Whether the actor has ended.
    pub fn is_closed(&self) -> bool {
        matches!(self, Self::Closed)
    }
}

impl StateInput {
    /// The variant name (for logs: never includes hostnames).
    pub fn name(&self) -> &'static str {
        match self {
            StateInput::Resolved { .. } => "Resolved",
            StateInput::TcpConnected { .. } => "TcpConnected",
            StateInput::HostKeyNeeded(_) => "HostKeyNeeded",
            StateInput::HostKeyAccepted => "HostKeyAccepted",
            StateInput::HostKeyRejected => "HostKeyRejected",
            StateInput::AuthStarted(_) => "AuthStarted",
            StateInput::PromptNeeded(_) => "PromptNeeded",
            StateInput::PromptAnswered => "PromptAnswered",
            StateInput::AuthSucceeded => "AuthSucceeded",
            StateInput::AuthFailed => "AuthFailed",
            StateInput::ChannelOpened => "ChannelOpened",
            StateInput::RemoteExit(_) => "RemoteExit",
            StateInput::TransportError(_) => "TransportError",
            StateInput::KeepaliveTimeout => "KeepaliveTimeout",
            StateInput::UserClose => "UserClose",
            StateInput::ReconnectRequested => "ReconnectRequested",
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use pretty_assertions::assert_eq;

    fn verification() -> Verification {
        Verification {
            hop: 9,
            of: 9,
            host: "example.org:22".to_owned(),
            fingerprint: "SHA256:abc".to_owned(),
            changed: false,
            ..Verification::default()
        }
    }

    fn prompt() -> AuthPrompt {
        AuthPrompt {
            hop: 9,
            of: 9,
            method: AuthMethod::None,
            prompts: vec![PromptLine {
                text: "Password:".to_owned(),
                echo: false,
            }],
            // M1-14
            ..AuthPrompt::new(
                PromptKind::KeyboardInteractive,
                "Authenticate to test".to_owned(),
                Vec::new(),
            )
        }
    }

    // `SessionState::name` / `StateInput::name` match without a wildcard: adding a
    // variant fails to compile there, and the count asserts below make T-01 grow.
    fn state_name(s: &SessionState) -> &'static str {
        s.name()
    }

    fn input_name(i: &StateInput) -> &'static str {
        i.name()
    }

    /// T-01: every (state, input) pair over all variants (with intermediate and final
    /// hops), checked against an explicit allow-list; everything else must be illegal.
    #[test]
    fn t01_transition_table_exhaustive() {
        let now = Instant::now();
        let earlier = now - std::time::Duration::from_secs(5);
        let host_key_at_1 = SessionState::AwaitingHostKey(Verification {
            hop: 1,
            of: 2,
            ..verification()
        });
        let user_at_2 = SessionState::AwaitingUser(AuthPrompt {
            hop: 2,
            of: 2,
            method: AuthMethod::KeyboardInteractive,
            ..prompt()
        });
        let states: Vec<(&str, SessionState)> = vec![
            ("resolving", SessionState::Resolving),
            ("conn1/2", SessionState::Connecting { hop: 1, of: 2 }),
            ("conn2/2", SessionState::Connecting { hop: 2, of: 2 }),
            ("hostkey1/2", host_key_at_1),
            (
                "auth1/2",
                SessionState::Authenticating {
                    method: AuthMethod::Password,
                    hop: 1,
                    of: 2,
                },
            ),
            (
                "auth2/2",
                SessionState::Authenticating {
                    method: AuthMethod::Password,
                    hop: 2,
                    of: 2,
                },
            ),
            ("user2/2", user_at_2),
            ("connected", SessionState::Connected { since: earlier }),
            (
                "disconnected",
                SessionState::Disconnected {
                    reason: DisconnectReason::Connect,
                    at: earlier,
                },
            ),
            ("closed", SessionState::Closed),
        ];
        let inputs: Vec<(&str, StateInput)> = vec![
            ("resolved", StateInput::Resolved { hops: 2 }),
            ("tcp1", StateInput::TcpConnected { hop: 1 }),
            ("tcp2", StateInput::TcpConnected { hop: 2 }),
            ("hkneeded", StateInput::HostKeyNeeded(verification())),
            ("hkaccepted", StateInput::HostKeyAccepted),
            ("hkrejected", StateInput::HostKeyRejected),
            (
                "authstarted",
                StateInput::AuthStarted(AuthMethod::PublicKey),
            ),
            ("promptneeded", StateInput::PromptNeeded(prompt())),
            ("promptanswered", StateInput::PromptAnswered),
            ("authok", StateInput::AuthSucceeded),
            ("authfailed", StateInput::AuthFailed),
            ("channel", StateInput::ChannelOpened),
            ("exit", StateInput::RemoteExit(3)),
            ("err", StateInput::TransportError(DisconnectReason::Resolve)),
            ("keepalive", StateInput::KeepaliveTimeout),
            ("close", StateInput::UserClose),
            ("reconnect", StateInput::ReconnectRequested),
        ];
        let disc = |reason| SessionState::Disconnected { reason, at: now };
        let auth = |method, hop, of| SessionState::Authenticating { method, hop, of };
        let user = |hop, of, method| {
            SessionState::AwaitingUser(AuthPrompt {
                hop,
                of,
                method,
                ..prompt()
            })
        };
        let hk = |hop, of| {
            SessionState::AwaitingHostKey(Verification {
                hop,
                of,
                ..verification()
            })
        };
        let connected = SessionState::Connected { since: now };
        let err = DisconnectReason::Resolve;
        let pw = AuthMethod::Password;
        let pk = AuthMethod::PublicKey;
        let ki = AuthMethod::KeyboardInteractive;
        // The ground truth (module docs). `UserClose` from every non-Closed state is
        // added below.
        let allowed: Vec<(&str, &str, SessionState)> = vec![
            (
                "resolving",
                "resolved",
                SessionState::Connecting { hop: 1, of: 2 },
            ),
            ("resolving", "channel", connected.clone()),
            ("resolving", "err", disc(err)),
            (
                "conn1/2",
                "tcp1",
                SessionState::Connecting { hop: 1, of: 2 },
            ),
            ("conn1/2", "hkneeded", hk(1, 2)),
            ("conn1/2", "authstarted", auth(pk, 1, 2)),
            ("conn1/2", "err", disc(err)),
            // M3-07
            ("conn1/2", "channel", connected.clone()),
            (
                "conn2/2",
                "tcp2",
                SessionState::Connecting { hop: 2, of: 2 },
            ),
            ("conn2/2", "hkneeded", hk(2, 2)),
            ("conn2/2", "authstarted", auth(pk, 2, 2)),
            ("conn2/2", "err", disc(err)),
            // M3-07
            ("conn2/2", "channel", connected.clone()),
            (
                "hostkey1/2",
                "hkaccepted",
                SessionState::Connecting { hop: 1, of: 2 },
            ),
            ("hostkey1/2", "hkrejected", disc(DisconnectReason::HostKey)),
            ("hostkey1/2", "keepalive", disc(DisconnectReason::HostKey)),
            ("hostkey1/2", "err", disc(err)),
            ("auth1/2", "promptneeded", user(1, 2, pw)),
            ("auth1/2", "authstarted", auth(pk, 1, 2)),
            (
                "auth1/2",
                "authok",
                SessionState::Connecting { hop: 2, of: 2 },
            ),
            ("auth1/2", "authfailed", disc(DisconnectReason::Auth)),
            ("auth1/2", "err", disc(err)),
            ("auth2/2", "promptneeded", user(2, 2, pw)),
            ("auth2/2", "authstarted", auth(pk, 2, 2)),
            ("auth2/2", "authok", auth(pw, 2, 2)),
            ("auth2/2", "channel", connected.clone()),
            ("auth2/2", "authfailed", disc(DisconnectReason::Auth)),
            ("auth2/2", "err", disc(err)),
            ("user2/2", "promptanswered", auth(ki, 2, 2)),
            ("user2/2", "err", disc(err)),
            ("connected", "exit", disc(DisconnectReason::Exited(3))),
            ("connected", "err", disc(err)),
            ("connected", "keepalive", disc(DisconnectReason::Timeout)),
            ("disconnected", "reconnect", SessionState::Resolving),
        ];

        let mut checked = 0;
        let mut seen_states = std::collections::BTreeSet::new();
        let mut seen_inputs = std::collections::BTreeSet::new();
        for (sname, state) in &states {
            seen_states.insert(state_name(state));
            for (iname, input) in &inputs {
                seen_inputs.insert(input_name(input));
                let got = state.transition(input.clone(), now);
                let expected = if *iname == "close" && *sname != "closed" {
                    Some(SessionState::Closed)
                } else {
                    allowed
                        .iter()
                        .find(|(s, i, _)| s == sname && i == iname)
                        .map(|(_, _, to)| to.clone())
                };
                match expected {
                    Some(to) => assert_eq!(got, Ok(to), "{sname} + {iname}"),
                    None => assert_eq!(
                        got,
                        Err(IllegalTransition {
                            from: Box::new(state.clone()),
                            input: Box::new(input.clone()),
                        }),
                        "{sname} + {iname} must be illegal"
                    ),
                }
                checked += 1;
            }
        }
        assert_eq!(checked, states.len() * inputs.len());
        // Every variant of both enums is covered.
        assert_eq!(seen_states.len(), 8);
        assert_eq!(seen_inputs.len(), 16);
        // Every allow-list row names a real sample.
        for (s, i, _) in &allowed {
            assert!(states.iter().any(|(n, _)| n == s), "{s}");
            assert!(inputs.iter().any(|(n, _)| n == i), "{i}");
        }
    }

    #[test]
    fn tcp_connected_for_another_hop_is_illegal() {
        let s = SessionState::Connecting { hop: 1, of: 2 };
        assert!(
            s.transition(StateInput::TcpConnected { hop: 2 }, Instant::now())
                .is_err()
        );
    }

    #[test]
    fn local_subset() {
        let now = Instant::now();
        let s = SessionState::Resolving
            .transition(StateInput::ChannelOpened, now)
            .unwrap();
        assert!(s.is_connected());
        let s = s.transition(StateInput::RemoteExit(0), now).unwrap();
        let s = s.transition(StateInput::UserClose, now).unwrap();
        assert!(s.is_closed());
    }

    /// T-11: a clean remote exit disconnects with `Exited(0)` and no reconnect banner.
    #[test]
    fn t11_remote_exit() {
        let now = Instant::now();
        let s = SessionState::Connected { since: now }
            .transition(StateInput::RemoteExit(0), now)
            .unwrap();
        let SessionState::Disconnected { reason, .. } = s else {
            panic!("expected Disconnected, got {s:?}");
        };
        assert_eq!(reason, DisconnectReason::Exited(0));
        assert!(!reason.offers_reconnect());
        assert_eq!(reason.message(), "Session ended (exit 0)");
        assert!(DisconnectReason::Timeout.offers_reconnect());
        assert!(DisconnectReason::Internal.offers_reconnect());
    }
}
