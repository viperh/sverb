//! Connection-attempt hooks for the connection log (`ConnLog`, SPEC §4.12, §9.12).
//!
//! Every session actor reports each connection attempt to a [`ConnLogSink`]:
//! - [`ConnLogSink::attempt_started`] when it starts connecting (the first connect and
//!   every reconnect: each attempt is its own entry),
//! - [`ConnLogSink::attempt_ended`] when the attempt is over: the connect failed, the
//!   connection dropped, the remote exited, or the user closed the session (also on
//!   quit, when the manager closes every session).
//!
//! The actor counts the session channel's bytes (`bytes_in`: output read from the
//! transport, `bytes_out`: input, pastes, mouse reports and terminal replies written to
//! it) and keeps the last error report of the attempt. Connectors don't need to call
//! anything: the SSH connector reports failures through
//! [`ConnectError`](crate::ConnectError) (`reason` + `report`) as it already does, and
//! the actor turns that into the attempt's end. [`Attempt::from_spec`] takes
//! go through the same actor path).
//!
//! The UI implements the sink (`sverb_tui::services::connlog`), which writes the
//! entries through the vault; the default is [`NoConnLog`].

use sverb_core::{
    error_report::ErrorReport,
    model::{ConnResult, ItemId, UnixMillis},
};

use crate::{
    session::{DisconnectReason, SessionId, SessionSpec},
    transport::TransportKind,
};

/// Message stored for an attempt the user closed before it connected.
pub const CANCELLED: &str = "cancelled before connecting";

/// A connection attempt that just started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    /// Which transport.
    pub kind: TransportKind,
    /// The host item (`None` for local shells and ephemeral hosts).
    pub host_id: Option<ItemId>,
    /// What the attempt is shown as (host label, `local`).
    pub label: String,
    /// `user@host:port` for SSH; `None` for local shells.
    pub target: Option<String>,
    /// When it started.
    pub started_at: UnixMillis,
}

impl Attempt {
    /// Describe an attempt to open `spec`.
    pub fn from_spec(spec: &SessionSpec, started_at: UnixMillis) -> Self {
        let (host_id, label, target) = match spec {
            // The saved host's item id and label (`host` for unsaved targets).
            SessionSpec::Ssh(ssh) => {
                let mut target = String::new();
                if let Some(user) = &ssh.user {
                    target.push_str(user);
                    target.push('@');
                }
                target.push_str(&ssh.host);
                if ssh.port != 0 {
                    target.push(':');
                    target.push_str(&ssh.port.to_string());
                }
                let label = ssh
                    .label
                    .clone()
                    .filter(|l| !l.is_empty())
                    .unwrap_or_else(|| ssh.host.clone());
                (ssh.host_id, label, Some(target))
            }
            SessionSpec::Local(_) => (None, "local".to_owned(), None),
            SessionSpec::Mock(_) => (None, "mock".to_owned(), None),
        };
        Self {
            kind: spec.kind(),
            host_id,
            label,
            target,
            started_at,
        }
    }
}

/// How an attempt ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// The session disconnected (a failed connect, a dropped connection, a remote exit).
    Disconnected(DisconnectReason),
    /// The user closed the session (or sverb quit).
    UserClosed {
        /// Whether the shell channel was open by then.
        connected: bool,
    },
}

/// The end of an attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptEnd {
    /// How it ended.
    pub outcome: AttemptOutcome,
    /// When.
    pub ended_at: UnixMillis,
    /// Session channel bytes received.
    pub bytes_in: u64,
    /// Session channel bytes sent.
    pub bytes_out: u64,
    /// The last error the attempt reported, if any.
    pub error: Option<ErrorReport>,
}

impl AttemptEnd {
    /// The `ConnLog` result.
    pub fn result(&self) -> ConnResult {
        match self.outcome {
            AttemptOutcome::Disconnected(reason) => conn_result(reason),
            AttemptOutcome::UserClosed { connected: true } => ConnResult::Ok,
            AttemptOutcome::UserClosed { connected: false } => {
                ConnResult::NetworkError(CANCELLED.to_owned())
            }
        }
    }

    /// The `ConnLog` `error_detail` (spec addition): for failures, the error report
    /// (short message, then the causes), or the reason's message without one.
    pub fn error_detail(&self) -> Option<Vec<String>> {
        if self.result() == ConnResult::Ok {
            return None;
        }
        if let Some(report) = &self.error {
            let mut lines = vec![report.short.clone()];
            lines.extend(report.chain.iter().cloned());
            return Some(lines);
        }
        let msg = match self.outcome {
            AttemptOutcome::Disconnected(reason) => reason.message(),
            AttemptOutcome::UserClosed { .. } => CANCELLED.to_owned(),
        };
        Some(vec![msg])
    }
}

/// `DisconnectReason` → `ConnLog` result: name resolution, connect,
/// negotiation, timeouts and internal errors are network errors with a short message;
/// `Auth` is `AuthFailed`, `HostKey` is `HostKeyRejected`, a remote exit or close is `Ok`.
pub fn conn_result(reason: DisconnectReason) -> ConnResult {
    match reason {
        DisconnectReason::Auth => ConnResult::AuthFailed,
        DisconnectReason::HostKey => ConnResult::HostKeyRejected,
        DisconnectReason::Exited(_) | DisconnectReason::Closed => ConnResult::Ok,
        DisconnectReason::Resolve
        | DisconnectReason::Connect
        | DisconnectReason::Negotiation
        | DisconnectReason::Timeout
        | DisconnectReason::Internal => ConnResult::NetworkError(reason.message()),
    }
}

/// Receives connection attempts. Called from session tasks: must not block (queue the
/// work, e.g. on a channel to a writer task).
pub trait ConnLogSink: Send + Sync + 'static {
    /// Session `session` started a connection attempt.
    fn attempt_started(&self, session: SessionId, attempt: Attempt);
    /// The current attempt of `session` ended. Ends without a started attempt (e.g.
    /// the supervisor reporting a crash after a normal end) must be ignored.
    fn attempt_ended(&self, session: SessionId, end: AttemptEnd);
}

/// A sink that drops everything (the default, and for tests).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoConnLog;

impl ConnLogSink for NoConnLog {
    fn attempt_started(&self, _: SessionId, _: Attempt) {}
    fn attempt_ended(&self, _: SessionId, _: AttemptEnd) {}
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;
    use crate::session::{LocalSpec, SshSpec};

    fn end(outcome: AttemptOutcome, error: Option<ErrorReport>) -> AttemptEnd {
        AttemptEnd {
            outcome,
            ended_at: UnixMillis(2),
            bytes_in: 0,
            bytes_out: 0,
            error,
        }
    }

    /// `DisconnectReason` → `ConnLog` result.
    #[test]
    fn t01_disconnect_reason_maps_to_result() {
        let net = |r: DisconnectReason| ConnResult::NetworkError(r.message());
        let table = [
            (DisconnectReason::Resolve, net(DisconnectReason::Resolve)),
            (DisconnectReason::Connect, net(DisconnectReason::Connect)),
            (
                DisconnectReason::Negotiation,
                net(DisconnectReason::Negotiation),
            ),
            (DisconnectReason::Timeout, net(DisconnectReason::Timeout)),
            (DisconnectReason::Internal, net(DisconnectReason::Internal)),
            (DisconnectReason::Auth, ConnResult::AuthFailed),
            (DisconnectReason::HostKey, ConnResult::HostKeyRejected),
            (DisconnectReason::Exited(0), ConnResult::Ok),
            (DisconnectReason::Exited(130), ConnResult::Ok),
            (DisconnectReason::Closed, ConnResult::Ok),
        ];
        for (reason, want) in table {
            assert_eq!(conn_result(reason), want, "{reason:?}");
            let e = end(AttemptOutcome::Disconnected(reason), None);
            assert_eq!(e.result(), want);
            // Failures always carry a detail; successes never do.
            assert_eq!(e.error_detail().is_some(), want != ConnResult::Ok);
        }
        assert_eq!(
            end(AttemptOutcome::UserClosed { connected: true }, None).result(),
            ConnResult::Ok
        );
        assert_eq!(
            end(AttemptOutcome::UserClosed { connected: false }, None).result(),
            ConnResult::NetworkError(CANCELLED.to_owned())
        );
    }

    #[test]
    fn error_detail_is_the_report_chain() {
        let report = ErrorReport::from_messages(["Permission denied", "publickey", "password"]);
        let e = end(
            AttemptOutcome::Disconnected(DisconnectReason::Auth),
            Some(report),
        );
        assert_eq!(
            e.error_detail(),
            Some(vec![
                "Permission denied".to_owned(),
                "publickey".to_owned(),
                "password".to_owned()
            ])
        );
        let e = end(
            AttemptOutcome::Disconnected(DisconnectReason::Resolve),
            None,
        );
        assert_eq!(
            e.error_detail(),
            Some(vec!["Could not resolve host".to_owned()])
        );
    }

    #[test]
    fn attempts_describe_their_spec() {
        let ssh = SessionSpec::Ssh(SshSpec {
            host: "10.0.0.5".into(),
            port: 2222,
            user: Some("deploy".into()),
            ..SshSpec::default()
        });
        let a = Attempt::from_spec(&ssh, UnixMillis(1));
        assert_eq!(a.kind, TransportKind::Ssh);
        assert_eq!(a.target.as_deref(), Some("deploy@10.0.0.5:2222"));
        assert_eq!(a.label, "10.0.0.5");
        assert_eq!(a.host_id, None);
        // A saved host reports its item and label.
        let id = sverb_core::model::ItemId::from_bytes([7; 16]);
        let saved = SessionSpec::Ssh(SshSpec {
            host: "10.0.0.5".into(),
            port: 22,
            host_id: Some(id),
            label: Some("db".into()),
            ..SshSpec::default()
        });
        let a = Attempt::from_spec(&saved, UnixMillis(1));
        assert_eq!(a.host_id, Some(id));
        assert_eq!(a.label, "db");
        let local = Attempt::from_spec(&SessionSpec::Local(LocalSpec::default()), UnixMillis(1));
        assert_eq!(local.label, "local");
        assert_eq!(local.target, None);
        assert_eq!(local.host_id, None);
    }
}

// The actor's hooks over mock transports (T-02/T-03 at the session level).
#[cfg(test)]
#[path = "connlog_tests.rs"]
mod actor_tests;
