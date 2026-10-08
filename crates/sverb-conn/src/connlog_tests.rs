//! M3-06: the session actor reports every connection attempt to the [`ConnLogSink`].
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex;
use pretty_assertions::assert_eq;
use sverb_core::{error_report::ErrorReport, model::ConnResult};
use tokio::sync::mpsc;

use super::*;
use crate::{
    ConnectCtx, ConnectError, Connector, SessionCmd, SessionEvent, SessionManager, SessionState,
    SshSpec, StateInput, Transport,
    mock::MockTransport,
    session::{AuthMethod, MockSpec},
};

#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    Started(SessionId, Attempt),
    Ended(SessionId, AttemptEnd),
}

#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<Call>>>);

impl ConnLogSink for Recorder {
    fn attempt_started(&self, session: SessionId, attempt: Attempt) {
        self.0.lock().push(Call::Started(session, attempt));
    }
    fn attempt_ended(&self, session: SessionId, end: AttemptEnd) {
        self.0.lock().push(Call::Ended(session, end));
    }
}

impl Recorder {
    async fn wait_ends(&self, n: usize) -> Vec<Call> {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let calls = self.0.lock().clone();
                if calls
                    .iter()
                    .filter(|c| matches!(c, Call::Ended(..)))
                    .count()
                    >= n
                {
                    return calls;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out: {:?}", self.0.lock()))
    }
}

fn manager() -> (
    SessionManager,
    Recorder,
    mpsc::UnboundedReceiver<(SessionId, SessionEvent)>,
) {
    let (tx, rx) = mpsc::unbounded_channel();
    let mgr = SessionManager::new(tx);
    let rec = Recorder::default();
    mgr.set_connlog_sink(Arc::new(rec.clone()));
    (mgr, rec, rx)
}

async fn wait_state(
    rx: &mut mpsc::UnboundedReceiver<(SessionId, SessionEvent)>,
    pred: impl Fn(&SessionState) -> bool,
) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let (_, SessionEvent::State(s)) = rx.recv().await.unwrap()
                && pred(&s)
            {
                return;
            }
        }
    })
    .await
    .expect("state not reached");
}

/// A successful session: one attempt, `Ok` at the remote exit, with the channel's bytes.
#[tokio::test]
async fn successful_session_counts_bytes_and_ends_ok() {
    let (mgr, rec, mut rx) = manager();
    let (transport, mut remote) = MockTransport::pair();
    let handle = mgr
        .open(SessionSpec::Mock(MockSpec::new(transport.boxed())))
        .unwrap();
    wait_state(&mut rx, |s| matches!(s, SessionState::Connected { .. })).await;
    remote.send(b"hello world").await.unwrap();
    handle
        .cmd_tx
        .send(SessionCmd::Input(Bytes::from_static(b"ls\r")))
        .await
        .unwrap();
    assert_eq!(remote.read_written(3).await, b"ls\r");
    // Let the read loop take the output before the remote exits.
    tokio::time::sleep(Duration::from_millis(50)).await;
    remote.finish(Some(0));
    let calls = rec.wait_ends(1).await;
    let [Call::Started(sid, attempt), Call::Ended(eid, end)] = calls.as_slice() else {
        panic!("{calls:?}");
    };
    assert_eq!((*sid, *eid), (handle.id, handle.id));
    assert_eq!(attempt.label, "mock");
    assert_eq!(
        end.outcome,
        AttemptOutcome::Disconnected(DisconnectReason::Exited(0))
    );
    assert_eq!(end.result(), ConnResult::Ok);
    assert_eq!(end.bytes_in, 11);
    assert_eq!(end.bytes_out, 3);
    assert!(end.ended_at >= attempt.started_at);
    assert_eq!(end.error_detail(), None);
}

/// An SSH connector whose authentication fails.
struct FailingAuth;

#[async_trait]
impl Connector for FailingAuth {
    async fn connect(
        &self,
        _spec: &SessionSpec,
        ctx: &mut ConnectCtx<'_>,
    ) -> Result<Box<dyn Transport>, ConnectError> {
        ctx.input(StateInput::Resolved { hops: 1 })?;
        ctx.input(StateInput::AuthStarted(AuthMethod::Password))?;
        ctx.input(StateInput::AuthFailed)?;
        Err(ConnectError::with_report(
            DisconnectReason::Auth,
            ErrorReport::from_messages(["Permission denied", "tried: password"]),
        ))
    }
}

/// Auth failure → `AuthFailed` with the report as the error detail; a reconnect is a
/// second attempt.
#[tokio::test]
async fn auth_failure_and_reconnect_are_separate_attempts() {
    let (mgr, rec, mut rx) = manager();
    mgr.register_connector(crate::TransportKind::Ssh, Arc::new(FailingAuth));
    let handle = mgr
        .open(SessionSpec::Ssh(SshSpec {
            host: "db.example".into(),
            port: 22,
            user: Some("root".into()),
            ..SshSpec::default()
        }))
        .unwrap();
    wait_state(&mut rx, |s| matches!(s, SessionState::Disconnected { .. })).await;
    let calls = rec.wait_ends(1).await;
    let Call::Ended(_, end) = &calls[1] else {
        panic!("{calls:?}")
    };
    assert_eq!(end.result(), ConnResult::AuthFailed);
    assert_eq!(
        end.error_detail(),
        Some(vec![
            "Permission denied".to_owned(),
            "tried: password".to_owned()
        ])
    );
    let Call::Started(_, attempt) = &calls[0] else {
        panic!("{calls:?}")
    };
    assert_eq!(attempt.target.as_deref(), Some("root@db.example:22"));

    handle.cmd_tx.send(SessionCmd::Reconnect).await.unwrap();
    let calls = rec.wait_ends(2).await;
    assert_eq!(calls.len(), 4, "{calls:?}");
    assert!(matches!(calls[2], Call::Started(..)));
    // Closing a disconnected session reports nothing more.
    handle.cmd_tx.send(SessionCmd::Close).await.unwrap();
    wait_state(&mut rx, |s| matches!(s, SessionState::Closed)).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(rec.0.lock().len(), 4);
}

/// Closing a connected session ends its attempt as `Ok`.
#[tokio::test]
async fn user_close_while_connected_is_ok() {
    let (mgr, rec, mut rx) = manager();
    let (transport, _remote) = MockTransport::pair();
    let handle = mgr
        .open(SessionSpec::Mock(MockSpec::new(transport.boxed())))
        .unwrap();
    wait_state(&mut rx, |s| matches!(s, SessionState::Connected { .. })).await;
    assert!(mgr.close(handle.id));
    let calls = rec.wait_ends(1).await;
    let Call::Ended(_, end) = &calls[1] else {
        panic!("{calls:?}")
    };
    assert_eq!(end.outcome, AttemptOutcome::UserClosed { connected: true });
    assert_eq!(end.result(), ConnResult::Ok);
}
