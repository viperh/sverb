//! M1-16: reconnecting reuses the emulator (scrollback kept), writes a separator and
//! resets the modes the old remote left on (SPEC §6.1.2).
//!
//! - T-05 / T-06 over `MockTransport` (a connector that hands out a fresh mock pair per
//!   connection),
//! - a T-07-like run over the loopback SSH server: the TCP link is cut by a proxy, the
//!   session is reconnected and output works again, with the old output still in the
//!   scrollback. (The Docker variants, T-07/T-08 with `docker restart`, belong to M1-18.)
#![allow(clippy::unwrap_used, clippy::expect_used, unreachable_pub)]

use std::{net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use parking_lot::Mutex;
use sverb_conn::{
    Bytes, ConnectCtx, ConnectError, Connector, DisconnectReason, MockSpec, OpenOptions,
    SessionCmd, SessionEvent, SessionHandle, SessionId, SessionManager, SessionSpec, SessionState,
    SshSpec, Transport, TransportKind,
    mock::{MockRemote, MockTransport},
    session::actor::MODE_RESET,
    ssh::{
        InsecureAcceptAnyHostKey, SshConnector,
        testing::{TestResolver, start_server},
    },
};
use sverb_term::{GridPoint, modes::MouseMode};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::JoinHandle,
};

type Events = mpsc::UnboundedReceiver<(SessionId, SessionEvent)>;

/// Hands out one fresh mock transport per connection; the test gets the remote sides.
struct QueueConnector {
    remotes: mpsc::UnboundedSender<MockRemote>,
}

#[async_trait]
impl Connector for QueueConnector {
    async fn connect(
        &self,
        _spec: &SessionSpec,
        _ctx: &mut ConnectCtx<'_>,
    ) -> Result<Box<dyn Transport>, ConnectError> {
        let (transport, remote) = MockTransport::pair();
        let _ = self.remotes.send(remote);
        Ok(transport.boxed())
    }
}

fn mock_session() -> (
    SessionManager,
    Events,
    SessionHandle,
    mpsc::UnboundedReceiver<MockRemote>,
) {
    let (tx, rx) = mpsc::unbounded_channel();
    let mgr = SessionManager::new(tx);
    let (remotes_tx, remotes) = mpsc::unbounded_channel();
    mgr.register_connector(
        TransportKind::Mock,
        Arc::new(QueueConnector {
            remotes: remotes_tx,
        }),
    );
    // The spec's own transport is never taken: the queue connector replaces it.
    let (unused, _) = MockTransport::pair();
    let handle = mgr
        .open_with(
            SessionSpec::Mock(MockSpec::new(unused.boxed())),
            OpenOptions::default(),
        )
        .unwrap();
    (mgr, rx, handle, remotes)
}

async fn wait_state(rx: &mut Events, pred: impl Fn(&SessionState) -> bool) -> SessionState {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let (_, SessionEvent::State(s)) = rx.recv().await.expect("events closed")
                && pred(&s)
            {
                return s;
            }
        }
    })
    .await
    .expect("state not reached")
}

fn connected(s: &SessionState) -> bool {
    matches!(s, SessionState::Connected { .. })
}

fn disconnected(s: &SessionState) -> bool {
    matches!(s, SessionState::Disconnected { .. })
}

/// Everything in the emulator: scrollback and screen.
fn all_text(h: &SessionHandle) -> String {
    let term = h.term.lock();
    let (cols, rows) = term.size();
    let history = i32::try_from(term.scrollback_len()).unwrap();
    term.grid_text(
        GridPoint::new(-history, 0),
        GridPoint::new(i32::from(rows) - 1, usize::from(cols) - 1),
    )
}

/// Wait until the emulator shows `needle`.
async fn wait_text(h: &SessionHandle, needle: &str) {
    tokio::time::timeout(Duration::from_secs(20), async {
        while !all_text(h).contains(needle) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{needle:?} never shown:\n{}", all_text(h)));
}

// T-05: 500 lines, disconnect, reconnect → the scrollback still has them, plus the
// separator.
#[tokio::test]
async fn t05_scrollback_preserved_across_reconnect() {
    let (_mgr, mut rx, h, mut remotes) = mock_session();
    wait_state(&mut rx, connected).await;
    let mut remote = remotes.recv().await.unwrap();
    let mut out = String::new();
    for i in 0..500 {
        out.push_str(&format!("line {i:04}\r\n"));
    }
    remote.send(out.as_bytes()).await.unwrap();
    wait_text(&h, "line 0499").await;

    remote.finish(None);
    let state = wait_state(&mut rx, disconnected).await;
    assert!(matches!(
        state,
        SessionState::Disconnected {
            reason: DisconnectReason::Closed,
            ..
        }
    ));
    h.cmd_tx.send(SessionCmd::Reconnect).await.unwrap();
    wait_state(&mut rx, connected).await;
    let mut remote = remotes.recv().await.unwrap();
    remote.send(b"after\r\n").await.unwrap();
    wait_text(&h, "after").await;

    let text = all_text(&h);
    let lines = text.lines().filter(|l| l.starts_with("line ")).count();
    assert_eq!(lines, 500, "all 500 lines are still there");
    let (rows, history) = {
        let term = h.term.lock();
        (usize::from(term.size().1), term.scrollback_len())
    };
    assert!(history + rows > 500, "{history} + {rows}");
    let sep = text
        .lines()
        .position(|l| l.contains("── reconnected at "))
        .expect("separator line");
    let last = text.lines().position(|l| l == "line 0499").unwrap();
    let after = text.lines().position(|l| l == "after").unwrap();
    assert!(last < sep && sep < after, "{last} < {sep} < {after}");
    // `── reconnected at HH:MM:SS ──`
    let line = text.lines().nth(sep).unwrap().trim();
    let re = regex_lite(line);
    assert!(re, "{line:?}");
}

/// `── reconnected at HH:MM:SS ──` without a regex dependency.
fn regex_lite(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("── reconnected at ") else {
        return false;
    };
    let Some(hms) = rest.strip_suffix(" ──") else {
        return false;
    };
    let b = hms.as_bytes();
    b.len() == 8
        && b[2] == b':'
        && b[5] == b':'
        && [0, 1, 3, 4, 6, 7].iter().all(|i| b[*i].is_ascii_digit())
}

// T-06: the remote left the alternate screen, DECCKM, bracketed paste and mouse
// tracking on before dropping → cleared after the reconnect.
#[tokio::test]
async fn t06_modes_reset_on_reconnect() {
    let (_mgr, mut rx, h, mut remotes) = mock_session();
    wait_state(&mut rx, connected).await;
    let mut remote = remotes.recv().await.unwrap();
    remote.send(b"shell output\r\n").await.unwrap();
    wait_text(&h, "shell output").await;
    remote
        .send(b"\x1b[?1049h\x1b[?1h\x1b=\x1b[?2004h\x1b[?1002h\x1b[?1006h\x1b[?1004h\x1b[?25lvim")
        .await
        .unwrap();
    wait_text(&h, "vim").await;
    {
        let modes = h.term.lock().modes();
        assert!(modes.alt_screen && modes.app_cursor && modes.bracketed_paste);
        assert!(modes.app_keypad && modes.focus_reporting && !modes.cursor_visible);
        assert_ne!(modes.mouse_mode, MouseMode::None);
    }
    remote.finish(None);
    wait_state(&mut rx, disconnected).await;
    h.cmd_tx.send(SessionCmd::Reconnect).await.unwrap();
    wait_state(&mut rx, connected).await;
    let _remote = remotes.recv().await.unwrap();

    let modes = h.term.lock().modes();
    assert!(!modes.alt_screen, "alt screen left");
    assert!(!modes.app_cursor, "DECCKM off");
    assert!(!modes.app_keypad, "DECKPNM");
    assert!(!modes.bracketed_paste);
    assert!(!modes.focus_reporting);
    assert_eq!(modes.mouse_mode, MouseMode::None);
    assert!(modes.cursor_visible);
    // Back on the primary screen: the shell's output and the separator are visible.
    let text = all_text(&h);
    assert!(text.contains("shell output"), "{text}");
    assert!(text.contains("── reconnected at "), "{text}");
    assert!(!MODE_RESET.is_empty());
}

// ------------------------------------------------------------------- over SSH

/// A TCP proxy whose open connections can be cut (like a dropped link).
async fn cuttable_proxy(target: SocketAddr) -> (SocketAddr, Arc<Mutex<Vec<JoinHandle<()>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let tasks: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::default();
    let registry = Arc::clone(&tasks);
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let task = tokio::spawn(async move {
                let Ok(mut server) = TcpStream::connect(target).await else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                let _ = client.shutdown().await;
            });
            registry.lock().push(task);
        }
    });
    (addr, tasks)
}

// T-07-like (no Docker): an SSH session whose link drops is reconnected in place; the
// new shell's output works and the old output is still in the scrollback.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_link_drop_then_reconnect_keeps_scrollback() {
    let (server, _) = start_server().await;
    let (proxy, links) = cuttable_proxy(server).await;
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mgr = SessionManager::new(tx);
    let connector = SshConnector::new(Arc::new(TestResolver {
        addr: proxy,
        password: "secret",
        edit: |_| {},
    }))
    .with_verifier(Arc::new(InsecureAcceptAnyHostKey::insecure_for_testing()));
    mgr.register_connector(TransportKind::Ssh, Arc::new(connector));
    let h = mgr
        .open_with(
            SessionSpec::Ssh(SshSpec {
                host: proxy.ip().to_string(),
                port: proxy.port(),
                ..SshSpec::default()
            }),
            OpenOptions::default(),
        )
        .unwrap();
    wait_state(&mut rx, connected).await;
    h.cmd_tx
        .send(SessionCmd::Input(Bytes::from_static(b"before\r")))
        .await
        .unwrap();
    wait_text(&h, "out:before").await;

    // Cut the link.
    for task in links.lock().drain(..) {
        task.abort();
    }
    let state = wait_state(&mut rx, disconnected).await;
    let SessionState::Disconnected { reason, .. } = state else {
        unreachable!()
    };
    assert!(
        sverb_conn::session::actor::backoff::retries(reason),
        "a dropped link may be retried: {reason:?}"
    );

    h.cmd_tx.send(SessionCmd::Reconnect).await.unwrap();
    wait_state(&mut rx, connected).await;
    // The new shell's greeting arrives below the separator (the test server's line
    // buffer spans connections, so its echo of new input is not checked verbatim).
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let text = all_text(&h);
            if let Some(sep) = text.find("── reconnected at ")
                && text[sep..].contains("FOO=bar")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no output after the reconnect:\n{}", all_text(&h)));
    let text = all_text(&h);
    let before = text.find("out:before").unwrap();
    let sep = text.find("── reconnected at ").unwrap();
    assert!(before < sep, "{text}");
    mgr.shutdown(Duration::from_secs(2)).await;
}
