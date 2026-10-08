//! Loopback tests against an in-process russh server (no Docker): a real TCP
//! handshake, password auth, env/pty/shell requests, data both ways, stderr, resize,
//! exit status, keepalive latency and timeout, legacy-only negotiation, host-key
//! prompts. T-17 (no hostnames in `info` logs) is `tests/ssh_logs.rs`: it needs a
//! process of its own for reliable log capture.
//!
//! The e2e variants against OpenSSH are in `crates/sverb-e2e/tests/openssh_transport.rs`
//! (M1-18 harness, `#[ignore]`d).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    net::SocketAddr,
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use russh::Pty;
use sverb_core::model::{AlgoOverrides, Backspace, Host};
use sverb_term::GridPoint;
use tokio::{net::TcpListener, sync::mpsc};

use super::testing::{TestResolver, pausable_proxy, start_legacy_server, start_server};
use super::*;
use crate::{
    Bytes, DisconnectReason, OpenOptions, SessionCmd, SessionEvent, SessionHandle, SessionId,
    SessionManager, SessionState, TransportKind, session::Decision,
};

type Events = mpsc::UnboundedReceiver<(SessionId, SessionEvent)>;

const WAIT: Duration = Duration::from_secs(10);

fn manager(connector: SshConnector) -> (SessionManager, Events) {
    let (tx, rx) = mpsc::unbounded_channel();
    let mgr = SessionManager::new(tx);
    mgr.register_connector(TransportKind::Ssh, Arc::new(connector));
    (mgr, rx)
}

fn connector(addr: SocketAddr, edit: fn(&mut Host)) -> SshConnector {
    SshConnector::new(Arc::new(TestResolver {
        addr,
        password: "secret",
        edit,
    }))
    .with_verifier(Arc::new(InsecureAcceptAnyHostKey::insecure_for_testing()))
}

fn open(mgr: &SessionManager) -> SessionHandle {
    mgr.open_with(
        crate::SessionSpec::Ssh(crate::SshSpec {
            host: "ignored".into(),
            port: 22,
            ..crate::SshSpec::default()
        }),
        OpenOptions {
            cols: 80,
            rows: 24,
            ..OpenOptions::default()
        },
    )
    .unwrap()
}

fn screen(handle: &SessionHandle) -> String {
    let term = handle.term.lock();
    let (cols, rows) = term.size();
    let top = -i32::try_from(term.scrollback_len()).unwrap();
    term.grid_text(
        GridPoint::new(top, 0),
        GridPoint::new(i32::from(rows) - 1, usize::from(cols) - 1),
    )
}

async fn wait_screen(handle: &SessionHandle, needle: &str) {
    let deadline = Instant::now() + WAIT;
    loop {
        let text = screen(handle);
        if text.contains(needle) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{needle:?} not on screen:\n{text}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Collect events until one matches `pred`.
async fn wait_event(
    rx: &mut Events,
    pred: impl Fn(&SessionEvent) -> bool,
) -> (SessionEvent, Vec<SessionEvent>) {
    let mut seen = Vec::new();
    let res = tokio::time::timeout(WAIT, async {
        loop {
            let (_, ev) = rx.recv().await.unwrap();
            if pred(&ev) {
                return ev;
            }
            seen.push(ev);
        }
    })
    .await;
    match res {
        Ok(ev) => (ev, seen),
        Err(_) => panic!("event not received; saw {seen:#?}"),
    }
}

fn is_state(ev: &SessionEvent, f: impl Fn(&SessionState) -> bool) -> bool {
    matches!(ev, SessionEvent::State(s) if f(s))
}

async fn send(handle: &SessionHandle, text: &str) {
    handle
        .cmd_tx
        .send(SessionCmd::Input(Bytes::copy_from_slice(text.as_bytes())))
        .await
        .unwrap();
}

// ---------------------------------------------------------------- tests

/// T-08/T-09/T-10/T-11/T-15 (loopback): connect, shell with TERM, env (rejected `BAR`
/// is not an error), resize, stderr, `exit 7` → `Exited(7)`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_session_end_to_end() {
    let (addr, seen) = start_server().await;
    let (mgr, mut rx) = manager(connector(addr, |_| {}));
    let handle = open(&mgr);

    let (_, before) = wait_event(&mut rx, |e| {
        is_state(e, |s| matches!(s, SessionState::Connected { .. }))
    })
    .await;
    // The flow went through each state, and reported the negotiated algorithms.
    let states: Vec<String> = before
        .iter()
        .filter_map(|e| match e {
            SessionEvent::State(s) => Some(
                format!("{s:?}")
                    .split([' ', '(', '{'])
                    .next()
                    .unwrap()
                    .to_owned(),
            ),
            _ => None,
        })
        .collect();
    assert_eq!(
        states,
        [
            "Resolving",
            "Connecting",
            "Connecting",
            "Authenticating",
            "Authenticating",
            "Authenticating"
        ]
    );
    let info = before
        .iter()
        .find_map(|e| match e {
            SessionEvent::SshInfo(i) => Some(i.clone()),
            _ => None,
        })
        .expect("SshInfo");
    assert_eq!(info.kex, "mlkem768x25519-sha256");
    assert_eq!(info.host_key, "ssh-ed25519");
    assert_eq!(info.cipher, "chacha20-poly1305@openssh.com");
    assert!(info.server_version.starts_with("SSH-2.0-"), "{info:?}");
    assert_eq!(info.peer, addr.to_string());
    assert!(
        !before.iter().any(|e| matches!(e, SessionEvent::Error(_))),
        "a rejected env var is no error: {before:?}"
    );

    // T-08: TERM; T-09: FOO accepted, BAR rejected; T-15: stderr reaches the pane.
    wait_screen(&handle, "TERM=xterm-256color").await;
    wait_screen(&handle, "FOO=bar").await;
    wait_screen(&handle, "ls: /nonexistent: No such file").await;
    {
        let seen = seen.lock();
        assert_eq!(seen.users, ["sverb"]);
        assert_eq!(
            seen.env,
            [
                ("FOO".into(), "bar".into(), true),
                ("BAR".into(), "nope".into(), false)
            ]
        );
        // T-04 on the wire: VERASE = DEL, IUTF8 = 1.
        assert_eq!(seen.modes, [(Pty::VERASE, 0x7f), (Pty::IUTF8, 1)]);
        assert_eq!(seen.sizes, [(80, 24)]);
    }

    // Data both ways.
    send(&handle, "echo hi\r").await;
    wait_screen(&handle, "out:echo hi").await;

    // T-10: resize.
    handle
        .cmd_tx
        .send(SessionCmd::Resize {
            cols: 100,
            rows: 30,
            px_w: 0,
            px_h: 0,
        })
        .await
        .unwrap();
    let deadline = Instant::now() + WAIT;
    while seen.lock().sizes.last() != Some(&(100, 30)) {
        assert!(Instant::now() < deadline, "no window-change");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // T-11: exit 7 → Exit event and Disconnected { Exited(7) } (no reconnect banner).
    send(&handle, "exit 7\r").await;
    let (ev, before) = wait_event(&mut rx, |e| {
        is_state(e, |s| matches!(s, SessionState::Disconnected { .. }))
    })
    .await;
    assert!(
        before.contains(&SessionEvent::Exit { code: 7 }),
        "{before:?}"
    );
    let SessionEvent::State(SessionState::Disconnected { reason, .. }) = ev else {
        unreachable!()
    };
    assert_eq!(reason, DisconnectReason::Exited(7));
    assert!(!reason.offers_reconnect());
    let report = mgr.shutdown(Duration::from_secs(2)).await;
    assert_eq!(report.aborted, 0);
}

/// T-04 on the wire: `backspace = ctrl-h` and a non-UTF-8 charset.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_pty_modes_follow_the_host() {
    let (addr, seen) = start_server().await;
    let (mgr, mut rx) = manager(connector(addr, |h| {
        h.backspace = Some(Backspace::CtrlH);
        h.charset = Some("ISO-8859-1".into());
    }));
    let _handle = open(&mgr);
    wait_event(&mut rx, |e| {
        is_state(e, |s| matches!(s, SessionState::Connected { .. }))
    })
    .await;
    assert_eq!(seen.lock().modes, [(Pty::VERASE, 8)]);
    mgr.shutdown(Duration::from_secs(2)).await;
}

/// Wrong password → `Disconnected { Auth }` naming the methods tried.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_auth_failure() {
    let (addr, _) = start_server().await;
    let connector = SshConnector::new(Arc::new(TestResolver {
        addr,
        password: "wrong",
        edit: |_| {},
    }))
    .with_verifier(Arc::new(InsecureAcceptAnyHostKey::insecure_for_testing()));
    let (mgr, mut rx) = manager(connector);
    let _handle = open(&mgr);
    let (ev, before) = wait_event(&mut rx, |e| {
        is_state(e, |s| matches!(s, SessionState::Disconnected { .. }))
    })
    .await;
    assert!(matches!(
        ev,
        SessionEvent::State(SessionState::Disconnected {
            reason: DisconnectReason::Auth,
            ..
        })
    ));
    let err = before.iter().find_map(|e| match e {
        SessionEvent::Error(r) => Some(r.short.clone()),
        _ => None,
    });
    assert_eq!(
        err.as_deref(),
        // M1-14: the stored password, then (russh's server drops `password` from the
        // list after a failure) keyboard-interactive; `none` is not a method tried.
        Some("Permission denied (methods tried: password, keyboard-interactive)")
    );
    mgr.shutdown(Duration::from_secs(2)).await;
}

/// T-14 (loopback): a legacy-only server → `Negotiation` naming the algorithm; with the
/// host override → connects.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_legacy_only_server() {
    let (addr, _) = start_legacy_server().await;
    let (mgr, mut rx) = manager(connector(addr, |_| {}));
    let _handle = open(&mgr);
    let (ev, before) = wait_event(&mut rx, |e| {
        is_state(e, |s| matches!(s, SessionState::Disconnected { .. }))
    })
    .await;
    assert!(
        matches!(
            ev,
            SessionEvent::State(SessionState::Disconnected {
                reason: DisconnectReason::Negotiation,
                ..
            })
        ),
        "{ev:?}"
    );
    let err = before
        .iter()
        .find_map(|e| match e {
            SessionEvent::Error(r) => Some(r.short.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        err,
        "No common key exchange: server offers diffie-hellman-group14-sha1. Enable it for this host in Host → Connection → Algorithms (legacy)."
    );
    mgr.shutdown(Duration::from_secs(2)).await;

    let (mgr, mut rx) = manager(connector(addr, |h| {
        h.algorithms = Some(AlgoOverrides {
            kex: Some(vec!["diffie-hellman-group14-sha1".into()]),
            ..AlgoOverrides::default()
        });
    }));
    let _handle = open(&mgr);
    let (_, before) = wait_event(&mut rx, |e| {
        is_state(e, |s| matches!(s, SessionState::Connected { .. }))
    })
    .await;
    let info = before.iter().find_map(|e| match e {
        SessionEvent::SshInfo(i) => Some(i.kex.clone()),
        _ => None,
    });
    assert_eq!(info.as_deref(), Some("diffie-hellman-group14-sha1"));
    mgr.shutdown(Duration::from_secs(2)).await;
}

/// T-12/T-13 (loopback): latency events arrive; pausing the link with
/// `keepalive_secs = 1` ends in `Disconnected { Timeout }` within about 4 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_keepalive_latency_and_timeout() {
    let (server, _) = start_server().await;
    let (addr, paused) = pausable_proxy(server).await;
    let (mgr, mut rx) = manager(connector(addr, |h| h.keepalive_secs = Some(1)));
    let _handle = open(&mgr);
    wait_event(&mut rx, |e| {
        is_state(e, |s| matches!(s, SessionState::Connected { .. }))
    })
    .await;
    // T-13: within 2 × keepalive.
    let t0 = Instant::now();
    let (ev, _) = wait_event(&mut rx, |e| matches!(e, SessionEvent::Latency(_))).await;
    assert!(t0.elapsed() <= Duration::from_secs(2), "{:?}", t0.elapsed());
    let SessionEvent::Latency(rtt) = ev else {
        unreachable!()
    };
    assert!(rtt < Duration::from_secs(1));

    // T-12.
    paused.store(true, Ordering::SeqCst);
    let t0 = Instant::now();
    let (ev, before) = wait_event(&mut rx, |e| {
        is_state(e, |s| matches!(s, SessionState::Disconnected { .. }))
    })
    .await;
    assert!(
        matches!(
            ev,
            SessionEvent::State(SessionState::Disconnected {
                reason: DisconnectReason::Timeout,
                ..
            })
        ),
        "{ev:?} after {before:?}"
    );
    assert!(t0.elapsed() < Duration::from_secs(7), "{:?}", t0.elapsed());
    let err = before.iter().rev().find_map(|e| match e {
        SessionEvent::Error(r) => Some(r.short.clone()),
        _ => None,
    });
    assert_eq!(
        err.as_deref(),
        Some("Connection lost (no response for 3 s)")
    );
    mgr.shutdown(Duration::from_secs(2)).await;
}

/// T-16 (loopback, stub snippet): the startup input is typed after the first output.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_startup_input() {
    #[derive(Debug)]
    struct WithSnippet(TestResolver);
    #[async_trait]
    impl HostResolver for WithSnippet {
        async fn resolve(&self, spec: &crate::SshSpec) -> Result<SshTarget, SshError> {
            let mut host = self.0.resolve(spec).await?;
            host.startup_input = Some("uptime\r".into());
            Ok(host)
        }
    }
    let (addr, seen) = start_server().await;
    let connector = SshConnector::new(Arc::new(WithSnippet(TestResolver {
        addr,
        password: "secret",
        edit: |_| {},
    })))
    .with_verifier(Arc::new(InsecureAcceptAnyHostKey::insecure_for_testing()));
    let (mgr, _rx) = manager(connector);
    let handle = open(&mgr);
    wait_screen(&handle, "out:uptime").await;
    assert_eq!(seen.lock().input, b"uptime\r");
    mgr.shutdown(Duration::from_secs(2)).await;
}

/// The host-key seam: the default verifier rejects; an asking verifier suspends the
/// handshake until the user decides (accept once → connects; reject → `HostKey`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_host_key_decisions() {
    let (addr, _) = start_server().await;
    let resolver = || {
        Arc::new(TestResolver {
            addr,
            password: "secret",
            edit: |_| {},
        })
    };

    // Default: never connects unverified.
    let (mgr, mut rx) = manager(SshConnector::new(resolver()));
    let _h = open(&mgr);
    let (ev, before) = wait_event(&mut rx, |e| {
        is_state(e, |s| matches!(s, SessionState::Disconnected { .. }))
    })
    .await;
    assert!(matches!(
        ev,
        SessionEvent::State(SessionState::Disconnected {
            reason: DisconnectReason::HostKey,
            ..
        })
    ));
    let report = before.iter().find_map(|e| match e {
        SessionEvent::Error(r) => Some(r.clone()),
        _ => None,
    });
    let report = report.unwrap();
    assert_eq!(report.short, "Host key verification failed");
    assert!(report.chain[0].contains("SHA256:"), "{report:?}");
    mgr.shutdown(Duration::from_secs(2)).await;

    for (decision, connected) in [(Decision::AcceptOnce, true), (Decision::Reject, false)] {
        let (mgr, mut rx) =
            manager(SshConnector::new(resolver()).with_verifier(Arc::new(AskEveryTime)));
        let handle = open(&mgr);
        let (ev, _) = wait_event(&mut rx, |e| matches!(e, SessionEvent::HostKey(_))).await;
        let SessionEvent::HostKey(v) = ev else {
            unreachable!()
        };
        assert!(v.fingerprint.starts_with("SHA256:"));
        assert_eq!((v.hop, v.of), (1, 1));
        handle
            .cmd_tx
            .send(SessionCmd::HostKeyDecision(decision))
            .await
            .unwrap();
        let (ev, _) = wait_event(&mut rx, |e| {
            is_state(e, |s| {
                matches!(
                    s,
                    SessionState::Connected { .. } | SessionState::Disconnected { .. }
                )
            })
        })
        .await;
        if connected {
            assert!(
                matches!(ev, SessionEvent::State(SessionState::Connected { .. })),
                "{ev:?}"
            );
        } else {
            assert!(
                matches!(
                    ev,
                    SessionEvent::State(SessionState::Disconnected {
                        reason: DisconnectReason::HostKey,
                        ..
                    })
                ),
                "{ev:?}"
            );
        }
        mgr.shutdown(Duration::from_secs(2)).await;
    }
}

/// Connection refused → `Connect` with the address.
#[tokio::test]
async fn refused_port_is_a_connect_error() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let (mgr, mut rx) = manager(connector(addr, |_| {}));
    let _h = open(&mgr);
    let (ev, before) = wait_event(&mut rx, |e| {
        is_state(e, |s| matches!(s, SessionState::Disconnected { .. }))
    })
    .await;
    assert!(matches!(
        ev,
        SessionEvent::State(SessionState::Disconnected {
            reason: DisconnectReason::Connect,
            ..
        })
    ));
    let err = before.iter().find_map(|e| match e {
        SessionEvent::Error(r) => Some(r.short.clone()),
        _ => None,
    });
    assert_eq!(err, Some(format!("Connection refused ({addr})")));
    mgr.shutdown(Duration::from_secs(2)).await;
}

/// A jump chain that can't be expanded fails loudly instead of connecting directly
/// (M2-05: the test resolver answers every hop with the same host, so it jumps
/// through itself).
#[tokio::test]
async fn unsupported_routes_fail() {
    let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let (mgr, mut rx) = manager(connector(addr, |h| {
        h.jump_chain = vec![sverb_core::model::ItemId::from_bytes([1; 16])]
    }));
    let _h = open(&mgr);
    let (_, before) = wait_event(&mut rx, |e| {
        is_state(e, |s| matches!(s, SessionState::Disconnected { .. }))
    })
    .await;
    assert!(
        before
            .iter()
            .any(|e| matches!(e, SessionEvent::Error(r) if r.short == "Jump chain cycle: test → test"))
    );
    mgr.shutdown(Duration::from_secs(2)).await;
}

// ---------------------------------------------------------------- e2e (M1-18 harness)

/// T-08…T-16 against OpenSSH in Docker live in the M1-18 harness crate
/// (`crates/sverb-e2e/tests/openssh_transport.rs`): a unit test of this crate cannot
/// use `sverb-e2e`, which depends on `sverb-conn`. Run them with
/// `SVERB_E2E=1 cargo test -p sverb-e2e --test openssh_transport -- --ignored`.
#[tokio::test]
#[ignore = "moved to crates/sverb-e2e/tests/openssh_transport.rs (M1-18 harness)"]
async fn e2e_openssh_t08_to_t16() {
    // M1-18: see crates/sverb-e2e/tests/openssh_transport.rs.
    eprintln!("moved: SVERB_E2E=1 cargo test -p sverb-e2e --test openssh_transport -- --ignored");
}
