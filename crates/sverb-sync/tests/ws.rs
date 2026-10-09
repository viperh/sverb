//! A fake server built on tokio-tungstenite plays the server's part.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use sverb_proto::ws::{ClientMsg, ServerMsg};
use sverb_sync::ws::{DisconnectReason, TokenError, TokenSource, WsConfig, WsEvent, run};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Tokens `t1`, `t2`, …: each refresh moves to the next; refresh number
/// `fail_on` reports `LoginRequired`.
struct Tokens {
    refreshes: Mutex<u32>,
    fail_on: Option<u32>,
}

impl Tokens {
    fn new(fail_on: Option<u32>) -> Self {
        Self {
            refreshes: Mutex::new(0),
            fail_on,
        }
    }

    fn refreshes(&self) -> u32 {
        *self.refreshes.lock().unwrap()
    }
}

impl TokenSource for Tokens {
    async fn access_token(&self) -> Result<String, TokenError> {
        Ok(format!("t{}", self.refreshes() + 1))
    }

    async fn refresh(&self) -> Result<(), TokenError> {
        let mut n = self.refreshes.lock().unwrap();
        *n += 1;
        if Some(*n) == self.fail_on {
            return Err(TokenError::LoginRequired);
        }
        Ok(())
    }
}

fn cfg(addr: SocketAddr) -> WsConfig {
    WsConfig::for_server(&format!("http://{addr}"))
}

async fn accept(l: &TcpListener) -> WebSocketStream<TcpStream> {
    let (tcp, _) = l.accept().await.unwrap();
    tokio_tungstenite::accept_async(tcp).await.unwrap()
}

/// Reads the client's auth message and returns its token.
async fn read_auth(ws: &mut WebSocketStream<TcpStream>) -> String {
    let m = ws.next().await.unwrap().unwrap();
    match serde_json::from_str::<ClientMsg>(m.to_text().unwrap()).unwrap() {
        ClientMsg::Auth { token } => token,
        other => panic!("expected auth, got {other:?}"),
    }
}

async fn send(ws: &mut WebSocketStream<TcpStream>, m: &ServerMsg) {
    ws.send(Message::text(serde_json::to_string(m).unwrap()))
        .await
        .unwrap();
}

async fn close_4401(ws: &mut WebSocketStream<TcpStream>) {
    ws.send(Message::Close(Some(CloseFrame {
        code: 4401.into(),
        reason: "auth_required".into(),
    })))
    .await
    .unwrap();
}

async fn next_event(rx: &mut mpsc::Receiver<WsEvent>) -> WsEvent {
    tokio::time::timeout(Duration::from_secs(120), rx.recv())
        .await
        .expect("no event")
        .expect("client stopped")
}

/// A refused connection is retried with 1, 2, 4, … 60, 60 s delays,
/// each jittered within [base/2, base].
#[tokio::test(start_paused = true)]
async fn t09_backoff_on_refused_connection() {
    // A port with nothing listening.
    let addr = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let tokens = Tokens::new(None);
    let (tx, mut rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let c2 = cancel.clone();
    let client = tokio::spawn(async move { run(cfg(addr), &tokens, tx, c2).await });

    let bases = [1u64, 2, 4, 8, 16, 32, 60, 60, 60];
    for base in bases {
        match next_event(&mut rx).await {
            WsEvent::Disconnected {
                reason: DisconnectReason::Io(_),
                retry_in,
            } => {
                let base = Duration::from_secs(base);
                assert!(
                    retry_in >= base / 2 && retry_in <= base,
                    "retry_in {retry_in:?} outside [{:?}, {base:?}]",
                    base / 2
                );
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    cancel.cancel();
    client.await.unwrap();
}

/// On 4401 the client refreshes exactly once and reconnects at once
/// with the new token; the next connection authenticates, the backoff is
/// reset, and notifications flow.
#[tokio::test]
async fn t09_4401_refreshes_once_then_reconnects() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let vault = Uuid::now_v7();
    let server = tokio::spawn(async move {
        let mut a = accept(&l).await;
        assert_eq!(read_auth(&mut a).await, "t1");
        close_4401(&mut a).await;
        let mut b = accept(&l).await;
        assert_eq!(read_auth(&mut b).await, "t2");
        send(&mut b, &ServerMsg::Ping).await;
        // The client answers the server's ping.
        let pong = b.next().await.unwrap().unwrap();
        assert_eq!(
            serde_json::from_str::<ClientMsg>(pong.to_text().unwrap()).unwrap(),
            ClientMsg::Pong
        );
        send(
            &mut b,
            &ServerMsg::VaultChanged {
                vault_id: vault,
                head_revision: 9,
            },
        )
        .await;
        // Keep the socket open until the client goes away.
        while let Some(Ok(_)) = b.next().await {}
    });

    let tokens = std::sync::Arc::new(Tokens::new(None));
    let (tx, mut rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (t2, c2) = (tokens.clone(), cancel.clone());
    let client = tokio::spawn(async move { run(cfg(addr), &*t2, tx, c2).await });

    assert_eq!(
        next_event(&mut rx).await,
        WsEvent::Disconnected {
            reason: DisconnectReason::AuthRejected,
            retry_in: Duration::ZERO
        }
    );
    assert_eq!(next_event(&mut rx).await, WsEvent::Connected);
    assert_eq!(
        next_event(&mut rx).await,
        WsEvent::Notification(ServerMsg::VaultChanged {
            vault_id: vault,
            head_revision: 9
        })
    );
    assert_eq!(tokens.refreshes(), 1);
    cancel.cancel();
    client.await.unwrap();
    server.await.unwrap();
}

/// A server that keeps rejecting: the second 4401 right after a refresh
/// backs off first; a refresh needing a new login stops the client.
#[tokio::test]
async fn repeated_4401_backs_off_and_login_required_stops() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let mut ws = accept(&l).await;
            read_auth(&mut ws).await;
            close_4401(&mut ws).await;
        }
    });
    let tokens = Tokens::new(Some(2));
    let (tx, mut rx) = mpsc::channel(16);
    let mut config = cfg(addr);
    config.backoff.initial = Duration::from_millis(100);
    run(config, &tokens, tx, CancellationToken::new()).await;

    let mut events = Vec::new();
    while let Ok(e) = rx.try_recv() {
        events.push(e);
    }
    assert_eq!(events.len(), 3, "{events:?}");
    assert_eq!(
        events[0],
        WsEvent::Disconnected {
            reason: DisconnectReason::AuthRejected,
            retry_in: Duration::ZERO
        }
    );
    match &events[1] {
        WsEvent::Disconnected {
            reason: DisconnectReason::AuthRejected,
            retry_in,
        } => assert!(*retry_in >= Duration::from_millis(50), "{retry_in:?}"),
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(events[2], WsEvent::NeedsLogin);
    assert_eq!(tokens.refreshes(), 2);
    server.await.unwrap();
}

/// The client pings on its own and drops a server that misses 2 pongs.
#[tokio::test]
async fn missed_pongs_reconnect() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut ws = accept(&l).await;
        read_auth(&mut ws).await;
        send(&mut ws, &ServerMsg::Ping).await;
        let mut client_pings = 0;
        // Never answer the client's pings.
        while let Some(Ok(m)) = ws.next().await {
            if let Ok(ClientMsg::Ping) =
                serde_json::from_str::<ClientMsg>(m.to_text().unwrap_or(""))
            {
                client_pings += 1;
            }
        }
        client_pings
    });
    let tokens = Tokens::new(None);
    let (tx, mut rx) = mpsc::channel(16);
    let mut config = cfg(addr);
    config.ping_interval = Duration::from_millis(100);
    let cancel = CancellationToken::new();
    let c2 = cancel.clone();
    let client = tokio::spawn(async move { run(config, &tokens, tx, c2).await });

    assert_eq!(next_event(&mut rx).await, WsEvent::Connected);
    match next_event(&mut rx).await {
        WsEvent::Disconnected {
            reason: DisconnectReason::PingTimeout,
            ..
        } => {}
        other => panic!("unexpected {other:?}"),
    }
    cancel.cancel();
    client.await.unwrap();
    assert_eq!(server.await.unwrap(), 2);
}
