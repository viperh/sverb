//! The terminal-sharing client against the real relay (in-process
//! `sverb-server` on its memory backend, served over loopback TCP).
//!
//! The host shares real sessions (`sverb-conn`): a local `/bin/sh` in a pty where a
//! shell is needed, a mock transport where the test must control
//! the output byte for byte. Viewers feed their own emulator, exactly
//! like the TUI's viewer pane, and are compared with the host's emulator.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_lines,
    unreachable_pub
)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sverb_conn::mock::{MockRemote, MockTransport};
use sverb_conn::session::{OutputObserver, ShareTap};
use sverb_conn::{
    Bytes, LocalConnector, LocalOptions, LocalSpec, MockSpec, OpenOptions, SessionCmd,
    SessionEvent, SessionHandle, SessionId, SessionManager, SessionSpec, TransportKind,
};
use sverb_crypto::share::{ShareKey, ShareLink};
use sverb_proto::share::ShareMode;
use sverb_server::auth::store::mem::{MemDevice, MemStore, MemToken, MemUser};
use sverb_server::auth::tokens::{ACCESS_TTL, NewToken, TokenKind};
use sverb_server::auth::{AuthRuntime, AuthStore, Clock, ManualClock};
use sverb_server::middleware::rate_limit::{LoginLimits, RateLimiters};
use sverb_server::{AppState, Config, app};
use sverb_sync::share::host::{self, HostConfig};
use sverb_sync::share::viewer::{self, INTEGRITY_ERROR, JoinConfig};
use sverb_sync::share::{
    FEED_CAPACITY, HostEvent, HostHandle, Screen, ScreenSource, ShareAuth, ShareFeed, ShareOptions,
    ViewerEvent, ViewerHandle, feed_channel,
};
use sverb_term::{AlacrittyEmulator, Emulator, EmulatorConfig, GridPoint};
use tokio::sync::mpsc;
use uuid::Uuid;

const SECRET: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const WAIT: Duration = Duration::from_secs(10);

// ------------------------------------------------------------------ server

struct Server {
    addr: SocketAddr,
    state: AppState,
    token: String,
}

impl Server {
    async fn start() -> Self {
        let mem = Arc::new(MemStore::new());
        let clock = Arc::new(ManualClock::new());
        let auth = AuthRuntime::new(AuthStore::Memory(mem.clone()), clock.clone());
        let env: HashMap<String, String> = HashMap::from([
            ("SVERB_SERVER_SECRET".into(), SECRET.into()),
            (
                "SVERB_PUBLIC_URL".into(),
                "https://sync.example.test".into(),
            ),
        ]);
        let config = Config::from_sources(None, |k| env.get(k).cloned()).unwrap();
        let n = NonZeroU32::new(1_000_000).unwrap();
        let limits = RateLimiters::new(LoginLimits {
            per_email_per_minute: n,
            per_ip_per_minute: n,
        });
        let pool =
            sverb_server::db::connect_lazy("postgres://sverb@127.0.0.1:1/unreachable").unwrap();
        let state = AppState::with_auth(config, pool, limits, auth);

        // One user with one device and an access token.
        let user = Uuid::now_v7();
        let device = Uuid::now_v7();
        let tok = NewToken::generate();
        let now = clock.now();
        mem.with_data(|d| {
            d.users.insert(
                user,
                MemUser {
                    email: "host@example.com".into(),
                    created_at: now,
                    is_instance_admin: false,
                    opaque_record: vec![0],
                    totp_secret_enc: None,
                    totp_pending_enc: None,
                    totp_last_step: None,
                    disabled: false,
                },
            );
            d.devices.insert(
                device,
                MemDevice {
                    user_id: user,
                    name: "laptop".into(),
                    platform: "linux".into(),
                    created_at: now,
                    last_seen_at: None,
                    revoked_at: None,
                },
            );
            d.tokens.insert(
                tok.hash,
                MemToken {
                    device_id: device,
                    kind: TokenKind::Access,
                    expires_at: now + ACCESS_TTL,
                    family: Uuid::now_v7(),
                    used_at: None,
                },
            );
        });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = app::router(state.clone());
        tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        Self {
            addr,
            state,
            token: tok.wire.to_string(),
        }
    }

    fn base(&self) -> String {
        format!("http://{}", self.addr)
    }
}

// ------------------------------------------------------------------ host side

/// The test's bridge between a session and the share host (the TUI has the same).
struct Source {
    term: sverb_conn::SharedEmulator,
    cmd: mpsc::Sender<SessionCmd>,
}

impl ScreenSource for Source {
    fn snapshot(&self, under_lock: &mut dyn FnMut()) -> Screen {
        let term = self.term.lock();
        under_lock();
        let (cols, rows) = term.size();
        Screen {
            cols,
            rows,
            vt: term.snapshot_vt().to_vec(),
        }
    }

    fn inject(&self, bytes: Vec<u8>) {
        let _ = self.cmd.try_send(SessionCmd::Input(Bytes::from(bytes)));
    }
}

/// The session tap feeding the share (optionally dropping chunks: a "congested"
/// queue for T-08).
struct Tap {
    feed: ShareFeed,
    congested: std::sync::atomic::AtomicBool,
}

impl OutputObserver for Tap {
    fn output(&self, bytes: &[u8]) {
        if self.congested.load(std::sync::atomic::Ordering::Acquire) {
            self.feed.mark_overflow();
        } else {
            self.feed.output(bytes);
        }
    }
    fn resize(&self, cols: u16, rows: u16) {
        self.feed.resize(cols, rows);
    }
    fn ended(&self) {
        self.feed.ended();
    }
}

struct Hosted {
    handle: HostHandle,
    events: mpsc::UnboundedReceiver<HostEvent>,
    seen: Vec<HostEvent>,
    tap: Arc<Tap>,
}

impl Hosted {
    async fn next(&mut self) -> HostEvent {
        let ev = tokio::time::timeout(WAIT, self.events.recv())
            .await
            .expect("no host event in time")
            .expect("host task gone");
        self.seen.push(ev.clone());
        ev
    }

    /// The next `ApprovalNeeded` (other events are kept in `seen`).
    async fn approval(&mut self) -> u32 {
        loop {
            if let HostEvent::ApprovalNeeded(v) = self.next().await {
                return v.viewer_id;
            }
        }
    }

    async fn until(&mut self, f: impl Fn(&HostEvent) -> bool) -> HostEvent {
        loop {
            let ev = self.next().await;
            if f(&ev) {
                return ev;
            }
        }
    }
}

async fn share(server: &Server, session: &SessionHandle, options: ShareOptions) -> Hosted {
    share_cap(server, session, options, FEED_CAPACITY).await
}

async fn share_cap(
    server: &Server,
    session: &SessionHandle,
    options: ShareOptions,
    cap: usize,
) -> Hosted {
    let (feed, rx) = feed_channel(cap);
    let tap = Arc::new(Tap {
        feed,
        congested: std::sync::atomic::AtomicBool::new(false),
    });
    session
        .cmd_tx
        .send(SessionCmd::AttachShareTap(ShareTap::new(tap.clone())))
        .await
        .unwrap();
    let source = Arc::new(Source {
        term: session.term.clone(),
        cmd: session.cmd_tx.clone(),
    });
    let cfg = HostConfig {
        base_url: server.base(),
        auth: ShareAuth::Token(server.token.clone()),
        tls: None,
        options,
    };
    let (handle, events) = host::start(cfg, source, rx).await.unwrap();
    Hosted {
        handle,
        events,
        seen: Vec::new(),
        tap,
    }
}

// ------------------------------------------------------------------ sessions

fn manager() -> SessionManager {
    let (tx, rx) = mpsc::unbounded_channel::<(SessionId, SessionEvent)>();
    // Keep the receiver alive for the test's duration.
    std::mem::forget(rx);
    let mgr = SessionManager::new(tx);
    mgr.register_connector(
        TransportKind::Local,
        Arc::new(LocalConnector::new(LocalOptions::default())),
    );
    mgr
}

fn local_shell(mgr: &SessionManager) -> SessionHandle {
    let spec = LocalSpec {
        cwd: None,
        shell: Some("/bin/sh".to_owned()),
        env: vec![("PS1".to_owned(), "$ ".to_owned())],
    };
    mgr.open_with(
        SessionSpec::Local(spec),
        OpenOptions {
            cols: 80,
            rows: 24,
            ..OpenOptions::default()
        },
    )
    .unwrap()
}

fn mock_session(mgr: &SessionManager, cols: u16, rows: u16) -> (SessionHandle, MockRemote) {
    let (transport, remote) = MockTransport::pair();
    let handle = mgr
        .open_with(
            SessionSpec::Mock(MockSpec::new(transport.boxed())),
            OpenOptions {
                cols,
                rows,
                ..OpenOptions::default()
            },
        )
        .unwrap();
    (handle, remote)
}

async fn type_into(session: &SessionHandle, text: &str) {
    session
        .cmd_tx
        .send(SessionCmd::Input(Bytes::copy_from_slice(text.as_bytes())))
        .await
        .unwrap();
}

/// The visible screen as text.
fn screen(term: &dyn Emulator) -> String {
    let (cols, rows) = term.size();
    term.grid_text(
        GridPoint::new(0, 0),
        GridPoint::new(i32::from(rows) - 1, usize::from(cols) - 1),
    )
}

fn host_screen(session: &SessionHandle) -> String {
    screen(&**session.term.lock())
}

async fn wait_host(session: &SessionHandle, what: &str, f: impl Fn(&str) -> bool) {
    let start = Instant::now();
    while start.elapsed() < WAIT {
        if f(&host_screen(session)) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("{what}: host screen was\n{}", host_screen(session));
}

// ------------------------------------------------------------------ viewer side

struct Viewer {
    handle: ViewerHandle,
    events: mpsc::UnboundedReceiver<ViewerEvent>,
    emu: Box<dyn Emulator>,
    seen: Vec<ViewerEvent>,
    snapshots: usize,
    ended: Option<String>,
    control: bool,
}

fn join_link(server: &Server, link: &str) -> Viewer {
    let link = ShareLink::parse(link).unwrap();
    let (handle, events) = viewer::join(JoinConfig {
        link,
        base_url: server.base(),
        name: "bob".into(),
        token: None,
        tls: None,
    });
    Viewer {
        handle,
        events,
        emu: Box::new(AlacrittyEmulator::new(EmulatorConfig {
            cols: 40,
            rows: 10,
            scrollback: 100,
        })),
        seen: Vec::new(),
        snapshots: 0,
        ended: None,
        control: false,
    }
}

impl Viewer {
    fn apply(&mut self, ev: &ViewerEvent) {
        match ev {
            ViewerEvent::Snapshot { cols, rows, vt } => {
                self.snapshots += 1;
                self.emu.resize(*cols, *rows);
                self.emu.feed(vt);
            }
            ViewerEvent::Output(b) => self.emu.feed(b),
            ViewerEvent::Resize { cols, rows } => self.emu.resize(*cols, *rows),
            ViewerEvent::ControlGranted(g) => self.control = *g,
            ViewerEvent::Ended { reason } => self.ended = Some(reason.clone()),
            _ => {}
        }
        // A viewer emulator's replies (DA, DSR) are never sent anywhere.
        drop(self.emu.take_responses());
        drop(self.emu.take_events());
    }

    /// Applies events until `f` holds (or panics after `within`).
    async fn until_within(&mut self, within: Duration, what: &str, f: impl Fn(&Self) -> bool) {
        let start = Instant::now();
        loop {
            if f(self) {
                return;
            }
            let left = within.saturating_sub(start.elapsed());
            match tokio::time::timeout(left, self.events.recv()).await {
                Ok(Some(ev)) => {
                    self.apply(&ev);
                    self.seen.push(ev);
                }
                Ok(None) => {
                    assert!(f(self), "{what}: viewer task ended; saw {:?}", self.seen);
                    return;
                }
                Err(_) => panic!(
                    "{what}: not within {within:?}; saw {:?}\nviewer screen:\n{}",
                    self.seen,
                    screen(&*self.emu)
                ),
            }
        }
    }

    async fn until(&mut self, what: &str, f: impl Fn(&Self) -> bool) {
        self.until_within(WAIT, what, f).await;
    }

    fn saw(&self, f: impl Fn(&ViewerEvent) -> bool) -> bool {
        self.seen.iter().any(f)
    }

    fn screen(&self) -> String {
        screen(&*self.emu)
    }
}

/// A line of command output is on screen: alone, or right after a prompt. Input typed
/// before the shell is ready to read it (before the first prompt, or while an earlier
/// command still runs) is echoed by the tty at once, and its output then follows the
/// next prompt on the same line (`$ READY_21`).
fn line_is(screen: &str, line: &str) -> bool {
    screen.lines().any(|l| {
        let l = l.trim_end();
        l == line
            || l.strip_suffix(line)
                .is_some_and(|head| head.ends_with("$ "))
    })
}

/// The readiness probe's output (`READY_21`) is on screen.
fn shell_ready(screen: &str) -> bool {
    line_is(screen, "READY_21")
}

/// Viewer and host show the same screen, cursor and modes.
async fn assert_mirrors(viewer: &mut Viewer, session: &SessionHandle) {
    let start = Instant::now();
    loop {
        let (host, cursor, modes, size) = {
            let t = session.term.lock();
            (screen(&**t), t.cursor().point, t.modes(), t.size())
        };
        let same = viewer.screen() == host
            && viewer.emu.cursor().point == cursor
            && viewer.emu.modes() == modes
            && viewer.emu.size() == size;
        if same {
            return;
        }
        if start.elapsed() > WAIT {
            panic!(
                "viewer does not mirror the host\n--- host {size:?} {cursor:?}\n{host}\n--- viewer {:?} {:?}\n{}",
                viewer.emu.size(),
                viewer.emu.cursor().point,
                viewer.screen()
            );
        }
        if let Ok(Some(ev)) =
            tokio::time::timeout(Duration::from_millis(50), viewer.events.recv()).await
        {
            viewer.apply(&ev);
            viewer.seen.push(ev);
        }
    }
}

fn opts(mode: ShareMode) -> ShareOptions {
    ShareOptions {
        mode,
        ..ShareOptions::default()
    }
}

// ------------------------------------------------------------------ tests

/// A local pty pane shared in view mode; the viewer's grid equals the host's
/// after the snapshot, and later output reaches the viewer within 1 s.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t01_view_share_snapshot_and_live_output() {
    let server = Server::start().await;
    let mgr = manager();
    let session = local_shell(&mgr);
    type_into(&session, "echo READY_$((20+1))\r").await;
    wait_host(&session, "shell ready", shell_ready).await;

    let mut hosted = share(&server, &session, opts(ShareMode::View)).await;
    let info = hosted.handle.info().clone();
    assert!(
        info.link
            .starts_with(&format!("sverb://join/{}/", server.addr))
    );
    assert!(info.web_link.starts_with("https://"));
    // The key is only in the fragment.
    let (before, key) = info.link.split_once('#').unwrap();
    assert_eq!(key.len(), 43);
    assert!(!before.contains(key));

    let mut viewer = join_link(&server, &info.link);
    let id = hosted.approval().await;
    viewer
        .until("waiting for approval", |v| {
            v.saw(|e| *e == ViewerEvent::WaitingForApproval)
        })
        .await;
    assert_eq!(viewer.snapshots, 0, "no screen before approval");
    hosted.handle.approve(id);
    viewer.until("snapshot", |v| v.snapshots == 1).await;
    assert!(viewer.saw(|e| *e == ViewerEvent::Approved));
    assert_mirrors(&mut viewer, &session).await;
    assert!(matches!(
        hosted.until(|e| matches!(e, HostEvent::ViewerJoined(_))).await,
        HostEvent::ViewerJoined(v) if v.name.as_deref() == Some("bob") && v.viewer_id == id
    ));

    type_into(&session, "echo hi\r").await;
    viewer
        .until_within(Duration::from_secs(1), "echo hi within 1 s", |v| {
            line_is(&v.screen(), "hi")
        })
        .await;
    assert_mirrors(&mut viewer, &session).await;

    hosted.handle.stop();
    viewer.until("ended", |v| v.ended.is_some()).await;
    assert_eq!(viewer.ended.as_deref(), Some("stopped by the host"));
    hosted.until(|e| matches!(e, HostEvent::Ended { .. })).await;
    // The share was deleted on the server (DELETE /v1/shares/{id}).
    let row = server
        .state
        .shares()
        .store()
        .get(info.share_id)
        .await
        .unwrap()
        .unwrap();
    assert!(row.closed_at.is_some());
}

/// Deny → the viewer sees "denied" and is disconnected.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t02_deny() {
    let server = Server::start().await;
    let mgr = manager();
    let (session, _remote) = mock_session(&mgr, 80, 24);
    let mut hosted = share(&server, &session, opts(ShareMode::View)).await;
    let mut viewer = join_link(&server, &hosted.handle.info().link.clone());
    let id = hosted.approval().await;
    hosted.handle.deny(id);
    viewer.until("ended", |v| v.ended.is_some()).await;
    assert!(viewer.saw(|e| *e == ViewerEvent::Denied));
    assert_eq!(viewer.ended.as_deref(), Some("denied by the host"));
    assert_eq!(viewer.snapshots, 0);
    hosted
        .until(|e| matches!(e, HostEvent::ViewerLeft { reason, .. } if reason == "denied"))
        .await;
}

/// A wrong key in the link → the host rejects the MAC and kicks the viewer;
/// no approval is ever asked for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t03_wrong_key_is_kicked_without_approval() {
    let server = Server::start().await;
    let mgr = manager();
    let (session, _remote) = mock_session(&mgr, 80, 24);
    let mut hosted = share(&server, &session, opts(ShareMode::View)).await;
    let good = ShareLink::parse(&hosted.handle.info().link).unwrap();
    let bad = ShareLink::new(
        good.server(),
        *good.share_id(),
        ShareKey::from_bytes([7; 32]),
    )
    .unwrap();
    let mut viewer = join_link(&server, &bad.to_sverb_link());
    let ev = hosted
        .until(|e| matches!(e, HostEvent::ViewerRejected { .. }))
        .await;
    assert!(matches!(ev, HostEvent::ViewerRejected { .. }));
    viewer.until("kicked", |v| v.ended.is_some()).await;
    assert_eq!(viewer.ended.as_deref(), Some("removed by the host"));
    assert!(!viewer.saw(|e| *e == ViewerEvent::WaitingForApproval));
    // Nothing more for the host: no approval modal.
    tokio::time::sleep(Duration::from_millis(200)).await;
    while let Ok(ev) = hosted.events.try_recv() {
        hosted.seen.push(ev);
    }
    assert!(
        !hosted
            .seen
            .iter()
            .any(|e| matches!(e, HostEvent::ApprovalNeeded(_))),
        "{:?}",
        hosted.seen
    );
}

/// Control mode: input before `ControlGranted` is ignored by the host; after
/// granting, the viewer's typing runs on the host; after revoking it is ignored again.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t04_control_grant_and_revoke() {
    let server = Server::start().await;
    let mgr = manager();
    let session = local_shell(&mgr);
    type_into(&session, "echo READY_$((20+1))\r").await;
    wait_host(&session, "shell ready", shell_ready).await;
    let mut hosted = share(&server, &session, opts(ShareMode::Control)).await;
    let mut viewer = join_link(&server, &hosted.handle.info().link.clone());
    let id = hosted.approval().await;
    hosted.handle.approve(id);
    viewer.until("snapshot", |v| v.snapshots == 1).await;

    // A crafted client sends input without control: dropped by the host.
    viewer
        .handle
        .send_input_unchecked(b"echo BEFORE_$((3+3))\r".to_vec());
    // The regular path doesn't even send it.
    viewer.handle.send_input(b"echo PLAIN_$((5+5))\r".to_vec());
    tokio::time::sleep(Duration::from_millis(500)).await;
    let s = host_screen(&session);
    assert!(!s.contains("BEFORE") && !s.contains("PLAIN"), "{s}");

    hosted.handle.set_control(id, true);
    viewer.until("granted", |v| v.control).await;
    viewer
        .handle
        .send_input(b"ls /\recho AFTER_$((1+1))\r".to_vec());
    wait_host(&session, "viewer input executed", |s| line_is(s, "AFTER_2")).await;
    viewer
        .until("output mirrored", |v| line_is(&v.screen(), "AFTER_2"))
        .await;

    hosted.handle.set_control(id, false);
    viewer.until("revoked", |v| !v.control).await;
    assert!(viewer.saw(|e| *e == ViewerEvent::ControlGranted(false)));
    viewer
        .handle
        .send_input_unchecked(b"echo REVOKED_$((2+2))\r".to_vec());
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!host_screen(&session).contains("REVOKED"));
    let changes: Vec<_> = hosted
        .seen
        .iter()
        .chain(
            std::iter::from_fn(|| hosted.events.try_recv().ok())
                .collect::<Vec<_>>()
                .iter(),
        )
        .filter(|e| matches!(e, HostEvent::ControlChanged { .. }))
        .cloned()
        .collect();
    assert_eq!(
        changes,
        [
            HostEvent::ControlChanged {
                viewer_id: id,
                granted: true
            },
            HostEvent::ControlChanged {
                viewer_id: id,
                granted: false
            }
        ]
    );
}

/// View mode: crafted input frames are dropped, and control can't be granted.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t05_view_mode_drops_input() {
    let server = Server::start().await;
    let mgr = manager();
    let session = local_shell(&mgr);
    type_into(&session, "echo READY_$((20+1))\r").await;
    wait_host(&session, "shell ready", shell_ready).await;
    let mut hosted = share(&server, &session, opts(ShareMode::View)).await;
    let mut viewer = join_link(&server, &hosted.handle.info().link.clone());
    let id = hosted.approval().await;
    hosted.handle.approve(id);
    viewer.until("snapshot", |v| v.snapshots == 1).await;
    hosted.handle.set_control(id, true); // no effect in view mode
    viewer
        .handle
        .send_input_unchecked(b"echo VIEW_$((4+4))\r".to_vec());
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!host_screen(&session).contains("VIEW_"));
    while let Ok(ev) = viewer.events.try_recv() {
        viewer.apply(&ev);
        viewer.seen.push(ev);
    }
    assert!(!viewer.saw(|e| matches!(e, ViewerEvent::ControlGranted(_))));
    // The viewer is still connected (dropping input is not an error).
    assert!(viewer.ended.is_none());
}

/// The alternate screen (vim) with its modes is in the snapshot.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t06_alt_screen_snapshot() {
    let server = Server::start().await;
    let mgr = manager();
    let (session, mut remote) = mock_session(&mgr, 80, 24);
    remote
        .send(b"shell history line\r\n$ vim notes.txt\r\n")
        .await
        .unwrap();
    // What vim does: alternate screen, DECCKM, bracketed paste, mouse, a bar cursor.
    remote
        .send(b"\x1b[?1049h\x1b[?1h\x1b=\x1b[?2004h\x1b[?1000h\x1b[?1006h\x1b[2J\x1b[H")
        .await
        .unwrap();
    remote
        .send(b"\x1b[1;33mhello from vim\x1b[0m\r\n~\r\n~\r\n\x1b[24;1H\"notes.txt\" 1L\x1b[1;6H\x1b[6 q")
        .await
        .unwrap();
    wait_host(&session, "vim drawn", |s| s.contains("hello from vim")).await;
    assert!(session.term.lock().modes().alt_screen);

    let mut hosted = share(&server, &session, opts(ShareMode::View)).await;
    let mut viewer = join_link(&server, &hosted.handle.info().link.clone());
    let id = hosted.approval().await;
    hosted.handle.approve(id);
    viewer.until("snapshot", |v| v.snapshots == 1).await;
    assert_mirrors(&mut viewer, &session).await;
    let m = viewer.emu.modes();
    assert!(m.alt_screen && m.app_cursor && m.bracketed_paste, "{m:?}");
    assert!(!viewer.screen().contains("shell history line"));
    // Leaving vim returns to the normal screen on both sides.
    remote.send(b"\x1b[?1049l\x1b[?1l\x1b>").await.unwrap();
    let start = Instant::now();
    while session.term.lock().modes().alt_screen {
        assert!(
            start.elapsed() < WAIT,
            "host never left the alternate screen"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_mirrors(&mut viewer, &session).await;
    assert!(!viewer.emu.modes().alt_screen);
}

/// Host resizes reach the viewer (its emulator follows the host's size); a
/// smaller viewer pane only changes the TUI's clipping (`views::share` tests).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t07_host_resize() {
    let server = Server::start().await;
    let mgr = manager();
    let (session, mut remote) = mock_session(&mgr, 100, 30);
    remote.send(b"before resize\r\n").await.unwrap();
    let mut hosted = share(&server, &session, opts(ShareMode::View)).await;
    let mut viewer = join_link(&server, &hosted.handle.info().link.clone());
    let id = hosted.approval().await;
    hosted.handle.approve(id);
    viewer.until("snapshot", |v| v.snapshots == 1).await;
    assert_eq!(viewer.emu.size(), (100, 30));
    for (cols, rows) in [(60, 20), (132, 43)] {
        session
            .cmd_tx
            .send(SessionCmd::Resize {
                cols,
                rows,
                px_w: 0,
                px_h: 0,
            })
            .await
            .unwrap();
        viewer
            .until("resize", |v| {
                v.saw(|e| *e == ViewerEvent::Resize { cols, rows })
            })
            .await;
        assert_eq!(viewer.emu.size(), (cols, rows));
        remote
            .send(format!("after {cols}x{rows}\r\n").as_bytes())
            .await
            .unwrap();
        assert_mirrors(&mut viewer, &session).await;
    }
}

/// A share that falls behind never slows the session: dropped output is
/// replaced by a fresh snapshot, and the viewer converges on the host's screen.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t08_backlog_resends_a_snapshot() {
    let server = Server::start().await;
    let mgr = manager();
    let (session, mut remote) = mock_session(&mgr, 80, 24);
    let mut hosted = share_cap(&server, &session, opts(ShareMode::View), 2).await;
    let mut viewer = join_link(&server, &hosted.handle.info().link.clone());
    let id = hosted.approval().await;
    hosted.handle.approve(id);
    viewer.until("snapshot", |v| v.snapshots == 1).await;

    // A congested share queue: every chunk is dropped while the session keeps going.
    hosted
        .tap
        .congested
        .store(true, std::sync::atomic::Ordering::Release);
    let start = Instant::now();
    for i in 0..2000 {
        remote
            .send(format!("flood line {i}\r\n").as_bytes())
            .await
            .unwrap();
    }
    wait_host(&session, "host got everything", |s| {
        line_is(s, "flood line 1999")
    })
    .await;
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "the session was slowed down"
    );
    hosted
        .tap
        .congested
        .store(false, std::sync::atomic::Ordering::Release);
    viewer.until("fresh snapshot", |v| v.snapshots >= 2).await;
    remote.send(b"after the backlog\r\n").await.unwrap();
    assert_mirrors(&mut viewer, &session).await;
    assert!(line_is(&viewer.screen(), "flood line 1999"));

    // A real flood through a tiny queue: whatever is dropped, the viewer converges.
    for i in 0..3000 {
        remote
            .send(format!("burst {i} {}\r\n", "x".repeat(i % 50)).as_bytes())
            .await
            .unwrap();
    }
    remote.send(b"done\r\n").await.unwrap();
    wait_host(&session, "burst done", |s| line_is(s, "done")).await;
    assert_mirrors(&mut viewer, &session).await;
}

/// The host's session ends → `Bye` → the viewer pane shows the end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t09_session_end_ends_the_share() {
    let server = Server::start().await;
    let mgr = manager();
    let (session, mut remote) = mock_session(&mgr, 80, 24);
    let mut hosted = share(&server, &session, opts(ShareMode::View)).await;
    let mut viewer = join_link(&server, &hosted.handle.info().link.clone());
    let id = hosted.approval().await;
    hosted.handle.approve(id);
    viewer.until("snapshot", |v| v.snapshots == 1).await;
    remote.send(b"logout\r\n").await.unwrap();
    remote.finish(Some(0));
    viewer.until("ended", |v| v.ended.is_some()).await;
    assert_eq!(viewer.ended.as_deref(), Some("the session ended"));
    assert!(matches!(
        hosted.until(|e| matches!(e, HostEvent::Ended { .. })).await,
        HostEvent::Ended { reason } if reason == "the session ended"
    ));
}

/// Expiry closes the share on both sides.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t10_expiry() {
    let server = Server::start().await;
    let mgr = manager();
    let (session, _remote) = mock_session(&mgr, 80, 24);
    let options = ShareOptions {
        expires_in: Duration::from_secs(2),
        ..opts(ShareMode::View)
    };
    let mut hosted = share(&server, &session, options).await;
    let mut viewer = join_link(&server, &hosted.handle.info().link.clone());
    let id = hosted.approval().await;
    hosted.handle.approve(id);
    viewer.until("snapshot", |v| v.snapshots == 1).await;
    viewer.until("expired", |v| v.ended.is_some()).await;
    let reason = viewer.ended.clone().unwrap();
    assert!(reason == "expired" || reason == "share ended", "{reason}");
    hosted.until(|e| matches!(e, HostEvent::Ended { .. })).await;
    assert!(!hosted.handle.is_running());
    // Nobody can join an expired share.
    let mut late = join_link(&server, &hosted.handle.info().link.clone());
    late.until("refused", |v| v.ended.is_some()).await;
    assert_ne!(late.ended.as_deref(), Some(INTEGRITY_ERROR));
}
