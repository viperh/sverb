#![allow(clippy::unwrap_used, clippy::expect_used, unreachable_pub)]

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use sverb_conn::{
    Bytes, DisconnectReason, LocalConnector, LocalOptions, LocalSpec, OpenOptions, SessionCmd,
    SessionEvent, SessionHandle, SessionId, SessionManager, SessionSpec, SessionState,
    TransportKind,
};
use sverb_term::GridPoint;
use tokio::sync::mpsc;

type Events = mpsc::UnboundedReceiver<(SessionId, SessionEvent)>;

const SHORT: Duration = Duration::from_secs(2);

fn manager(opts: LocalOptions) -> (SessionManager, Events) {
    let (tx, rx) = mpsc::unbounded_channel();
    let mgr = SessionManager::new(tx);
    mgr.register_connector(TransportKind::Local, Arc::new(LocalConnector::new(opts)));
    (mgr, rx)
}

#[cfg(unix)]
fn sh(cwd: Option<&str>) -> LocalSpec {
    LocalSpec {
        cwd: cwd.map(Into::into),
        shell: Some("/bin/sh".to_owned()),
        env: Vec::new(),
    }
}

fn open(mgr: &SessionManager, spec: LocalSpec, opts: OpenOptions) -> SessionHandle {
    mgr.open_with(SessionSpec::Local(spec), opts).unwrap()
}

async fn send(handle: &SessionHandle, text: &str) {
    handle
        .cmd_tx
        .send(SessionCmd::Input(Bytes::copy_from_slice(text.as_bytes())))
        .await
        .unwrap();
}

/// The whole grid (scrollback and screen) as text.
fn screen(handle: &SessionHandle) -> String {
    let term = handle.term.lock();
    let (cols, rows) = term.size();
    let top = -i32::try_from(term.scrollback_len()).unwrap();
    term.grid_text(
        GridPoint::new(top, 0),
        GridPoint::new(i32::from(rows) - 1, usize::from(cols) - 1),
    )
}

/// A grid line, trimmed, without a leading `sh` prompt. Input typed before the
/// shell printed its first prompt is echoed by the tty first, so the command's
/// output can land on the prompt line (`$ hello`, or `# hello` as root).
fn output_line(l: &str) -> &str {
    let l = l.trim();
    l.strip_prefix("$ ")
        .or_else(|| l.strip_prefix("# "))
        .unwrap_or(l)
}

/// Wait until some grid line, trimmed (and without a prompt), equals `line`.
async fn wait_line(handle: &SessionHandle, line: &str, within: Duration) {
    let deadline = Instant::now() + within;
    loop {
        let text = screen(handle);
        if text.lines().any(|l| output_line(l) == line) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "line {line:?} not on screen within {within:?}:\n{text}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Wait for a state of session `id` matching `pred`; returns it.
async fn wait_state(
    rx: &mut Events,
    id: SessionId,
    within: Duration,
    pred: impl Fn(&SessionState) -> bool,
) -> SessionState {
    tokio::time::timeout(within, async {
        loop {
            let (sid, ev) = rx.recv().await.expect("event channel closed");
            if sid == id
                && let SessionEvent::State(state) = ev
                && pred(&state)
            {
                return state;
            }
        }
    })
    .await
    .expect("state not reached in time")
}

fn connected(s: &SessionState) -> bool {
    matches!(s, SessionState::Connected { .. })
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn t01_echo() {
    let (mgr, mut rx) = manager(LocalOptions::default());
    let h = open(&mgr, sh(None), OpenOptions::default());
    wait_state(&mut rx, h.id, SHORT, connected).await;
    // Quoted so the echoed command line itself doesn't match.
    send(&h, "echo hel''lo\r").await;
    wait_line(&h, "hello", SHORT).await;
    mgr.shutdown(SHORT).await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn t02_term_default_and_configured() {
    for (opts, want) in [
        (LocalOptions::default(), "T=xterm-256color. C=truecolor."),
        (
            LocalOptions {
                term: "xterm".to_owned(),
                colorterm: true,
            },
            "T=xterm. C=truecolor.",
        ),
    ] {
        let (mgr, mut rx) = manager(opts);
        let h = open(&mgr, sh(None), OpenOptions::default());
        wait_state(&mut rx, h.id, SHORT, connected).await;
        send(&h, "echo \"T=${TERM}. C=${COLORTERM}.\"\r").await;
        wait_line(&h, want, SHORT).await;
        mgr.shutdown(SHORT).await;
    }
}

// Runs itself in a child test process with `SVERB_HOME` set (setting variables
// in this process would need `unsafe`).
#[cfg(unix)]
#[test]
fn t03_no_sverb_leak() {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "t03_inner", "--ignored", "--nocapture"])
        .env("SVERB_HOME", "/nonexistent/sverb-test-home")
        .env("SVERB_SOMETHING_ELSE", "1")
        .status()
        .unwrap();
    assert!(status.success(), "inner test failed: {status}");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "run by t03_no_sverb_leak with SVERB_HOME set"]
async fn t03_inner() {
    assert!(
        std::env::var_os("SVERB_HOME").is_some(),
        "run via t03_no_sverb_leak"
    );
    let (mgr, mut rx) = manager(LocalOptions::default());
    let h = open(
        &mgr,
        sh(None),
        OpenOptions {
            id: Some(SessionId(42)),
            ..OpenOptions::default()
        },
    );
    wait_state(&mut rx, h.id, SHORT, connected).await;
    send(&h, "echo \"n=$(env | grep -c SVERB_) p=${SVERB_PANE}.\"\r").await;
    // Only SVERB_PANE is left.
    wait_line(&h, "n=1 p=42.", SHORT).await;
    send(&h, "env | grep SVERB_HOME; echo \"h=[${SVERB_HOME}]\"\r").await;
    wait_line(&h, "h=[]", SHORT).await;
    mgr.shutdown(SHORT).await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn t04_resize() {
    let (mgr, mut rx) = manager(LocalOptions::default());
    let h = open(&mgr, sh(None), OpenOptions::default());
    wait_state(&mut rx, h.id, SHORT, connected).await;
    h.cmd_tx
        .send(SessionCmd::Resize {
            cols: 100,
            rows: 30,
            px_w: 0,
            px_h: 0,
        })
        .await
        .unwrap();
    send(&h, "stty size\r").await;
    wait_line(&h, "30 100", SHORT).await;
    mgr.shutdown(SHORT).await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn t05_exit_code() {
    let (mgr, mut rx) = manager(LocalOptions::default());
    let h = open(&mgr, sh(None), OpenOptions::default());
    wait_state(&mut rx, h.id, SHORT, connected).await;
    send(&h, "exit 3\r").await;
    let state = wait_state(&mut rx, h.id, SHORT, |s| {
        matches!(s, SessionState::Disconnected { .. })
    })
    .await;
    assert!(
        matches!(
            state,
            SessionState::Disconnected {
                reason: DisconnectReason::Exited(3),
                ..
            }
        ),
        "{state:?}"
    );
    // Restart (`Enter` on the exited pane): a fresh shell in the same session.
    h.cmd_tx.send(SessionCmd::Reconnect).await.unwrap();
    wait_state(&mut rx, h.id, SHORT, connected).await;
    send(&h, "echo re''started\r").await;
    wait_line(&h, "restarted", SHORT).await;
    mgr.shutdown(SHORT).await;
}

#[cfg(unix)]
fn alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn t06_close_kills_the_child() {
    let (mgr, mut rx) = manager(LocalOptions::default());
    let h = open(&mgr, sh(None), OpenOptions::default());
    wait_state(&mut rx, h.id, SHORT, connected).await;
    send(&h, "echo \"pid=$$.\"\r").await;
    let deadline = Instant::now() + SHORT;
    let pid = loop {
        let text = screen(&h);
        if let Some(pid) = text.lines().find_map(|l| {
            output_line(l)
                .strip_prefix("pid=")
                .and_then(|p| p.strip_suffix('.'))
                .and_then(|p| p.parse::<u32>().ok())
        }) {
            break pid;
        }
        assert!(Instant::now() < deadline, "no pid:\n{text}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    send(&h, "exec sleep 1000\r").await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(alive(pid));

    let started = Instant::now();
    assert!(mgr.close(h.id));
    wait_state(&mut rx, h.id, SHORT, |s| matches!(s, SessionState::Closed)).await;
    while alive(pid) {
        assert!(
            started.elapsed() < SHORT,
            "pid {pid} still alive after close"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    mgr.shutdown(SHORT).await;
}

// T-06 (direct): a child that ignores SIGHUP is killed after the grace period.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn t06_close_escalates_to_kill() {
    use sverb_conn::{LocalTransport, Transport};
    use tokio::io::AsyncReadExt;

    let mut t = tokio::task::spawn_blocking(|| {
        LocalTransport::spawn(
            &LocalSpec {
                shell: Some("/bin/sh".to_owned()),
                ..LocalSpec::default()
            },
            &LocalOptions::default(),
            1,
            80,
            24,
        )
    })
    .await
    .unwrap()
    .unwrap();
    let pid = t.pid().unwrap();
    t.write(b"trap '' HUP; echo tr''apped; exec sleep 1000\r")
        .await
        .unwrap();
    let mut seen = Vec::new();
    let mut buf = [0_u8; 4096];
    tokio::time::timeout(SHORT, async {
        while !String::from_utf8_lossy(&seen).contains("trapped") {
            let n = t.reader().read(&mut buf).await.unwrap();
            assert!(n > 0, "EOF");
            seen.extend_from_slice(&buf[..n]);
        }
    })
    .await
    .unwrap();
    let started = Instant::now();
    t.close().await.unwrap();
    assert!(!alive(pid));
    assert!(started.elapsed() >= Duration::from_millis(900));
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn t07_cwd() {
    let (mgr, mut rx) = manager(LocalOptions::default());
    let h = open(&mgr, sh(Some("/tmp")), OpenOptions::default());
    wait_state(&mut rx, h.id, SHORT, connected).await;
    send(&h, "pwd\r").await;
    wait_line(&h, "/tmp", SHORT).await;
    mgr.shutdown(SHORT).await;
}

/// Counts what it is fed; renders nothing (T-08 measures the transport, not alacritty).
mod counting {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use ratatui_core::{buffer::Buffer, layout::Rect};
    use regex::Regex;
    use sverb_conn::Bytes;
    use sverb_term::{
        ColorScheme, CursorInfo, CursorShape, Direction, Emulator, GridPoint, Match, TermEvent,
        TermModes, ViewState,
    };

    pub struct Counting {
        pub bytes: Arc<AtomicUsize>,
        pub feeds: Arc<AtomicUsize>,
        pub size: (u16, u16),
    }

    impl Emulator for Counting {
        fn feed(&mut self, bytes: &[u8]) {
            self.bytes.fetch_add(bytes.len(), Ordering::Relaxed);
            self.feeds.fetch_add(1, Ordering::Relaxed);
        }
        fn resize(&mut self, cols: u16, rows: u16) {
            self.size = (cols, rows);
        }
        fn modes(&self) -> TermModes {
            TermModes::default()
        }
        fn render(&self, _area: Rect, _buf: &mut Buffer, _view: &ViewState) {}
        fn take_responses(&mut self) -> Vec<Bytes> {
            Vec::new()
        }
        fn take_events(&mut self) -> Vec<TermEvent> {
            Vec::new()
        }
        fn scrollback_len(&self) -> usize {
            0
        }
        fn search(&self, _re: &Regex, _dir: Direction, _from: GridPoint) -> Option<Match> {
            None
        }
        fn snapshot_vt(&self) -> Bytes {
            Bytes::new()
        }
        fn cursor(&self) -> CursorInfo {
            CursorInfo {
                point: GridPoint::new(0, 0),
                shape: CursorShape::Block,
                blinking: false,
                visible: true,
            }
        }
        fn grid_text(&self, _start: GridPoint, _end: GridPoint) -> String {
            String::new()
        }
        fn set_color_scheme(&mut self, _scheme: &ColorScheme) {}
        fn set_pixel_size(&mut self, _w: u16, _h: u16) {}
        fn size(&self) -> (u16, u16) {
            self.size
        }
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn t08_large_output_coalesces_dirty() {
    const TOTAL: usize = 50_000_000;
    let bytes = Arc::new(AtomicUsize::new(0));
    let feeds = Arc::new(AtomicUsize::new(0));
    let emulator = counting::Counting {
        bytes: Arc::clone(&bytes),
        feeds: Arc::clone(&feeds),
        size: (80, 24),
    };
    let (mgr, mut rx) = manager(LocalOptions::default());
    let h = open(
        &mgr,
        sh(None),
        OpenOptions {
            emulator: Some(Box::new(emulator)),
            ..OpenOptions::default()
        },
    );
    wait_state(&mut rx, h.id, SHORT, connected).await;
    let started = Instant::now();
    send(&h, &format!("yes | head -c {TOTAL}; exit 7\r")).await;

    // The UI: one frame (16 ms) per Dirty, then clear the flag.
    let mut dirty_events = 0_usize;
    let mut frames = 0_usize;
    let exit = tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            let (sid, ev) = rx.recv().await.unwrap();
            if sid != h.id {
                continue;
            }
            match ev {
                SessionEvent::Dirty => {
                    dirty_events += 1;
                    tokio::time::sleep(Duration::from_millis(16)).await;
                    h.dirty.store(false, Ordering::Release);
                    frames += 1;
                }
                SessionEvent::State(SessionState::Disconnected { reason, .. }) => {
                    return reason;
                }
                _ => {}
            }
        }
    })
    .await
    .expect("no deadlock: the output completes");
    let elapsed = started.elapsed();
    assert_eq!(exit, DisconnectReason::Exited(7));
    // `onlcr` turns every `\n` into `\r\n`: at least TOTAL bytes arrive.
    assert!(bytes.load(Ordering::Relaxed) >= TOTAL);
    let feeds = feeds.load(Ordering::Relaxed);
    let budget = usize::try_from(elapsed.as_millis() / 16).unwrap() + 2;
    eprintln!(
        "t08: {elapsed:?}, {feeds} feeds, {dirty_events} Dirty, {frames} frames, budget {budget}"
    );
    assert!(dirty_events <= frames + 1);
    assert!(
        dirty_events <= budget,
        "{dirty_events} Dirty events in {elapsed:?}"
    );
    assert!(dirty_events < feeds, "Dirty is coalesced across reads");
    mgr.shutdown(SHORT).await;
}

// A spawn failure is a connect error with a toast, not a crash.
#[tokio::test(flavor = "multi_thread")]
async fn missing_shell_fails_to_connect() {
    let (mgr, mut rx) = manager(LocalOptions::default());
    let h = open(
        &mgr,
        LocalSpec {
            shell: Some("/nonexistent/sverb-no-such-shell".to_owned()),
            ..LocalSpec::default()
        },
        OpenOptions::default(),
    );
    let state = wait_state(&mut rx, h.id, SHORT, |s| {
        matches!(s, SessionState::Disconnected { .. })
    })
    .await;
    assert!(matches!(
        state,
        SessionState::Disconnected {
            reason: DisconnectReason::Connect,
            ..
        }
    ));
    mgr.shutdown(SHORT).await;
}

// T-09 (Windows only; not run on Linux).
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn t09_windows_cmd() {
    let (mgr, mut rx) = manager(LocalOptions::default());
    let h = open(
        &mgr,
        LocalSpec {
            shell: Some("cmd.exe".to_owned()),
            ..LocalSpec::default()
        },
        OpenOptions::default(),
    );
    wait_state(&mut rx, h.id, Duration::from_secs(10), connected).await;
    let comspec = std::env::var("ComSpec").unwrap();
    send(&h, "echo %COMSPEC%\r").await;
    wait_line(&h, &comspec, Duration::from_secs(10)).await;
    h.cmd_tx
        .send(SessionCmd::Resize {
            cols: 100,
            rows: 30,
            px_w: 0,
            px_h: 0,
        })
        .await
        .unwrap();
    send(&h, "mode con\r").await;
    wait_line(&h, "Columns:       100", Duration::from_secs(10)).await;
    send(&h, "exit 3\r").await;
    let state = wait_state(&mut rx, h.id, Duration::from_secs(10), |s| {
        matches!(s, SessionState::Disconnected { .. })
    })
    .await;
    assert!(matches!(
        state,
        SessionState::Disconnected {
            reason: DisconnectReason::Exited(3),
            ..
        }
    ));
    mgr.shutdown(SHORT).await;
}
