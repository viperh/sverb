#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use parking_lot::Mutex;
use pretty_assertions::assert_eq;
use ratatui_core::{buffer::Buffer, layout::Rect};
use regex::Regex;
use sverb_term::{
    ColorScheme, CursorInfo, CursorShape, Direction, Emulator, GridPoint, Match, TermEvent,
    TermModes, ViewState,
};
use tokio::sync::mpsc;

use super::*;
use crate::{
    manager::{OpenOptions, SessionManager, ShutdownReport},
    mock::{MockOp, MockRemote, MockTransport},
};

type Events = mpsc::UnboundedReceiver<(SessionId, SessionEvent)>;

const DA1: &[u8] = b"\x1b[c";
const DA1_REPLY: &[u8] = b"\x1b[?62;22c";

/// A cheap emulator that records what it is fed and answers DA1 with a fixed reply.
#[derive(Default)]
struct StubEmulator {
    fed: Arc<AtomicUsize>,
    chunks: Arc<Mutex<Vec<usize>>>,
    responses: Vec<Bytes>,
    size: (u16, u16),
}

impl StubEmulator {
    fn new() -> (Self, Arc<AtomicUsize>, Arc<Mutex<Vec<usize>>>) {
        let stub = Self {
            size: (80, 24),
            ..Self::default()
        };
        let fed = Arc::clone(&stub.fed);
        let chunks = Arc::clone(&stub.chunks);
        (stub, fed, chunks)
    }
}

impl Emulator for StubEmulator {
    fn feed(&mut self, bytes: &[u8]) {
        self.chunks.lock().push(bytes.len());
        if bytes.windows(DA1.len()).any(|w| w == DA1) {
            self.responses.push(Bytes::from_static(DA1_REPLY));
        }
        // A little work per byte, like a parser.
        let sum = bytes.iter().fold(0_u8, |a, b| a.wrapping_add(*b));
        std::hint::black_box(sum);
        self.fed.fetch_add(bytes.len(), Ordering::SeqCst);
    }
    fn resize(&mut self, cols: u16, rows: u16) {
        self.size = (cols, rows);
    }
    fn modes(&self) -> TermModes {
        TermModes::default()
    }
    fn render(&self, _area: Rect, _buf: &mut Buffer, _view: &ViewState) {}
    fn take_responses(&mut self) -> Vec<Bytes> {
        std::mem::take(&mut self.responses)
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

fn manager() -> (SessionManager, Events) {
    let (tx, rx) = mpsc::unbounded_channel();
    (SessionManager::new(tx), rx)
}

fn open_mock(
    mgr: &SessionManager,
    transport: MockTransport,
    emulator: Option<Box<dyn Emulator>>,
) -> SessionHandle {
    mgr.open_with(
        SessionSpec::Mock(MockSpec::new(transport.boxed())),
        OpenOptions {
            emulator,
            ..OpenOptions::default()
        },
    )
    .unwrap()
}

/// Wait (up to 10 s) for an event of session `id` matching `pred`; returns every
/// event of that session seen on the way, the match last.
async fn wait_for(
    rx: &mut Events,
    id: SessionId,
    pred: impl Fn(&SessionEvent) -> bool,
) -> Vec<SessionEvent> {
    let mut seen = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let (sid, ev) = rx.recv().await.expect("event channel closed");
            if sid != id {
                continue;
            }
            let done = pred(&ev);
            seen.push(ev);
            if done {
                return;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out; saw {seen:?}"));
    seen
}

fn is_connected(ev: &SessionEvent) -> bool {
    matches!(ev, SessionEvent::State(SessionState::Connected { .. }))
}

fn drain(rx: &mut Events, id: SessionId) -> Vec<SessionEvent> {
    let mut out = Vec::new();
    while let Ok((sid, ev)) = rx.try_recv() {
        if sid == id {
            out.push(ev);
        }
    }
    out
}

async fn wait_fed(fed: &AtomicUsize, n: usize) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while fed.load(Ordering::SeqCst) < n {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("fed {} of {n} bytes", fed.load(Ordering::SeqCst)));
}

/// A `MakeWriter` collecting log output.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// An illegal input is logged at `error` and ends in `Disconnected { Internal }`.
#[tokio::test]
async fn t02_illegal_transition_degrades_to_disconnected() {
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(capture.clone())
        .with_max_level(tracing::Level::ERROR)
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let (mgr, mut rx) = manager();
    let (transport, _remote) = MockTransport::pair();
    let spec = MockSpec::new(transport.boxed()).with_script(vec![StateInput::HostKeyAccepted]);
    let h = mgr.open(SessionSpec::Mock(spec)).unwrap();
    let seen = wait_for(&mut rx, h.id, |ev| {
        matches!(ev, SessionEvent::State(SessionState::Disconnected { .. }))
    })
    .await;
    assert_eq!(seen[0], SessionEvent::State(SessionState::Resolving));
    let SessionEvent::State(SessionState::Disconnected { reason, .. }) = seen.last().unwrap()
    else {
        unreachable!()
    };
    assert_eq!(*reason, DisconnectReason::Internal);
    let log = String::from_utf8(capture.0.lock().clone()).unwrap();
    assert!(log.contains("ERROR"), "{log}");
    assert!(
        log.contains("illegal session transition: HostKeyAccepted in state Resolving"),
        "{log}"
    );

    // Still alive: Close ends it.
    h.cmd_tx.send(SessionCmd::Close).await.unwrap();
    wait_for(&mut rx, h.id, |ev| {
        *ev == SessionEvent::State(SessionState::Closed)
    })
    .await;
}

/// A flood with no acknowledgement gives exactly one `Dirty`; after the ack,
/// one more chunk gives exactly one more.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t03_dirty_coalescing() {
    let (mgr, mut rx) = manager();
    let (transport, mut remote) = MockTransport::pair();
    let (stub, fed, _) = StubEmulator::new();
    let h = open_mock(&mgr, transport, Some(Box::new(stub)));
    wait_for(&mut rx, h.id, is_connected).await;

    for _ in 0..10_000 {
        remote.send(b"x\n").await.unwrap();
    }
    wait_fed(&fed, 20_000).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let dirty = |evs: &[SessionEvent]| evs.iter().filter(|e| **e == SessionEvent::Dirty).count();
    assert_eq!(dirty(&drain(&mut rx, h.id)), 1);

    h.dirty.store(false, Ordering::Release);
    remote.send(b"y\n").await.unwrap();
    wait_fed(&fed, 20_002).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(dirty(&drain(&mut rx, h.id)), 1);
    assert!(h.dirty.load(Ordering::Acquire));
}

/// 1 MiB in one read is fed in ≤ 64 KiB slices.
#[tokio::test]
async fn t04_lock_chunks() {
    let (mgr, mut rx) = manager();
    let (transport, mut remote) = MockTransport::pair();
    let (stub, fed, chunks) = StubEmulator::new();
    let h = mgr
        .open_with(
            SessionSpec::Mock(MockSpec::new(transport.boxed())),
            OpenOptions {
                emulator: Some(Box::new(stub)),
                read_buffer: 1024 * 1024,
                ..OpenOptions::default()
            },
        )
        .unwrap();
    wait_for(&mut rx, h.id, is_connected).await;
    // Current-thread runtime: the whole MiB is buffered before the actor reads again.
    remote.send(&vec![b'a'; 1024 * 1024]).await.unwrap();
    wait_fed(&fed, 1024 * 1024).await;
    let chunks = chunks.lock().clone();
    assert!(chunks.iter().all(|&n| n <= actor::LOCK_CHUNK), "{chunks:?}");
    assert_eq!(chunks, vec![actor::LOCK_CHUNK; 16]);
}

/// The emulator's replies (DA1) are written back to the transport.
#[tokio::test]
async fn t05_responses_written_back() {
    let (mgr, mut rx) = manager();
    let (transport, mut remote) = MockTransport::pair();
    let (stub, _, _) = StubEmulator::new();
    let h = open_mock(&mgr, transport, Some(Box::new(stub)));
    wait_for(&mut rx, h.id, is_connected).await;
    remote.send(DA1).await.unwrap();
    assert_eq!(remote.read_written(DA1_REPLY.len()).await, DA1_REPLY);

    // And with the real emulator.
    let (transport, mut remote) = MockTransport::pair();
    let h = open_mock(&mgr, transport, None);
    wait_for(&mut rx, h.id, is_connected).await;
    remote.send(DA1).await.unwrap();
    let reply = remote.read_written(3).await;
    assert!(reply.starts_with(b"\x1b[?"), "{reply:?}");
}

/// A render thread locking the emulator at ~1 kHz while 50 MB are fed: no
/// deadlock within 10 s (the lock is never held across `.await`; clippy denies
/// `await_holding_lock` as well).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t06_no_lock_across_await_stress() {
    const TOTAL: usize = 50 * 1024 * 1024;
    let (mgr, mut rx) = manager();
    let (transport, mut remote) = MockTransport::pair();
    let (stub, fed, _) = StubEmulator::new();
    let h = open_mock(&mgr, transport, Some(Box::new(stub)));
    wait_for(&mut rx, h.id, is_connected).await;

    let stop = Arc::new(AtomicBool::new(false));
    let renders = Arc::new(AtomicUsize::new(0));
    let render = {
        let term = Arc::clone(&h.term);
        let stop = Arc::clone(&stop);
        let renders = Arc::clone(&renders);
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                {
                    let term = term.lock();
                    std::hint::black_box(term.size());
                }
                renders.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(1));
            }
        })
    };
    let block = vec![b'z'; 64 * 1024];
    let feed = async {
        for _ in 0..TOTAL / block.len() {
            remote.send(&block).await.unwrap();
        }
        while fed.load(Ordering::SeqCst) < TOTAL {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    };
    let result = tokio::time::timeout(Duration::from_secs(10), feed).await;
    stop.store(true, Ordering::SeqCst);
    render.join().unwrap();
    assert!(
        result.is_ok(),
        "deadlock or too slow: fed {}",
        fed.load(Ordering::SeqCst)
    );
    assert!(renders.load(Ordering::SeqCst) > 0);
}

/// A panicking session reports `Disconnected { Internal }`; others keep working.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t08_panic_containment() {
    let (mgr, mut rx) = manager();
    let (bad, _bad_remote) = MockTransport::pair();
    let (good, mut good_remote) = MockTransport::pair();
    let bad = open_mock(&mgr, bad.panic_on_read(), None);
    let good = open_mock(&mgr, good, None);

    let seen = wait_for(&mut rx, bad.id, |ev| {
        matches!(
            ev,
            SessionEvent::State(SessionState::Disconnected {
                reason: DisconnectReason::Internal,
                ..
            })
        )
    })
    .await;
    assert!(seen.iter().any(is_connected));
    wait_for(&mut rx, bad.id, |ev| {
        *ev == SessionEvent::Error(sverb_core::error_report::ErrorReport::msg(
            "session crashed (see log)",
        ))
    })
    .await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while mgr.get(bad.id).is_some() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();

    // The other session still works both ways.
    good_remote.send(b"hello").await.unwrap();
    wait_for(&mut rx, good.id, |ev| *ev == SessionEvent::Dirty).await;
    good.cmd_tx
        .send(SessionCmd::Input(Bytes::from_static(b"ls\r")))
        .await
        .unwrap();
    assert_eq!(good_remote.read_written(3).await, b"ls\r");
    assert_eq!(mgr.ids(), vec![good.id]);
}

/// Shutdown closes every session; one that ignores Close is aborted after the
/// timeout (virtual time).
#[tokio::test(start_paused = true)]
async fn t09_shutdown() {
    let (mgr, mut rx) = manager();
    let mut remotes: Vec<MockRemote> = Vec::new();
    let mut ids = Vec::new();
    for i in 0..5 {
        let (t, r) = MockTransport::pair();
        let t = if i == 2 { t.hang_on_close() } else { t };
        let h = open_mock(&mgr, t, None);
        wait_for(&mut rx, h.id, is_connected).await;
        ids.push(h.id);
        remotes.push(r);
    }
    let start = tokio::time::Instant::now();
    let report = mgr.shutdown(Duration::from_secs(2)).await;
    assert_eq!(
        report,
        ShutdownReport {
            closed: 4,
            aborted: 1
        }
    );
    assert!(start.elapsed() >= Duration::from_secs(2));
    assert!(mgr.is_empty());
    // Every session reports Closed (graceful or aborted).
    let mut closed = std::collections::BTreeSet::new();
    while let Ok((id, ev)) = rx.try_recv() {
        if ev == SessionEvent::State(SessionState::Closed) {
            closed.insert(id);
        }
    }
    assert_eq!(closed.into_iter().collect::<Vec<_>>(), ids);
    // The graceful ones closed their transports.
    for (i, r) in remotes.iter_mut().enumerate() {
        assert!(r.drain_ops().contains(&MockOp::Close), "session {i}");
    }
}

/// A 1,000-char OSC title arrives capped at 256 chars; the same title twice is
/// one event.
#[tokio::test]
async fn t10_title_cap_and_coalescing() {
    let (mgr, mut rx) = manager();
    let (transport, mut remote) = MockTransport::pair();
    let h = open_mock(&mgr, transport, None);
    wait_for(&mut rx, h.id, is_connected).await;
    let osc = format!("\x1b]2;{}\x07", "t".repeat(1000));
    remote.send(osc.as_bytes()).await.unwrap();
    remote.send(osc.as_bytes()).await.unwrap();
    remote.send(b"\x07").await.unwrap();
    // The bell is last: once it arrives, both titles were processed.
    let seen = wait_for(&mut rx, h.id, |ev| *ev == SessionEvent::Bell).await;
    let titles: Vec<_> = seen
        .iter()
        .filter_map(|ev| match ev {
            SessionEvent::Title(t) => Some(t.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(titles.len(), 1, "{seen:?}");
    assert!(titles[0].chars().count() <= MAX_TITLE_CHARS);
    assert!(!titles[0].is_empty());
}

/// Remote exit: `Exit { code }`, `Disconnected { Exited }`, then Close → `Closed`.
#[tokio::test]
async fn remote_exit_then_close() {
    let (mgr, mut rx) = manager();
    let (transport, mut remote) = MockTransport::pair();
    let h = open_mock(&mgr, transport, None);
    wait_for(&mut rx, h.id, is_connected).await;
    remote.finish(Some(0));
    let seen = wait_for(&mut rx, h.id, |ev| {
        matches!(ev, SessionEvent::State(SessionState::Disconnected { .. }))
    })
    .await;
    assert!(seen.contains(&SessionEvent::Exit { code: 0 }));
    let Some(SessionEvent::State(SessionState::Disconnected { reason, .. })) = seen.last() else {
        unreachable!()
    };
    assert_eq!(*reason, DisconnectReason::Exited(0));
    assert!(mgr.close(h.id));
    wait_for(&mut rx, h.id, |ev| {
        *ev == SessionEvent::State(SessionState::Closed)
    })
    .await;
}

/// Reconnecting a mock session fails (its transport is used up) but stays well-formed.
#[tokio::test]
async fn reconnect_runs_the_state_machine_again() {
    let (mgr, mut rx) = manager();
    let (transport, mut remote) = MockTransport::pair();
    let h = open_mock(&mgr, transport, None);
    wait_for(&mut rx, h.id, is_connected).await;
    remote.finish(None);
    wait_for(&mut rx, h.id, |ev| {
        matches!(
            ev,
            SessionEvent::State(SessionState::Disconnected {
                reason: DisconnectReason::Closed,
                ..
            })
        )
    })
    .await;
    h.cmd_tx.send(SessionCmd::Reconnect).await.unwrap();
    let seen = wait_for(&mut rx, h.id, |ev| {
        matches!(
            ev,
            SessionEvent::State(SessionState::Disconnected {
                reason: DisconnectReason::Connect,
                ..
            })
        )
    })
    .await;
    assert_eq!(seen[0], SessionEvent::State(SessionState::Resolving));
}

/// Input and resize reach the transport and the emulator; ids are unique.
#[tokio::test]
async fn input_and_resize() {
    let (mgr, mut rx) = manager();
    let (transport, mut remote) = MockTransport::pair();
    let id = SessionId(42);
    let h = mgr
        .open_with(
            SessionSpec::Mock(MockSpec::new(transport.boxed())),
            OpenOptions {
                id: Some(id),
                ..OpenOptions::default()
            },
        )
        .unwrap();
    assert_eq!(h.id, id);
    let (t2, _r2) = MockTransport::pair();
    assert_eq!(
        mgr.open_with(
            SessionSpec::Mock(MockSpec::new(t2.boxed())),
            OpenOptions {
                id: Some(id),
                ..OpenOptions::default()
            },
        )
        .unwrap_err(),
        crate::manager::OpenError::IdInUse(id)
    );
    // Typed ahead while connecting: delivered after connecting, in order.
    h.cmd_tx
        .send(SessionCmd::Input(Bytes::from_static(b"ab")))
        .await
        .unwrap();
    h.cmd_tx
        .send(SessionCmd::Resize {
            cols: 100,
            rows: 30,
            px_w: 0,
            px_h: 0,
        })
        .await
        .unwrap();
    h.cmd_tx
        .send(SessionCmd::Input(Bytes::from_static(b"c")))
        .await
        .unwrap();
    wait_for(&mut rx, h.id, is_connected).await;
    assert_eq!(
        remote.next_op().await,
        Some(MockOp::Write(Bytes::from_static(b"ab")))
    );
    assert_eq!(
        remote.next_op().await,
        Some(MockOp::Resize {
            cols: 100,
            rows: 30
        })
    );
    assert_eq!(
        remote.next_op().await,
        Some(MockOp::Write(Bytes::from_static(b"c")))
    );
    assert_eq!(h.term.lock().size(), (100, 30));
    let registry = mgr.registry();
    assert!(registry.term(id).is_some());
    assert!(!registry.is_dirty(id));
    assert!(mgr.get(SessionId(42)).is_some());
    let other = open_mock(&mgr, MockTransport::pair().0, None);
    assert_eq!(other.id, SessionId(43));
}

mod input_encoding {
    use pretty_assertions::assert_eq;
    use sverb_term::{
        ClipboardTarget,
        modes::input::{BackspaceMode, EncodeOpts, Key, KeyInput, KeyMods},
    };

    use super::*;

    /// Feed `data` to the session's real emulator and wait until it was processed (a BEL
    /// after it comes back as `Bell`).
    async fn feed_and_sync(rx: &mut Events, id: SessionId, remote: &mut MockRemote, data: &[u8]) {
        remote.send(data).await.unwrap();
        remote.send(b"\x07").await.unwrap();
        wait_for(rx, id, |ev| *ev == SessionEvent::Bell).await;
    }

    /// The same `Up` sent to two sessions is encoded with each one's own
    /// DECCKM: `ESC [ A` vs `ESC O A`.
    #[tokio::test]
    async fn t06_per_pane_key_encoding() {
        let (mgr, mut rx) = manager();
        let (t1, mut r1) = MockTransport::pair();
        let (t2, mut r2) = MockTransport::pair();
        let a = open_mock(&mgr, t1, None);
        let b = open_mock(&mgr, t2, None);
        wait_for(&mut rx, a.id, is_connected).await;
        wait_for(&mut rx, b.id, is_connected).await;
        // Only pane b turns on application cursor keys.
        feed_and_sync(&mut rx, b.id, &mut r2, b"\x1b[?1h").await;
        let up = KeyInput::plain(Key::Up);
        a.cmd_tx.send(SessionCmd::Key(up)).await.unwrap();
        b.cmd_tx.send(SessionCmd::Key(up)).await.unwrap();
        assert_eq!(r1.read_written(3).await, b"\x1b[A");
        assert_eq!(r2.read_written(3).await, b"\x1bOA");
    }

    /// The host's `backspace = ctrl-h` reaches the encoder.
    #[tokio::test]
    async fn backspace_option() {
        let (mgr, mut rx) = manager();
        let (transport, mut remote) = MockTransport::pair();
        let h = mgr
            .open_with(
                SessionSpec::Mock(MockSpec::new(transport.boxed())),
                OpenOptions {
                    encode: EncodeOpts {
                        backspace: BackspaceMode::CtrlH,
                    },
                    ..OpenOptions::default()
                },
            )
            .unwrap();
        wait_for(&mut rx, h.id, is_connected).await;
        let bs = KeyInput::new(Key::Backspace, KeyMods::NONE);
        h.cmd_tx.send(SessionCmd::Key(bs)).await.unwrap();
        assert_eq!(remote.read_written(1).await, b"\x08");
    }

    /// Pastes: bracketed when the remote asked; a multi-line paste without it asks the UI
    /// first, and the confirmed paste is sent with `\r` line ends.
    #[tokio::test]
    async fn paste_bracketed_and_confirm() {
        let (mgr, mut rx) = manager();
        let (transport, mut remote) = MockTransport::pair();
        let h = open_mock(&mgr, transport, None);
        wait_for(&mut rx, h.id, is_connected).await;
        let paste = |text: &str, confirm_multiline| SessionCmd::Paste {
            text: text.to_owned(),
            confirm_multiline,
        };
        h.cmd_tx.send(paste("a\nb", true)).await.unwrap();
        let seen = wait_for(&mut rx, h.id, |ev| {
            matches!(ev, SessionEvent::PasteConfirm(_))
        })
        .await;
        assert_eq!(
            seen.last(),
            Some(&SessionEvent::PasteConfirm("a\nb".to_owned()))
        );
        h.cmd_tx.send(paste("a\nb", false)).await.unwrap();
        assert_eq!(remote.read_written(3).await, b"a\rb");

        feed_and_sync(&mut rx, h.id, &mut remote, b"\x1b[?2004h").await;
        h.cmd_tx.send(paste("x\x1b[201~y\n", true)).await.unwrap();
        let want = b"\x1b[200~xy\n\x1b[201~";
        assert_eq!(remote.read_written(want.len()).await, want);
    }

    /// OSC 52 writes from the remote become `ClipboardWrite` events.
    #[tokio::test]
    async fn osc52_write_is_reported() {
        let (mgr, mut rx) = manager();
        let (transport, mut remote) = MockTransport::pair();
        let h = open_mock(&mgr, transport, None);
        wait_for(&mut rx, h.id, is_connected).await;
        // "hello" in base64.
        remote.send(b"\x1b]52;c;aGVsbG8=\x07").await.unwrap();
        let seen = wait_for(&mut rx, h.id, |ev| {
            matches!(ev, SessionEvent::ClipboardWrite { .. })
        })
        .await;
        assert_eq!(
            seen.last(),
            Some(&SessionEvent::ClipboardWrite {
                target: ClipboardTarget::Clipboard,
                text: "hello".to_owned(),
            })
        );
    }
}

mod mouse_routing {
    use pretty_assertions::assert_eq;
    use sverb_term::modes::input::{KeyMods, MouseAction, MouseButton, MouseInput};

    use super::*;

    /// Mouse events: reported to the remote once it asks (SGR), otherwise back to sverb;
    /// Shift always goes to sverb.
    #[tokio::test]
    async fn mouse_is_routed_by_the_pane_modes() {
        let (mgr, mut rx) = manager();
        let (transport, mut remote) = MockTransport::pair();
        let h = open_mock(&mgr, transport, None);
        wait_for(&mut rx, h.id, is_connected).await;
        let click = MouseInput {
            action: MouseAction::Press(MouseButton::Left),
            col: 0,
            row: 0,
            mods: KeyMods::NONE,
        };
        h.cmd_tx.send(SessionCmd::Mouse(click)).await.unwrap();
        let seen = wait_for(&mut rx, h.id, |ev| matches!(ev, SessionEvent::Mouse(_))).await;
        assert_eq!(seen.last(), Some(&SessionEvent::Mouse(click)));

        remote.send(b"\x1b[?1000h\x1b[?1006h\x07").await.unwrap();
        wait_for(&mut rx, h.id, |ev| *ev == SessionEvent::Bell).await;
        h.cmd_tx.send(SessionCmd::Mouse(click)).await.unwrap();
        assert_eq!(remote.read_written(9).await, b"\x1b[<0;1;1M");
        let shifted = MouseInput {
            mods: KeyMods::SHIFT,
            ..click
        };
        h.cmd_tx.send(SessionCmd::Mouse(shifted)).await.unwrap();
        let seen = wait_for(&mut rx, h.id, |ev| matches!(ev, SessionEvent::Mouse(_))).await;
        assert_eq!(seen.last(), Some(&SessionEvent::Mouse(shifted)));
    }
}

mod recording {
    use pretty_assertions::assert_eq;
    use sverb_crypto::Key32;
    use sverb_term::recording::{
        EventKind, RecorderMeta, RecorderOptions, SyncWrite, read_recording, spawn_recorder,
    };

    use super::*;

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Buf {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.0.lock().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl SyncWrite for Buf {}

    fn key() -> Key32 {
        Key32::from_bytes([3; 32])
    }

    /// Output, resizes and (opted-in) input flow from the actor into the recording;
    /// the tap is attached while connecting and detached with `StopRecording`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn actor_feeds_the_recording_tap() {
        for include_input in [false, true] {
            let (mgr, mut rx) = manager();
            let (transport, mut remote) = MockTransport::pair();
            let (stub, fed, _) = StubEmulator::new();
            let h = open_mock(&mgr, transport, Some(Box::new(stub)));
            let buf = Buf::default();
            let mut opts = RecorderOptions::new([5; 16], key());
            opts.meta = RecorderMeta {
                include_input,
                ..RecorderMeta::default()
            };
            let (tap, rec) = spawn_recorder(buf.clone(), opts).unwrap();
            // Sent before the session is connected: deferred, then attached.
            h.cmd_tx
                .send(SessionCmd::AttachRecorder(tap))
                .await
                .unwrap();
            wait_for(&mut rx, h.id, is_connected).await;
            remote.send(b"hello from remote\r\n").await.unwrap();
            wait_fed(&fed, 19).await;
            h.cmd_tx
                .send(SessionCmd::Input(Bytes::from_static(b"secret\r")))
                .await
                .unwrap();
            h.cmd_tx
                .send(SessionCmd::Resize {
                    cols: 100,
                    rows: 30,
                    px_w: 0,
                    px_h: 0,
                })
                .await
                .unwrap();
            h.cmd_tx.send(SessionCmd::StopRecording).await.unwrap();
            // The writer finishes once the actor dropped the tap.
            let summary = tokio::time::timeout(Duration::from_secs(10), rec.join)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(summary.dropped_bytes, 0);
            // Output after stopping is not recorded.
            remote.send(b"after stop").await.unwrap();

            let file = buf.0.lock().clone();
            let rec = read_recording(&file[..], key()).unwrap();
            assert!(!rec.incomplete);
            assert_eq!((rec.header.width, rec.header.height), (80, 24));
            let kinds: Vec<(EventKind, &str)> = rec
                .events
                .iter()
                .map(|e| (e.kind, e.data.as_str()))
                .collect();
            let mut expected = vec![(EventKind::Output, "hello from remote\r\n")];
            if include_input {
                expected.push((EventKind::Input, "secret\r"));
            }
            expected.push((EventKind::Resize, "100x30"));
            assert_eq!(kinds, expected);
            mgr.close(h.id);
        }
    }
}
