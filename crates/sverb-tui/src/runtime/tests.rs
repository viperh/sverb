#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{Terminal, backend::TestBackend};
use tokio::{
    task::JoinHandle,
    time::{Instant, sleep},
};

use super::{
    EventLoop, FRAME, LoopChannels, LoopObserver, TerminalControl,
    input::{self, InputSender},
    sessions::{self, SessionNotice, SessionSender},
    signals::{self, LoopSignal, SignalSender},
};
use crate::app::{App, Config, InputEvent, LaunchIntent, SessionId, UiEvent};

/// No real terminal: records calls.
#[derive(Debug, Default)]
struct FakeControl {
    mouse: Vec<bool>,
    suspends: usize,
}

impl TerminalControl for FakeControl {
    fn set_mouse(&mut self, on: bool) -> io::Result<()> {
        self.mouse.push(on);
        Ok(())
    }

    fn suspend(&mut self) -> io::Result<()> {
        self.suspends += 1;
        Ok(())
    }
}

#[derive(Debug, Default)]
struct Record {
    /// Virtual time of each draw, relative to the test start.
    draws: Vec<Duration>,
    /// Key events applied so far.
    keys: usize,
    /// Key count at each draw.
    keys_at_draw: Vec<usize>,
    /// Virtual time each key was applied.
    key_times: Vec<Duration>,
    /// Session flag value right after each draw.
    flag_at_draw: Vec<bool>,
    /// `Resize` and `Launch` events in the order the loop applied them.
    sizing: Vec<String>,
}

#[derive(Clone)]
struct Probe {
    start: Instant,
    rec: Arc<Mutex<Record>>,
    /// Draw number (0-based) → simulated draw duration.
    stall: Option<(usize, Duration)>,
    flag: Option<Arc<AtomicBool>>,
    /// Queue a resize after every draw, so every frame tick has something to draw.
    redirty: Option<InputSender>,
}

impl Probe {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            rec: Arc::default(),
            stall: None,
            flag: None,
            redirty: None,
        }
    }

    fn rec(&self) -> std::sync::MutexGuard<'_, Record> {
        self.rec.lock().unwrap()
    }
}

impl LoopObserver for Probe {
    fn on_event(&mut self, ev: &UiEvent) {
        match ev {
            UiEvent::Input(InputEvent::Resize { cols, rows }) => {
                self.rec().sizing.push(format!("resize {cols}x{rows}"));
            }
            UiEvent::Launch(_) => self.rec().sizing.push("launch".to_owned()),
            _ => {}
        }
        if let UiEvent::Input(InputEvent::Key(_)) = ev {
            let now = self.start.elapsed();
            let mut rec = self.rec();
            rec.keys += 1;
            rec.key_times.push(now);
        }
    }

    fn on_draw(&mut self, _app: &App) {
        let now = self.start.elapsed();
        let flag = self.flag.as_ref().map(|f| f.load(Ordering::Acquire));
        let mut rec = self.rec();
        rec.draws.push(now);
        let keys = rec.keys;
        rec.keys_at_draw.push(keys);
        if let Some(flag) = flag {
            rec.flag_at_draw.push(flag);
        }
        if let Some(tx) = &self.redirty {
            let _ = tx.try_send(InputEvent::Resize { cols: 80, rows: 24 });
        }
    }

    fn simulated_draw_time(&mut self) -> Option<Duration> {
        let n = self.rec().draws.len();
        match self.stall {
            Some((at, d)) if n == at + 1 => Some(d),
            _ => None,
        }
    }
}

struct Rig {
    input: InputSender,
    sessions: SessionSender,
    signals: SignalSender,
    probe: Probe,
    event_loop: EventLoop<TestBackend, FakeControl, Probe>,
}

fn rig(app: App, probe: Probe) -> Rig {
    rig_sized(app, probe, 80, 24)
}

/// A rig whose terminal is `cols` × `rows`.
fn rig_sized(app: App, mut probe: Probe, cols: u16, rows: u16) -> Rig {
    let (input, input_rx) = input::channel();
    if probe.redirty.is_some() {
        // Placeholder replaced by the loop's real input sender.
        probe.redirty = Some(input.clone());
    }
    let (sessions, session_rx) = sessions::channel();
    let (signals, signal_rx) = signals::channel();
    let (events_tx, events) = tokio::sync::mpsc::channel(super::EVENT_CAPACITY);
    let ch = LoopChannels {
        input: input_rx,
        sessions: session_rx,
        events,
        events_tx,
        signals: signal_rx,
    };
    let terminal = Terminal::new(TestBackend::new(cols, rows)).unwrap();
    let event_loop =
        EventLoop::new(app, terminal, FakeControl::default(), ch).with_observer(probe.clone());
    Rig {
        input,
        sessions,
        signals,
        probe,
        event_loop,
    }
}

fn app() -> App {
    App::new(Arc::new(Config::default()))
}

fn key(c: char) -> InputEvent {
    InputEvent::Key(KeyEvent::from(KeyCode::Char(c)))
}

/// Send `Shutdown` at `at` (virtual time from now).
fn shutdown_at(signals: &SignalSender, at: Duration) -> JoinHandle<()> {
    let tx = signals.clone();
    tokio::spawn(async move {
        sleep(at).await;
        tx.send(LoopSignal::Shutdown).await.unwrap();
    })
}

/// A session that produces output every millisecond, following the dirty protocol.
fn flooding_session(tx: &SessionSender, id: SessionId, until: Duration) -> Arc<AtomicBool> {
    let flag = Arc::new(AtomicBool::new(false));
    tx.send(SessionNotice::Opened {
        id,
        dirty: Arc::clone(&flag),
    })
    .unwrap();
    let tx = tx.clone();
    let dirty = Arc::clone(&flag);
    let start = Instant::now();
    tokio::spawn(async move {
        while start.elapsed() < until {
            if !dirty.swap(true, Ordering::AcqRel) && tx.send(SessionNotice::Dirty(id)).is_err() {
                break;
            }
            sleep(Duration::from_millis(1)).await;
        }
    });
    flag
}

async fn run(rig: &mut Rig) -> i32 {
    rig.event_loop.run(LaunchIntent::Plain).await.unwrap()
}

#[tokio::test(start_paused = true)]
async fn idle_draws_nothing() {
    let mut rig = rig(app(), Probe::new());
    shutdown_at(&rig.signals, Duration::from_secs(10));
    assert_eq!(run(&mut rig).await, 0);
    let rec = rig.probe.rec();
    assert_eq!(rec.draws, [Duration::ZERO], "only the initial frame");
}

#[tokio::test(start_paused = true)]
async fn frame_rate_is_capped() {
    let mut a = app();
    let id = SessionId(1);
    a.focus_session(id);
    let mut rig = rig(a, Probe::new());
    flooding_session(&rig.sessions, id, Duration::from_secs(2));
    shutdown_at(&rig.signals, Duration::from_secs(1));
    run(&mut rig).await;
    let rec = rig.probe.rec();
    assert!(rec.draws.len() <= 61, "{} draws", rec.draws.len());
    assert!(rec.draws.len() >= 55, "{} draws", rec.draws.len());
}

#[tokio::test(start_paused = true)]
async fn missed_ticks_are_skipped_not_bursted() {
    let mut probe = Probe::new();
    // The 4th draw takes 100 ms.
    probe.stall = Some((3, Duration::from_millis(100)));
    // Something is dirty at every tick, so a burst of ticks would be a burst of draws.
    probe.redirty = Some(input::channel().0);
    let mut rig = rig(app(), probe);
    shutdown_at(&rig.signals, Duration::from_millis(400));
    run(&mut rig).await;
    let rec = rig.probe.rec();
    let slow = rec.draws[3];
    let next = rec.draws[4];
    assert!(next >= slow + Duration::from_millis(100), "{:?}", rec.draws);
    // Every draw sits on a frame boundary of the interval, and no two draws are
    // closer than one frame (no catch-up burst).
    let frame = FRAME.as_micros();
    for t in &rec.draws {
        let off = t.as_micros() % frame;
        assert!(off < 1_000 || frame - off < 1_000, "{t:?} off-grid");
    }
    for w in rec.draws.windows(2) {
        assert!(
            w[1] - w[0] + Duration::from_millis(1) >= FRAME,
            "{:?}",
            rec.draws
        );
    }
    let after_stall = rec
        .draws
        .iter()
        .filter(|t| **t > slow && **t <= slow + Duration::from_millis(117))
        .count();
    assert!(after_stall <= 2, "burst after the stall: {:?}", rec.draws);
}

#[tokio::test(start_paused = true)]
async fn all_queued_input_is_applied_before_the_first_draw() {
    let rig_app = app();
    let mut rig = rig(rig_app, Probe::new());
    for _ in 0..500 {
        // `x` is unbound in Normal mode: harmless.
        rig.input.try_send(key('x')).unwrap();
    }
    shutdown_at(&rig.signals, Duration::from_millis(100));
    run(&mut rig).await;
    let rec = rig.probe.rec();
    assert_eq!(rec.keys, 500);
    assert_eq!(
        rec.keys_at_draw.first(),
        Some(&500),
        "{:?}",
        rec.keys_at_draw
    );
}

#[tokio::test(start_paused = true)]
async fn output_flood_does_not_starve_input() {
    let mut a = app();
    let id = SessionId(1);
    a.focus_session(id);
    let mut rig = rig(a, Probe::new());
    flooding_session(&rig.sessions, id, Duration::from_secs(2));
    let tx = rig.input.clone();
    tokio::spawn(async move {
        sleep(Duration::from_millis(100)).await;
        tx.send(key('j')).await.unwrap();
    });
    shutdown_at(&rig.signals, Duration::from_millis(300));
    run(&mut rig).await;
    let rec = rig.probe.rec();
    assert_eq!(rec.key_times.len(), 1);
    assert!(
        rec.key_times[0] < Duration::from_millis(117),
        "{:?}",
        rec.key_times
    );
    // The flood kept frames coming (the session was being drawn).
    assert!(rec.draws.len() > 10);
}

// A draw that includes the pane acknowledges it.
#[tokio::test(start_paused = true)]
async fn draw_acknowledges_a_visible_session() {
    let mut a = app();
    let id = SessionId(1);
    a.focus_session(id);
    let flag = Arc::new(AtomicBool::new(false));
    let mut probe = Probe::new();
    probe.flag = Some(Arc::clone(&flag));
    let mut rig = rig(a, probe);
    rig.sessions
        .send(SessionNotice::Opened {
            id,
            dirty: Arc::clone(&flag),
        })
        .unwrap();
    let tx = rig.sessions.clone();
    let dirty = Arc::clone(&flag);
    tokio::spawn(async move {
        sleep(Duration::from_millis(50)).await;
        assert!(!dirty.swap(true, Ordering::AcqRel));
        tx.send(SessionNotice::Dirty(id)).unwrap();
    });
    shutdown_at(&rig.signals, Duration::from_millis(200));
    run(&mut rig).await;
    let rec = rig.probe.rec();
    // Initial frame, then one frame for the dirty session.
    assert_eq!(rec.draws.len(), 2, "{:?}", rec.draws);
    assert!(!flag.load(Ordering::Acquire));
    assert_eq!(rec.flag_at_draw, [false, false]);
}

// A draw without the pane (hidden) leaves the flag set.
#[tokio::test(start_paused = true)]
async fn draw_without_the_pane_keeps_the_flag() {
    // Focus stays on Hosts: session 1 is hidden.
    let id = SessionId(1);
    let flag = Arc::new(AtomicBool::new(false));
    let mut rig = rig(app(), Probe::new());
    rig.sessions
        .send(SessionNotice::Opened {
            id,
            dirty: Arc::clone(&flag),
        })
        .unwrap();
    let tx = rig.sessions.clone();
    let dirty = Arc::clone(&flag);
    tokio::spawn(async move {
        sleep(Duration::from_millis(50)).await;
        assert!(!dirty.swap(true, Ordering::AcqRel));
        tx.send(SessionNotice::Dirty(id)).unwrap();
    });
    // Something else needs a redraw at 80 ms.
    let input = rig.input.clone();
    tokio::spawn(async move {
        sleep(Duration::from_millis(80)).await;
        input
            .send(InputEvent::Resize {
                cols: 100,
                rows: 30,
            })
            .await
            .unwrap();
    });
    shutdown_at(&rig.signals, Duration::from_millis(200));
    run(&mut rig).await;
    let rec = rig.probe.rec();
    // The hidden session's Dirty scheduled no frame; the resize did.
    assert_eq!(rec.draws.len(), 2, "{:?}", rec.draws);
    assert!(flag.load(Ordering::Acquire));
}

#[tokio::test(start_paused = true)]
async fn timers_and_signals_reach_the_reducer() {
    let mut rig = rig(app(), Probe::new());
    // A toast schedules its expiry through the loop-owned timer service.
    rig.event_loop
        .apply(UiEvent::Launch(LaunchIntent::Join("l".into())))
        .unwrap();
    assert_eq!(rig.event_loop.app().toasts().len(), 1);
    rig.signals.send(LoopSignal::Continued).await.unwrap();
    shutdown_at(&rig.signals, Duration::from_secs(10));
    run(&mut rig).await;
    // The toast expired (5 s), so the redraw for it happened, and Continued forced one.
    assert!(rig.event_loop.app().toasts().is_empty());
    assert!(rig.probe.rec().draws.len() >= 2);
}

#[tokio::test(start_paused = true)]
async fn mouse_capture_and_suspend_are_loop_owned() {
    let mut rig = rig(app(), Probe::new());
    rig.event_loop
        .apply(UiEvent::Input(InputEvent::Key(KeyEvent::new(
            KeyCode::Char('z'),
            crossterm::event::KeyModifiers::CONTROL,
        ))))
        .unwrap();
    assert_eq!(rig.event_loop.control.suspends, usize::from(cfg!(unix)));
    assert_eq!(rig.event_loop.full_repaint, cfg!(unix));
    rig.event_loop.control.set_mouse(false).unwrap();
    assert_eq!(rig.event_loop.control.mouse, [false]);
}

// ---- The terminal size reaches the reducer (bug: remote shells wrapped at 80 columns) ----

/// The terminal never sends a resize on startup. The loop must still tell the reducer
/// the real size, before the launch event (a session opened at launch is sized from it).
#[tokio::test(start_paused = true)]
async fn initial_terminal_size_reaches_the_reducer_before_launch() {
    let mut rig = rig_sized(app(), Probe::new(), 200, 50);
    shutdown_at(&rig.signals, Duration::from_millis(100));
    run(&mut rig).await;
    assert_eq!(rig.event_loop.app.layout.size, Some((200, 50)));
    assert_eq!(
        rig.probe.rec().sizing,
        ["resize 200x50", "launch"],
        "the size is applied first, once"
    );
}

/// A session opened before any resize event is sized from the real window, not the
/// 80×24 default: what the remote pty gets (`docker ps` wrapped short of the pane).
#[tokio::test(start_paused = true)]
async fn session_opened_before_any_resize_gets_the_pane_size() {
    let mut rig = rig_sized(app(), Probe::new(), 200, 50);
    let leader = KeyEvent::new(KeyCode::Char('\\'), crossterm::event::KeyModifiers::CONTROL);
    rig.input.send(InputEvent::Key(leader)).await.unwrap();
    rig.input.send(key('t')).await.unwrap();
    shutdown_at(&rig.signals, Duration::from_millis(500));
    run(&mut rig).await;

    let app = &rig.event_loop.app;
    let tab = app.active_tab().expect("a local tab was opened");
    let rects =
        crate::views::sessions::panes::pane_rects(&tab.layout, tab.zoomed, app.shell_rects().main);
    assert_eq!(rects.len(), 1);
    let want = crate::views::sessions::panes::content_size(rects[0].1);
    assert!(
        want.0 > 150,
        "a 200-column window gives a wide pane: {want:?}"
    );
    let sent: Vec<_> = app.tabs().sent_sizes.values().copied().collect();
    assert_eq!(
        sent,
        [want],
        "the session was opened (or resized) at the pane's size"
    );
}

/// After a resume (`LoopSignal::Continued`) the loop re-reads the size: the window may
/// have been resized while sverb was suspended. Nothing is sent when it didn't change.
#[tokio::test(start_paused = true)]
async fn size_is_resynced_and_unchanged_size_sends_nothing() {
    let mut rig = rig_sized(app(), Probe::new(), 100, 30);
    assert_eq!(rig.event_loop.sync_terminal_size().unwrap(), None);
    assert_eq!(rig.event_loop.app.layout.size, Some((100, 30)));
    // Same size: no event.
    rig.event_loop.sync_terminal_size().unwrap();
    assert_eq!(rig.probe.rec().sizing, ["resize 100x30"]);
    // The window changed while suspended.
    rig.event_loop.terminal.backend_mut().resize(140, 45);
    rig.event_loop.sync_terminal_size().unwrap();
    assert_eq!(rig.event_loop.app.layout.size, Some((140, 45)));
    assert_eq!(rig.probe.rec().sizing, ["resize 100x30", "resize 140x45"]);
}

/// `tab` cycles focus through the sidebar (Normal mode). The reducer only offers the
/// sidebar when it thinks the window is wide enough (≥ 100 columns); before the startup
/// size sync it assumed 80×24, so the sidebar was drawn on a wide screen but `tab` never
/// reached it.
#[tokio::test(start_paused = true)]
async fn tab_reaches_the_sidebar_on_a_wide_terminal_without_a_resize_event() {
    use crate::views::shell::Region;
    let mut rig = rig_sized(app(), Probe::new(), 160, 48);
    let tab = InputEvent::Key(KeyEvent::from(KeyCode::Tab));
    rig.input.send(tab.clone()).await.unwrap();
    rig.input.send(tab).await.unwrap();
    shutdown_at(&rig.signals, Duration::from_millis(200));
    run(&mut rig).await;
    let app = &rig.event_loop.app;
    assert!(
        app.shell_rects().sidebar.is_some(),
        "a 160-column window shows the sidebar"
    );
    assert_eq!(app.shell().region, Region::Sidebar);
}
