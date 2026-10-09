//! The runtime: terminal I/O and the event loop around the reducer (M0-09, SPEC §2.1).
//!
//! [`run`] is the binary's entry point. It enters TUI mode through the M0-05
//! [`TerminalGuard`], starts the input task, OS signal handlers and the config
//! watcher, and drives an [`EventLoop`] until an `Effect::Quit`.
//!
//! # Event sources, in priority order (`tokio::select! { biased; … }`)
//! 1. **input**: crossterm events from the input task, bounded ([`input`]),
//! 2. **sessions**: coalesced `Dirty` notifications, unbounded ([`sessions`]; the
//!    backpressure contract for M1-08 is documented there),
//! 3. **effect results / config / sync** (the bounded [`EventSender`] channel),
//!    **timers** ([`timers::Timers`], driven by `ScheduleTimer`/`CancelTimer`) and
//!    **signals** ([`signals`]),
//! 4. the **frame tick**: a [`FRAME`] interval with `MissedTickBehavior::Skip`.
//!
//! # Rendering
//! Drawing is dirty-driven: a frame is drawn on a tick only if
//! [`App::needs_redraw`] is set, a visible session is dirty, or a full repaint was
//! requested (resume after a stop). Before drawing, the loop drains **all** queued
//! input with `try_recv`, so a frame never shows state older than the keys already
//! typed, and output floods delay a keystroke by at most one frame. Missed ticks are
//! skipped, never bursted. There is no periodic `Tick` event.
//!
//! # Loop-owned effects
//! `Quit`, `Suspend`, `SetMouseCapture`, `ScheduleTimer` and `CancelTimer` are
//! executed here; everything else goes to [`Services`].

use std::{
    io::{self, stdout},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use ratatui::{
    Terminal,
    backend::{Backend, CrosstermBackend},
    layout::Rect,
};
// M0-07
use sverb_core::config::{ConfigWatcher, Validators};
use tokio::{sync::mpsc, time::MissedTickBehavior};
use tracing::warn;

// M0-05
use self::terminal::{TerminalGuard, TerminalSetup};
use self::{
    input::InputReceiver,
    sessions::{DirtyTracker, SessionNotice, SessionReceiver},
    signals::{LoopSignal, SignalReceiver},
    timers::Timers,
};
use crate::{
    app::{App, Config, Effect, InputEvent, LaunchIntent, UiEvent},
    keymap::Keymap,
    services::{EventSender, Services},
    // M0-11:
    theme::ThemeEnv,
};
// M1-08
use crate::services::sessions::{SessionService, to_ui_event};
// M1-04
use crate::services::vault::{VaultService, keyring_from_env};
// M1-11
use crate::services::clipboard::ClipboardService;

// M7-04: terminal capability detection shared with `sverb doctor`.
pub mod capabilities;
// M0-09
pub mod input;
pub mod sessions;
pub mod signals;
// M0-05: mode bookkeeping, `restore_terminal` (panic-safe) and the RAII guard.
pub mod terminal;
// M0-05: crash-path hooks for the binary's PTY tests; never in release builds.
#[cfg(feature = "test-hooks")]
mod test_hooks;
pub mod timers;

#[cfg(test)]
mod tests;

/// Capacity of the bounded channel for effect results, config and sync events.
pub const EVENT_CAPACITY: usize = 1024;

/// Frame budget: at most 60 draws per second (1/60 s).
pub const FRAME: Duration = Duration::from_micros(16_667);

/// How long `Quit` waits for sessions to close (M1-08's `SessionManager::shutdown`).
pub const SESSION_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

// M0-07
/// Everything the binary hands to the TUI besides the [`LaunchIntent`].
#[derive(Debug)]
pub struct LaunchCtx {
    /// The config loaded at startup (defaults if the file was rejected).
    pub config: Config,
    /// The keymap (M0-10 derives it from `config` instead).
    pub keymap: Keymap,
    /// `config.toml` to watch for hot reload; `None` disables the watcher.
    pub config_file: Option<PathBuf>,
    /// Validators for reloaded files (the same ones used at startup).
    pub validators: Validators,
    // M1-04
    /// Where the database lives. `Some`: the vault service opens the store and the UI
    /// starts locked (first run or unlock). `None`: no vault (UI tests).
    pub paths: Option<sverb_core::paths::Paths>,
}

impl LaunchCtx {
    /// A context with the built-in keymap, default validators and no hot reload.
    pub fn new(config: Config) -> Self {
        // M0-10: built-ins merged with `general.leader` and `[keys.*]`.
        let keymap = Keymap::from_config(&config);
        Self {
            config,
            keymap,
            config_file: None,
            // M0-10: the real keymap validator.
            validators: crate::keymap::validators(),
            // M1-04
            paths: None,
        }
    }
}

/// Run the UI until an `Effect::Quit`, and return its exit code.
///
/// `intent` is delivered to the reducer as the first event ([`UiEvent::Launch`]).
/// The caller must check that stdout is a terminal first (M0-07).
pub async fn run(intent: LaunchIntent, ctx: LaunchCtx) -> io::Result<i32> {
    let LaunchCtx {
        config,
        keymap,
        config_file,
        validators,
        paths,
    } = ctx;
    let config = Arc::new(config);
    // M1-04: open the store before touching the terminal, so a database error is
    // printed normally. The keyring is the OS keyring unless `SVERB_KEYRING=off`.
    let vault = match &paths {
        Some(paths) => Some(
            VaultService::open(paths, keyring_from_env())
                .await
                .map_err(io::Error::other)?,
        ),
        None => None,
    };
    // M1-10: terminal color schemes (built-ins + `themes/*.toml` next to config.toml).
    let themes_dir = config_file
        .as_deref()
        .and_then(std::path::Path::parent)
        .map(|dir| dir.join("themes"));
    let (schemes, scheme_errors) =
        crate::widgets::terminal_pane::load_schemes(themes_dir.as_deref());
    for err in &scheme_errors {
        warn!("color scheme skipped: {err}");
    }
    // M0-05: tracked modes; the guard's `Drop` (and the panic hook) restore them.
    // Bracketed paste and focus events on; mouse capture follows `ui.mouse`.
    let mut guard = TerminalGuard::enter(TerminalSetup {
        mouse: config.ui.mouse,
        bracketed_paste: true,
        focus_events: true,
    })?;
    let terminal = Terminal::new(CrosstermBackend::new(stdout()))?;
    // M0-05
    #[cfg(feature = "test-hooks")]
    if let Some(code) = test_hooks::after_start().await {
        return Ok(code);
    }
    // M1-11: the kitty keyboard protocol when the terminal supports it (`ctrl-i` ≠ `tab`),
    // popped on restore. Queried before the input reader starts, so the reply isn't keys.
    let kitty = guard.enable_kitty_keyboard();
    tracing::debug!(kitty, "kitty keyboard protocol");

    let (input_tx, input_rx) = input::channel();
    let input_task = input::spawn_terminal_input(input_tx);
    let (signal_tx, signal_rx) = signals::channel();
    let signal_tasks = signals::spawn(&signal_tx);
    // M1-08: the session manager reports on the session channel.
    let (session_tx, session_rx) = sessions::channel();
    let session_service = SessionService::new(session_tx);
    // M1-12: `terminal.term` for local shells (applies to new sessions).
    session_service.set_local_options(sverb_conn::LocalOptions {
        term: config.terminal.term.clone(),
        ..sverb_conn::LocalOptions::default()
    });
    // M1-13: SSH sessions resolve saved hosts through the vault (settings apply to new
    // connections).
    session_service.set_ssh_connector(crate::services::ssh::ssh_connector(
        vault.clone(),
        Arc::clone(&config),
    ));
    let session_manager = session_service.manager().clone();
    let (ev_tx, ev_rx) = mpsc::channel(EVENT_CAPACITY);
    // M1-15: the same connector, with the known-hosts store reporting saves ("Added host
    // key for …" toasts) on the event channel.
    session_service.set_ssh_connector(crate::services::ssh::ssh_connector_with_events(
        vault.clone(),
        Arc::clone(&config),
        Some(ev_tx.clone()),
    ));
    // M2-07: `confirm_on_use` prompts and the control socket (`sverb lock`).
    let mut agent = crate::services::agent::AgentService::start(vault.clone(), ev_tx.clone());
    if let Some(paths) = &paths
        && let Some(path) = sverb_conn::agent::control::control_path(paths)
    {
        match paths.ensure(sverb_core::paths::DirKind::Run) {
            Ok(()) => agent.listen_control(&path, ev_tx.clone()).await,
            Err(err) => warn!(%err, "no runtime directory; `sverb lock` cannot reach this TUI"),
        }
    }
    // M2-07: forwarded agent channels are served by the built-in / system agent.
    session_service.set_ssh_connector(
        crate::services::ssh::ssh_connector_with_events(
            vault.clone(),
            Arc::clone(&config),
            Some(ev_tx.clone()),
        )
        .with_agent_forwarding(agent.forwarding()),
    );
    // M0-07: hot reload; kept alive (and stopped on drop) for the whole loop.
    let watcher = config_file.and_then(|file| spawn_watcher(&file, validators, &config, &ev_tx));

    // M1-11
    let clipboard_osc52 = config.clipboard.osc52;
    // M3-06: every connection attempt becomes a ConnLog entry (written through the vault).
    let connlog = crate::services::connlog::ConnLogService::new(
        vault.clone(),
        ev_tx.clone(),
        config.logs.sync,
    );
    session_manager.set_connlog_sink(Arc::new(connlog.clone()));
    // M7-01: command history (shell integration, the heuristic tier, snippet runs).
    let history = crate::services::history::HistoryService::new(
        vault.clone(),
        ev_tx.clone(),
        crate::app::history::HistoryPolicy::from_config(&config),
    );
    // M0-11: `NO_COLOR`/`COLORTERM` for the theme, and the `--debug` ring for the log pane.
    let app = App::new(config)
        .with_keymap(keymap)
        .with_theme_env(ThemeEnv::from_process())
        // M7-07: `ui.ascii = "auto"`.
        .with_ascii_env(crate::runtime::capabilities::TermEnv::from_process().wants_ascii())
        .with_debug_ring(sverb_core::logging::debug_ring())
        // M1-10
        .with_schemes(schemes)
        // M3-04: copy mode and mouse selection read the session emulators.
        .with_terms(Arc::new(session_service.registry()));
    // M1-04: start locked; the vault service reports first run / keyring / prompt.
    let app = match &vault {
        Some(vault) => {
            vault.report_status(&ev_tx);
            app.with_vault()
        }
        None => app,
    };
    let channels = LoopChannels {
        input: input_rx,
        sessions: session_rx,
        events: ev_rx,
        events_tx: ev_tx,
        signals: signal_rx,
    };
    // M4-09: the sync engine (started on unlock), devices, the account wizard.
    #[cfg(feature = "sync")]
    let sync = vault
        .clone()
        .map(|v| crate::services::sync::SyncService::new(v, Arc::clone(app.config())));
    let mut services = Services::new()
        // M1-04
        .with_vault_opt(vault)
        .with_sessions(session_service)
        // M1-11
        .with_clipboard(ClipboardService::from_env(clipboard_osc52))
        // M3-06
        .with_connlog(connlog.clone())
        // M3-04: confirmed links open in the system browser.
        .with_url_opener(Box::new(crate::services::opener::SystemOpener))
        // M2-07
        .with_agent(agent)
        // M7-01
        .with_history(history.clone());
    #[cfg(feature = "sync")]
    if let Some(sync) = sync.clone() {
        services = services.with_sync(sync);
    }
    // M3-05: encrypted recordings in `state_dir/recordings`.
    if let Some(paths) = &paths {
        services = services.with_recordings_dir(paths.recordings_dir());
    }
    let mut event_loop =
        EventLoop::new(app, terminal, &mut guard, channels).with_services(services);
    let result = event_loop.run(intent).await;
    drop(event_loop);

    // Quit: stop reading the terminal before it is restored (joined, not just aborted),
    // stop the signal forwarders and the watcher, close sessions, flush the store.
    input::stop(input_task).await;
    for task in signal_tasks {
        task.abort();
    }
    drop(watcher);
    // M1-08: close every session; abort the ones that don't close in time.
    let report = session_manager.shutdown(SESSION_SHUTDOWN_TIMEOUT).await;
    if report.aborted > 0 {
        warn!(aborted = report.aborted, "sessions aborted on quit");
    }
    // M3-06: finalize open attempts (`ended_at` = quit time) and flush their writes.
    connlog.shutdown().await;
    // M7-01: flush history writes.
    history.shutdown().await;
    // M4-09: stop the sync engine (closes its WebSocket).
    #[cfg(feature = "sync")]
    if let Some(sync) = &sync {
        sync.stop();
    }
    // M1-03: flush the store.
    // M1-10: give the user's cursor shape back (panes pass theirs through with DECSCUSR).
    if let Err(err) = guard.set_cursor_shape(None) {
        warn!(%err, "cannot reset the cursor shape");
    }
    guard.restore();
    result
}

/// The terminal operations the loop needs besides drawing (fake in tests).
pub trait TerminalControl {
    /// Toggle mouse capture live (`Effect::SetMouseCapture`).
    fn set_mouse(&mut self, on: bool) -> io::Result<()>;

    /// Restore the terminal, stop the process, re-apply the modes once continued.
    /// `ErrorKind::Unsupported` where there is no job control.
    fn suspend(&mut self) -> io::Result<()>;

    // M1-10
    /// DECSCUSR passthrough for the focused pane: `Some((shape, blinking))`, or `None` for
    /// the user's default shape.
    fn set_cursor_shape(
        &mut self,
        _shape: Option<(sverb_term::CursorShape, bool)>,
    ) -> io::Result<()> {
        Ok(())
    }
}

impl TerminalControl for TerminalGuard {
    fn set_mouse(&mut self, on: bool) -> io::Result<()> {
        TerminalGuard::set_mouse(self, on)
    }

    fn suspend(&mut self) -> io::Result<()> {
        TerminalGuard::suspend(self)
    }

    // M1-10
    fn set_cursor_shape(
        &mut self,
        shape: Option<(sverb_term::CursorShape, bool)>,
    ) -> io::Result<()> {
        crossterm::execute!(stdout(), crate::widgets::terminal_pane::cursor_style(shape))
    }
}

impl<T: TerminalControl + ?Sized> TerminalControl for &mut T {
    fn set_mouse(&mut self, on: bool) -> io::Result<()> {
        (**self).set_mouse(on)
    }

    fn suspend(&mut self) -> io::Result<()> {
        (**self).suspend()
    }

    // M1-10
    fn set_cursor_shape(
        &mut self,
        shape: Option<(sverb_term::CursorShape, bool)>,
    ) -> io::Result<()> {
        (**self).set_cursor_shape(shape)
    }
}

/// Instrumentation hooks (loop tests, benchmarks). All methods default to no-ops.
pub trait LoopObserver {
    /// An event is about to be applied by the reducer.
    fn on_event(&mut self, _ev: &UiEvent) {}

    /// A frame was drawn.
    fn on_draw(&mut self, _app: &App) {}

    /// Test hook: pretend the frame just drawn took this long (virtual time).
    #[doc(hidden)]
    fn simulated_draw_time(&mut self) -> Option<Duration> {
        None
    }
}

impl LoopObserver for () {}

/// The receivers (and the effect-result sender) an [`EventLoop`] runs on.
#[derive(Debug)]
pub struct LoopChannels {
    /// Terminal input (bounded).
    pub input: InputReceiver,
    /// Session notifications (unbounded, coalesced).
    pub sessions: SessionReceiver,
    /// Effect results, config and sync events (bounded).
    pub events: mpsc::Receiver<UiEvent>,
    /// The sender [`Services`] report effect results on.
    pub events_tx: EventSender,
    /// OS signals.
    pub signals: SignalReceiver,
}

/// The UI event loop over any ratatui backend.
pub struct EventLoop<B: Backend, C: TerminalControl, O: LoopObserver = ()> {
    app: App,
    terminal: Terminal<B>,
    control: C,
    services: Services,
    timers: Timers,
    dirty: DirtyTracker,
    observer: O,
    ch: LoopChannels,
    /// Clear the screen and repaint everything on the next frame (resume).
    full_repaint: bool,
    // M1-10
    /// The cursor shape last sent with DECSCUSR (`None`: never sent).
    cursor_shape: Option<(sverb_term::CursorShape, bool)>,
}

impl<B, C> EventLoop<B, C, ()>
where
    B: Backend,
    B::Error: Send + Sync + 'static,
    C: TerminalControl,
{
    /// A loop with no observer.
    pub fn new(app: App, terminal: Terminal<B>, control: C, ch: LoopChannels) -> Self {
        Self {
            app,
            terminal,
            control,
            services: Services::new(),
            timers: Timers::new(),
            dirty: DirtyTracker::new(),
            observer: (),
            ch,
            full_repaint: false,
            // M1-10
            cursor_shape: None,
        }
    }

    /// Attach an observer.
    pub fn with_observer<O: LoopObserver>(self, observer: O) -> EventLoop<B, C, O> {
        EventLoop {
            app: self.app,
            terminal: self.terminal,
            control: self.control,
            services: self.services,
            timers: self.timers,
            dirty: self.dirty,
            observer,
            ch: self.ch,
            full_repaint: self.full_repaint,
            // M1-10
            cursor_shape: self.cursor_shape,
        }
    }
}

impl<B, C, O> EventLoop<B, C, O>
where
    B: Backend,
    B::Error: Send + Sync + 'static,
    C: TerminalControl,
    O: LoopObserver,
{
    /// The app (state after the loop ended, in tests).
    pub fn app(&self) -> &App {
        &self.app
    }

    /// The terminal (its backend, in tests).
    pub fn terminal(&self) -> &Terminal<B> {
        &self.terminal
    }

    /// The observer.
    pub fn observer(&self) -> &O {
        &self.observer
    }

    // M1-08
    /// Replace the effect executor (to give it a session service).
    #[must_use]
    pub fn with_services(mut self, services: Services) -> Self {
        self.services = services;
        self
    }

    /// Run until an `Effect::Quit`; returns its code. `intent` is the first event.
    pub async fn run(&mut self, intent: LaunchIntent) -> io::Result<i32> {
        // The reducer must know the real terminal size before the launch event: a session
        // opened at launch (and every one opened before the first resize event) is sized
        // from it. Terminals don't send a resize on startup, so without this the app
        // assumed 80×24 and remote shells wrapped far short of the drawn pane.
        if let Some(code) = self.sync_terminal_size()? {
            return Ok(code);
        }
        if let Some(code) = self.apply(UiEvent::Launch(intent))? {
            return Ok(code);
        }
        let mut frame = tokio::time::interval(FRAME);
        frame.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            let quit = tokio::select! {
                biased;
                Some(input) = self.ch.input.recv() => self.apply_input(input)?,
                Some(notice) = self.ch.sessions.recv() => match notice {
                    // M1-08: title, bell, state, prompts and errors go to the reducer.
                    SessionNotice::Event(id, ev) => match to_ui_event(id, ev) {
                        Some(ev) => self.apply(ev)?,
                        None => None,
                    },
                    notice => {
                        let visible = self.app.visible_sessions();
                        // M1-17: output in a hidden pane sets its tab's activity marker
                        // (one `Dirty` per hidden period: the flag stays set until shown).
                        let hidden = match &notice {
                            SessionNotice::Dirty(id) if !visible.contains(id) => Some(*id),
                            _ => None,
                        };
                        self.dirty.on_notice(notice, &visible);
                        match hidden {
                            Some(id) => self.apply(UiEvent::Session(
                                id,
                                sverb_conn::SessionEvent::Dirty,
                            ))?,
                            None => None,
                        }
                    }
                },
                Some(ev) = self.ch.events.recv() => self.apply(ev)?,
                fired = self.timers.next(), if !self.timers.is_empty() => {
                    self.apply(UiEvent::Timer(fired))?
                }
                Some(signal) = self.ch.signals.recv() => match signal {
                    LoopSignal::Shutdown => self.apply(UiEvent::ShutdownRequested)?,
                    LoopSignal::Continued => {
                        self.full_repaint = true;
                        // The window may have been resized while suspended.
                        self.sync_terminal_size()?
                    }
                },
                _ = frame.tick() => self.on_frame().await?,
            };
            if let Some(code) = quit {
                return Ok(code);
            }
        }
    }

    /// Frame tick: apply all queued input, then draw if anything is dirty.
    async fn on_frame(&mut self) -> io::Result<Option<i32>> {
        while let Ok(input) = self.ch.input.try_recv() {
            if let Some(code) = self.apply_input(input)? {
                return Ok(Some(code));
            }
        }
        if self.app.needs_redraw() || self.dirty.any_pending() || self.full_repaint {
            self.draw().await?;
        }
        Ok(None)
    }

    async fn draw(&mut self) -> io::Result<()> {
        // Acknowledge before drawing: output arriving during the draw re-arms `Dirty`.
        let visible = self.app.visible_sessions();
        self.dirty.ack_visible(&visible);
        if std::mem::take(&mut self.full_repaint) {
            // Not `Terminal::clear`: it queries the cursor position (`ESC[6n`) and
            // blocks when the terminal doesn't answer. For the fullscreen viewport,
            // `resize` clears the screen and resets the back buffer without a query.
            let size = self.terminal.size().map_err(io::Error::other)?;
            self.terminal
                .resize(Rect::new(0, 0, size.width, size.height))
                .map_err(io::Error::other)?;
        }
        let app = &self.app;
        // M1-10: session content from the registry (the emulator mutex is locked only
        // inside this synchronous draw); the focused pane's cursor shape goes out with
        // DECSCUSR when it changes.
        let registry = self.services.sessions().map(SessionService::registry);
        let mut cursor = None;
        self.terminal
            .draw(|f| match &registry {
                Some(registry) => cursor = app.render_with_panes(f, registry),
                None => app.render(f),
            })
            .map_err(io::Error::other)?;
        if let Some(c) = cursor {
            let shape = (c.shape, c.blinking);
            if self.cursor_shape != Some(shape) {
                self.cursor_shape = Some(shape);
                if let Err(err) = self.control.set_cursor_shape(Some(shape)) {
                    warn!(%err, "cannot set the cursor shape");
                }
            }
        }
        self.app.mark_drawn();
        self.observer.on_draw(&self.app);
        if let Some(stall) = self.observer.simulated_draw_time() {
            tokio::time::sleep(stall).await;
        }
        Ok(())
    }

    /// Tell the reducer the terminal's current size (as an `InputEvent::Resize`) when it
    /// differs from the size the reducer knows. Sessions are sized from it.
    fn sync_terminal_size(&mut self) -> io::Result<Option<i32>> {
        let size = self.terminal.size().map_err(io::Error::other)?;
        if size.width == 0 || size.height == 0 {
            return Ok(None);
        }
        if self.app.layout.size == Some((size.width, size.height)) {
            return Ok(None);
        }
        self.apply(UiEvent::Input(InputEvent::Resize {
            cols: size.width,
            rows: size.height,
        }))
    }

    fn apply_input(&mut self, input: InputEvent) -> io::Result<Option<i32>> {
        if matches!(input, InputEvent::Resize { .. }) {
            // The frame tick still caps the draw rate.
            self.terminal.autoresize().map_err(io::Error::other)?;
        }
        self.apply(UiEvent::Input(input))
    }

    /// Feed one event to the reducer and run its effects. `Some(code)` means quit.
    fn apply(&mut self, ev: UiEvent) -> io::Result<Option<i32>> {
        self.observer.on_event(&ev);
        let effects = self.app.handle(ev);
        // M0-11: the reducer never reads the clock; new notifications get their
        // timestamp here, right after the event that created them.
        if self.app.has_unstamped_notifications() {
            self.app.stamp_notifications(chrono::Local::now());
        }
        for effect in effects {
            match effect {
                Effect::Quit { code } => return Ok(Some(code)),
                Effect::Suspend => self.suspend()?,
                Effect::SetMouseCapture(on) => {
                    if let Err(err) = self.control.set_mouse(on) {
                        warn!(%err, on, "cannot toggle mouse capture");
                    }
                }
                Effect::ScheduleTimer { kind, after } => self.timers.schedule(kind, after),
                Effect::CancelTimer(kind) => self.timers.cancel(kind),
                other => self.services.execute(other, &self.ch.events_tx),
            }
        }
        Ok(None)
    }

    // M0-05: restore → SIGTSTP → re-enable the recorded modes on SIGCONT; then repaint.
    fn suspend(&mut self) -> io::Result<()> {
        match self.control.suspend() {
            Ok(()) => {
                self.full_repaint = true;
                Ok(())
            }
            // The reducer shows a toast on Windows; nothing else lacks job control.
            Err(err) if err.kind() == io::ErrorKind::Unsupported => {
                warn!(%err, "suspend ignored");
                Ok(())
            }
            Err(err) => Err(err),
        }
    }
}

impl<B: Backend, C: TerminalControl, O: LoopObserver> std::fmt::Debug for EventLoop<B, C, O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventLoop")
            .field("timers", &self.timers)
            .field("dirty", &self.dirty)
            .field("full_repaint", &self.full_repaint)
            .finish_non_exhaustive()
    }
}

// M0-07: start the `config.toml` watcher (SPEC §15). Its events arrive on a plain
// thread, so they are forwarded with `blocking_send`. Failing to start only loses
// hot reload, so it is logged and the UI runs without it.
fn spawn_watcher(
    file: &std::path::Path,
    validators: Validators,
    config: &Arc<Config>,
    ev_tx: &EventSender,
) -> Option<ConfigWatcher> {
    let tx = ev_tx.clone();
    let sink = move |event| {
        // The receiver is gone only while the UI shuts down.
        let _ = tx.blocking_send(UiEvent::Config(event));
    };
    match ConfigWatcher::spawn(file, validators, Arc::clone(config), sink) {
        Ok(watcher) => Some(watcher),
        Err(err) => {
            warn!(%err, "config hot reload disabled");
            None
        }
    }
}
