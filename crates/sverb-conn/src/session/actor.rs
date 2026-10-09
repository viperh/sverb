//! The session actor (SPEC §2.1): one tokio task per session.
//!
//! The actor owns the transport (after connecting), shares the emulator with the
//! renderer (`Arc<parking_lot::Mutex<Box<dyn Emulator>>>`) and the dirty flag
//! (`Arc<AtomicBool>`), receives [`SessionCmd`]s on a bounded channel and emits
//! [`SessionEvent`]s through an [`EventSink`].
//!
//! # Life cycle
//! `Resolving` → connect (the [`Connector`] for the spec's kind drives the state machine)
//! → `ChannelOpened` → the connected loop → `Disconnected` (wait for `Reconnect` or
//! `Close`) → … → `Closed`, and the task ends.
//!
//! # Connected loop
//! `select!` (biased) over the cancellation token, `cmd_rx.recv()` and the transport's
//! reader (keepalive and latency ticks are SSH's: M1-13 adds them to its transport).
//!
//! - Output is read into a buffer of [`READ_BUFFER`] bytes and fed to the emulator in
//!   chunks of at most [`LOCK_CHUNK`] bytes, **one lock per chunk**; the lock is
//!   released before anything is awaited. Replies the emulator owes the remote
//!   (`take_responses`, DA/DSR, SPEC §7.1) are written back after each chunk.
//! - After feeding, `if !dirty.swap(true)` sends `Dirty`: at most one outstanding
//!   `Dirty` until the UI clears the flag. The read loop never waits on the UI.
//! - Titles are sanitized (≤ 256 chars) and sent only when they change; at most one
//!   `Bell` is sent per read.
//! - M3-05: with a recorder attached ([`SessionCmd::AttachRecorder`]), every read is
//!   also handed to the recording tap (a `try_send` that never blocks; see
//!   `sverb_term::recording::tap`), as are resizes and, when the tap records input,
//!   the bytes written for keys, input and pastes.
//! - M6-03: with a share tap attached ([`SessionCmd::AttachShareTap`]), every chunk
//!   fed to the emulator and every resize is reported to it **while the emulator is
//!   locked** (see [`super::share_tap`]); the tap is told `ended` and detached when the
//!   connection ends.
//! - M3-06: every connection attempt is reported to the [`ConnLogSink`] (start, then
//!   end with the outcome, the session channel's byte counts and the last error).
//!
//! # Reconnect (M1-16, SPEC §6.1.2)
//! `Reconnect` while disconnected reuses the **same emulator**, so scrollback is kept.
//! Before the new connection the actor writes into the emulator (never to the remote):
//! a mode reset ([`MODE_RESET`]: soft reset, leave the alternate screen, mouse modes,
//! bracketed paste, DECCKM, keypad, …), so a remote that died inside vim doesn't leave
//! the pane in application-cursor mode, then a dim separator line
//! `── reconnected at HH:MM:SS ──` ([`reconnect_separator`]). The backoff schedule of
//! the optional auto-reconnect is [`backoff`]; the countdown runs in the UI, which
//! sends `Reconnect` when it expires.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use sverb_core::error_report::ErrorReport;
use sverb_term::TermEvent;
// M3-05
use sverb_term::recording::RecordingTap;
// M1-11
use sverb_term::modes::input::{
    EncodeOpts, MouseRoute, encode_key, encode_paste, needs_confirmation, route_mouse,
};
use tokio::{io::AsyncReadExt, sync::mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use super::{
    EventSink, SessionCmd, SessionEvent, SessionId, SessionSpec, SessionState, SharedEmulator,
    StateInput, event::sanitize_title, state::DisconnectReason,
};
use crate::transport::{ConnectCtx, ConnectError, Connector, Transport, apply_input};
// M1-13
use crate::transport::TransportFailure;
// M3-06
use crate::connlog::{Attempt, AttemptEnd, AttemptOutcome, ConnLogSink};
use sverb_core::model::UnixMillis;

/// Maximum bytes fed to the emulator per lock acquisition (SPEC §2.1).
pub const LOCK_CHUNK: usize = 64 * 1024;

/// Default size of the transport read buffer.
pub const READ_BUFFER: usize = 64 * 1024;

// M1-16: `sverb_conn::session::actor::backoff` (`session/mod.rs` is held by M1-14).
#[path = "backoff.rs"]
pub mod backoff;

// M1-16
/// Terminal modes reset before a reconnect: DECSTR soft reset, then leave the
/// alternate screen, and explicitly clear what DECSTR doesn't cover everywhere (mouse
/// tracking and encodings, focus reporting, bracketed paste, DECCKM, DECKPAM, LNM,
/// modifyOtherKeys, kitty keyboard flags, origin/insert modes, scroll region, SGR,
/// charsets, hidden cursor and its shape). The scroll region and origin mode are reset
/// inside a cursor save/restore, because both move the cursor home.
pub const MODE_RESET: &[u8] = b"\x1b[!p\x1b[?1049l\x1b[?47l\x1b[?1047l\
\x1b[?9l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1005l\x1b[?1006l\x1b[?1015l\
\x1b[?1004l\x1b[?2004l\x1b[?1l\x1b>\x1b[20l\x1b[>4m\x1b[<99u\x1b[4l\x1b[?7h\
\x1b7\x1b[?6l\x1b[r\x1b8\x1b[0m\x1b(B\x0f\x1b[?25h\x1b[0 q";

// M1-16
/// The dim separator written into the emulator before a reconnect (`verb`:
/// "reconnected", or "restarted" for a local shell), at local time `hms` (`HH:MM:SS`).
pub fn reconnect_separator(verb: &str, hms: &str) -> Vec<u8> {
    format!("\r\n\x1b[2m── {verb} at {hms} ──\x1b[0m\r\n").into_bytes()
}

/// How the connected loop ended.
enum Ended {
    /// The user closed the session (state `Closed`).
    Closed,
    /// The connection is gone (state `Disconnected`).
    Disconnected,
}

/// What a command did.
enum Flow {
    Continue,
    Closed,
    Failed(std::io::Error),
}

/// The actor's state. Built by the manager, consumed by [`Actor::run`].
pub(crate) struct Actor {
    pub(crate) id: SessionId,
    pub(crate) spec: SessionSpec,
    pub(crate) connector: Option<Arc<dyn Connector>>,
    pub(crate) term: SharedEmulator,
    pub(crate) dirty: Arc<AtomicBool>,
    pub(crate) cmd_rx: mpsc::Receiver<SessionCmd>,
    pub(crate) sink: Arc<dyn EventSink>,
    pub(crate) cancel: CancellationToken,
    pub(crate) read_buffer: usize,
    pub(crate) state: SessionState,
    pub(crate) last_title: Option<String>,
    pub(crate) deferred: Vec<SessionCmd>,
    // M1-11
    /// Key encoding options (the host's `backspace`).
    pub(crate) encode: EncodeOpts,
    // M3-05
    /// The recording tap, while recording. Kept across reconnects.
    pub(crate) recorder: Option<RecordingTap>,
    // M3-06
    /// Where connection attempts are reported.
    pub(crate) connlog: Arc<dyn ConnLogSink>,
    /// The current attempt (counters, error), between `attempt_started` and `attempt_ended`.
    pub(crate) attempt: Option<AttemptStats>,
    // M2-08
    /// Told about each connection (port forwards).
    pub(crate) forwards: Option<Arc<dyn crate::forward::ForwardHook>>,
    /// Standalone tunnel: connect without a shell channel.
    pub(crate) tunnel_only: bool,
    // M6-03
    /// The share tap, while the session is shared.
    pub(crate) share_tap: Option<super::share_tap::ShareTap>,
}

// M3-06
/// What the actor tracks for the current connection attempt.
#[derive(Debug, Default)]
pub(crate) struct AttemptStats {
    /// The shell channel opened.
    connected: bool,
    /// Session channel bytes read.
    bytes_in: u64,
    /// Session channel bytes written.
    bytes_out: u64,
    /// The last error report of this attempt.
    error: Option<ErrorReport>,
}

impl Actor {
    /// Run until `Closed`.
    pub(crate) async fn run(mut self) {
        self.emit(SessionEvent::State(self.state.clone()));
        loop {
            // M3-06: one ConnLog entry per attempt (first connect and every reconnect).
            self.begin_attempt();
            if let Some(transport) = self.connect().await {
                if let Some(stats) = &mut self.attempt {
                    stats.connected = true;
                }
                let ended = self.connected(transport).await;
                // M6-03: a share ends with the connection.
                self.end_share_tap();
                self.end_attempt();
                if let Ended::Closed = ended {
                    return;
                }
            } else {
                self.end_attempt();
            }
            if self.state.is_closed() || !self.wait_disconnected().await {
                return;
            }
        }
    }

    fn emit(&self, ev: SessionEvent) {
        self.sink.send(self.id, ev);
    }

    // M3-06
    /// Report the start of a connection attempt.
    fn begin_attempt(&mut self) {
        self.end_attempt();
        self.attempt = Some(AttemptStats::default());
        self.connlog
            .attempt_started(self.id, Attempt::from_spec(&self.spec, UnixMillis::now()));
    }

    // M3-06
    /// Report the end of the current attempt (no-op without one), from the state.
    fn end_attempt(&mut self) {
        let Some(stats) = self.attempt.take() else {
            return;
        };
        let outcome = match &self.state {
            SessionState::Disconnected { reason, .. } => AttemptOutcome::Disconnected(*reason),
            _ => AttemptOutcome::UserClosed {
                connected: stats.connected,
            },
        };
        self.connlog.attempt_ended(
            self.id,
            AttemptEnd {
                outcome,
                ended_at: UnixMillis::now(),
                bytes_in: stats.bytes_in,
                bytes_out: stats.bytes_out,
                error: stats.error,
            },
        );
    }

    // M3-06
    /// Keep `report` as the attempt's error detail.
    fn note_error(&mut self, report: &ErrorReport) {
        if let Some(stats) = &mut self.attempt {
            stats.error = Some(report.clone());
        }
    }

    // M3-06
    /// Write to the transport, counting the bytes (`bytes_out`).
    async fn write_out(
        &mut self,
        transport: &mut dyn Transport,
        bytes: &[u8],
    ) -> std::io::Result<()> {
        transport.write(bytes).await?;
        if let Some(stats) = &mut self.attempt {
            stats.bytes_out = stats.bytes_out.saturating_add(bytes.len() as u64);
        }
        Ok(())
    }

    /// Apply a state input (illegal inputs degrade to `Disconnected { Internal }`).
    fn input(&mut self, input: StateInput) -> bool {
        apply_input(
            self.id,
            &mut self.state,
            self.sink.as_ref(),
            input,
            Instant::now(),
        )
    }

    fn user_closed(&self) -> bool {
        self.cancel.is_cancelled() || self.deferred.iter().any(|c| matches!(c, SessionCmd::Close))
    }

    /// Connect through the spec's connector. `None`: not connected (state is
    /// `Disconnected` or `Closed`).
    async fn connect(&mut self) -> Option<Box<dyn Transport>> {
        let Some(connector) = self.connector.clone() else {
            let report = ErrorReport::msg(format!(
                "{:?} sessions are not available yet",
                self.spec.kind()
            ));
            // M3-06
            self.note_error(&report);
            self.emit(SessionEvent::Error(report));
            self.input(StateInput::TransportError(DisconnectReason::Connect));
            return None;
        };
        let size = self.term.lock().size();
        let result = {
            let mut ctx = ConnectCtx {
                id: self.id,
                state: &mut self.state,
                sink: self.sink.as_ref(),
                cmd_rx: &mut self.cmd_rx,
                size,
                deferred: &mut self.deferred,
                // M1-13
                owned_sink: Arc::clone(&self.sink),
                // M2-08
                forwards: self.forwards.clone(),
                tunnel_only: self.tunnel_only,
            };
            tokio::select! {
                biased;
                () = self.cancel.cancelled() => Err(ConnectError::closed()),
                r = connector.connect(&self.spec, &mut ctx) => r,
            }
        };
        match result {
            Ok(mut transport) => {
                if self.user_closed() {
                    let _ = transport.close().await;
                    self.input(StateInput::UserClose);
                    return None;
                }
                if self.input(StateInput::ChannelOpened) {
                    Some(transport)
                } else {
                    let _ = transport.close().await;
                    None
                }
            }
            Err(err) => {
                // M3-06: the attempt's error detail.
                if let Some(report) = &err.report {
                    self.note_error(report);
                }
                if self.user_closed() {
                    self.input(StateInput::UserClose);
                } else if !matches!(
                    self.state,
                    SessionState::Disconnected { .. } | SessionState::Closed
                ) {
                    if let Some(report) = err.report {
                        self.emit(SessionEvent::Error(report));
                    }
                    self.input(StateInput::TransportError(err.reason));
                }
                None
            }
        }
    }

    /// The connected loop.
    async fn connected(&mut self, mut transport: Box<dyn Transport>) -> Ended {
        // Commands that arrived while connecting (typed-ahead input, resizes, Close).
        for cmd in std::mem::take(&mut self.deferred) {
            match self.handle_cmd(transport.as_mut(), cmd).await {
                Flow::Continue => {}
                Flow::Closed => return Ended::Closed,
                Flow::Failed(err) => return self.transport_failed(&err),
            }
        }
        let mut buf = vec![0_u8; self.read_buffer.max(1)];
        loop {
            tokio::select! {
                biased;
                () = self.cancel.cancelled() => {
                    return self.close(transport.as_mut()).await;
                }
                cmd = self.cmd_rx.recv() => {
                    let Some(cmd) = cmd else {
                        // Every sender is gone: nobody can talk to this session anymore.
                        return self.close(transport.as_mut()).await;
                    };
                    match self.handle_cmd(transport.as_mut(), cmd).await {
                        Flow::Continue => {}
                        Flow::Closed => return Ended::Closed,
                        Flow::Failed(err) => return self.transport_failed(&err),
                    }
                }
                read = transport.reader().read(&mut buf) => match read {
                    Ok(0) => {
                        match transport.exit_status().await {
                            Some(code) => {
                                self.emit(SessionEvent::Exit { code });
                                self.input(StateInput::RemoteExit(code));
                            }
                            None => {
                                self.input(StateInput::TransportError(DisconnectReason::Closed));
                            }
                        }
                        return Ended::Disconnected;
                    }
                    Ok(n) => {
                        // M3-06
                        if let Some(stats) = &mut self.attempt {
                            stats.bytes_in = stats.bytes_in.saturating_add(n as u64);
                        }
                        if let Err(err) = self.feed(transport.as_mut(), &buf[..n]).await {
                            return self.transport_failed(&err);
                        }
                    }
                    Err(err) => return self.transport_failed(&err),
                },
            }
        }
    }

    fn transport_failed(&mut self, err: &std::io::Error) -> Ended {
        // M1-13: a transport may name the reason (SSH keepalive timeout → `Timeout`).
        let (reason, report) = match TransportFailure::from_io(err) {
            Some(failure) => (failure.reason, failure.report.clone()),
            None => (DisconnectReason::Connect, ErrorReport::from_error(err)),
        };
        // M3-06
        self.note_error(&report);
        self.emit(SessionEvent::Error(report));
        self.input(StateInput::TransportError(reason));
        Ended::Disconnected
    }

    async fn close(&mut self, transport: &mut dyn Transport) -> Ended {
        if let Err(err) = transport.close().await {
            debug!(session = %self.id, %err, "error while closing");
        }
        self.input(StateInput::UserClose);
        Ended::Closed
    }

    /// Feed one read to the emulator, ≤ [`LOCK_CHUNK`] bytes per lock, and write the
    /// emulator's replies back.
    async fn feed(&mut self, transport: &mut dyn Transport, data: &[u8]) -> std::io::Result<()> {
        // M3-05: never blocks (a full recorder queue drops and counts).
        if let Some(tap) = &self.recorder {
            tap.output(data);
        }
        let mut bell = false;
        for chunk in data.chunks(LOCK_CHUNK) {
            let (responses, events) = {
                let mut term = self.term.lock();
                term.feed(chunk);
                // M6-03: under the lock, so a share snapshot sees a consistent cut.
                if let Some(tap) = &self.share_tap {
                    tap.0.output(chunk);
                }
                (term.take_responses(), term.take_events())
            };
            for response in responses {
                // M3-06: counted (`bytes_out`).
                self.write_out(transport, &response).await?;
            }
            for event in events {
                match event {
                    TermEvent::Title(title) => {
                        let title = sanitize_title(title.as_deref().unwrap_or(""));
                        if self.last_title.as_deref() != Some(title.as_str()) {
                            self.last_title = Some(title.clone());
                            self.emit(SessionEvent::Title(title));
                        }
                    }
                    TermEvent::Bell => bell = true,
                    // M1-11: the UI applies `clipboard.allow_remote_write`.
                    TermEvent::ClipboardWriteRequest { target, text } => {
                        self.emit(SessionEvent::ClipboardWrite { target, text });
                    }
                    // M7-01: commands captured by shell integration (history).
                    TermEvent::Command(command) => self.emit(SessionEvent::Command(command)),
                    // Prompt marks are consumed by the emulator's tracker; cwd: not routed yet.
                    _ => trace!(session = %self.id, "terminal event not routed"),
                }
            }
        }
        if bell {
            self.emit(SessionEvent::Bell);
        }
        if !self.dirty.swap(true, Ordering::AcqRel) {
            self.emit(SessionEvent::Dirty);
        }
        Ok(())
    }

    // M3-05
    /// Record input sent to the remote (only when the tap records input).
    fn record_input(&self, bytes: &[u8]) {
        if let Some(tap) = &self.recorder
            && tap.include_input()
        {
            tap.input(bytes);
        }
    }

    // M3-05
    /// Attach (replacing any previous recorder) or detach the recording tap.
    fn set_recorder(&mut self, tap: Option<RecordingTap>) {
        if let Some(tap) = &tap {
            let (cols, rows) = self.term.lock().size();
            tap.resize(cols, rows);
        }
        debug!(session = %self.id, recording = tap.is_some(), "recorder changed");
        self.recorder = tap;
    }

    // M6-03
    /// Attach (reporting the current size, under the emulator lock) or detach the share
    /// tap. A replaced tap is told `ended`.
    fn set_share_tap(&mut self, tap: Option<super::share_tap::ShareTap>) {
        if let Some(old) = self.share_tap.take()
            && tap.is_some()
        {
            old.0.ended();
        }
        if let Some(tap) = &tap {
            let term = self.term.lock();
            let (cols, rows) = term.size();
            tap.0.resize(cols, rows);
        }
        debug!(session = %self.id, shared = tap.is_some(), "share tap changed");
        self.share_tap = tap;
    }

    // M6-03
    /// The connection ended: tell the share tap and detach it.
    fn end_share_tap(&mut self) {
        if let Some(tap) = self.share_tap.take() {
            tap.0.ended();
        }
    }

    async fn handle_cmd(&mut self, transport: &mut dyn Transport, cmd: SessionCmd) -> Flow {
        match cmd {
            SessionCmd::Input(bytes) => {
                self.record_input(&bytes);
                if let Err(err) = self.write_out(transport, &bytes).await {
                    return Flow::Failed(err);
                }
            }
            SessionCmd::Resize {
                cols,
                rows,
                px_w,
                px_h,
            } => {
                {
                    let mut term = self.term.lock();
                    term.resize(cols, rows);
                    if cols > 0 && rows > 0 && px_w > 0 && px_h > 0 {
                        term.set_pixel_size(px_w / cols, px_h / rows);
                    }
                    // M6-03
                    if let Some(tap) = &self.share_tap {
                        let (c, r) = term.size();
                        tap.0.resize(c, r);
                    }
                }
                // M3-05
                if let Some(tap) = &self.recorder {
                    tap.resize(cols, rows);
                }
                if let Err(err) = transport.resize(cols, rows).await {
                    warn!(session = %self.id, %err, "resize failed");
                }
            }
            SessionCmd::Close => {
                self.close(transport).await;
                return Flow::Closed;
            }
            // M3-05
            SessionCmd::StartRecording => {
                debug!(session = %self.id, "StartRecording without a tap ignored (use AttachRecorder)");
            }
            SessionCmd::StopRecording => self.set_recorder(None),
            SessionCmd::AttachRecorder(tap) => self.set_recorder(Some(tap)),
            // M6-03
            SessionCmd::AttachShareTap(tap) => self.set_share_tap(Some(tap)),
            SessionCmd::DetachShareTap => self.set_share_tap(None),
            SessionCmd::HostKeyDecision(_) | SessionCmd::AuthAnswer(_) => {
                debug!(session = %self.id, "prompt answer ignored: not connecting");
            }
            SessionCmd::Reconnect => {
                debug!(session = %self.id, "reconnect ignored: connected");
            }
            // M1-11: encoded here, with this pane's modes (per-pane for broadcast, §9.8).
            SessionCmd::Key(key) => {
                let modes = self.term.lock().modes();
                match encode_key(key, &modes, &self.encode) {
                    Some(bytes) => {
                        self.record_input(&bytes);
                        if let Err(err) = self.write_out(transport, &bytes).await {
                            return Flow::Failed(err);
                        }
                    }
                    None => trace!(session = %self.id, "key has no encoding"),
                }
            }
            SessionCmd::Paste {
                text,
                confirm_multiline,
            } => {
                let modes = self.term.lock().modes();
                if needs_confirmation(&text, &modes, confirm_multiline) {
                    self.emit(SessionEvent::PasteConfirm(text));
                } else {
                    let bytes = encode_paste(&text, &modes);
                    self.record_input(&bytes);
                    if let Err(err) = self.write_out(transport, &bytes).await {
                        return Flow::Failed(err);
                    }
                }
            }
            SessionCmd::Mouse(ev) => {
                let route = route_mouse(&ev, &self.term.lock().modes());
                match route {
                    MouseRoute::Remote(bytes) => {
                        if let Err(err) = self.write_out(transport, &bytes).await {
                            return Flow::Failed(err);
                        }
                    }
                    MouseRoute::Sverb => self.emit(SessionEvent::Mouse(ev)),
                    MouseRoute::Drop => {}
                }
            }
        }
        Flow::Continue
    }

    // M1-16
    /// Reset the modes the old remote left on and write the separator line, into the
    /// emulator only. Replies the emulator might owe are dropped (they were not asked
    /// for by the next remote).
    fn mark_reconnect(&mut self) {
        let verb = match self.spec.kind() {
            crate::transport::TransportKind::Local => "restarted",
            _ => "reconnected",
        };
        let hms = chrono::Local::now().format("%H:%M:%S").to_string();
        {
            let mut term = self.term.lock();
            term.feed(MODE_RESET);
            term.feed(&reconnect_separator(verb, &hms));
            drop(term.take_responses());
            drop(term.take_events());
        }
        if !self.dirty.swap(true, Ordering::AcqRel) {
            self.emit(SessionEvent::Dirty);
        }
    }

    /// Disconnected: wait for `Reconnect` (→ `true`, state `Resolving`) or `Close`
    /// (→ `false`, state `Closed`).
    async fn wait_disconnected(&mut self) -> bool {
        self.deferred.clear();
        loop {
            let cmd = tokio::select! {
                biased;
                () = self.cancel.cancelled() => None,
                cmd = self.cmd_rx.recv() => cmd,
            };
            match cmd {
                None | Some(SessionCmd::Close) => {
                    self.input(StateInput::UserClose);
                    return false;
                }
                Some(SessionCmd::Reconnect) => {
                    if self.input(StateInput::ReconnectRequested) {
                        // M1-16: same emulator (scrollback kept), modes reset, separator.
                        self.mark_reconnect();
                        return true;
                    }
                }
                Some(SessionCmd::Resize { cols, rows, .. }) => {
                    self.term.lock().resize(cols, rows);
                    // M3-05
                    if let Some(tap) = &self.recorder {
                        tap.resize(cols, rows);
                    }
                }
                // M3-05: recording can be toggled while disconnected.
                Some(SessionCmd::AttachRecorder(tap)) => self.set_recorder(Some(tap)),
                Some(SessionCmd::StopRecording) => self.set_recorder(None),
                // M6-03: a disconnected session can't be shared.
                Some(SessionCmd::AttachShareTap(tap)) => tap.0.ended(),
                Some(other) => {
                    debug!(session = %self.id, cmd = other.name(), "command ignored while disconnected");
                }
            }
        }
    }
}
