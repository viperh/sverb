//! M6-03: the terminal-sharing service (feature `share`, SPEC §14).
//!
//! **Hosting** (`ShareEffect::Start`): the pane's session gets a share tap
//! (`SessionCmd::AttachShareTap`, wrapping a `sverb_sync::share::ShareFeed`), then
//! `sverb_sync::share::host::start` creates the share with this device's tokens
//! (the server it syncs with) and runs the host task. Its events become
//! `UiEvent::Share`. Approvals, control, kicks and stop go to the running
//! `HostHandle`. When the share ends the tap is detached.
//!
//! **Viewing** (`ShareEffect::Join`): the viewer pane is a session over a
//! `ViewerTransport` (opened through the session service, so it renders, focuses
//! and closes like any pane). The viewer task's frames are written into that
//! transport's read side: the snapshot (after resizing the pane's emulator to the
//! host's size and resetting it), live output, resizes, and status lines
//! ("Waiting for host approval…", "Share ended (…)"). The transport discards
//! everything the session writes (the emulator's DA/DSR replies must never reach the
//! host); keys typed in the pane arrive as `ShareEffect::Input` instead and are
//! encoded here with the **viewer emulator's** modes, then sent only while the host
//! granted control.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};

use async_trait::async_trait;
use sverb_conn::session::{OutputObserver, ShareTap};
use sverb_conn::{MockSpec, SessionCmd, SessionSpec, SharedEmulator, Transport, TransportKind};
use sverb_crypto::share::ShareLink;
use sverb_store::Store;
use sverb_sync::share::host::{self, HostConfig};
use sverb_sync::share::viewer::{self, INTEGRITY_ERROR, JoinConfig};
use sverb_sync::share::{
    FEED_CAPACITY, HostEvent, HostHandle, Screen, ScreenSource, ShareAuth, ShareFeed, ShareOptions,
    ViewerEvent, ViewerHandle, base_url_for, feed_channel,
};
use sverb_sync::{ApiClient, TokenManager};
use sverb_term::modes::input::{EncodeOpts, MouseRoute, encode_key, encode_paste, route_mouse};
use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::mpsc;
use tracing::debug;

use super::EventSender;
use super::sessions::SessionService;
use super::vault::VaultService;
use crate::app::share::{ShareEffect, ShareEvent, ShareStartOptions, ViewerInfo, ViewerStatus};
use crate::app::{SessionId, SessionInput, UiEvent};

/// Running shares and viewer panes. Cheap to clone.
#[derive(Clone, Default)]
pub struct ShareService {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Default)]
struct Inner {
    hosts: HashMap<SessionId, HostHandle>,
    viewers: HashMap<SessionId, Arc<ViewerSlot>>,
}

impl std::fmt::Debug for ShareService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.lock();
        f.debug_struct("ShareService")
            .field("hosting", &inner.hosts.len())
            .field("viewing", &inner.viewers.len())
            .finish()
    }
}

fn conn_id(id: SessionId) -> sverb_conn::SessionId {
    sverb_conn::SessionId(id.0)
}

async fn send(tx: &EventSender, ev: ShareEvent) {
    let _ = tx.send(UiEvent::Share(ev)).await;
}

fn try_send(tx: &EventSender, ev: ShareEvent) {
    let tx = tx.clone();
    tokio::spawn(async move { send(&tx, ev).await });
}

impl ShareService {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Executes a `ShareEffect`. Must be called inside a tokio runtime.
    pub fn execute(
        &self,
        op: ShareEffect,
        vault: Option<&VaultService>,
        sessions: Option<&mut SessionService>,
        tx: &EventSender,
    ) {
        let host = |session: SessionId| self.lock().hosts.get(&session).cloned();
        match op {
            ShareEffect::Start { session, options } => {
                self.start(session, options, vault, sessions, tx);
            }
            ShareEffect::Approve { session, viewer } => {
                if let Some(h) = host(session) {
                    h.approve(viewer);
                }
            }
            ShareEffect::Deny { session, viewer } => {
                if let Some(h) = host(session) {
                    h.deny(viewer);
                }
            }
            ShareEffect::SetControl {
                session,
                viewer,
                granted,
            } => {
                if let Some(h) = host(session) {
                    h.set_control(viewer, granted);
                }
            }
            ShareEffect::Kick { session, viewer } => {
                if let Some(h) = host(session) {
                    h.kick(viewer);
                }
            }
            ShareEffect::Stop { session } => {
                if let Some(h) = host(session) {
                    h.stop();
                }
            }
            ShareEffect::Join { id, link } => self.join(id, &link, vault, sessions, tx),
            ShareEffect::Input { id, input } => self.input(id, input),
        }
    }

    // ------------------------------------------------------------------ host

    fn start(
        &self,
        session: SessionId,
        options: ShareStartOptions,
        vault: Option<&VaultService>,
        sessions: Option<&mut SessionService>,
        tx: &EventSender,
    ) {
        let fail = |error: &str| {
            try_send(
                tx,
                ShareEvent::StartFailed {
                    session,
                    error: error.to_owned(),
                },
            );
        };
        let Some(sessions) = sessions else {
            return fail("no session manager");
        };
        let Some(handle) = sessions.manager().get(conn_id(session)) else {
            return fail("the pane's session is gone");
        };
        let Some(vault) = vault else {
            return fail("no vault");
        };
        let Some(unlocked) = vault.unlocked() else {
            return fail("the vault is locked");
        };
        let store = vault.store().clone();
        let lmk = unlocked.lmk().clone();
        let (feed, rx) = feed_channel(FEED_CAPACITY);
        let tap = ShareTap::new(Arc::new(Tap(feed)));
        let _ = sessions.command(session, SessionCmd::AttachShareTap(tap));
        let cmd_tx = handle.cmd_tx.clone();
        let source = Arc::new(PaneScreen {
            term: handle.term,
            cmd: handle.cmd_tx,
        });
        let opts = ShareOptions {
            mode: options.mode,
            expires_in: options.expires_in(),
            require_account: options.require_account,
            skip_approval: options.skip_approval,
        };
        let this = self.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let started = async {
                let (url, tokens) = signed_in(&store, lmk)
                    .await?
                    .ok_or_else(|| "this device is not signed in to a server".to_owned())?;
                let cfg = HostConfig {
                    base_url: url,
                    auth: ShareAuth::Tokens(Arc::new(tokens)),
                    tls: None,
                    options: opts,
                };
                host::start(cfg, source, rx)
                    .await
                    .map_err(|e| e.to_string())
            }
            .await;
            let (handle, mut events) = match started {
                Ok(x) => x,
                Err(error) => {
                    let _ = cmd_tx.try_send(SessionCmd::DetachShareTap);
                    send(&tx, ShareEvent::StartFailed { session, error }).await;
                    return;
                }
            };
            let info = handle.info().clone();
            this.lock().hosts.insert(session, handle);
            let expires = info
                .expires_at
                .with_timezone(&chrono::Local)
                .format("%H:%M")
                .to_string();
            send(
                &tx,
                ShareEvent::Started {
                    session,
                    link: info.link,
                    web_link: info.web_link,
                    expires,
                    mode: info.mode,
                },
            )
            .await;
            while let Some(ev) = events.recv().await {
                let ended = matches!(ev, HostEvent::Ended { .. });
                send(&tx, host_event(session, ev)).await;
                if ended {
                    break;
                }
            }
            this.lock().hosts.remove(&session);
            let _ = cmd_tx.try_send(SessionCmd::DetachShareTap);
        });
    }

    // ------------------------------------------------------------------ viewer

    fn join(
        &self,
        id: SessionId,
        link: &str,
        vault: Option<&VaultService>,
        sessions: Option<&mut SessionService>,
        tx: &EventSender,
    ) {
        let unavailable = |message: String| {
            try_send(
                tx,
                ShareEvent::Unavailable {
                    id: Some(id),
                    message,
                },
            );
        };
        let link = match ShareLink::parse(link) {
            Ok(l) => l,
            Err(e) => return unavailable(format!("Not a usable share link: {e}")),
        };
        let Some(sessions) = sessions else {
            return unavailable("no session manager".to_owned());
        };
        let (chunks, rx) = mpsc::unbounded_channel();
        let slot = Arc::new(ViewerSlot::default());
        let transport = ViewerTransport {
            reader: ViewerReader {
                rx,
                buf: Vec::new(),
                pos: 0,
                slot: Arc::clone(&slot),
            },
            slot: Arc::clone(&slot),
        };
        sessions.open(
            id,
            SessionSpec::Mock(MockSpec::new(Box::new(transport))),
            80,
            24,
        );
        let Some(handle) = sessions.manager().get(conn_id(id)) else {
            return unavailable("the viewer pane could not open".to_owned());
        };
        *slot.term.lock().unwrap_or_else(PoisonError::into_inner) = Some(handle.term);
        self.lock().viewers.insert(id, Arc::clone(&slot));
        let _ = chunks.send(Chunk::Bytes(status_line("Joining the shared terminal…")));

        let store = vault.map(|v| v.store().clone());
        let lmk = vault
            .and_then(VaultService::unlocked)
            .map(|u| u.lmk().clone());
        let this = self.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            // Signed in to the link's server: join with the account; else anonymously.
            let (known, token) = match (store, lmk) {
                (Some(store), Some(lmk)) => match signed_in(&store, lmk).await {
                    Ok(Some((url, tokens)))
                        if sverb_sync::share::link_server(&url)
                            .eq_ignore_ascii_case(link.server()) =>
                    {
                        let token = tokens.access().await.ok();
                        (Some(url), token)
                    }
                    Ok(Some((url, _))) => (Some(url), None),
                    _ => (None, None),
                },
                _ => (None, None),
            };
            let base_url = base_url_for(&link, known.as_deref());
            let (handle, mut events) = viewer::join(JoinConfig {
                link,
                base_url,
                name: String::new(),
                token,
                tls: None,
            });
            if slot.closed.load(Ordering::Acquire) {
                handle.close();
                return;
            }
            *slot.handle.lock().unwrap_or_else(PoisonError::into_inner) = Some(handle);
            while let Some(ev) = events.recv().await {
                let (out, status) = viewer_event(ev);
                for c in out {
                    let _ = chunks.send(c);
                }
                if let Some(status) = status {
                    let ended = matches!(status, ViewerStatus::Ended { .. });
                    send(&tx, ShareEvent::Viewer { id, status }).await;
                    if ended {
                        break;
                    }
                }
            }
            this.lock().viewers.remove(&id);
        });
    }

    /// Keys, pastes and mouse reports typed in a viewer pane: encoded with the viewer
    /// emulator's modes (they mirror the host's) and sent while control is granted
    /// (the viewer task drops them otherwise).
    fn input(&self, id: SessionId, input: SessionInput) {
        let Some(slot) = self.lock().viewers.get(&id).cloned() else {
            return;
        };
        let Some(term) = slot
            .term
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
        else {
            return;
        };
        let modes = term.lock().modes();
        let bytes = match input {
            SessionInput::Key(chord) => chord
                .to_key_input()
                .and_then(|k| encode_key(k, &modes, &EncodeOpts::default())),
            SessionInput::Paste(text) | SessionInput::PasteUnchecked(text) => {
                Some(encode_paste(&text, &modes))
            }
            SessionInput::Mouse(ev) => match route_mouse(&ev, &modes) {
                MouseRoute::Remote(b) => Some(b),
                _ => None,
            },
            SessionInput::Raw(b) => Some(b.into()),
        };
        if let Some(bytes) = bytes
            && let Some(h) = slot
                .handle
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_ref()
        {
            h.send_input(bytes.to_vec());
        }
    }
}

/// The server URL and tokens of this device, if it is signed in.
async fn signed_in(
    store: &Store,
    lmk: sverb_crypto::Key32,
) -> Result<Option<(String, TokenManager)>, String> {
    let Some(url) = store
        .get_sync_state()
        .await
        .map_err(|e| e.to_string())?
        .and_then(|s| s.server_url)
    else {
        return Ok(None);
    };
    let api =
        ApiClient::new(&url, None, sverb_sync::http::HTTP_TIMEOUT).map_err(|e| e.to_string())?;
    let tokens = TokenManager::load(store.clone(), lmk, api)
        .await
        .map_err(|e| e.to_string())?;
    Ok(Some((url, tokens)))
}

fn viewer_info(v: sverb_proto::share::ShareViewer) -> ViewerInfo {
    ViewerInfo {
        id: v.viewer_id,
        name: v.name,
        account: v.account,
        ip_hint: v.ip_hint,
        control: false,
    }
}

fn host_event(session: SessionId, ev: HostEvent) -> ShareEvent {
    match ev {
        HostEvent::ApprovalNeeded(v) => ShareEvent::ApprovalNeeded {
            session,
            viewer: viewer_info(v),
        },
        HostEvent::ViewerJoined(v) => ShareEvent::ViewerJoined {
            session,
            viewer: viewer_info(v),
        },
        HostEvent::ViewerRejected { viewer_id, .. } => ShareEvent::ViewerRejected {
            session,
            viewer: viewer_id,
        },
        HostEvent::ViewerLeft { viewer_id, reason } => ShareEvent::ViewerLeft {
            session,
            viewer: viewer_id,
            reason,
        },
        HostEvent::ControlChanged { viewer_id, granted } => ShareEvent::ControlChanged {
            session,
            viewer: viewer_id,
            granted,
        },
        HostEvent::Ended { reason } => ShareEvent::Ended { session, reason },
    }
}

/// A dim status line written into the viewer pane.
fn status_line(text: &str) -> Vec<u8> {
    format!("\x1b[0m\x1b[2m{text}\x1b[0m\r\n").into_bytes()
}

/// What a viewer event writes into the pane, and what the reducer is told.
fn viewer_event(ev: ViewerEvent) -> (Vec<Chunk>, Option<ViewerStatus>) {
    match ev {
        ViewerEvent::Joined { mode, .. } => (Vec::new(), Some(ViewerStatus::Joined { mode })),
        ViewerEvent::WaitingForApproval => (
            vec![Chunk::Bytes(status_line("Waiting for host approval…"))],
            Some(ViewerStatus::Waiting),
        ),
        ViewerEvent::Snapshot { cols, rows, vt } => {
            // A fresh emulator state, then the host's screen.
            let mut reset = sverb_conn::session::actor::MODE_RESET.to_vec();
            reset.extend_from_slice(b"\x1b[H\x1b[2J\x1b[3J");
            (
                vec![
                    Chunk::Resize(cols, rows),
                    Chunk::Bytes(reset),
                    Chunk::Bytes(vt),
                ],
                Some(ViewerStatus::Live { cols, rows }),
            )
        }
        ViewerEvent::Output(b) => (vec![Chunk::Bytes(b)], None),
        ViewerEvent::Resize { cols, rows } => (
            vec![Chunk::Resize(cols, rows)],
            Some(ViewerStatus::Resized { cols, rows }),
        ),
        ViewerEvent::ControlGranted(g) => (Vec::new(), Some(ViewerStatus::Control(g))),
        ViewerEvent::Ended { reason } => {
            let line = if reason == INTEGRITY_ERROR {
                INTEGRITY_ERROR.to_owned()
            } else {
                format!("Share ended ({reason})")
            };
            (
                vec![Chunk::Bytes(
                    format!("\r\n\x1b[0m\x1b[7m {line} \x1b[0m\r\n").into_bytes(),
                )],
                Some(ViewerStatus::Ended { reason }),
            )
        }
        ViewerEvent::Approved | ViewerEvent::Denied | ViewerEvent::HostAway => (Vec::new(), None),
    }
}

// ---------------------------------------------------------------------- host seams

/// The shared pane for the host task.
struct PaneScreen {
    term: SharedEmulator,
    cmd: mpsc::Sender<SessionCmd>,
}

impl ScreenSource for PaneScreen {
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
        if self
            .cmd
            .try_send(SessionCmd::Input(sverb_conn::Bytes::from(bytes)))
            .is_err()
        {
            debug!("viewer input dropped: session queue full");
        }
    }
}

/// The session tap of a shared pane.
struct Tap(ShareFeed);

impl OutputObserver for Tap {
    fn output(&self, bytes: &[u8]) {
        self.0.output(bytes);
    }

    fn resize(&self, cols: u16, rows: u16) {
        self.0.resize(cols, rows);
    }

    fn ended(&self) {
        self.0.ended();
    }
}

// ---------------------------------------------------------------------- viewer pane

/// What the viewer task writes into the pane.
#[derive(Debug)]
enum Chunk {
    Bytes(Vec<u8>),
    /// Resize the pane's emulator (the host's size).
    Resize(u16, u16),
}

#[derive(Default)]
struct ViewerSlot {
    /// The pane's emulator (set once the session is open).
    term: Mutex<Option<SharedEmulator>>,
    /// The viewer task (set once joining starts).
    handle: Mutex<Option<ViewerHandle>>,
    /// The pane was closed.
    closed: AtomicBool,
}

/// The read side of a viewer pane: chunks from the viewer task. Resizes are applied
/// to the pane's emulator between reads, so they stay in order with the output. It
/// never reports EOF: an ended share stays on screen until the pane is closed.
struct ViewerReader {
    rx: mpsc::UnboundedReceiver<Chunk>,
    buf: Vec<u8>,
    pos: usize,
    slot: Arc<ViewerSlot>,
}

impl AsyncRead for ViewerReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.pos < self.buf.len() {
                let n = (self.buf.len() - self.pos).min(out.remaining());
                let start = self.pos;
                out.put_slice(&self.buf[start..start + n]);
                self.pos += n;
                return Poll::Ready(Ok(()));
            }
            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(Chunk::Bytes(b))) => {
                    self.buf = b;
                    self.pos = 0;
                }
                Poll::Ready(Some(Chunk::Resize(cols, rows))) => {
                    let term = self
                        .slot
                        .term
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .clone();
                    if let Some(term) = term {
                        term.lock().resize(cols, rows);
                    }
                }
                // The viewer task is gone: stay open (no EOF), nothing more comes.
                Poll::Ready(None) | Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// A viewer pane's transport. Writes are discarded: they are the emulator's replies
/// to queries in the host's output (keys go through `ShareEffect::Input`).
struct ViewerTransport {
    reader: ViewerReader,
    slot: Arc<ViewerSlot>,
}

#[async_trait]
impl Transport for ViewerTransport {
    async fn write(&mut self, _data: &[u8]) -> io::Result<()> {
        Ok(())
    }

    async fn resize(&mut self, _cols: u16, _rows: u16) -> io::Result<()> {
        Ok(())
    }

    fn reader(&mut self) -> &mut (dyn AsyncRead + Unpin + Send) {
        &mut self.reader
    }

    async fn close(&mut self) -> io::Result<()> {
        self.slot.closed.store(true, Ordering::Release);
        if let Some(h) = self
            .slot
            .handle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            h.close();
        }
        Ok(())
    }

    fn kind(&self) -> TransportKind {
        TransportKind::Mock
    }
}

#[cfg(test)]
#[path = "share_tests.rs"]
mod tests;
