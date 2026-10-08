//! The per-replica relay: one [`Relay`] per live share with its host and
//! viewer sockets (SPEC §14.1 steps 4–6, §14.2 relay framing, §14.3; task
//! M6-01).
//!
//! ```text
//!   host socket ──reader──► Relay::host_frame ──try_send──► viewer queue ──writer──► viewer socket
//!   viewer socket ──reader── stamp viewer_id ──send().await──► host queue ──writer──► host socket
//! ```
//!
//! Every socket has a reader (the connection task) and a writer task that
//! drains a bounded queue into the socket, plus a kill switch that makes
//! both stop and closes the socket with a code. Host → viewer uses
//! `try_send`: a viewer whose queue ([`VIEWER_QUEUE`]) is full is
//! disconnected with `4408` and never slows the host down. Viewer → host
//! awaits queue space, so a slow host only slows viewer input.
//!
//! The relay never parses payloads; it reads the 4-byte routing header and
//! logs ids and lengths only.
//!
//! Sessions are written against a [`RelayFrame`] stream and sink (not
//! axum's socket) so tests can also drive them over in-memory channels with
//! paused time (auth window, heartbeat, host grace, expiry).

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use chrono::{DateTime, Utc};
use futures::{Sink, SinkExt, Stream, StreamExt};
use sverb_proto::share::{
    CLOSE_AUTH_REQUIRED, CLOSE_FORBIDDEN, CLOSE_KICKED, CLOSE_NOT_FOUND, CLOSE_REPLACED,
    CLOSE_SHARE_ENDED, CLOSE_SHARE_FULL, CLOSE_SLOW_CONSUMER, HostClientMsg, HostServerMsg,
    LeaveReason, RelayEnvelope, ShareViewer, VIEWER_QUEUE, ViewerClientMsg, ViewerServerMsg,
};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, Interval, MissedTickBehavior};
use uuid::Uuid;

use super::sessions::ShareRow;
use super::{ShareTiming, authenticate, clean_name};
use crate::error::ApiError;
use crate::metrics::{SHARE_BYTES_RELAYED_TOTAL, SHARE_RELAYS_ACTIVE, SHARE_VIEWERS_ACTIVE};
use crate::state::AppState;

/// Messages queued towards the host before it counts as slow (it receives
/// every viewer's input plus control messages).
pub const HOST_QUEUE: usize = 1024;

/// Upper bound for sending a close frame to a peer that may not read.
const CLOSE_SEND_TIMEOUT: Duration = Duration::from_secs(2);

/// Normal closure.
const CLOSE_NORMAL: u16 = 1000;
/// Server error.
const CLOSE_INTERNAL: u16 = 1011;

/// A WebSocket message as the relay sees it.
#[derive(Clone, PartialEq, Eq)]
pub enum RelayFrame {
    /// JSON control message.
    Text(String),
    /// A [`RelayEnvelope`] in wire form.
    Binary(Vec<u8>),
    /// A close frame.
    Close {
        /// Close code.
        code: u16,
        /// Reason.
        reason: String,
    },
    /// Transport-level ping/pong (ignored).
    Other,
}

impl std::fmt::Debug for RelayFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Text frames can carry tokens; binary frames terminal data.
            Self::Text(t) => write!(f, "Text({} bytes)", t.len()),
            Self::Binary(b) => write!(f, "Binary({} bytes)", b.len()),
            Self::Close { code, reason } => write!(f, "Close({code}, {reason:?})"),
            Self::Other => f.write_str("Other"),
        }
    }
}

fn text<T: serde::Serialize>(msg: &T) -> RelayFrame {
    RelayFrame::Text(serde_json::to_string(msg).unwrap_or_default())
}

// ---------------------------------------------------------------- outbox

type KillReason = Option<(u16, String)>;

/// The sending side of one socket: its queue and kill switch.
#[derive(Debug, Clone)]
struct Outbox {
    tx: mpsc::Sender<RelayFrame>,
    kill: Arc<watch::Sender<KillReason>>,
}

impl Outbox {
    /// Closes the socket with `code` (the first reason wins).
    fn kill(&self, code: u16, reason: &str) {
        self.kill.send_if_modified(|k| {
            if k.is_none() {
                *k = Some((code, reason.to_owned()));
                true
            } else {
                false
            }
        });
    }

    fn try_send(&self, frame: RelayFrame) -> Result<(), mpsc::error::TrySendError<RelayFrame>> {
        self.tx.try_send(frame)
    }
}

fn outbox(
    capacity: usize,
) -> (
    Outbox,
    mpsc::Receiver<RelayFrame>,
    watch::Receiver<KillReason>,
) {
    let (tx, rx) = mpsc::channel(capacity);
    let (kill, kill_rx) = watch::channel(None);
    (
        Outbox {
            tx,
            kill: Arc::new(kill),
        },
        rx,
        kill_rx,
    )
}

/// Drains the queue into the socket until killed; then sends the close
/// frame (bounded by [`CLOSE_SEND_TIMEOUT`], the peer may not be reading).
async fn write_loop<O>(
    mut out: O,
    mut rx: mpsc::Receiver<RelayFrame>,
    mut kill: watch::Receiver<KillReason>,
) where
    O: Sink<RelayFrame> + Unpin + Send,
{
    loop {
        if kill.borrow_and_update().is_some() {
            break;
        }
        let frame = tokio::select! {
            biased;
            r = kill.changed() => {
                if r.is_err() {
                    break;
                }
                continue;
            }
            f = rx.recv() => match f {
                Some(f) => f,
                None => break,
            },
        };
        tokio::select! {
            biased;
            _ = kill.changed() => break,
            r = out.send(frame) => if r.is_err() {
                return;
            },
        }
    }
    let reason = kill.borrow().clone();
    if let Some((code, reason)) = reason {
        let _ = tokio::time::timeout(CLOSE_SEND_TIMEOUT, async {
            let _ = out.send(RelayFrame::Close { code, reason }).await;
            let _ = out.close().await;
        })
        .await;
    }
}

/// Sends a close frame before the writer exists (auth failures).
async fn close_now<O>(out: &mut O, code: u16, reason: &str)
where
    O: Sink<RelayFrame> + Unpin,
{
    let _ = tokio::time::timeout(CLOSE_SEND_TIMEOUT, async {
        let _ = out
            .send(RelayFrame::Close {
                code,
                reason: reason.to_owned(),
            })
            .await;
        let _ = out.close().await;
    })
    .await;
}

/// Waits for the first text message (skipping transport frames).
async fn first_text<I>(incoming: &mut I) -> Option<String>
where
    I: Stream<Item = RelayFrame> + Unpin,
{
    loop {
        match incoming.next().await? {
            RelayFrame::Text(t) => return Some(t),
            RelayFrame::Close { .. } | RelayFrame::Binary(_) => return None,
            RelayFrame::Other => {}
        }
    }
}

// ------------------------------------------------------------- heartbeat

/// `ping` every interval; the peer times out after `max` unanswered ones.
struct Heartbeat {
    ticker: Interval,
    awaiting: bool,
    missed: u32,
    max: u32,
}

impl Heartbeat {
    fn new(t: &ShareTiming) -> Self {
        let mut ticker =
            tokio::time::interval_at(Instant::now() + t.ping_interval, t.ping_interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        Self {
            ticker,
            awaiting: false,
            missed: 0,
            max: t.max_missed_pongs,
        }
    }

    async fn tick(&mut self) {
        self.ticker.tick().await;
    }

    /// After a tick: `false` when the peer timed out, else a ping is due.
    fn on_tick(&mut self) -> bool {
        if self.awaiting {
            self.missed += 1;
            if self.missed >= self.max {
                return false;
            }
        }
        self.awaiting = true;
        true
    }

    fn on_pong(&mut self) {
        self.awaiting = false;
        self.missed = 0;
    }
}

// ----------------------------------------------------------------- relay

struct HostSlot {
    conn: u64,
    out: Outbox,
}

struct ViewerSlot {
    out: Outbox,
    info: ShareViewer,
}

#[derive(Default)]
struct Inner {
    ended: bool,
    host: Option<HostSlot>,
    next_conn: u64,
    viewers: BTreeMap<u32, ViewerSlot>,
    next_viewer: u32,
    expiry_task: Option<JoinHandle<()>>,
    grace_task: Option<JoinHandle<()>>,
}

/// One live share on this replica.
pub struct Relay {
    share: ShareRow,
    timing: ShareTiming,
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for Relay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.lock();
        f.debug_struct("Relay")
            .field("share_id", &self.share.id)
            .field("host", &inner.host.is_some())
            .field("viewers", &inner.viewers.len())
            .field("ended", &inner.ended)
            .finish()
    }
}

impl Relay {
    fn new(share: ShareRow, timing: ShareTiming) -> Self {
        Self {
            share,
            timing,
            inner: Mutex::new(Inner {
                next_viewer: 1,
                ..Inner::default()
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The share row this relay was opened with.
    #[must_use]
    pub const fn share(&self) -> &ShareRow {
        &self.share
    }

    /// Connected viewers.
    #[must_use]
    pub fn viewer_count(&self) -> usize {
        self.lock().viewers.len()
    }

    /// A host connection is live.
    #[must_use]
    pub fn has_host(&self) -> bool {
        self.lock().host.is_some()
    }

    /// Schedules the expiry and the initial host grace (nobody hosts yet).
    fn start(self: &Arc<Self>, state: &AppState) {
        let left = (self.share.expires_at - state.auth().now())
            .to_std()
            .unwrap_or_default();
        let st = state.clone();
        let id = self.share.id;
        let expiry = tokio::spawn(async move {
            tokio::time::sleep(left).await;
            // Detached, so aborting this task can't interrupt the ending.
            tokio::spawn(async move { end_share(&st, id, "expired").await });
        });
        let mut inner = self.lock();
        inner.expiry_task = Some(expiry);
        self.start_grace(&mut inner, state);
    }

    /// Ends the share unless a host (re)connects within the grace period.
    fn start_grace(self: &Arc<Self>, inner: &mut Inner, state: &AppState) {
        if let Some(h) = inner.grace_task.take() {
            h.abort();
        }
        let weak: Weak<Self> = Arc::downgrade(self);
        let st = state.clone();
        let id = self.share.id;
        let grace = self.timing.host_grace;
        inner.grace_task = Some(tokio::spawn(async move {
            tokio::time::sleep(grace).await;
            if weak.upgrade().is_some_and(|r| r.has_host()) {
                return;
            }
            tokio::spawn(async move { end_share(&st, id, "host disconnected").await });
        }));
    }

    /// Sends a control message to the host; a full host queue disconnects
    /// the host (`4408`, it reconnects and gets the viewer list again).
    fn to_host_locked(inner: &Inner, msg: &HostServerMsg) {
        if let Some(h) = &inner.host
            && let Err(mpsc::error::TrySendError::Full(_)) = h.out.try_send(text(msg))
        {
            h.out.kill(CLOSE_SLOW_CONSUMER, "host too slow");
        }
    }

    fn remove_viewer_locked(inner: &mut Inner, viewer_id: u32, reason: LeaveReason) -> bool {
        let Some(slot) = inner.viewers.remove(&viewer_id) else {
            return false;
        };
        let (code, why) = match reason {
            LeaveReason::Left => (CLOSE_NORMAL, "bye"),
            LeaveReason::Kicked => (CLOSE_KICKED, "kicked by host"),
            LeaveReason::Slow => (CLOSE_SLOW_CONSUMER, "too slow"),
        };
        slot.out.kill(code, why);
        metrics::gauge!(SHARE_VIEWERS_ACTIVE).decrement(1.0);
        Self::to_host_locked(inner, &HostServerMsg::ViewerLeft { viewer_id, reason });
        true
    }

    /// Disconnects a viewer (kick, slow, or it left); the host gets
    /// `viewer_left`. `false` if it was already gone.
    pub fn remove_viewer(&self, viewer_id: u32, reason: LeaveReason) -> bool {
        let removed = Self::remove_viewer_locked(&mut self.lock(), viewer_id, reason);
        if removed {
            tracing::debug!(share_id = %self.share.id, viewer_id, ?reason, "share viewer left");
        }
        removed
    }

    /// Routes one host message (wire envelope) to its viewer.
    fn host_frame(&self, bytes: Vec<u8>) {
        let Ok(viewer_id) = RelayEnvelope::peek_viewer_id(&bytes) else {
            return;
        };
        let len = bytes.len();
        let mut inner = self.lock();
        let Some(slot) = inner.viewers.get(&viewer_id) else {
            // Control id 0, or a viewer that just left: dropped.
            return;
        };
        match slot.out.try_send(RelayFrame::Binary(bytes)) {
            Ok(()) => {
                metrics::counter!(SHARE_BYTES_RELAYED_TOTAL).increment(len as u64);
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                Self::remove_viewer_locked(&mut inner, viewer_id, LeaveReason::Slow);
                drop(inner);
                tracing::info!(share_id = %self.share.id, viewer_id, "share viewer too slow; disconnected");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
    }

    /// The host's queue, for viewer → host traffic.
    fn host_tx(&self) -> Option<mpsc::Sender<RelayFrame>> {
        self.lock().host.as_ref().map(|h| h.out.tx.clone())
    }

    /// Installs a host connection (replacing any previous one); `None` if
    /// the share ended.
    fn attach_host(&self, out: &Outbox) -> Option<u64> {
        let mut inner = self.lock();
        if inner.ended {
            return None;
        }
        inner.next_conn += 1;
        let conn = inner.next_conn;
        if let Some(old) = inner.host.replace(HostSlot {
            conn,
            out: out.clone(),
        }) {
            old.out
                .kill(CLOSE_REPLACED, "replaced by a new host connection");
        }
        if let Some(h) = inner.grace_task.take() {
            h.abort();
        }
        let _ = out.try_send(text(&HostServerMsg::Ready {
            share_id: self.share.id,
            mode: self.share.mode,
            expires_at: self.share.expires_at,
        }));
        let mut slow = Vec::new();
        for (id, v) in &inner.viewers {
            let _ = out.try_send(text(&HostServerMsg::ViewerJoined(v.info.clone())));
            if let Err(mpsc::error::TrySendError::Full(_)) =
                v.out.try_send(text(&ViewerServerMsg::HostConnected))
            {
                slow.push(*id);
            }
        }
        for id in slow {
            Self::remove_viewer_locked(&mut inner, id, LeaveReason::Slow);
        }
        Some(conn)
    }

    /// The host connection `conn` ended; starts the grace period if it was
    /// the current one.
    fn detach_host(self: &Arc<Self>, state: &AppState, conn: u64) {
        let mut inner = self.lock();
        if inner.host.as_ref().map(|h| h.conn) != Some(conn) {
            return;
        }
        inner.host = None;
        if inner.ended {
            return;
        }
        let mut slow = Vec::new();
        for (id, v) in &inner.viewers {
            if let Err(mpsc::error::TrySendError::Full(_)) =
                v.out.try_send(text(&ViewerServerMsg::HostDisconnected))
            {
                slow.push(*id);
            }
        }
        for id in slow {
            Self::remove_viewer_locked(&mut inner, id, LeaveReason::Slow);
        }
        self.start_grace(&mut inner, state);
    }

    /// Admits a viewer: assigns its id, queues `joined` and tells the host.
    fn attach_viewer(
        &self,
        mut info: ShareViewer,
        out: &Outbox,
    ) -> Result<ShareViewer, (u16, &'static str)> {
        let mut inner = self.lock();
        if inner.ended {
            return Err((CLOSE_SHARE_ENDED, "share ended"));
        }
        if inner.viewers.len() >= self.share.max_viewers as usize {
            return Err((CLOSE_SHARE_FULL, "share is full"));
        }
        let id = inner.next_viewer;
        inner.next_viewer = id
            .checked_add(1)
            .ok_or((CLOSE_SHARE_FULL, "share is full"))?;
        info.viewer_id = id;
        let _ = out.try_send(text(&ViewerServerMsg::Joined {
            viewer_id: id,
            mode: self.share.mode,
        }));
        if inner.host.is_some() {
            let _ = out.try_send(text(&ViewerServerMsg::HostConnected));
        }
        inner.viewers.insert(
            id,
            ViewerSlot {
                out: out.clone(),
                info: info.clone(),
            },
        );
        metrics::gauge!(SHARE_VIEWERS_ACTIVE).increment(1.0);
        Self::to_host_locked(&inner, &HostServerMsg::ViewerJoined(info.clone()));
        Ok(info)
    }

    /// Closes every socket with `code` and stops the timers.
    fn shutdown(&self, code: u16, reason: &str) {
        let mut inner = self.lock();
        inner.ended = true;
        if let Some(h) = inner.host.take() {
            h.out.kill(code, reason);
        }
        let n = inner.viewers.len();
        for (_, v) in std::mem::take(&mut inner.viewers) {
            v.out.kill(code, reason);
        }
        metrics::gauge!(SHARE_VIEWERS_ACTIVE).decrement(n as f64);
        for h in [inner.expiry_task.take(), inner.grace_task.take()]
            .into_iter()
            .flatten()
        {
            h.abort();
        }
    }
}

// ---------------------------------------------------------------- relays

/// Why a share can't be relayed.
#[derive(Debug)]
pub enum OpenError {
    /// No such share.
    NotFound,
    /// Closed or expired.
    Ended {
        /// Its owner.
        owner: Uuid,
    },
    /// Database error.
    Internal(ApiError),
}

/// The live relays of this replica, by share id.
#[derive(Debug, Default)]
pub struct Relays {
    map: Mutex<HashMap<Uuid, Arc<Relay>>>,
}

impl Relays {
    fn lock(&self) -> MutexGuard<'_, HashMap<Uuid, Arc<Relay>>> {
        self.map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The live relay of a share on this replica.
    #[must_use]
    pub fn get(&self, share_id: Uuid) -> Option<Arc<Relay>> {
        self.lock().get(&share_id).cloned()
    }

    /// Live relays on this replica.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// No live relay on this replica.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// The relay of a live share, created (with its expiry and host-grace
    /// timers) on first use.
    ///
    /// # Errors
    /// [`OpenError`].
    pub async fn open(&self, state: &AppState, share_id: Uuid) -> Result<Arc<Relay>, OpenError> {
        if let Some(r) = self.get(share_id) {
            return Ok(r);
        }
        let row = state
            .shares()
            .store()
            .get(share_id)
            .await
            .map_err(OpenError::Internal)?
            .ok_or(OpenError::NotFound)?;
        if !row.is_live(state.auth().now()) {
            return Err(OpenError::Ended {
                owner: row.owner_user_id,
            });
        }
        let mut map = self.lock();
        if let Some(r) = map.get(&share_id) {
            return Ok(r.clone());
        }
        let relay = Arc::new(Relay::new(row, state.shares().timing()));
        relay.start(state);
        map.insert(share_id, relay.clone());
        metrics::gauge!(SHARE_RELAYS_ACTIVE).increment(1.0);
        Ok(relay)
    }

    fn remove(&self, share_id: Uuid) -> Option<Arc<Relay>> {
        let r = self.lock().remove(&share_id);
        if r.is_some() {
            metrics::gauge!(SHARE_RELAYS_ACTIVE).decrement(1.0);
        }
        r
    }
}

/// Ends a share (§14.3): sets `closed_at` (idempotent), then closes every
/// socket of its relay on this replica with `4410`. Returns the effective
/// `closed_at` (`None` for an unknown share).
///
/// # Errors
/// Database errors (the relay is shut down regardless).
pub async fn end_share(
    state: &AppState,
    share_id: Uuid,
    reason: &str,
) -> Result<Option<DateTime<Utc>>, ApiError> {
    let shares = state.shares();
    // Mark it closed first: a connection racing this then either joins the
    // relay we are about to shut down, or reads the closed row.
    let closed = shares.store().close(share_id, state.auth().now()).await;
    if let Err(e) = &closed {
        tracing::warn!(%share_id, error = %e, "share: setting closed_at failed");
    }
    if let Some(relay) = shares.relays().remove(share_id) {
        relay.shutdown(CLOSE_SHARE_ENDED, reason);
        tracing::info!(%share_id, reason, "share ended");
    }
    closed
}

// ----------------------------------------------------------- connections

/// Runs one host connection (`/v1/shares/{id}/host`) to completion.
pub async fn run_host<I, O>(state: AppState, share_id: Uuid, mut incoming: I, mut outgoing: O)
where
    I: Stream<Item = RelayFrame> + Unpin + Send,
    O: Sink<RelayFrame> + Unpin + Send + 'static,
{
    let timing = state.shares().timing();
    state.ws().ensure_started(&state);

    // 1. Auth: the owner's access token, first message, within the window.
    let token = tokio::time::timeout(timing.auth_timeout, first_text(&mut incoming))
        .await
        .ok()
        .flatten()
        .and_then(|t| match serde_json::from_str::<HostClientMsg>(&t) {
            Ok(HostClientMsg::Auth { token }) => Some(token),
            _ => None,
        });
    let ctx = match token {
        Some(t) => authenticate(&state, &t).await,
        None => None,
    };
    let Some(ctx) = ctx else {
        close_now(&mut outgoing, CLOSE_AUTH_REQUIRED, "auth_required").await;
        return;
    };

    // 2. The share must be the caller's and live.
    let relay = match state.shares().relays().open(&state, share_id).await {
        Ok(r) if r.share().owner_user_id == ctx.user_id => r,
        Err(OpenError::Ended { owner }) if owner == ctx.user_id => {
            close_now(&mut outgoing, CLOSE_SHARE_ENDED, "share ended").await;
            return;
        }
        Ok(_) | Err(OpenError::NotFound | OpenError::Ended { .. }) => {
            close_now(&mut outgoing, CLOSE_FORBIDDEN, "forbidden").await;
            return;
        }
        Err(OpenError::Internal(e)) => {
            tracing::warn!(%share_id, error = %e, "share host: loading the share failed");
            close_now(&mut outgoing, CLOSE_INTERNAL, "internal error").await;
            return;
        }
    };
    let (out, rx, mut kill) = outbox(HOST_QUEUE);
    let Some(conn) = relay.attach_host(&out) else {
        close_now(&mut outgoing, CLOSE_SHARE_ENDED, "share ended").await;
        return;
    };
    let writer = tokio::spawn(write_loop(outgoing, rx, kill.clone()));
    tracing::debug!(%share_id, conn, "share host connected");

    // 3. Relay loop.
    let mut hb = Heartbeat::new(&timing);
    loop {
        tokio::select! {
            _ = kill.changed() => break,
            () = hb.tick() => {
                if !hb.on_tick() {
                    out.kill(CLOSE_SLOW_CONSUMER, "ping timeout");
                    break;
                }
                if out.try_send(text(&HostServerMsg::Ping)).is_err() {
                    out.kill(CLOSE_SLOW_CONSUMER, "host too slow");
                    break;
                }
            }
            frame = incoming.next() => match frame {
                None | Some(RelayFrame::Close { .. }) => break,
                Some(RelayFrame::Other) => {}
                Some(RelayFrame::Binary(b)) => relay.host_frame(b),
                Some(RelayFrame::Text(t)) => match serde_json::from_str::<HostClientMsg>(&t) {
                    Ok(HostClientMsg::Kick { viewer_id }) => {
                        relay.remove_viewer(viewer_id, LeaveReason::Kicked);
                    }
                    Ok(HostClientMsg::Ping) => {
                        if out.try_send(text(&HostServerMsg::Pong)).is_err() {
                            out.kill(CLOSE_SLOW_CONSUMER, "host too slow");
                            break;
                        }
                    }
                    Ok(HostClientMsg::Pong) => hb.on_pong(),
                    // A second auth, or something unknown: ignored.
                    Ok(HostClientMsg::Auth { .. }) | Err(_) => {}
                },
            },
        }
    }
    relay.detach_host(&state, conn);
    out.kill(CLOSE_NORMAL, "bye");
    let _ = writer.await;
    tracing::debug!(%share_id, conn, "share host disconnected");
}

/// Runs one viewer connection (`/v1/shares/{id}/join`) to completion.
/// `ip` is the resolved client address (for the coarse hint).
pub async fn run_viewer<I, O>(
    state: AppState,
    share_id: Uuid,
    ip: Option<IpAddr>,
    mut incoming: I,
    mut outgoing: O,
) where
    I: Stream<Item = RelayFrame> + Unpin + Send,
    O: Sink<RelayFrame> + Unpin + Send + 'static,
{
    let timing = state.shares().timing();
    state.ws().ensure_started(&state);

    let relay = match state.shares().relays().open(&state, share_id).await {
        Ok(r) => r,
        Err(OpenError::NotFound) => {
            close_now(&mut outgoing, CLOSE_NOT_FOUND, "no such share").await;
            return;
        }
        Err(OpenError::Ended { .. }) => {
            close_now(&mut outgoing, CLOSE_SHARE_ENDED, "share ended").await;
            return;
        }
        Err(OpenError::Internal(e)) => {
            tracing::warn!(%share_id, error = %e, "share join: loading the share failed");
            close_now(&mut outgoing, CLOSE_INTERNAL, "internal error").await;
            return;
        }
    };

    // 1. `join` (anonymous, if allowed) or `auth`, first, within the window.
    let first = tokio::time::timeout(timing.auth_timeout, first_text(&mut incoming))
        .await
        .ok()
        .flatten()
        .and_then(|t| serde_json::from_str::<ViewerClientMsg>(&t).ok());
    let (name, account) = match first {
        Some(ViewerClientMsg::Join { name }) if !relay.share().require_account => (name, None),
        Some(ViewerClientMsg::Auth { token, name }) => {
            let Some(ctx) = authenticate(&state, &token).await else {
                close_now(&mut outgoing, CLOSE_AUTH_REQUIRED, "auth_required").await;
                return;
            };
            let email = match state.auth().store().user_by_id(ctx.user_id).await {
                Ok(u) => u.map(|u| u.email),
                Err(e) => {
                    tracing::warn!(error = %e, "share join: user lookup failed");
                    None
                }
            };
            (name, email)
        }
        Some(ViewerClientMsg::Join { .. }) => {
            close_now(&mut outgoing, CLOSE_AUTH_REQUIRED, "account required").await;
            return;
        }
        _ => {
            close_now(&mut outgoing, CLOSE_AUTH_REQUIRED, "auth_required").await;
            return;
        }
    };
    let info = ShareViewer {
        viewer_id: 0,
        name: clean_name(name.as_deref()),
        account,
        ip_hint: ip.and_then(super::ip_hint),
    };

    // 2. Admission.
    let (out, rx, mut kill) = outbox(VIEWER_QUEUE);
    let info = match relay.attach_viewer(info, &out) {
        Ok(info) => info,
        Err((code, reason)) => {
            close_now(&mut outgoing, code, reason).await;
            return;
        }
    };
    let viewer_id = info.viewer_id;
    let writer = tokio::spawn(write_loop(outgoing, rx, kill.clone()));
    tracing::debug!(%share_id, viewer_id, "share viewer joined");
    state
        .ws()
        .share_join_request(relay.share().owner_user_id, share_id, info);

    // 3. Relay loop.
    let mut hb = Heartbeat::new(&timing);
    loop {
        tokio::select! {
            _ = kill.changed() => break,
            () = hb.tick() => {
                if !hb.on_tick() || out.try_send(text(&ViewerServerMsg::Ping)).is_err() {
                    relay.remove_viewer(viewer_id, LeaveReason::Slow);
                    break;
                }
            }
            frame = incoming.next() => match frame {
                None | Some(RelayFrame::Close { .. }) => break,
                Some(RelayFrame::Other) => {}
                Some(RelayFrame::Binary(mut b)) => {
                    // Whatever id the viewer wrote, it is this viewer.
                    if RelayEnvelope::stamp(&mut b, viewer_id).is_err() {
                        continue;
                    }
                    let Some(host) = relay.host_tx() else { continue };
                    let len = b.len();
                    tokio::select! {
                        biased;
                        _ = kill.changed() => break,
                        r = host.send(RelayFrame::Binary(b)) => if r.is_ok() {
                            metrics::counter!(SHARE_BYTES_RELAYED_TOTAL).increment(len as u64);
                        },
                    }
                }
                Some(RelayFrame::Text(t)) => match serde_json::from_str::<ViewerClientMsg>(&t) {
                    Ok(ViewerClientMsg::Ping) => {
                        if out.try_send(text(&ViewerServerMsg::Pong)).is_err() {
                            relay.remove_viewer(viewer_id, LeaveReason::Slow);
                            break;
                        }
                    }
                    Ok(ViewerClientMsg::Pong) => hb.on_pong(),
                    Ok(ViewerClientMsg::Auth { .. } | ViewerClientMsg::Join { .. }) | Err(_) => {}
                },
            },
        }
    }
    relay.remove_viewer(viewer_id, LeaveReason::Left);
    out.kill(CLOSE_NORMAL, "bye");
    let _ = writer.await;
}
