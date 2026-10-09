//! M6-03: the host side of a terminal share (SPEC §14.1, §14.3).
//!
//! [`start`] creates the share and spawns the host task, which:
//!
//! - answers each viewer's `Hello` (M6-02 handshake). A `Hello` whose MAC does not
//!   verify (wrong link key) gets the viewer kicked at once: the host is never
//!   asked about it ([`HostEvent::ViewerRejected`]);
//! - asks the host about every authenticated viewer ([`HostEvent::ApprovalNeeded`],
//!   while the viewer is told `ApprovalPending`), unless "skip approval" is set;
//! - on approval sends `Approved`, a `Snapshot` of the screen, then the live
//!   `Output` / `Resize` stream from the session tap;
//! - injects a viewer's `Input` into the session **only** in control mode and only
//!   while the host granted that viewer control ([`HostHandle::set_control`]);
//!   anything else is dropped;
//! - ends on [`HostHandle::stop`], when the session ends, at the expiry, or when the
//!   host stream closes: `Bye` to every viewer, then `DELETE /v1/shares/{id}`.
//!
//! The link key is generated here and only leaves the process inside the link
//! (its fragment never reaches the server).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use futures::{SinkExt, StreamExt};
use sverb_crypto::share::{Channel, HostHandshake, ShareKey, ShareLink};
use sverb_proto::share::{
    CLOSE_AUTH_REQUIRED, CreateShareRequest, CreateShareResponse, HostClientMsg, HostServerMsg,
    LeaveReason, RelayEnvelope, ShareMode, ShareViewer,
};
use sverb_proto::share_frame::{ShareChannelExt, ShareFrame, SharePayload};
use sverb_proto::version::{API_PREFIX, PROTO_HEADER, PROTO_VERSION};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, warn};
use uuid::Uuid;

use super::{
    FeedEvent, FeedNext, FeedReceiver, MAX_OUTPUT_FRAME, ScreenSource, ShareAuth, ShareError,
    ShareOptions, WsStream, check_base_url, close_code, close_message, connect_ws, link_server,
    text,
};

/// Everything needed to host a share.
#[derive(Debug, Clone)]
pub struct HostConfig {
    /// The server (`https://…`, or `http://` on loopback).
    pub base_url: String,
    /// The owner's credentials.
    pub auth: ShareAuth,
    /// TLS (`None`: `ring` + webpki roots).
    pub tls: Option<Arc<rustls::ClientConfig>>,
    /// What the start dialog chose.
    pub options: ShareOptions,
}

/// A running share, as shown to the host.
#[derive(Clone, PartialEq, Eq)]
pub struct ShareInfo {
    /// The share.
    pub share_id: Uuid,
    /// `sverb://join/<server>/<id>#<key>`.
    pub link: String,
    /// `https://<server>/s/<id>#<key>` (future web viewer).
    pub web_link: String,
    /// When it ends at the latest.
    pub expires_at: DateTime<Utc>,
    /// View or control.
    pub mode: ShareMode,
}

impl std::fmt::Debug for ShareInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The links carry the key.
        f.debug_struct("ShareInfo")
            .field("share_id", &self.share_id)
            .field("expires_at", &self.expires_at)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

/// What the host task reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostEvent {
    /// An authenticated viewer waits for the host's decision (the approval modal).
    ApprovalNeeded(ShareViewer),
    /// A viewer was admitted and got the snapshot.
    ViewerJoined(ShareViewer),
    /// A viewer's `Hello` failed verification (wrong link key): it was kicked.
    ViewerRejected {
        /// The viewer.
        viewer_id: u32,
        /// Why.
        reason: String,
    },
    /// A viewer is gone.
    ViewerLeft {
        /// The viewer.
        viewer_id: u32,
        /// Why (`left`, `denied`, `kicked`, …).
        reason: String,
    },
    /// The host granted or revoked a viewer's control.
    ControlChanged {
        /// The viewer.
        viewer_id: u32,
        /// Granted.
        granted: bool,
    },
    /// The share is over (`Bye` sent, share deleted).
    Ended {
        /// Why.
        reason: String,
    },
}

/// A host decision for the task.
#[derive(Debug, Clone, PartialEq, Eq)]
enum HostCmd {
    Approve(u32),
    Deny(u32),
    SetControl(u32, bool),
    Kick(u32),
    Stop(String),
}

/// Controls a running share. Cheap to clone; dropping every handle stops the share.
#[derive(Debug, Clone)]
pub struct HostHandle {
    tx: mpsc::UnboundedSender<HostCmd>,
    info: ShareInfo,
}

impl HostHandle {
    /// The share's id, links and expiry.
    pub fn info(&self) -> &ShareInfo {
        &self.info
    }

    /// Admit a viewer waiting for approval.
    pub fn approve(&self, viewer_id: u32) {
        let _ = self.tx.send(HostCmd::Approve(viewer_id));
    }

    /// Refuse a viewer (it is told `Denied` and disconnected).
    pub fn deny(&self, viewer_id: u32) {
        let _ = self.tx.send(HostCmd::Deny(viewer_id));
    }

    /// Grant or revoke a viewer's control (control-mode shares only).
    pub fn set_control(&self, viewer_id: u32, granted: bool) {
        let _ = self.tx.send(HostCmd::SetControl(viewer_id, granted));
    }

    /// Disconnect a viewer.
    pub fn kick(&self, viewer_id: u32) {
        let _ = self.tx.send(HostCmd::Kick(viewer_id));
    }

    /// End the share.
    pub fn stop(&self) {
        let _ = self.tx.send(HostCmd::Stop("stopped by the host".into()));
    }

    /// Whether the host task is still running.
    pub fn is_running(&self) -> bool {
        !self.tx.is_closed()
    }
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

struct Http {
    base: String,
    http: reqwest::Client,
}

impl Http {
    fn new(base_url: &str, tls: Option<Arc<rustls::ClientConfig>>) -> Result<Self, ShareError> {
        check_base_url(base_url)?;
        let tls = tls.unwrap_or_else(crate::ws::default_tls);
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .use_preconfigured_tls((*tls).clone())
            .build()
            .map_err(|e| ShareError::Transport(e.to_string()))?;
        Ok(Self {
            base: base_url.trim().trim_end_matches('/').to_owned(),
            http,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{API_PREFIX}{path}", self.base)
    }

    async fn check(resp: reqwest::Response) -> Result<Vec<u8>, ShareError> {
        let status = resp.status();
        let body = resp
            .bytes()
            .await
            .map_err(|e| ShareError::Transport(e.to_string()))?;
        if status.is_success() {
            return Ok(body.to_vec());
        }
        let message = serde_json::from_slice::<sverb_proto::ErrorEnvelope>(&body)
            .map(|e| e.error.message)
            .unwrap_or_else(|_| status.canonical_reason().unwrap_or("error").to_owned());
        Err(ShareError::Api {
            status: status.as_u16(),
            message,
        })
    }

    async fn create(
        &self,
        token: &str,
        req: &CreateShareRequest,
    ) -> Result<CreateShareResponse, ShareError> {
        let resp = self
            .http
            .post(self.url(sverb_proto::share::SHARES_PATH))
            .header(PROTO_HEADER, PROTO_VERSION.to_string())
            .bearer_auth(token)
            .json(req)
            .send()
            .await
            .map_err(|e| ShareError::Transport(e.to_string()))?;
        let body = Self::check(resp).await?;
        serde_json::from_slice(&body)
            .map_err(|e| ShareError::Transport(format!("unexpected response: {e}")))
    }

    async fn delete(&self, token: &str, id: Uuid) -> Result<(), ShareError> {
        let resp = self
            .http
            .delete(self.url(&format!("{}/{id}", sverb_proto::share::SHARES_PATH)))
            .header(PROTO_HEADER, PROTO_VERSION.to_string())
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| ShareError::Transport(e.to_string()))?;
        Self::check(resp).await.map(drop)
    }
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

/// Creates the share, opens the host stream and spawns the host task. Must be called
/// inside a tokio runtime.
///
/// # Errors
/// [`ShareError`] if the share can't be created or the host stream can't be opened
/// (nothing is left running then; a created share is deleted).
pub async fn start(
    cfg: HostConfig,
    source: Arc<dyn ScreenSource>,
    feed: FeedReceiver,
) -> Result<(HostHandle, mpsc::UnboundedReceiver<HostEvent>), ShareError> {
    let http = Http::new(&cfg.base_url, cfg.tls.clone())?;
    let opts = cfg.options;
    let req = CreateShareRequest {
        mode: opts.mode,
        expires_in_s: Some(opts.expires_in.as_secs().max(1)),
        max_viewers: None,
        require_account: opts.require_account,
    };
    let mut token = cfg.auth.access().await?;
    let created = match http.create(&token, &req).await {
        Err(ShareError::Api { status: 401, .. }) => {
            cfg.auth.rejected(&token).await?;
            token = cfg.auth.access().await?;
            http.create(&token, &req).await?
        }
        other => other?,
    };
    let share_id = created.share_id;
    let key = ShareKey::generate(&mut sverb_crypto::random::os_rng());
    let link = ShareLink::new(
        &link_server(&cfg.base_url),
        *share_id.as_bytes(),
        key.clone(),
    )
    .map_err(|e| ShareError::Local(e.to_string()))?;
    let info = ShareInfo {
        share_id,
        link: link.to_sverb_link(),
        web_link: link.to_web_link(),
        expires_at: created.expires_at,
        mode: opts.mode,
    };

    let ws = match open_host_stream(&cfg, share_id, &token).await {
        Ok(ws) => ws,
        Err(e) => {
            let _ = http.delete(&token, share_id).await;
            return Err(e);
        }
    };

    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (ev_tx, ev_rx) = mpsc::unbounded_channel();
    let task = HostTask {
        ws,
        http,
        auth: cfg.auth.clone(),
        key,
        share_id,
        options: opts,
        source,
        feed,
        events: ev_tx,
        cmds: cmd_rx,
        viewers: BTreeMap::new(),
        attached: false,
        deferred: Vec::new(),
    };
    tokio::spawn(task.run());
    Ok((HostHandle { tx: cmd_tx, info }, ev_rx))
}

async fn open_host_stream(
    cfg: &HostConfig,
    share_id: Uuid,
    token: &str,
) -> Result<WsStream, ShareError> {
    let path = format!("{}/{share_id}/host", sverb_proto::share::SHARES_PATH);
    let mut token = token.to_owned();
    for attempt in 0..2 {
        let mut ws = connect_ws(&cfg.base_url, &path, cfg.tls.clone()).await?;
        ws.send(text(&HostClientMsg::Auth {
            token: token.clone(),
        }))
        .await
        .map_err(|e| ShareError::Transport(e.to_string()))?;
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(15), ws.next())
                .await
                .map_err(|_| ShareError::Transport("no answer from the server".into()))?;
            match msg {
                Some(Ok(Message::Text(t))) => match serde_json::from_str::<HostServerMsg>(&t) {
                    Ok(HostServerMsg::Ready { .. }) => return Ok(ws),
                    Ok(HostServerMsg::Ping) => {
                        let _ = ws.send(text(&HostClientMsg::Pong)).await;
                    }
                    _ => {}
                },
                Some(Ok(Message::Close(frame))) => {
                    let code = close_code(frame.as_ref()).unwrap_or(1000);
                    if code == CLOSE_AUTH_REQUIRED && attempt == 0 {
                        cfg.auth.rejected(&token).await?;
                        token = cfg.auth.access().await?;
                        break;
                    }
                    return Err(ShareError::Closed(code));
                }
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(ShareError::Transport(e.to_string())),
                None => return Err(ShareError::Transport("connection closed".into())),
            }
        }
    }
    Err(ShareError::Closed(CLOSE_AUTH_REQUIRED))
}

// ---------------------------------------------------------------------------
// The host task
// ---------------------------------------------------------------------------

/// How long a viewer told `Denied` / `Bye` gets to leave before it is kicked (so
/// the frame reaches it before the relay closes its socket).
const LEAVE_GRACE: Duration = Duration::from_secs(2);

struct Viewer {
    info: ShareViewer,
    channel: Option<Channel>,
    /// Admitted (snapshot sent, stream live).
    live: bool,
    /// The host granted input.
    control: bool,
    /// Told to go (and already reported as gone): kicked at this deadline.
    closing: Option<tokio::time::Instant>,
}

/// Whether `bytes` switch back from the alternate screen (`CSI ? 1049 l`, `?1047 l`,
/// `?47 l`). A sequence split across two chunks is missed (the screen then only
/// catches up at the next resync).
fn leaves_alt_screen(bytes: &[u8]) -> bool {
    const SEQS: [&[u8]; 3] = [b"\x1b[?1049l", b"\x1b[?1047l", b"\x1b[?47l"];
    SEQS.iter()
        .any(|seq| bytes.windows(seq.len()).any(|w| w == *seq))
}

async fn sleep_until(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending().await,
    }
}

struct HostTask {
    ws: WsStream,
    http: Http,
    auth: ShareAuth,
    key: ShareKey,
    share_id: Uuid,
    options: ShareOptions,
    source: Arc<dyn ScreenSource>,
    feed: FeedReceiver,
    events: mpsc::UnboundedSender<HostEvent>,
    cmds: mpsc::UnboundedReceiver<HostCmd>,
    viewers: BTreeMap<u32, Viewer>,
    /// The session tap reported its size (it is attached).
    attached: bool,
    /// Approvals waiting for the tap.
    deferred: Vec<u32>,
}

/// A send to the relay failed: the host stream is gone.
struct Gone;

impl HostTask {
    async fn run(mut self) {
        let expiry = tokio::time::sleep(self.options.expires_in);
        tokio::pin!(expiry);
        let reason = loop {
            let kick_at = self.next_kick();
            let step = tokio::select! {
                biased;
                cmd = self.cmds.recv() => match cmd {
                    Some(cmd) => self.on_cmd(cmd).await,
                    None => Err(Some("stopped by the host".to_owned())),
                },
                () = &mut expiry => Err(Some("expired".to_owned())),
                () = sleep_until(kick_at) => self.kick_overdue().await.map_err(|Gone| None),
                msg = self.ws.next() => self.on_ws(msg).await,
                next = self.feed.next() => self.on_feed(next).await,
            };
            if let Err(reason) = step {
                break reason;
            }
        };
        self.end(reason).await;
    }

    fn emit(&self, ev: HostEvent) {
        let _ = self.events.send(ev);
    }

    async fn send_ws(&mut self, msg: Message) -> Result<(), Gone> {
        self.ws.send(msg).await.map_err(|_| Gone)
    }

    /// Seal `frame` on viewer `id`'s channel and send it.
    async fn send_frame(&mut self, id: u32, frame: &ShareFrame) -> Result<(), Gone> {
        let Some(ch) = self.viewers.get_mut(&id).and_then(|v| v.channel.as_mut()) else {
            return Ok(());
        };
        let Ok(wire) = ch.seal_frame(frame) else {
            debug!(viewer = id, "share channel closed; frame dropped");
            return Ok(());
        };
        let env = RelayEnvelope {
            viewer_id: id,
            payload: SharePayload::Frame(wire).encode(),
        };
        self.send_ws(Message::binary(env.encode())).await
    }

    async fn kick(&mut self, id: u32) -> Result<(), Gone> {
        self.send_ws(text(&HostClientMsg::Kick { viewer_id: id }))
            .await
    }

    /// The earliest deadline of a closing viewer.
    fn next_kick(&self) -> Option<tokio::time::Instant> {
        self.viewers.values().filter_map(|v| v.closing).min()
    }

    /// Kick the closing viewers whose grace ran out.
    async fn kick_overdue(&mut self) -> Result<(), Gone> {
        let now = tokio::time::Instant::now();
        let due: Vec<u32> = self
            .viewers
            .iter()
            .filter(|(_, v)| v.closing.is_some_and(|d| d <= now))
            .map(|(id, _)| *id)
            .collect();
        for id in due {
            self.viewers.remove(&id);
            self.kick(id).await?;
        }
        Ok(())
    }

    /// Stop talking to a viewer, report it gone, and kick it after [`LEAVE_GRACE`]
    /// unless it leaves by itself.
    fn close_viewer(&mut self, id: u32, reason: &str) {
        let Some(v) = self.viewers.get_mut(&id) else {
            return;
        };
        if v.closing.is_some() {
            return;
        }
        v.live = false;
        v.control = false;
        v.closing = Some(tokio::time::Instant::now() + LEAVE_GRACE);
        self.deferred.retain(|d| *d != id);
        self.emit(HostEvent::ViewerLeft {
            viewer_id: id,
            reason: reason.to_owned(),
        });
    }

    fn live_ids(&self) -> Vec<u32> {
        self.viewers
            .iter()
            .filter(|(_, v)| v.live)
            .map(|(id, _)| *id)
            .collect()
    }

    /// `Err(Some(reason))` ends the share; `Err(None)` too (relay gone).
    async fn on_cmd(&mut self, cmd: HostCmd) -> Result<(), Option<String>> {
        let r = match cmd {
            HostCmd::Approve(id) => self.approve(id).await,
            HostCmd::Deny(id) => self.deny(id).await,
            HostCmd::SetControl(id, granted) => self.set_control(id, granted).await,
            HostCmd::Kick(id) => self.remove(id, "kicked", true).await,
            HostCmd::Stop(reason) => return Err(Some(reason)),
        };
        r.map_err(|Gone| Some("connection to the server lost".to_owned()))
    }

    async fn approve(&mut self, id: u32) -> Result<(), Gone> {
        let Some(v) = self.viewers.get(&id) else {
            return Ok(());
        };
        if v.live || v.channel.is_none() || v.closing.is_some() {
            return Ok(());
        }
        if !self.attached {
            if !self.deferred.contains(&id) {
                self.deferred.push(id);
            }
            return Ok(());
        }
        self.send_frame(id, &ShareFrame::Approved).await?;
        self.resync(&[id], false).await?;
        if let Some(v) = self.viewers.get(&id) {
            self.emit(HostEvent::ViewerJoined(v.info.clone()));
        }
        Ok(())
    }

    async fn deny(&mut self, id: u32) -> Result<(), Gone> {
        if self
            .viewers
            .get(&id)
            .is_some_and(|v| !v.live && v.closing.is_none())
        {
            self.send_frame(id, &ShareFrame::Denied).await?;
            self.close_viewer(id, "denied");
        }
        Ok(())
    }

    async fn set_control(&mut self, id: u32, granted: bool) -> Result<(), Gone> {
        if self.options.mode != ShareMode::Control {
            return Ok(());
        }
        let Some(v) = self.viewers.get_mut(&id) else {
            return Ok(());
        };
        if !v.live || v.control == granted {
            return Ok(());
        }
        v.control = granted;
        self.send_frame(id, &ShareFrame::ControlGranted(granted))
            .await?;
        self.emit(HostEvent::ControlChanged {
            viewer_id: id,
            granted,
        });
        Ok(())
    }

    /// Say `Bye` (if `bye`) and close a viewer (kicked after the grace).
    async fn remove(&mut self, id: u32, reason: &str, bye: bool) -> Result<(), Gone> {
        if self.viewers.get(&id).is_none_or(|v| v.closing.is_some()) {
            return Ok(());
        }
        if bye {
            self.send_frame(
                id,
                &ShareFrame::Bye {
                    reason: "removed by the host".into(),
                },
            )
            .await?;
        }
        self.close_viewer(id, reason);
        Ok(())
    }

    /// Snapshot the screen. Chunks queued before the snapshot go to the viewers that
    /// were already live; the snapshot goes to `new` viewers, and to everyone when
    /// output was dropped (overflow).
    async fn resync(&mut self, new: &[u32], everyone: bool) -> Result<(), Gone> {
        let mut drained = (Vec::new(), false);
        let screen = {
            let feed = &mut self.feed;
            self.source.snapshot(&mut || drained = feed.drain())
        };
        let (pending, overflow) = drained;
        let old: Vec<u32> = self
            .live_ids()
            .into_iter()
            .filter(|id| !new.contains(id))
            .collect();
        let targets: Vec<u32> = if overflow || everyone {
            debug!(
                viewers = old.len(),
                "share feed overflowed; resending the screen"
            );
            old.iter().chain(new).copied().collect()
        } else {
            for ev in pending {
                self.forward(&old, ev).await?;
            }
            new.to_vec()
        };
        let frame = ShareFrame::Snapshot {
            cols: screen.cols,
            rows: screen.rows,
            vt: screen.vt,
        };
        for id in targets {
            self.send_frame(id, &frame).await?;
            if let Some(v) = self.viewers.get_mut(&id) {
                v.live = true;
            }
        }
        Ok(())
    }

    /// One tap event to `ids`.
    async fn forward(&mut self, ids: &[u32], ev: FeedEvent) -> Result<(), Gone> {
        match ev {
            FeedEvent::Output(bytes) => {
                for chunk in bytes.chunks(MAX_OUTPUT_FRAME) {
                    let frame = ShareFrame::Output(chunk.to_vec());
                    for id in ids {
                        self.send_frame(*id, &frame).await?;
                    }
                }
            }
            FeedEvent::Resize { cols, rows } => {
                let frame = ShareFrame::Resize { cols, rows };
                for id in ids {
                    self.send_frame(*id, &frame).await?;
                }
            }
        }
        Ok(())
    }

    async fn on_feed(&mut self, next: FeedNext) -> Result<(), Option<String>> {
        let r = match next {
            FeedNext::Ended => return Err(Some("the session ended".to_owned())),
            FeedNext::Overflow => {
                if self.live_ids().is_empty() {
                    let _ = self.feed.drain();
                    Ok(())
                } else {
                    self.resync(&[], true).await
                }
            }
            FeedNext::Event(ev) => {
                let first = !self.attached;
                self.attached = true;
                let live = self.live_ids();
                // Leaving the alternate screen shows the primary screen, which the
                // viewers never got (snapshots hold the visible grid only).
                let resized = match &ev {
                    FeedEvent::Resize { .. } => true,
                    FeedEvent::Output(b) => leaves_alt_screen(b),
                };
                let mut r = self.forward(&live, ev).await;
                // A resize reflows with the host's scrollback, which viewers don't
                // have: follow it (and an alternate-screen exit) with a fresh screen.
                if resized && !live.is_empty() && r.is_ok() {
                    r = self.resync(&[], true).await;
                }
                if first && r.is_ok() {
                    for id in std::mem::take(&mut self.deferred) {
                        if self.approve(id).await.is_err() {
                            return Err(None);
                        }
                    }
                }
                r
            }
        };
        r.map_err(|Gone| None)
    }

    async fn on_ws(
        &mut self,
        msg: Option<Result<Message, tokio_tungstenite::tungstenite::Error>>,
    ) -> Result<(), Option<String>> {
        let r = match msg {
            None => return Err(Some("connection to the server lost".to_owned())),
            Some(Err(e)) => {
                warn!(%e, "share host stream failed");
                return Err(Some("connection to the server lost".to_owned()));
            }
            Some(Ok(Message::Close(frame))) => {
                let code = close_code(frame.as_ref()).unwrap_or(1000);
                return Err(Some(close_message(code)));
            }
            Some(Ok(Message::Text(t))) => match serde_json::from_str::<HostServerMsg>(&t) {
                Ok(HostServerMsg::ViewerJoined(info)) => {
                    self.viewers.insert(
                        info.viewer_id,
                        Viewer {
                            info,
                            channel: None,
                            live: false,
                            control: false,
                            closing: None,
                        },
                    );
                    Ok(())
                }
                Ok(HostServerMsg::ViewerLeft { viewer_id, reason }) => {
                    let announced = self
                        .viewers
                        .get(&viewer_id)
                        .is_some_and(|v| v.closing.is_some());
                    if self.viewers.remove(&viewer_id).is_some() && !announced {
                        self.deferred.retain(|d| *d != viewer_id);
                        self.emit(HostEvent::ViewerLeft {
                            viewer_id,
                            reason: match reason {
                                LeaveReason::Left => "left",
                                LeaveReason::Kicked => "kicked",
                                LeaveReason::Slow => "too slow",
                            }
                            .to_owned(),
                        });
                    }
                    Ok(())
                }
                Ok(HostServerMsg::Ping) => self.send_ws(text(&HostClientMsg::Pong)).await,
                _ => Ok(()),
            },
            Some(Ok(Message::Binary(b))) => self.on_relay(&b).await,
            Some(Ok(_)) => Ok(()),
        };
        r.map_err(|Gone| None)
    }

    async fn on_relay(&mut self, bytes: &[u8]) -> Result<(), Gone> {
        let Ok(env) = RelayEnvelope::decode(bytes) else {
            return Ok(());
        };
        let id = env.viewer_id;
        if self.viewers.get(&id).is_none_or(|v| v.closing.is_some()) {
            return Ok(());
        }
        match SharePayload::decode(&env.payload) {
            Ok(SharePayload::Hello(hello)) => self.on_hello(id, &hello).await,
            Ok(SharePayload::Frame(wire)) => self.on_frame(id, &wire).await,
            Ok(SharePayload::Welcome(_)) | Err(_) => self.integrity(id).await,
        }
    }

    async fn on_hello(&mut self, id: u32, hello: &sverb_crypto::share::Hello) -> Result<(), Gone> {
        if self.viewers.get(&id).is_some_and(|v| v.channel.is_some()) {
            debug!(viewer = id, "second Hello ignored");
            return Ok(());
        }
        let respond = HostHandshake::respond(
            &self.key,
            self.share_id.as_bytes(),
            id,
            hello,
            &mut sverb_crypto::random::os_rng(),
        );
        let Ok((welcome, channel)) = respond else {
            // Wrong link key (or a forged Hello): never shown to the host.
            self.viewers.remove(&id);
            self.kick(id).await?;
            self.emit(HostEvent::ViewerRejected {
                viewer_id: id,
                reason: "the join request did not verify (wrong link key)".into(),
            });
            return Ok(());
        };
        let env = RelayEnvelope {
            viewer_id: id,
            payload: SharePayload::Welcome(welcome).encode(),
        };
        self.send_ws(Message::binary(env.encode())).await?;
        let info = {
            let Some(v) = self.viewers.get_mut(&id) else {
                return Ok(());
            };
            v.channel = Some(channel);
            // The name inside the MAC'd Hello wins over the relay's.
            if !hello.name.trim().is_empty() {
                v.info.name = Some(hello.name.clone());
            }
            v.info.clone()
        };
        if self.options.skip_approval {
            self.approve(id).await
        } else {
            self.send_frame(id, &ShareFrame::ApprovalPending).await?;
            self.emit(HostEvent::ApprovalNeeded(info));
            Ok(())
        }
    }

    async fn on_frame(&mut self, id: u32, wire: &[u8]) -> Result<(), Gone> {
        let opened = match self.viewers.get_mut(&id).and_then(|v| v.channel.as_mut()) {
            Some(ch) => ch.open_frame(wire),
            None => return self.integrity(id).await,
        };
        let frame = match opened {
            Ok(f) => f,
            Err(e) => {
                debug!(viewer = id, %e, "share frame rejected");
                return self.integrity(id).await;
            }
        };
        match frame {
            ShareFrame::Input(bytes) => {
                let allowed = self.options.mode == ShareMode::Control
                    && self.viewers.get(&id).is_some_and(|v| v.live && v.control);
                if allowed {
                    self.source.inject(bytes);
                } else {
                    debug!(viewer = id, "viewer input dropped (no control)");
                }
            }
            ShareFrame::Bye { .. } => self.close_viewer(id, "left"),
            _ => debug!(viewer = id, "unexpected frame from a viewer ignored"),
        }
        Ok(())
    }

    /// A viewer broke the channel (auth, sequence, garbage): kick it.
    async fn integrity(&mut self, id: u32) -> Result<(), Gone> {
        if self.viewers.remove(&id).is_none() {
            return Ok(());
        }
        self.deferred.retain(|d| *d != id);
        self.kick(id).await?;
        self.emit(HostEvent::ViewerLeft {
            viewer_id: id,
            reason: "Share connection integrity error".into(),
        });
        Ok(())
    }

    /// `Bye` to every viewer, give them [`LEAVE_GRACE`] to leave (so the `Bye`
    /// arrives before the relay closes their sockets), close, delete the share.
    async fn end(mut self, reason: Option<String>) {
        self.cmds.close();
        let reason = reason.unwrap_or_else(|| "connection to the server lost".to_owned());
        let ids: Vec<u32> = self
            .viewers
            .iter()
            .filter(|(_, v)| v.channel.is_some() && v.closing.is_none())
            .map(|(id, _)| *id)
            .collect();
        let mut waiting = Vec::new();
        for id in ids {
            let bye = ShareFrame::Bye {
                reason: reason.clone(),
            };
            if self.send_frame(id, &bye).await.is_err() {
                waiting.clear();
                break;
            }
            waiting.push(id);
        }
        let deadline = tokio::time::Instant::now() + LEAVE_GRACE;
        while !waiting.is_empty() {
            let msg = tokio::select! {
                () = tokio::time::sleep_until(deadline) => break,
                msg = self.ws.next() => msg,
            };
            match msg {
                Some(Ok(Message::Text(t))) => match serde_json::from_str::<HostServerMsg>(&t) {
                    Ok(HostServerMsg::ViewerLeft { viewer_id, .. }) => {
                        waiting.retain(|id| *id != viewer_id);
                    }
                    Ok(HostServerMsg::Ping) => {
                        let _ = self.ws.send(text(&HostClientMsg::Pong)).await;
                    }
                    _ => {}
                },
                Some(Ok(
                    Message::Binary(_) | Message::Ping(_) | Message::Pong(_) | Message::Frame(_),
                )) => {}
                _ => break,
            }
        }
        let _ = self.ws.close(None).await;
        if let Ok(token) = self.auth.access().await
            && let Err(e) = self.http.delete(&token, self.share_id).await
        {
            debug!(%e, "share delete failed");
        }
        self.emit(HostEvent::Ended { reason });
    }
}

#[cfg(test)]
mod tests {
    use super::leaves_alt_screen;

    #[test]
    fn alt_screen_exit_is_seen() {
        assert!(leaves_alt_screen(b"text\x1b[?1049l$ "));
        assert!(leaves_alt_screen(b"\x1b[?47l"));
        assert!(!leaves_alt_screen(b"\x1b[?1049h"));
        assert!(!leaves_alt_screen(b"plain"));
    }
}
