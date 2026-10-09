//! The viewer side of a terminal share (SPEC §14.1 step 5, §14.2, §14.3).
//!
//! [`join`] spawns the viewer task for a parsed [`ShareLink`]: it opens
//! `/v1/shares/{id}/join` (signed in when a token is given, else anonymously with a
//! display name), sends the MAC'd `Hello` once the host is connected, checks the
//! `Welcome`, and from then on reports the host's frames as [`ViewerEvent`]s.
//!
//! Any authentication or sequence failure (bad `Welcome` MAC, a forged, replayed,
//! reordered or dropped frame) ends the share with
//! "Share connection integrity error". Viewer input ([`ViewerHandle::send_input`])
//! is only sent while the host has granted control.

use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use sverb_crypto::share::{Channel, ShareLink, ViewerHandshake, format_uuid};
use sverb_proto::share::{RelayEnvelope, ShareMode, ViewerClientMsg, ViewerServerMsg};
use sverb_proto::share_frame::{ShareChannelExt, ShareFrame, SharePayload};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tracing::debug;

use super::{ShareError, WsStream, close_code, close_message, connect_ws, text};

/// The message shown when the channel fails authentication or sequencing.
pub const INTEGRITY_ERROR: &str = "Share connection integrity error";

/// How to join.
#[derive(Clone)]
pub struct JoinConfig {
    /// The link (key included).
    pub link: ShareLink,
    /// Where to reach its server (see [`super::base_url_for`]).
    pub base_url: String,
    /// Display name shown to the host ("" = anonymous).
    pub name: String,
    /// An access token for that server (signed-in join), if any.
    pub token: Option<String>,
    /// TLS (`None`: `ring` + webpki roots).
    pub tls: Option<Arc<rustls::ClientConfig>>,
}

impl std::fmt::Debug for JoinConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JoinConfig")
            .field("link", &self.link)
            .field("base_url", &self.base_url)
            .field("name", &self.name)
            .field("signed_in", &self.token.is_some())
            .finish_non_exhaustive()
    }
}

/// What the viewer task reports, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewerEvent {
    /// The relay admitted this viewer.
    Joined {
        /// Relay-assigned id.
        viewer_id: u32,
        /// The share's mode.
        mode: ShareMode,
    },
    /// The host is deciding ("Waiting for host approval…").
    WaitingForApproval,
    /// The host admitted this viewer (a `Snapshot` follows).
    Approved,
    /// The host refused; `Ended` follows.
    Denied,
    /// The host's screen: size the emulator to `cols`×`rows`, then feed `vt`.
    Snapshot {
        /// Host columns.
        cols: u16,
        /// Host rows.
        rows: u16,
        /// VT bytes.
        vt: Vec<u8>,
    },
    /// Live output.
    Output(Vec<u8>),
    /// The host pane was resized.
    Resize {
        /// Columns.
        cols: u16,
        /// Rows.
        rows: u16,
    },
    /// Control granted (`true`) or revoked.
    ControlGranted(bool),
    /// The host's connection dropped; the share ends unless it returns.
    HostAway,
    /// The share is over for this viewer (last event).
    Ended {
        /// Why ("denied by the host", "share ended", [`INTEGRITY_ERROR`], …).
        reason: String,
    },
}

enum ViewerCmd {
    Input(Vec<u8>),
    /// Test hook: an `Input` frame sent whatever the control state (the host must
    /// still drop it, T-04/T-05).
    InputUnchecked(Vec<u8>),
    Close,
}

/// Talks to a running viewer task. Cheap to clone; dropping every handle leaves.
#[derive(Clone)]
pub struct ViewerHandle {
    tx: mpsc::UnboundedSender<ViewerCmd>,
}

impl std::fmt::Debug for ViewerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ViewerHandle")
    }
}

impl ViewerHandle {
    /// Keys typed in the viewer pane, already encoded with the viewer emulator's
    /// modes. Dropped unless the host granted control.
    pub fn send_input(&self, bytes: Vec<u8>) {
        let _ = self.tx.send(ViewerCmd::Input(bytes));
    }

    /// Test hook: send an `Input` frame even without control (a crafted client).
    #[doc(hidden)]
    pub fn send_input_unchecked(&self, bytes: Vec<u8>) {
        let _ = self.tx.send(ViewerCmd::InputUnchecked(bytes));
    }

    /// Leave the share.
    pub fn close(&self) {
        let _ = self.tx.send(ViewerCmd::Close);
    }

    /// Whether the viewer task is still running.
    pub fn is_running(&self) -> bool {
        !self.tx.is_closed()
    }
}

/// Starts joining (spawns the viewer task). Failures arrive as
/// [`ViewerEvent::Ended`]. Must be called inside a tokio runtime.
pub fn join(cfg: JoinConfig) -> (ViewerHandle, mpsc::UnboundedReceiver<ViewerEvent>) {
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (ev_tx, ev_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let reason = match run(&cfg, cmd_rx, &ev_tx).await {
            Ok(reason) => reason,
            Err(ShareError::Integrity) => INTEGRITY_ERROR.to_owned(),
            Err(ShareError::Closed(code)) => close_message(code),
            Err(e) => e.to_string(),
        };
        let _ = ev_tx.send(ViewerEvent::Ended { reason });
    });
    (ViewerHandle { tx: cmd_tx }, ev_rx)
}

struct State {
    viewer_id: Option<u32>,
    handshake: Option<ViewerHandshake>,
    channel: Option<Channel>,
    control: bool,
}

/// Runs until the share ends; `Ok(reason)` for an orderly end.
async fn run(
    cfg: &JoinConfig,
    mut cmds: mpsc::UnboundedReceiver<ViewerCmd>,
    events: &mpsc::UnboundedSender<ViewerEvent>,
) -> Result<String, ShareError> {
    let id = format_uuid(cfg.link.share_id());
    let path = format!("{}/{id}/join", sverb_proto::share::SHARES_PATH);
    let mut ws = connect_ws(&cfg.base_url, &path, cfg.tls.clone()).await?;
    let name = (!cfg.name.trim().is_empty()).then(|| cfg.name.clone());
    let first = match &cfg.token {
        Some(token) => ViewerClientMsg::Auth {
            token: token.clone(),
            name: name.clone(),
        },
        None => ViewerClientMsg::Join { name: name.clone() },
    };
    send(&mut ws, text(&first)).await?;
    let mut st = State {
        viewer_id: None,
        handshake: None,
        channel: None,
        control: false,
    };
    loop {
        tokio::select! {
            cmd = cmds.recv() => match cmd {
                Some(ViewerCmd::Input(bytes)) => {
                    if st.control
                        && let Some(vid) = st.viewer_id
                        && let Some(ch) = st.channel.as_mut()
                    {
                        let wire = ch
                            .seal_frame(&ShareFrame::Input(bytes))
                            .map_err(|_| ShareError::Integrity)?;
                        send(&mut ws, frame_msg(vid, wire)).await?;
                    }
                }
                Some(ViewerCmd::InputUnchecked(bytes)) => {
                    if let Some(vid) = st.viewer_id
                        && let Some(ch) = st.channel.as_mut()
                    {
                        let wire = ch
                            .seal_frame(&ShareFrame::Input(bytes))
                            .map_err(|_| ShareError::Integrity)?;
                        send(&mut ws, frame_msg(vid, wire)).await?;
                    }
                }
                Some(ViewerCmd::Close) | None => {
                    if let (Some(vid), Some(ch)) = (st.viewer_id, st.channel.as_mut())
                        && let Ok(wire) = ch.seal_frame(&ShareFrame::Bye {
                            reason: "viewer left".into(),
                        })
                    {
                        let _ = ws.send(frame_msg(vid, wire)).await;
                    }
                    let _ = ws.close(None).await;
                    return Ok("you left the share".to_owned());
                }
            },
            msg = ws.next() => {
                let msg = match msg {
                    None => return Ok("connection lost".to_owned()),
                    Some(Err(e)) => return Err(ShareError::Transport(e.to_string())),
                    Some(Ok(m)) => m,
                };
                match msg {
                    Message::Close(frame) => {
                        return Err(ShareError::Closed(close_code(frame.as_ref()).unwrap_or(1000)));
                    }
                    Message::Text(t) => {
                        on_text(cfg, &mut ws, &mut st, events, &t).await?;
                    }
                    Message::Binary(b) => {
                        if let Some(reason) = on_binary(&mut st, events, &b)? {
                            let _ = ws.close(None).await;
                            return Ok(reason);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

fn frame_msg(viewer_id: u32, wire: Vec<u8>) -> Message {
    Message::binary(
        RelayEnvelope {
            viewer_id,
            payload: SharePayload::Frame(wire).encode(),
        }
        .encode(),
    )
}

async fn send(ws: &mut WsStream, msg: Message) -> Result<(), ShareError> {
    ws.send(msg)
        .await
        .map_err(|e| ShareError::Transport(e.to_string()))
}

async fn on_text(
    cfg: &JoinConfig,
    ws: &mut WsStream,
    st: &mut State,
    events: &mpsc::UnboundedSender<ViewerEvent>,
    t: &str,
) -> Result<(), ShareError> {
    match serde_json::from_str::<ViewerServerMsg>(t) {
        Ok(ViewerServerMsg::Joined { viewer_id, mode }) => {
            st.viewer_id = Some(viewer_id);
            let _ = events.send(ViewerEvent::Joined { viewer_id, mode });
        }
        Ok(ViewerServerMsg::HostConnected) => {
            let Some(vid) = st.viewer_id else {
                return Ok(());
            };
            if st.channel.is_some() || st.handshake.is_some() {
                return Ok(());
            }
            let (hello, hs) = ViewerHandshake::start(
                cfg.link.key(),
                cfg.link.share_id(),
                &cfg.name,
                &mut sverb_crypto::random::os_rng(),
            )
            .map_err(|e| ShareError::Local(e.to_string()))?;
            st.handshake = Some(hs);
            let env = RelayEnvelope {
                viewer_id: vid,
                payload: SharePayload::Hello(hello).encode(),
            };
            send(ws, Message::binary(env.encode())).await?;
        }
        Ok(ViewerServerMsg::HostDisconnected) => {
            let _ = events.send(ViewerEvent::HostAway);
        }
        Ok(ViewerServerMsg::Ping) => {
            send(ws, text(&ViewerClientMsg::Pong)).await?;
        }
        _ => {}
    }
    Ok(())
}

/// `Ok(Some(reason))` ends the share in order.
fn on_binary(
    st: &mut State,
    events: &mpsc::UnboundedSender<ViewerEvent>,
    bytes: &[u8],
) -> Result<Option<String>, ShareError> {
    let env = RelayEnvelope::decode(bytes).map_err(|_| ShareError::Integrity)?;
    let Some(vid) = st.viewer_id else {
        return Err(ShareError::Integrity);
    };
    match SharePayload::decode(&env.payload).map_err(|_| ShareError::Integrity)? {
        SharePayload::Welcome(welcome) => {
            let hs = st.handshake.take().ok_or(ShareError::Integrity)?;
            let ch = hs
                .finish(&welcome, vid)
                .map_err(|_| ShareError::Integrity)?;
            st.channel = Some(ch);
        }
        SharePayload::Frame(wire) => {
            let ch = st.channel.as_mut().ok_or(ShareError::Integrity)?;
            let frame = ch.open_frame(&wire).map_err(|e| {
                debug!(%e, "share frame rejected");
                ShareError::Integrity
            })?;
            let ev = match frame {
                ShareFrame::ApprovalPending => ViewerEvent::WaitingForApproval,
                ShareFrame::Approved => ViewerEvent::Approved,
                ShareFrame::Denied => {
                    let _ = events.send(ViewerEvent::Denied);
                    return Ok(Some("denied by the host".to_owned()));
                }
                ShareFrame::Snapshot { cols, rows, vt } => ViewerEvent::Snapshot { cols, rows, vt },
                ShareFrame::Output(b) => ViewerEvent::Output(b),
                ShareFrame::Resize { cols, rows } => ViewerEvent::Resize { cols, rows },
                ShareFrame::ControlGranted(g) => {
                    st.control = g;
                    ViewerEvent::ControlGranted(g)
                }
                ShareFrame::Bye { reason } => return Ok(Some(reason)),
                ShareFrame::Input(_) => return Ok(None),
            };
            let _ = events.send(ev);
        }
        SharePayload::Hello(_) => return Err(ShareError::Integrity),
    }
    Ok(None)
}
