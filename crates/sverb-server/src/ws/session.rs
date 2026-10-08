//! One `/v1/ws` connection (SPEC §10.4).
//!
//! The session is written against a [`Frame`] stream and sink rather than
//! axum's socket, so tests drive it over in-memory channels with paused
//! time (the 5 s auth window, the 30 s heartbeat and token expiry).
//!
//! 1. **Auth**: the first text message must be `{"type":"auth","token"}`
//!    within the auth timeout; anything else, an invalid token, or silence
//!    → close 4401.
//! 2. **Subscribe**: the user topic first (so a grant that races the vault
//!    listing is not lost), then every vault the user is a member of.
//! 3. **Loop**: forward hub messages; answer `ping`; send `ping` every
//!    interval (the first right after auth, which also tells the client it
//!    is authenticated) and close 4408 after `max_missed_pongs` unanswered
//!    ones; close 4401 when the access token expires, when the device is
//!    revoked or the account disabled (bus event), or when the heartbeat's
//!    token revalidation fails.

use std::time::Duration;

use futures::{Sink, SinkExt, Stream, StreamExt};
use sverb_proto::ws::{
    AccessChange, CLOSE_AUTH_REQUIRED, CLOSE_PING_TIMEOUT, ClientMsg, ServerMsg,
};
use tokio::time::{Instant, MissedTickBehavior};

use super::hub::{HubMsg, Topic};
use crate::auth::store::AccessCtx;
use crate::auth::tokens::{TokenHash, hash_presented};
use crate::state::AppState;

/// Standard close code for server errors.
const CLOSE_INTERNAL: u16 = 1011;

/// A WebSocket message, reduced to what the protocol uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// A text message (JSON).
    Text(String),
    /// A close frame.
    Close {
        /// Close code.
        code: u16,
        /// Reason.
        reason: String,
    },
    /// Binary data and transport-level ping/pong (ignored).
    Other,
}

/// Session timing (SPEC §10.4 defaults; shortened in no test, time is
/// paused instead).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WsTiming {
    /// The auth message must arrive within this.
    pub auth_timeout: Duration,
    /// Heartbeat period.
    pub ping_interval: Duration,
    /// Unanswered pings before closing.
    pub max_missed_pongs: u32,
}

impl Default for WsTiming {
    fn default() -> Self {
        use sverb_proto::ws::{AUTH_TIMEOUT_SECS, MAX_MISSED_PONGS, PING_INTERVAL_SECS};
        Self {
            auth_timeout: Duration::from_secs(AUTH_TIMEOUT_SECS),
            ping_interval: Duration::from_secs(PING_INTERVAL_SECS),
            max_missed_pongs: MAX_MISSED_PONGS,
        }
    }
}

/// Keeps `sverb_ws_connections_active` right however the session ends.
struct ConnGauge;

impl ConnGauge {
    fn new() -> Self {
        metrics::gauge!(crate::metrics::WS_CONNECTIONS_ACTIVE).increment(1.0);
        Self
    }
}

impl Drop for ConnGauge {
    fn drop(&mut self) {
        metrics::gauge!(crate::metrics::WS_CONNECTIONS_ACTIVE).decrement(1.0);
    }
}

async fn close<O>(out: &mut O, code: u16, reason: &str)
where
    O: Sink<Frame> + Unpin,
{
    let _ = out
        .send(Frame::Close {
            code,
            reason: reason.to_owned(),
        })
        .await;
    let _ = out.close().await;
}

/// Sends a server message; `false` when the socket is gone.
async fn send<O>(out: &mut O, msg: &ServerMsg) -> bool
where
    O: Sink<Frame> + Unpin,
{
    let Ok(text) = serde_json::to_string(msg) else {
        return true;
    };
    let ok = out.send(Frame::Text(text)).await.is_ok();
    if ok {
        metrics::counter!(crate::metrics::WS_MESSAGES_SENT_TOTAL).increment(1);
    }
    ok
}

/// Waits for the auth message; `None` on anything else.
async fn read_auth<I>(incoming: &mut I) -> Option<String>
where
    I: Stream<Item = Frame> + Unpin,
{
    loop {
        match incoming.next().await? {
            Frame::Text(t) => {
                return match serde_json::from_str::<ClientMsg>(&t) {
                    Ok(ClientMsg::Auth { token }) => Some(token),
                    _ => None,
                };
            }
            Frame::Close { .. } => return None,
            Frame::Other => {}
        }
    }
}

/// Validates a presented token: the caller and the token's expiry.
async fn authenticate(state: &AppState, token: &str) -> Option<(TokenHash, AccessCtx, Instant)> {
    let hash = hash_presented(token)?;
    let auth = state.auth();
    let ctx = auth.store().lookup_access(&hash, auth.now()).await.ok()??;
    let expires_at = auth
        .store()
        .access_expires_at(&hash, auth.now())
        .await
        .ok()??;
    let left = (expires_at - auth.now()).to_std().unwrap_or_default();
    Some((hash, ctx, Instant::now() + left))
}

/// What to do after a hub message.
enum Next {
    Continue,
    Close(u16, &'static str),
}

/// Runs one connection to completion.
pub async fn run<I, O>(state: AppState, mut incoming: I, mut outgoing: O)
where
    I: Stream<Item = Frame> + Unpin + Send,
    O: Sink<Frame> + Unpin + Send,
{
    let ws = state.ws();
    ws.ensure_started(&state);
    let timing = ws.timing();

    // 1. Auth within the window.
    let token = tokio::time::timeout(timing.auth_timeout, read_auth(&mut incoming))
        .await
        .ok()
        .flatten();
    let authed = match token {
        Some(t) => authenticate(&state, &t).await,
        None => None,
    };
    let Some((hash, ctx, expires)) = authed else {
        close(&mut outgoing, CLOSE_AUTH_REQUIRED, "auth_required").await;
        return;
    };
    let _gauge = ConnGauge::new();

    // 2. Subscriptions: the user topic before listing vaults.
    let mut sub = ws.hub().register();
    sub.subscribe(Topic::User(ctx.user_id));
    match state.sync().store().list_vaults(ctx.user_id).await {
        Ok(vaults) => {
            for v in vaults {
                sub.subscribe(Topic::Vault(v.id));
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "ws: listing vaults failed");
            close(&mut outgoing, CLOSE_INTERNAL, "internal error").await;
            return;
        }
    }
    tracing::debug!(user_id = %ctx.user_id, device_id = %ctx.device_id, "ws authenticated");

    // 3. The loop.
    let expiry = tokio::time::sleep_until(expires);
    tokio::pin!(expiry);
    let mut ticker = tokio::time::interval(timing.ping_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut first_tick = true;
    let mut awaiting_pong = false;
    let mut missed: u32 = 0;

    loop {
        tokio::select! {
            () = &mut expiry => {
                close(&mut outgoing, CLOSE_AUTH_REQUIRED, "token expired").await;
                return;
            }
            _ = ticker.tick() => {
                if awaiting_pong {
                    missed += 1;
                    if missed >= timing.max_missed_pongs {
                        close(&mut outgoing, CLOSE_PING_TIMEOUT, "ping timeout").await;
                        return;
                    }
                }
                // Safety net for revocations whose bus event was missed.
                if !first_tick {
                    let auth = state.auth();
                    if let Ok(None) = auth.store().access_expires_at(&hash, auth.now()).await {
                        close(&mut outgoing, CLOSE_AUTH_REQUIRED, "auth_required").await;
                        return;
                    }
                }
                first_tick = false;
                if !send(&mut outgoing, &ServerMsg::Ping).await {
                    return;
                }
                awaiting_pong = true;
            }
            msg = sub.recv() => {
                let Some(msg) = msg else { return };
                match on_hub(&mut outgoing, &sub, ctx, msg).await {
                    Some(Next::Continue) => {}
                    Some(Next::Close(code, reason)) => {
                        close(&mut outgoing, code, reason).await;
                        return;
                    }
                    None => return,
                }
            }
            frame = incoming.next() => match frame {
                None | Some(Frame::Close { .. }) => return,
                Some(Frame::Other) => {}
                Some(Frame::Text(t)) => match serde_json::from_str::<ClientMsg>(&t) {
                    Ok(ClientMsg::Ping) => {
                        if !send(&mut outgoing, &ServerMsg::Pong).await {
                            return;
                        }
                    }
                    Ok(ClientMsg::Pong) => {
                        awaiting_pong = false;
                        missed = 0;
                    }
                    // A second auth, or something unknown: ignored.
                    Ok(ClientMsg::Auth { .. }) | Err(_) => {}
                },
            },
        }
    }
}

/// Handles one hub message; `None` when the socket is gone.
async fn on_hub<O>(
    out: &mut O,
    sub: &super::hub::Subscription,
    ctx: AccessCtx,
    msg: HubMsg,
) -> Option<Next>
where
    O: Sink<Frame> + Unpin,
{
    let forward = match msg {
        HubMsg::Notify(m) => m,
        HubMsg::Access { vault_id, change } => {
            match change {
                AccessChange::Granted => sub.subscribe(Topic::Vault(vault_id)),
                AccessChange::Revoked => sub.unsubscribe(Topic::Vault(vault_id)),
                AccessChange::Rotated => {}
            }
            ServerMsg::VaultAccess { vault_id, change }
        }
        HubMsg::AccountChanged {
            key_version,
            origin_device,
        } => {
            if origin_device == Some(ctx.device_id) {
                return Some(Next::Continue);
            }
            ServerMsg::AccountChanged { key_version }
        }
        HubMsg::DeviceRevoked { device_id } => {
            return Some(if device_id == ctx.device_id {
                Next::Close(CLOSE_AUTH_REQUIRED, "device revoked")
            } else {
                Next::Continue
            });
        }
        HubMsg::UserDisabled => {
            return Some(Next::Close(CLOSE_AUTH_REQUIRED, "account disabled"));
        }
    };
    send(out, &forward).await.then_some(Next::Continue)
}
