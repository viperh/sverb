//! `/v1/shares` (SPEC §10.4 "Sharing"; task M6-01).

use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{delete, get, post};
use axum::{Extension, Json, Router};
use futures::{SinkExt, StreamExt};
use sverb_proto::share::{CreateShareRequest, CreateShareResponse, MAX_RELAY_MESSAGE};
use uuid::Uuid;

use super::ShareLimits;
use super::relay::{RelayFrame, end_share, run_host, run_viewer};
use super::sessions::ShareRow;
use crate::auth::AuthCtx;
use crate::error::ApiError;
use crate::middleware::client_ip::ClientIp;
use crate::state::AppState;

/// `/shares` routes (nested under `/v1`).
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/shares", post(create))
        .route("/shares/{id}", delete(remove))
        .route("/shares/{id}/host", get(host))
        .route("/shares/{id}/join", get(join))
}

/// The effective `(lifetime, max_viewers)` of a request: defaults to and
/// clamped at the configured limits; `0` is invalid.
///
/// # Errors
/// `Invalid` for a zero lifetime or viewer cap.
pub fn effective(
    req: &CreateShareRequest,
    limits: ShareLimits,
) -> Result<(Duration, u32), ApiError> {
    let ttl = match req.expires_in_s {
        None => limits.max_ttl,
        Some(0) => return Err(ApiError::Invalid("expires_in_s must be positive".into())),
        Some(s) => Duration::from_secs(s).min(limits.max_ttl),
    };
    let max_viewers = match req.max_viewers {
        None => limits.max_viewers,
        Some(0) => return Err(ApiError::Invalid("max_viewers must be positive".into())),
        Some(n) => n.min(limits.max_viewers),
    };
    Ok((ttl, max_viewers))
}

async fn create(
    State(state): State<AppState>,
    ctx: AuthCtx,
    Json(req): Json<CreateShareRequest>,
) -> Result<Json<CreateShareResponse>, ApiError> {
    let (ttl, max_viewers) = effective(&req, state.shares().limits())?;
    let now = state.auth().now();
    let ttl = chrono::Duration::from_std(ttl).map_err(ApiError::internal)?;
    let row = ShareRow {
        id: Uuid::now_v7(),
        owner_user_id: ctx.user_id,
        created_at: now,
        expires_at: now + ttl,
        mode: req.mode,
        max_viewers,
        require_account: req.require_account,
        closed_at: None,
    };
    state.shares().store().create(&row).await?;
    tracing::info!(share_id = %row.id, user_id = %ctx.user_id, mode = row.mode.as_str(), "share created");
    Ok(Json(CreateShareResponse {
        share_id: row.id,
        expires_at: row.expires_at,
        max_viewers,
    }))
}

async fn remove(
    State(state): State<AppState>,
    ctx: AuthCtx,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    match state.shares().store().get(id).await? {
        Some(row) if row.owner_user_id == ctx.user_id => {}
        // Someone else's share is indistinguishable from none.
        _ => return Err(ApiError::NotFound("no such share".into())),
    }
    end_share(&state, id, "ended by host").await?;
    Ok(StatusCode::NO_CONTENT)
}

fn limited(ws: WebSocketUpgrade) -> WebSocketUpgrade {
    ws.max_message_size(MAX_RELAY_MESSAGE)
        .max_frame_size(MAX_RELAY_MESSAGE)
}

async fn host(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    ws: WebSocketUpgrade,
) -> Response {
    limited(ws).on_upgrade(move |socket| async move {
        let (incoming, outgoing) = adapt(socket);
        run_host(state, id, incoming, outgoing).await;
    })
}

async fn join(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    ip: Option<Extension<ClientIp>>,
    ws: WebSocketUpgrade,
) -> Response {
    let ip = ip.map(|Extension(ClientIp(ip))| ip);
    limited(ws).on_upgrade(move |socket| async move {
        let (incoming, outgoing) = adapt(socket);
        run_viewer(state, id, ip, incoming, outgoing).await;
    })
}

fn from_axum(msg: Message) -> RelayFrame {
    match msg {
        Message::Text(t) => RelayFrame::Text(t.as_str().to_owned()),
        Message::Binary(b) => RelayFrame::Binary(b.to_vec()),
        Message::Close(c) => RelayFrame::Close {
            code: c.as_ref().map_or(1005, |c| c.code),
            reason: c.map(|c| c.reason.as_str().to_owned()).unwrap_or_default(),
        },
        Message::Ping(_) | Message::Pong(_) => RelayFrame::Other,
    }
}

fn to_axum(frame: RelayFrame) -> Message {
    match frame {
        RelayFrame::Text(t) => Message::Text(t.into()),
        RelayFrame::Binary(b) => Message::Binary(b.into()),
        RelayFrame::Close { code, reason } => Message::Close(Some(CloseFrame {
            code,
            reason: reason.into(),
        })),
        RelayFrame::Other => Message::Ping(Default::default()),
    }
}

/// axum's socket as a [`RelayFrame`] stream and sink.
fn adapt(
    socket: WebSocket,
) -> (
    impl futures::Stream<Item = RelayFrame> + Unpin + Send,
    impl futures::Sink<RelayFrame> + Unpin + Send + 'static,
) {
    let (sink, stream) = socket.split();
    let incoming = stream.filter_map(|m| std::future::ready(m.ok().map(from_axum)));
    let outgoing = sink.with(|f: RelayFrame| std::future::ready(Ok::<_, axum::Error>(to_axum(f))));
    (incoming, Box::pin(outgoing))
}
