//! Prometheus metrics (SPEC §18, §10.4).
//!
//! One process-wide recorder is installed on first use ([`handle`]); later
//! tasks record into it with the `metrics` macros and the names below, so
//! dashboards keep working:
//!
//! | Name | Kind | Labels | Recorded by |
//! |---|---|---|---|
//! | `http_requests_total` | counter | `method`, `route`, `status` | [`layer`] |
//! | `http_request_duration_seconds` | histogram | `method`, `route` | [`layer`] |
//! | `sverb_ws_connections_active` | gauge | | M4-05 |
//! | `sverb_ws_messages_sent_total` | counter | | M4-05 |
//! | `sverb_sync_push_items_total`, `sverb_sync_push_bytes_total` | counter | | M4-04 |
//! | `sverb_sync_pull_items_total`, `sverb_sync_pull_bytes_total` | counter | | M4-04 |
//! | `sverb_share_relays_active`, `sverb_share_viewers_active` | gauge | | M6-01 |
//! | `sverb_share_bytes_relayed_total` | counter | | M6-01 |

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use axum::extract::{MatchedPath, Request};
use axum::middleware::Next;
use axum::response::Response;
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};

/// HTTP requests by method, route template and status.
pub const HTTP_REQUESTS_TOTAL: &str = "http_requests_total";
/// HTTP latency histogram by method and route template.
pub const HTTP_REQUEST_DURATION_SECONDS: &str = "http_request_duration_seconds";
/// Open WebSocket connections.
pub const WS_CONNECTIONS_ACTIVE: &str = "sverb_ws_connections_active";
/// M4-05: WebSocket messages sent (notifications and heartbeats).
pub const WS_MESSAGES_SENT_TOTAL: &str = "sverb_ws_messages_sent_total";
/// Items accepted by push.
pub const SYNC_PUSH_ITEMS_TOTAL: &str = "sverb_sync_push_items_total";
/// Envelope bytes accepted by push.
pub const SYNC_PUSH_BYTES_TOTAL: &str = "sverb_sync_push_bytes_total";
/// Items returned by pull.
pub const SYNC_PULL_ITEMS_TOTAL: &str = "sverb_sync_pull_items_total";
/// Envelope bytes returned by pull.
pub const SYNC_PULL_BYTES_TOTAL: &str = "sverb_sync_pull_bytes_total";
/// Active share relays.
pub const SHARE_RELAYS_ACTIVE: &str = "sverb_share_relays_active";
/// Connected share viewers.
pub const SHARE_VIEWERS_ACTIVE: &str = "sverb_share_viewers_active";
/// M6-01: relayed share bytes (both directions, envelope header included).
pub const SHARE_BYTES_RELAYED_TOTAL: &str = "sverb_share_bytes_relayed_total";

/// How often histogram/summary upkeep runs.
pub const UPKEEP_INTERVAL: Duration = Duration::from_secs(5);

const LATENCY_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];

static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

fn describe_all() {
    use metrics::{Unit, describe_counter, describe_gauge, describe_histogram};
    describe_counter!(
        HTTP_REQUESTS_TOTAL,
        "HTTP requests by method, route and status"
    );
    describe_histogram!(
        HTTP_REQUEST_DURATION_SECONDS,
        Unit::Seconds,
        "HTTP request latency by method and route"
    );
    describe_gauge!(WS_CONNECTIONS_ACTIVE, "Open WebSocket connections");
    describe_counter!(WS_MESSAGES_SENT_TOTAL, "WebSocket messages sent");
    describe_counter!(SYNC_PUSH_ITEMS_TOTAL, "Items accepted by push");
    describe_counter!(
        SYNC_PUSH_BYTES_TOTAL,
        Unit::Bytes,
        "Envelope bytes accepted by push"
    );
    describe_counter!(SYNC_PULL_ITEMS_TOTAL, "Items returned by pull");
    describe_counter!(
        SYNC_PULL_BYTES_TOTAL,
        Unit::Bytes,
        "Envelope bytes returned by pull"
    );
    describe_gauge!(SHARE_RELAYS_ACTIVE, "Active terminal-share relays");
    describe_gauge!(SHARE_VIEWERS_ACTIVE, "Connected terminal-share viewers");
    describe_counter!(
        SHARE_BYTES_RELAYED_TOTAL,
        Unit::Bytes,
        "Terminal-share bytes relayed"
    );
    // Register the non-HTTP series at zero so they are scrapeable from the start.
    metrics::gauge!(WS_CONNECTIONS_ACTIVE).set(0.0);
    metrics::counter!(WS_MESSAGES_SENT_TOTAL).absolute(0);
    metrics::counter!(SYNC_PUSH_ITEMS_TOTAL).absolute(0);
    metrics::counter!(SYNC_PUSH_BYTES_TOTAL).absolute(0);
    metrics::counter!(SYNC_PULL_ITEMS_TOTAL).absolute(0);
    metrics::counter!(SYNC_PULL_BYTES_TOTAL).absolute(0);
    metrics::gauge!(SHARE_RELAYS_ACTIVE).set(0.0);
    metrics::gauge!(SHARE_VIEWERS_ACTIVE).set(0.0);
    metrics::counter!(SHARE_BYTES_RELAYED_TOTAL).absolute(0);
}

/// The process-wide Prometheus handle, installing the recorder on first call.
///
/// If another global recorder was installed first (never in this binary),
/// a detached recorder is used and rendering yields only its own data.
pub fn handle() -> PrometheusHandle {
    HANDLE
        .get_or_init(|| {
            let builder = PrometheusBuilder::new();
            let builder = match builder.set_buckets_for_metric(
                Matcher::Full(HTTP_REQUEST_DURATION_SECONDS.to_owned()),
                LATENCY_BUCKETS,
            ) {
                Ok(b) => b,
                Err(_) => PrometheusBuilder::new(),
            };
            let recorder = builder.build_recorder();
            let handle = recorder.handle();
            if metrics::set_global_recorder(recorder).is_ok() {
                describe_all();
            } else {
                tracing::warn!("a metrics recorder was already installed; /metrics may be empty");
            }
            handle
        })
        .clone()
}

/// Runs histogram upkeep every [`UPKEEP_INTERVAL`].
pub fn spawn_upkeep(handle: PrometheusHandle) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(UPKEEP_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            handle.run_upkeep();
        }
    })
}

/// Records `http_requests_total` and `http_request_duration_seconds`.
/// Unmatched paths share the route label `unmatched` (bounded cardinality).
pub async fn layer(req: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = req.method().as_str().to_owned();
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "unmatched".to_owned(), |p| p.as_str().to_owned());
    let resp = next.run(req).await;
    let status = resp.status().as_u16().to_string();
    metrics::counter!(
        HTTP_REQUESTS_TOTAL,
        "method" => method.clone(),
        "route" => route.clone(),
        "status" => status
    )
    .increment(1);
    metrics::histogram!(
        HTTP_REQUEST_DURATION_SECONDS,
        "method" => method,
        "route" => route
    )
    .record(start.elapsed().as_secs_f64());
    resp
}
