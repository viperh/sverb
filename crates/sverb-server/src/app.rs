//! Router assembly and the middleware stack (SPEC §10.1, §10.4).
//!
//! Request flow, outermost first:
//! 1. request ID (assign/validate, echo),
//! 2. tracing span carrying the request ID,
//! 3. error normalisation (bare 404/405/408/413/5xx → JSON envelope),
//! 4. metrics (`http_requests_total`, latency),
//! 5. `Sverb-Proto` negotiation,
//! 6. compression, CORS,
//! 7. client IP resolution (trusted proxies),
//! 8. body limit (12 MiB), timeout,
//! 9. the route.

use axum::Router;
use axum::extract::{DefaultBodyLimit, Request};
use axum::http::{HeaderName, HeaderValue, Method, StatusCode, header};
use axum::middleware::{from_fn, from_fn_with_state};
use sverb_proto::version::{API_PREFIX, PROTO_HEADER, REQUEST_ID_HEADER};
use tower::ServiceBuilder;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::middleware::{client_ip, errors, proto_version, request_id};
use crate::routes;
use crate::state::AppState;

/// Request body limit: the push batch's 8 MiB of envelopes plus JSON and
/// base64 overhead (M4-04: base64 alone makes 8 MiB into 10.7 MiB, so the
/// former 9 MiB rejected valid batches with 413 before the handler could
/// apply the §10.5 limit).
pub const BODY_LIMIT: usize = 12 * 1024 * 1024;

/// All routes without middleware: ops endpoints at the root, the API under
/// `/v1`.
pub fn routes(state: &AppState) -> Router<AppState> {
    Router::new()
        .merge(routes::ops::router(state))
        .nest(API_PREFIX, routes::api_v1())
}

/// The complete application.
pub fn router(state: AppState) -> Router {
    with_layers(routes(&state), state)
}

fn cors(state: &AppState) -> CorsLayer {
    let origins: Vec<HeaderValue> = state
        .config()
        .cors_allowed_origins
        .iter()
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();
    // No allowed origins: CorsLayer::new() adds no allow-origin header, so
    // browsers reject every cross-origin request (deny by default).
    if origins.is_empty() {
        return CorsLayer::new();
    }
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            HeaderName::from_static(PROTO_HEADER),
            HeaderName::from_static(REQUEST_ID_HEADER),
        ])
        .expose_headers([
            HeaderName::from_static(PROTO_HEADER),
            HeaderName::from_static(REQUEST_ID_HEADER),
            header::RETRY_AFTER,
        ])
}

/// Applies the middleware stack and state to `router`. Tests use this to
/// wrap extra routes in exactly the production stack.
pub fn with_layers(router: Router<AppState>, state: AppState) -> Router {
    let trace = TraceLayer::new_for_http().make_span_with(|req: &Request| {
        let rid = req
            .extensions()
            .get::<request_id::RequestId>()
            .map_or("", |r| r.0.as_str());
        tracing::info_span!(
            "request",
            method = %req.method(),
            path = %req.uri().path(),
            request_id = %rid,
        )
    });
    let stack = ServiceBuilder::new()
        .layer(from_fn(request_id::layer))
        .layer(trace)
        .layer(from_fn(errors::layer))
        .layer(from_fn(crate::metrics::layer))
        .layer(from_fn(proto_version::layer))
        .layer(CompressionLayer::new())
        .layer(cors(&state))
        .layer(from_fn_with_state(state.clone(), client_ip::layer))
        .layer(RequestBodyLimitLayer::new(BODY_LIMIT))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            state.config().request_timeout,
        ))
        .layer(DefaultBodyLimit::max(BODY_LIMIT));
    router.layer(stack).with_state(state)
}
