//! HTTP-level tests through the production middleware stack (no database):
//! T-03, T-04, T-05, T-06, T-07, T-08, T-14.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use axum::body::{Body, Bytes};
use axum::extract::{Extension, Path, State};
use axum::http::{StatusCode, header};
use axum::routing::{get, post};
use axum::{Json, Router};
use common::{METRICS_TOKEN, config, json, lazy_state, req, send};
use serde::Deserialize;
use sverb_server::middleware::client_ip::ClientIp;
use sverb_server::{ApiError, AppState, app};

fn error_for(code: &str) -> ApiError {
    match code {
        "conflict" => ApiError::Conflict("c".into()),
        "forbidden" => ApiError::Forbidden("f".into()),
        "not_found" => ApiError::NotFound("n".into()),
        "rate_limited" => ApiError::RateLimited {
            message: "r".into(),
            retry_after_s: 17,
        },
        "invalid" => ApiError::Invalid("i".into()),
        "gone" => ApiError::Gone("g".into()),
        "rotating" => ApiError::Rotating("ro".into()),
        "auth_required" => ApiError::AuthRequired("a".into()),
        _ => ApiError::internal(std::io::Error::other("secret detail")),
    }
}

#[derive(Deserialize)]
struct Login {
    email: String,
}

/// Test routes standing in for later tasks' handlers.
fn test_app(state: AppState) -> Router {
    let extra = Router::new()
        .route(
            "/test/error/{code}",
            get(|Path(code): Path<String>| async move { Err::<(), _>(error_for(&code)) }),
        )
        .route(
            "/test/echo",
            post(|body: Bytes| async move { body.len().to_string() }),
        )
        .route(
            "/test/ip",
            get(|Extension(ClientIp(ip)): Extension<ClientIp>| async move { ip.to_string() }),
        )
        // the real `/v1/auth/login/start`, which now exists in the router).
        .route(
            "/test/login/start",
            post(
                |State(state): State<AppState>,
                 Extension(ClientIp(ip)): Extension<ClientIp>,
                 Json(body): Json<Login>| async move {
                    state.rate_limits().check_login(&body.email, ip)?;
                    Ok::<_, ApiError>(Json(serde_json::json!({ "ok": true })))
                },
            ),
        );
    app::with_layers(app::routes(&state).merge(extra), state)
}

fn get_req(uri: &str) -> axum::http::Request<Body> {
    req("GET", uri, "198.51.100.1:5555")
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn t03_error_envelope_for_every_code() {
    let app = test_app(lazy_state(config(&[])));
    let table = [
        ("conflict", 409, "c"),
        ("forbidden", 403, "f"),
        ("not_found", 404, "n"),
        ("rate_limited", 429, "r"),
        ("invalid", 400, "i"),
        ("gone", 410, "g"),
        ("rotating", 409, "ro"),
        ("auth_required", 401, "a"),
        ("internal", 500, "internal server error"),
    ];
    for (code, status, message) in table {
        let (st, headers, body) = send(&app, get_req(&format!("/test/error/{code}"))).await;
        assert_eq!(st.as_u16(), status, "{code}");
        assert!(
            headers[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("application/json")
        );
        let v = json(&body);
        assert_eq!(v["error"]["code"], code);
        assert_eq!(v["error"]["message"], message);
        let obj = v["error"].as_object().unwrap();
        if code == "rate_limited" {
            assert_eq!(v["error"]["retry_after_s"], 17);
            assert_eq!(headers[header::RETRY_AFTER], "17");
        } else {
            assert!(!obj.contains_key("retry_after_s"), "{code}");
            assert!(headers.get(header::RETRY_AFTER).is_none());
        }
        assert_eq!(v.as_object().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn t03_router_errors_use_the_envelope() {
    let app = test_app(lazy_state(config(&[])));
    let (st, _, body) = send(&app, get_req("/v1/does-not-exist")).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert_eq!(json(&body)["error"]["code"], "not_found");

    let (st, _, body) = send(
        &app,
        req("DELETE", "/healthz", "198.51.100.1:1")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(json(&body)["error"]["code"], "invalid");

    // Extractor rejection (bad JSON) keeps its explanation.
    let (st, _, body) = send(
        &app,
        req("POST", "/test/login/start", "198.51.100.1:1")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("{not json"))
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let v = json(&body);
    assert_eq!(v["error"]["code"], "invalid");
    assert!(!v["error"]["message"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn t04_request_id_echo_generate_replace() {
    let app = test_app(lazy_state(config(&[])));

    let r = req("GET", "/healthz", "198.51.100.1:1")
        .header("x-request-id", "client-supplied-ID-42")
        .body(Body::empty())
        .unwrap();
    let (st, h, _) = send(&app, r).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(h["x-request-id"], "client-supplied-ID-42");

    let (_, h, _) = send(&app, get_req("/healthz")).await;
    let generated = h["x-request-id"].to_str().unwrap();
    let uuid = uuid::Uuid::parse_str(generated).unwrap();
    assert_eq!(uuid.get_version_num(), 7);

    for bad in ["has space", "semi;colon", &"x".repeat(129)] {
        let r = req("GET", "/healthz", "198.51.100.1:1")
            .header("x-request-id", bad)
            .body(Body::empty())
            .unwrap();
        let (_, h, _) = send(&app, r).await;
        let id = h["x-request-id"].to_str().unwrap();
        assert_ne!(id, bad);
        assert_eq!(uuid::Uuid::parse_str(id).unwrap().get_version_num(), 7);
    }

    // Error responses carry it too.
    let r = req("GET", "/test/error/gone", "198.51.100.1:1")
        .header("x-request-id", "err-id")
        .body(Body::empty())
        .unwrap();
    let (_, h, _) = send(&app, r).await;
    assert_eq!(h["x-request-id"], "err-id");
}

#[tokio::test]
async fn t05_protocol_version_negotiation() {
    let app = test_app(lazy_state(config(&[])));
    for (header_value, ok) in [
        (Some("1"), true),
        (Some("0"), true),
        (None, true),
        (Some("5"), false),
        (Some("abc"), false),
    ] {
        let mut b = req("GET", "/healthz", "198.51.100.1:1");
        if let Some(v) = header_value {
            b = b.header("sverb-proto", v);
        }
        let (st, h, body) = send(&app, b.body(Body::empty()).unwrap()).await;
        assert_eq!(h["sverb-proto"], "1", "{header_value:?}");
        if ok {
            assert_eq!(st, StatusCode::OK, "{header_value:?}");
        } else {
            assert_eq!(st, StatusCode::BAD_REQUEST, "{header_value:?}");
            assert_eq!(json(&body)["error"]["code"], "invalid");
        }
    }
    let (_, _, body) = send(
        &app,
        req("GET", "/healthz", "198.51.100.1:1")
            .header("sverb-proto", "5")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let msg = json(&body)["error"]["message"].as_str().unwrap().to_owned();
    assert!(msg.contains("client protocol too new"), "{msg}");
}

fn login(email: &str, peer: &str, xff: Option<&str>) -> axum::http::Request<Body> {
    let mut b =
        req("POST", "/test/login/start", peer).header(header::CONTENT_TYPE, "application/json");
    if let Some(x) = xff {
        b = b.header("x-forwarded-for", x);
    }
    b.body(Body::from(
        serde_json::json!({ "email": email }).to_string(),
    ))
    .unwrap()
}

#[tokio::test]
async fn t06_rate_limit_per_email() {
    let app = test_app(lazy_state(config(&[])));
    for i in 0..5 {
        // Different IPs: only the email limit applies.
        let (st, _, _) = send(
            &app,
            login("bob@example.test", &format!("198.51.100.{i}:1"), None),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "attempt {i}");
    }
    let (st, h, body) = send(&app, login("BOB@example.test", "198.51.100.99:1", None)).await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
    let v = json(&body);
    assert_eq!(v["error"]["code"], "rate_limited");
    let retry = v["error"]["retry_after_s"].as_u64().unwrap();
    assert!((1..=60).contains(&retry));
    assert_eq!(h[header::RETRY_AFTER].to_str().unwrap(), retry.to_string());
    // Another email is unaffected.
    let (st, _, _) = send(&app, login("carol@example.test", "198.51.100.99:1", None)).await;
    assert_eq!(st, StatusCode::OK);
}

#[tokio::test]
async fn t06_rate_limit_per_ip() {
    let app = test_app(lazy_state(config(&[])));
    for i in 0..50 {
        let (st, _, _) = send(
            &app,
            login(&format!("u{i}@example.test"), "203.0.113.5:1", None),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "attempt {i}");
    }
    let (st, _, body) = send(&app, login("u50@example.test", "203.0.113.5:1", None)).await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(json(&body)["error"]["code"], "rate_limited");
    let (st, _, _) = send(&app, login("u50@example.test", "203.0.113.6:1", None)).await;
    assert_eq!(st, StatusCode::OK);
}

#[tokio::test]
async fn t07_forwarded_for_ignored_unless_proxy_trusted() {
    // Untrusted: the peer address is used, the header is ignored.
    let app = test_app(lazy_state(config(&[])));
    let r = req("GET", "/test/ip", "10.1.2.3:1")
        .header("x-forwarded-for", "192.0.2.77")
        .body(Body::empty())
        .unwrap();
    let (_, _, body) = send(&app, r).await;
    assert_eq!(&body[..], b"10.1.2.3");
    // ...so rotating X-Forwarded-For does not evade the per-IP limit.
    for i in 0..50 {
        let (st, _, _) = send(
            &app,
            login(
                &format!("x{i}@example.test"),
                "10.1.2.3:1",
                Some(&format!("192.0.2.{i}")),
            ),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
    }
    let (st, _, _) = send(
        &app,
        login("x50@example.test", "10.1.2.3:1", Some("192.0.2.250")),
    )
    .await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);

    // Trusted proxy: the forwarded client address is used.
    let app = test_app(lazy_state(config(&[(
        "SVERB_TRUSTED_PROXIES",
        "10.0.0.0/8",
    )])));
    let r = req("GET", "/test/ip", "10.1.2.3:1")
        .header("x-forwarded-for", "6.6.6.6, 192.0.2.77")
        .body(Body::empty())
        .unwrap();
    let (_, _, body) = send(&app, r).await;
    assert_eq!(&body[..], b"192.0.2.77");
    for i in 0..60 {
        let (st, _, _) = send(
            &app,
            login(
                &format!("y{i}@example.test"),
                "10.1.2.3:1",
                Some(&format!("192.0.2.{i}")),
            ),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "attempt {i}");
    }
}

#[tokio::test]
async fn t08_metrics_requires_token() {
    let app = test_app(lazy_state(config(&[(
        "SVERB_METRICS_TOKEN",
        METRICS_TOKEN,
    )])));
    let (st, _, _) = send(&app, get_req("/healthz")).await;
    assert_eq!(st, StatusCode::OK);

    let (st, _, body) = send(&app, get_req("/metrics")).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(json(&body)["error"]["code"], "auth_required");

    let wrong = req("GET", "/metrics", "198.51.100.1:1")
        .header(header::AUTHORIZATION, "Bearer nope-nope-nope-nope")
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&app, wrong).await.0, StatusCode::UNAUTHORIZED);

    let ok = req("GET", "/metrics", "198.51.100.1:1")
        .header(header::AUTHORIZATION, format!("Bearer {METRICS_TOKEN}"))
        .body(Body::empty())
        .unwrap();
    let (st, h, body) = send(&app, ok).await;
    assert_eq!(st, StatusCode::OK);
    assert!(
        h[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/plain")
    );
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(text.contains("http_requests_total"), "{text}");
    assert!(text.contains("route=\"/healthz\""), "{text}");
    assert!(
        text.contains("http_request_duration_seconds_bucket"),
        "{text}"
    );
    assert!(text.contains("sverb_ws_connections_active"), "{text}");
}

#[tokio::test]
async fn metrics_not_exposed_without_token_or_bind() {
    let app = test_app(lazy_state(config(&[])));
    let (st, _, body) = send(&app, get_req("/metrics")).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert_eq!(json(&body)["error"]["code"], "not_found");
}

#[tokio::test]
async fn healthz_ok_and_readyz_503_without_database() {
    let app = test_app(lazy_state(config(&[])));
    let (st, _, body) = send(&app, get_req("/healthz")).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(json(&body)["status"], "ok");
    let (st, _, body) = send(&app, get_req("/readyz")).await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
    let v = json(&body);
    assert_eq!(v["status"], "not_ready");
    assert_eq!(v["database"], "unreachable");
}

#[tokio::test]
async fn t14_body_limit_maps_to_invalid_too_large() {
    let app = test_app(lazy_state(config(&[])));
    // Follows the limit (12 MiB since the push batch needs it).
    let big = vec![b'x'; app::BODY_LIMIT + 1024 * 1024];

    // With Content-Length: rejected up front.
    let r = req("POST", "/test/echo", "198.51.100.1:1")
        .header(header::CONTENT_LENGTH, big.len())
        .body(Body::from(big.clone()))
        .unwrap();
    let (st, _, body) = send(&app, r).await;
    assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE);
    let v = json(&body);
    assert_eq!(v["error"]["code"], "invalid");
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("too large")
    );

    // Streaming without Content-Length: rejected while reading.
    let stream = futures_stream(big);
    let r = req("POST", "/test/echo", "198.51.100.1:1")
        .body(stream)
        .unwrap();
    let (st, _, body) = send(&app, r).await;
    assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE);
    let v = json(&body);
    assert_eq!(v["error"]["code"], "invalid");
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("too large")
    );

    // Just under the limit passes.
    let ok = vec![b'y'; 8 * 1024 * 1024];
    let r = req("POST", "/test/echo", "198.51.100.1:1")
        .body(Body::from(ok))
        .unwrap();
    let (st, _, body) = send(&app, r).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(&body[..], (8 * 1024 * 1024).to_string().as_bytes());
}

/// A body without a known size (chunked upload).
fn futures_stream(data: Vec<u8>) -> Body {
    let chunks: Vec<Result<Bytes, std::io::Error>> = data
        .chunks(64 * 1024)
        .map(|c| Ok(Bytes::copy_from_slice(c)))
        .collect();
    Body::from_stream(tokio_stream_iter(chunks))
}

fn tokio_stream_iter(
    items: Vec<Result<Bytes, std::io::Error>>,
) -> impl futures_core::Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static {
    struct Iter(std::vec::IntoIter<Result<Bytes, std::io::Error>>);
    impl futures_core::Stream for Iter {
        type Item = Result<Bytes, std::io::Error>;
        fn poll_next(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            std::task::Poll::Ready(self.0.next())
        }
    }
    Iter(items.into_iter())
}

#[tokio::test]
async fn cors_denies_by_default_and_allows_configured_origins() {
    let app = test_app(lazy_state(config(&[])));
    let r = req("GET", "/healthz", "198.51.100.1:1")
        .header(header::ORIGIN, "https://evil.example")
        .body(Body::empty())
        .unwrap();
    let (_, h, _) = send(&app, r).await;
    assert!(h.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());

    let app = test_app(lazy_state(config(&[(
        "SVERB_CORS_ORIGINS",
        "https://viewer.example.test",
    )])));
    let r = req("GET", "/healthz", "198.51.100.1:1")
        .header(header::ORIGIN, "https://viewer.example.test")
        .body(Body::empty())
        .unwrap();
    let (_, h, _) = send(&app, r).await;
    assert_eq!(
        h[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "https://viewer.example.test"
    );
}
