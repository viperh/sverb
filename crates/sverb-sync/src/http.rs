//! The HTTP client of the sync API (§10.4): reqwest over rustls (`ring`),
//! `Sverb-Proto: 1` on every request, a 30 s timeout, and the base URL from
//! `sync_state.server_url` (there is no default server, §1.1).
//!
//! Plain `http://` is accepted for loopback servers only (development and
//! tests); everything else must be `https://`.

use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde::Serialize;
use serde::de::DeserializeOwned;
use sverb_proto::ErrorEnvelope;
use sverb_proto::auth::{RefreshRequest, TokenPair};
use sverb_proto::sync::{PullResponse, PushRequest, PushResponse, VaultView};
use sverb_proto::version::{API_PREFIX, PROTO_HEADER, PROTO_VERSION};
use uuid::Uuid;

use crate::error::SyncError;

/// Request timeout (§12.5).
pub const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// The sync API client. Cheap to clone.
#[derive(Debug, Clone)]
pub struct ApiClient {
    base: String,
    http: reqwest::Client,
}

fn is_loopback_http(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = if let Some(v6) = host.strip_prefix('[') {
        v6.split(']').next().unwrap_or("")
    } else {
        host.rsplit_once(':').map_or(host, |(h, _)| h)
    };
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

impl ApiClient {
    /// A client for the server at `base_url` (`https://sync.example.com`).
    /// `tls` defaults to the `ring` provider with the webpki roots
    /// ([`crate::ws::default_tls`]); the WebSocket client should get the same.
    ///
    /// # Errors
    /// [`SyncError::NotConfigured`] for an empty or non-https URL,
    /// [`SyncError::Transport`] if the client can't be built.
    pub fn new(
        base_url: &str,
        tls: Option<Arc<rustls::ClientConfig>>,
        timeout: Duration,
    ) -> Result<Self, SyncError> {
        let base = base_url.trim().trim_end_matches('/').to_owned();
        if base.is_empty() {
            return Err(SyncError::NotConfigured("no server URL"));
        }
        if !base.starts_with("https://") && !is_loopback_http(&base) {
            return Err(SyncError::NotConfigured(
                "the server URL must start with https://",
            ));
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            PROTO_HEADER,
            HeaderValue::from_str(&PROTO_VERSION.to_string())
                .map_err(|e| SyncError::Transport(e.to_string()))?,
        );
        let tls = tls.unwrap_or_else(crate::ws::default_tls);
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout.min(Duration::from_secs(10)))
            .default_headers(headers)
            .use_preconfigured_tls((*tls).clone())
            .build()
            .map_err(|e| SyncError::Transport(e.to_string()))?;
        Ok(Self { base, http })
    }

    /// The base URL (no trailing slash).
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base
    }

    fn url(&self, path: &str) -> String {
        format!("{}{API_PREFIX}{path}", self.base)
    }

    async fn send<T: DeserializeOwned>(&self, rb: reqwest::RequestBuilder) -> Result<T, SyncError> {
        let (status, _, bytes) = self.fetch(rb).await?;
        serde_json::from_slice(&bytes).map_err(|e| SyncError::Api {
            status,
            code: None,
            message: format!("unexpected response body: {e}"),
        })
    }

    // M4-08: `send` split so bodiless responses (204) and headers are usable.
    /// Sends `rb`; a 2xx gives `(status, headers, body)`, anything else the
    /// error envelope as [`SyncError::Api`].
    async fn fetch(
        &self,
        rb: reqwest::RequestBuilder,
    ) -> Result<(u16, HeaderMap, Vec<u8>), SyncError> {
        let resp = rb
            .send()
            .await
            .map_err(|e| SyncError::Transport(transport_message(&e)))?;
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| SyncError::Transport(transport_message(&e)))?;
        if status.is_success() {
            return Ok((status.as_u16(), headers, bytes.to_vec()));
        }
        let (code, message) = match serde_json::from_slice::<ErrorEnvelope>(&bytes) {
            Ok(env) => (Some(env.error.code), env.error.message),
            Err(_) => (
                None,
                status.canonical_reason().unwrap_or("error").to_owned(),
            ),
        };
        Err(SyncError::Api {
            status: status.as_u16(),
            code,
            message,
        })
    }

    fn authed(&self, rb: reqwest::RequestBuilder, token: &str) -> reqwest::RequestBuilder {
        rb.header(AUTHORIZATION, format!("Bearer {token}"))
    }

    async fn post_json<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        token: Option<&str>,
    ) -> Result<T, SyncError> {
        let mut rb = self.http.post(self.url(path)).json(body);
        if let Some(t) = token {
            rb = self.authed(rb, t);
        }
        self.send(rb).await
    }

    // M4-08: the account endpoints (`crate::account`).
    /// `POST /v1{path}` with a JSON body and a JSON response.
    pub(crate) async fn post_v1<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        token: Option<&str>,
    ) -> Result<T, SyncError> {
        self.post_json(path, body, token).await
    }

    /// `POST /v1{path}` whose success response has no body (204 / 202).
    pub(crate) async fn post_v1_empty<B: Serialize + ?Sized>(
        &self,
        path: &str,
        body: Option<&B>,
        token: Option<&str>,
    ) -> Result<(), SyncError> {
        let mut rb = self.http.post(self.url(path));
        if let Some(b) = body {
            rb = rb.json(b);
        }
        if let Some(t) = token {
            rb = self.authed(rb, t);
        }
        self.fetch(rb).await.map(drop)
    }

    /// `GET /healthz` (outside `/v1`): whether the server is up, and the
    /// protocol version it echoes in `Sverb-Proto` (`None` when absent).
    ///
    /// # Errors
    /// [`SyncError::Transport`] / [`SyncError::Api`].
    pub async fn probe(&self) -> Result<Option<u32>, SyncError> {
        let rb = self.http.get(format!("{}/healthz", self.base));
        let (_, headers, _) = self.fetch(rb).await?;
        Ok(headers
            .get(PROTO_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse().ok()))
    }

    /// `GET /v1/vaults`.
    ///
    /// # Errors
    /// [`SyncError::Api`] / [`SyncError::Transport`].
    pub async fn list_vaults(&self, token: &str) -> Result<Vec<VaultView>, SyncError> {
        let rb = self.authed(self.http.get(self.url("/vaults")), token);
        self.send(rb).await
    }

    // M5-03: the keys are pinned and compared by `crate::trust` (§13.3).
    /// `GET /v1/users/{id}/public-keys`.
    ///
    /// # Errors
    /// [`SyncError::Api`] (`404 not_found`) / [`SyncError::Transport`].
    pub async fn user_public_keys(
        &self,
        token: &str,
        user: Uuid,
    ) -> Result<sverb_proto::users::UserPublicKeys, SyncError> {
        let url = self.url(&format!("/users/{user}/public-keys"));
        let rb = self.authed(self.http.get(url), token);
        self.send(rb).await
    }

    /// `GET /v1/vaults/{id}/changes?since=&limit=` (§12.2).
    ///
    /// # Errors
    /// [`SyncError::Api`] (`410 gone` below the GC floor) /
    /// [`SyncError::Transport`].
    pub async fn pull(
        &self,
        token: &str,
        vault: Uuid,
        since: u64,
        limit: u32,
    ) -> Result<PullResponse, SyncError> {
        let url = self.url(&format!(
            "/vaults/{vault}/changes?since={since}&limit={limit}"
        ));
        let rb = self.authed(self.http.get(url), token);
        self.send(rb).await
    }

    /// `POST /v1/vaults/{id}/changes` (§12.3).
    ///
    /// # Errors
    /// [`SyncError::Api`] (`403 forbidden`, `409 rotating`, `400 invalid`) /
    /// [`SyncError::Transport`].
    pub async fn push(
        &self,
        token: &str,
        vault: Uuid,
        req: &PushRequest,
    ) -> Result<PushResponse, SyncError> {
        self.post_json(&format!("/vaults/{vault}/changes"), req, Some(token))
            .await
    }

    /// `POST /v1/auth/refresh`: rotates the token pair.
    ///
    /// # Errors
    /// [`SyncError::Api`] (`401 auth_required` for an invalid or reused
    /// refresh token) / [`SyncError::Transport`].
    pub async fn refresh(&self, refresh_token: &str) -> Result<TokenPair, SyncError> {
        let req = RefreshRequest {
            refresh_token: refresh_token.to_owned(),
        };
        self.post_json("/auth/refresh", &req, None).await
    }
}

/// reqwest's error with its source chain (the top-level message alone is
/// often just "error sending request").
fn transport_message(e: &reqwest::Error) -> String {
    use std::error::Error as _;
    let mut msg = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        msg.push_str(": ");
        msg.push_str(&s.to_string());
        src = s.source();
    }
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_required_except_loopback() {
        assert!(ApiClient::new("https://sync.example.com/", None, HTTP_TIMEOUT).is_ok());
        assert!(ApiClient::new("http://127.0.0.1:8080", None, HTTP_TIMEOUT).is_ok());
        assert!(ApiClient::new("http://localhost:1/x", None, HTTP_TIMEOUT).is_ok());
        assert!(ApiClient::new("http://[::1]:9", None, HTTP_TIMEOUT).is_ok());
        assert!(matches!(
            ApiClient::new("http://sync.example.com", None, HTTP_TIMEOUT),
            Err(SyncError::NotConfigured(_))
        ));
        assert!(matches!(
            ApiClient::new("", None, HTTP_TIMEOUT),
            Err(SyncError::NotConfigured(_))
        ));
        let c = ApiClient::new("https://a.example/", None, HTTP_TIMEOUT).unwrap_or_else(|_| {
            unreachable!("valid URL");
        });
        assert_eq!(c.url("/vaults"), "https://a.example/v1/vaults");
    }
}
