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

// The shared vault endpoints (create, members, grants, org vaults).
mod shared_vaults;
// The key rotation endpoint.
mod rotation;

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

    // `send` split so bodiless responses (204) and headers are usable.
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

    // The account endpoints (`crate::account`).
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

    // The keys are pinned and compared by `crate::trust` (§13.3).
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

    // Settings → Devices and `sverb devices`.
    /// `GET /v1/devices`.
    ///
    /// # Errors
    /// [`SyncError::Api`] / [`SyncError::Transport`].
    pub async fn list_devices(
        &self,
        token: &str,
    ) -> Result<Vec<sverb_proto::auth::DeviceView>, SyncError> {
        let rb = self.authed(self.http.get(self.url("/devices")), token);
        self.send(rb).await
    }

    /// `DELETE /v1/devices/{id}`: revokes the device and its tokens.
    ///
    /// # Errors
    /// [`SyncError::Api`] (`404 not_found`) / [`SyncError::Transport`].
    pub async fn revoke_device(&self, token: &str, device: Uuid) -> Result<(), SyncError> {
        let url = self.url(&format!("/devices/{device}"));
        let rb = self.authed(self.http.delete(url), token);
        self.fetch(rb).await.map(drop)
    }

    // Orgs, members, invites, the audit log.
    /// `GET /v1/orgs`.
    ///
    /// # Errors
    /// [`SyncError::Api`] / [`SyncError::Transport`].
    pub async fn list_orgs(
        &self,
        token: &str,
    ) -> Result<Vec<sverb_proto::orgs::OrgView>, SyncError> {
        let rb = self.authed(self.http.get(self.url("/orgs")), token);
        self.send(rb).await
    }

    /// `POST /v1/orgs`.
    ///
    /// # Errors
    /// [`SyncError::Api`] / [`SyncError::Transport`].
    pub async fn create_org(
        &self,
        token: &str,
        name: &str,
    ) -> Result<sverb_proto::orgs::OrgView, SyncError> {
        let req = sverb_proto::orgs::CreateOrgRequest {
            name: name.to_owned(),
        };
        self.post_json("/orgs", &req, Some(token)).await
    }

    /// `GET /v1/orgs/{id}/members`.
    ///
    /// # Errors
    /// [`SyncError::Api`] (`404` for an org the caller is not in) / [`SyncError::Transport`].
    pub async fn org_members(
        &self,
        token: &str,
        org: Uuid,
    ) -> Result<Vec<sverb_proto::orgs::MemberView>, SyncError> {
        let rb = self.authed(
            self.http.get(self.url(&format!("/orgs/{org}/members"))),
            token,
        );
        self.send(rb).await
    }

    /// `PATCH /v1/orgs/{id}/members/{user}`.
    ///
    /// # Errors
    /// [`SyncError::Api`] (`403`, `400` last owner) / [`SyncError::Transport`].
    pub async fn set_member_role(
        &self,
        token: &str,
        org: Uuid,
        user: Uuid,
        role: sverb_proto::orgs::Role,
    ) -> Result<(), SyncError> {
        let req = sverb_proto::orgs::UpdateMemberRequest { role };
        let url = self.url(&format!("/orgs/{org}/members/{user}"));
        let rb = self.authed(self.http.patch(url).json(&req), token);
        self.fetch(rb).await.map(drop)
    }

    /// `DELETE /v1/orgs/{id}/members/{user}` (also leaving: `user` = self).
    ///
    /// # Errors
    /// [`SyncError::Api`] / [`SyncError::Transport`].
    pub async fn remove_member(&self, token: &str, org: Uuid, user: Uuid) -> Result<(), SyncError> {
        let url = self.url(&format!("/orgs/{org}/members/{user}"));
        let rb = self.authed(self.http.delete(url), token);
        self.fetch(rb).await.map(drop)
    }

    /// `POST /v1/orgs/{id}/invites`.
    ///
    /// # Errors
    /// [`SyncError::Api`] (`403`) / [`SyncError::Transport`].
    pub async fn create_invite(
        &self,
        token: &str,
        org: Uuid,
        req: &sverb_proto::orgs::CreateInviteRequest,
    ) -> Result<sverb_proto::orgs::InviteCreated, SyncError> {
        self.post_json(&format!("/orgs/{org}/invites"), req, Some(token))
            .await
    }

    /// `POST /v1/invites/{token}/accept`.
    ///
    /// # Errors
    /// [`SyncError::Api`] (`404` used/expired, `403` other email) / [`SyncError::Transport`].
    pub async fn accept_invite(
        &self,
        token: &str,
        invite_token: &str,
    ) -> Result<sverb_proto::orgs::InviteAccepted, SyncError> {
        let url = self.url(&format!("/invites/{invite_token}/accept"));
        let rb = self.authed(self.http.post(url), token);
        self.send(rb).await
    }

    /// `GET /v1/orgs/{id}/audit?before=&limit=`.
    ///
    /// # Errors
    /// [`SyncError::Api`] (`403` for members) / [`SyncError::Transport`].
    pub async fn org_audit(
        &self,
        token: &str,
        org: Uuid,
        before: Option<i64>,
        limit: u32,
    ) -> Result<sverb_proto::orgs::AuditPage, SyncError> {
        let mut path = format!("/orgs/{org}/audit?limit={limit}");
        if let Some(b) = before {
            path.push_str(&format!("&before={b}"));
        }
        let rb = self.authed(self.http.get(self.url(&path)), token);
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
