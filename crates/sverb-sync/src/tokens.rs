//! The token manager (§12.5, M4-02 §2.2).
//!
//! * The access and refresh tokens are stored in `sync_state.tokens_enc`,
//!   AEAD-wrapped under the LMK (purpose [`WrapPurpose::SyncTokens`]).
//! * The access token is refreshed 60 s before it expires, and after a 401.
//! * A refresh **persists the new pair before it is used**: refresh tokens are
//!   single-use with strict reuse detection, so losing a rotated pair (crash
//!   between the response and the write) would log the device out.
//! * Only one refresh is in flight (the state mutex is held across it); a
//!   caller whose rejected token was already replaced just uses the new one.
//! * A rejected refresh (`401 auth_required`: expired, revoked, or reuse
//!   detected) means the user must sign in again: [`SyncError::NeedsLogin`].

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use sverb_core::model::DeviceId;
use sverb_crypto::Key32;
use sverb_crypto::random::os_rng;
use sverb_crypto::wrap::{WrapPurpose, unwrap_key, wrap_key};
use sverb_proto::auth::TokenPair;
use sverb_store::{Store, SyncState};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::SyncError;
use crate::http::ApiClient;
use crate::ws::{TokenError, TokenSource};

/// Refresh this long before the access token expires.
pub const REFRESH_MARGIN_MS: i64 = 60_000;

/// The decrypted content of `tokens_enc`.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct StoredTokens {
    access_token: String,
    refresh_token: String,
    /// UNIX ms (device clock) when the access token expires.
    access_expires_at: i64,
}

impl StoredTokens {
    fn from_pair(pair: &TokenPair, now_ms: i64) -> Self {
        let ttl = i64::try_from(pair.access_expires_in_s.saturating_mul(1000)).unwrap_or(i64::MAX);
        Self {
            access_token: pair.access_token.clone(),
            refresh_token: pair.refresh_token.clone(),
            access_expires_at: now_ms.saturating_add(ttl),
        }
    }

    fn seal(&self, lmk: &Key32) -> Result<Vec<u8>, SyncError> {
        let json =
            Zeroizing::new(serde_json::to_vec(self).map_err(|e| SyncError::Crypto(e.to_string()))?);
        wrap_key(lmk, &WrapPurpose::SyncTokens, &json, &mut os_rng())
            .map_err(|e| SyncError::Crypto(e.to_string()))
    }

    fn open(lmk: &Key32, enc: &[u8]) -> Result<Self, SyncError> {
        let json = unwrap_key(lmk, &WrapPurpose::SyncTokens, enc)
            .map_err(|e| SyncError::Crypto(format!("sync tokens: {e}")))?;
        serde_json::from_slice(&json).map_err(|e| SyncError::Crypto(format!("sync tokens: {e}")))
    }
}

enum State {
    Valid(StoredTokens),
    /// The refresh token was rejected; nothing works until a new login.
    Dead,
}

/// Holds the tokens while the vault is unlocked. Cheap to share (`Arc`).
pub struct TokenManager {
    store: Store,
    lmk: Key32,
    api: ApiClient,
    state: tokio::sync::Mutex<State>,
    refreshes: AtomicU64,
}

impl std::fmt::Debug for TokenManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenManager")
            .field("server", &self.api.base_url())
            .field("refreshes", &self.refreshes.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// Persists `tokens_enc` (keeps the rest of the row).
async fn persist(store: &Store, enc: Vec<u8>) -> Result<(), SyncError> {
    store
        .write(move |w| {
            let mut st = w.as_read().get_sync_state()?.unwrap_or_default();
            st.tokens_enc = Some(enc);
            w.set_sync_state(&st)
        })
        .await?;
    Ok(())
}

impl TokenManager {
    /// Saves a fresh token pair (after login or registration, M4-08) together
    /// with the server URL and the server-assigned device id.
    ///
    /// # Errors
    /// [`SyncError::Crypto`] / [`SyncError::Store`].
    pub async fn save_login(
        store: &Store,
        lmk: &Key32,
        server_url: &str,
        device_id: Option<DeviceId>,
        pair: &TokenPair,
    ) -> Result<(), SyncError> {
        let enc = StoredTokens::from_pair(pair, store.now()).seal(lmk)?;
        let state = SyncState {
            server_url: Some(server_url.to_owned()),
            device_id,
            tokens_enc: Some(enc),
        };
        store.set_sync_state(state).await?;
        Ok(())
    }

    /// Loads the stored tokens.
    ///
    /// # Errors
    /// [`SyncError::NeedsLogin`] when no tokens are stored,
    /// [`SyncError::Crypto`] when they don't unwrap under `lmk`.
    pub async fn load(store: Store, lmk: Key32, api: ApiClient) -> Result<Self, SyncError> {
        let enc = store
            .get_sync_state()
            .await?
            .and_then(|s| s.tokens_enc)
            .ok_or(SyncError::NeedsLogin)?;
        let tokens = StoredTokens::open(&lmk, &enc)?;
        Ok(Self {
            store,
            lmk,
            api,
            state: tokio::sync::Mutex::new(State::Valid(tokens)),
            refreshes: AtomicU64::new(0),
        })
    }

    /// Successful refreshes so far (test hook).
    pub fn refresh_count(&self) -> u64 {
        self.refreshes.load(Ordering::SeqCst)
    }

    /// The API client.
    pub fn api(&self) -> &ApiClient {
        &self.api
    }

    /// A usable access token, refreshing first when it expires within
    /// [`REFRESH_MARGIN_MS`].
    ///
    /// # Errors
    /// [`SyncError::NeedsLogin`], or the refresh's transport error.
    pub async fn access(&self) -> Result<String, SyncError> {
        let mut st = self.state.lock().await;
        let expiring = match &*st {
            State::Dead => return Err(SyncError::NeedsLogin),
            State::Valid(t) => t.access_expires_at - REFRESH_MARGIN_MS <= self.store.now(),
        };
        if expiring {
            self.refresh_locked(&mut st).await?;
        }
        match &*st {
            State::Valid(t) => Ok(t.access_token.clone()),
            State::Dead => Err(SyncError::NeedsLogin),
        }
    }

    /// The server rejected `rejected` with 401: refresh, unless another
    /// caller already replaced it.
    ///
    /// # Errors
    /// [`SyncError::NeedsLogin`], or the refresh's transport error.
    pub async fn refresh_after_401(&self, rejected: &str) -> Result<(), SyncError> {
        let mut st = self.state.lock().await;
        match &*st {
            State::Dead => Err(SyncError::NeedsLogin),
            State::Valid(t) if t.access_token != rejected => Ok(()),
            State::Valid(_) => self.refresh_locked(&mut st).await,
        }
    }

    async fn refresh_locked(&self, st: &mut State) -> Result<(), SyncError> {
        let State::Valid(current) = &*st else {
            return Err(SyncError::NeedsLogin);
        };
        match self.api.refresh(&current.refresh_token).await {
            Ok(pair) => {
                let next = StoredTokens::from_pair(&pair, self.store.now());
                // Persist before anything uses the new pair (strict reuse
                // detection: the old refresh token is now spent).
                persist(&self.store, next.seal(&self.lmk)?).await?;
                *st = State::Valid(next);
                self.refreshes.fetch_add(1, Ordering::SeqCst);
                tracing::debug!("sync tokens refreshed");
                Ok(())
            }
            Err(e) if e.is_status(401) || e.is_status(403) => {
                tracing::warn!(error = %e, "refresh token rejected; sign-in required");
                *st = State::Dead;
                Err(SyncError::NeedsLogin)
            }
            Err(e) => Err(e),
        }
    }
}

impl TokenSource for TokenManager {
    async fn access_token(&self) -> Result<String, TokenError> {
        self.access().await.map_err(to_token_error)
    }

    async fn refresh(&self) -> Result<(), TokenError> {
        let current = {
            let st = self.state.lock().await;
            match &*st {
                State::Valid(t) => t.access_token.clone(),
                State::Dead => return Err(TokenError::LoginRequired),
            }
        };
        self.refresh_after_401(&current)
            .await
            .map_err(to_token_error)
    }
}

fn to_token_error(e: SyncError) -> TokenError {
    match e {
        SyncError::NeedsLogin => TokenError::LoginRequired,
        other => TokenError::Transient(other.to_string()),
    }
}

/// `Arc<TokenManager>` is what the engine shares with the WebSocket task.
pub type SharedTokens = Arc<TokenManager>;
