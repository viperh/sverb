//! The sync engine task (§12, §2.1; task M4-07).
//!
//! One [`SyncEngine`] runs per unlocked vault, spawned by the TUI's sync
//! service or by headless `sverb sync`. It owns the HTTP client, the token
//! manager, the WebSocket client (M4-05) and the timers, and talks to the
//! store through its async API (SQLite and crypto run on the blocking pool:
//! every page is decrypted, merged and committed inside one
//! [`Store::write`] closure).
//!
//! Triggers (§12.5):
//! * startup: a full cycle (vault list, pull, push);
//! * a local change ([`SyncHandle::local_change`]): push after the debounce
//!   (`sync.push_debounce_ms`, 2 s), then pull;
//! * a WS `vault_changed` with a head beyond the cursor: pull that vault;
//!   WS (re)connected: pull everything; `vault_access`: refresh the vault list;
//! * the fallback poll (`sync.poll_fallback_secs`, 300 s);
//! * [`SyncHandle::sync_now`] (`sverb sync --now`);
//! * after a transport failure: retry with exponential backoff (1 s → 5 min).
//!   Offline edits stay queued indefinitely.
//!
//! Locking the vault stops the engine ([`SyncHandle::shutdown`]): the WS is
//! disconnected and the keys are dropped. Unlock starts a new engine.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Mutex, RwLock};
use sverb_core::model::{ClockSkew, HlcClock, ItemBody, ItemId, ItemKind, VaultId};
use sverb_crypto::Key32;
use sverb_proto::ws::{AccessChange, ServerMsg};
use sverb_store::Store;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::error::SyncError;
use crate::http::{ApiClient, HTTP_TIMEOUT};
use crate::keys::{VaultKeySource, VaultKeys};
use crate::status::{SyncEvent, SyncStatus, ToastLevel};
use crate::tokens::TokenManager;
use crate::ws::{self, Backoff, BackoffPolicy, WsConfig, WsEvent};

/// The device HLC shared between the item service and the engine.
pub type SharedHlc = Arc<Mutex<HlcClock>>;

/// Wraps an HLC for [`SyncEngine::new`].
#[must_use]
pub fn shared_hlc(clock: HlcClock) -> SharedHlc {
    Arc::new(Mutex::new(clock))
}

/// At most this many push rounds per item before a conflict is surfaced
/// (§12.3).
pub const MAX_CONFLICT_ROUNDS: u32 = 5;

/// Which device-local kinds may leave the device (§12.6): `HistoryEntry`
/// only with `history.sync`, `ConnLog` only with `logs.sync`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SyncPolicy {
    /// `history.sync`.
    pub history_sync: bool,
    /// `logs.sync`.
    pub logs_sync: bool,
}

impl SyncPolicy {
    /// Whether items of `kind` are pushed.
    #[must_use]
    pub const fn allows(&self, kind: ItemKind) -> bool {
        match kind {
            ItemKind::HistoryEntry => self.history_sync,
            ItemKind::ConnLog => self.logs_sync,
            _ => true,
        }
    }
}

/// Engine settings.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Push this long after the last local change (§12.5: 2 s).
    pub push_debounce: Duration,
    /// Fallback poll (§12.5: 300 s).
    pub poll_interval: Duration,
    /// Device-local kinds (§12.6).
    pub policy: SyncPolicy,
    /// Run the `/v1/ws` notification client.
    pub websocket: bool,
    /// HTTP request timeout (30 s).
    pub http_timeout: Duration,
    /// TLS for HTTP and WS (`None`: `ring` + webpki roots).
    pub tls: Option<Arc<rustls::ClientConfig>>,
    /// Retry backoff after transport errors (1 s → 5 min).
    pub retry: BackoffPolicy,
    /// Pull page size (≤ 500).
    pub page_limit: u32,
    /// Test hook (T-06): panic inside the page transaction after applying
    /// this many items of a page.
    #[doc(hidden)]
    pub crash_after_items: Option<usize>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            push_debounce: Duration::from_millis(2000),
            poll_interval: Duration::from_secs(300),
            policy: SyncPolicy::default(),
            websocket: true,
            http_timeout: HTTP_TIMEOUT,
            tls: None,
            retry: BackoffPolicy {
                initial: Duration::from_secs(1),
                max: Duration::from_secs(300),
            },
            page_limit: sverb_proto::sync::MAX_PULL_LIMIT,
            crash_after_items: None,
        }
    }
}

impl EngineConfig {
    /// The settings from `config.toml` (`[sync]`, `history.sync`,
    /// `logs.sync`).
    #[must_use]
    pub fn from_config(config: &sverb_core::config::Config) -> Self {
        Self {
            push_debounce: Duration::from_millis(u64::from(config.sync.push_debounce_ms)),
            poll_interval: Duration::from_secs(u64::from(config.sync.poll_fallback_secs)),
            policy: SyncPolicy {
                history_sync: config.history.sync,
                logs_sync: config.logs.sync,
            },
            ..Self::default()
        }
    }
}

/// Why an item is held back from pushing (in memory, for this engine's
/// lifetime; the item stays dirty and its local change is kept).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BlockReason {
    /// `403 forbidden`: read-only membership.
    ReadOnly,
    /// `too_large` (envelope over 1 MiB, or quota).
    TooLarge(String),
    /// Still conflicting after [`MAX_CONFLICT_ROUNDS`].
    Conflict,
    /// The local copy does not decrypt.
    Undecryptable,
}

#[derive(Debug, Clone)]
pub(crate) struct Blocked {
    pub(crate) reason: BlockReason,
}

/// The engine's state, owned by its task.
pub(crate) struct Ctx {
    pub(crate) store: Store,
    pub(crate) api: ApiClient,
    pub(crate) tokens: Arc<TokenManager>,
    pub(crate) keys: Arc<RwLock<VaultKeys>>,
    pub(crate) lmk: Key32,
    pub(crate) key_source: Arc<dyn VaultKeySource>,
    pub(crate) hlc: Arc<Mutex<HlcClock>>,
    pub(crate) config: EngineConfig,
    pub(crate) events: Option<mpsc::UnboundedSender<SyncEvent>>,
    pub(crate) blocked: HashMap<ItemId, Blocked>,
    pub(crate) conflicts: HashMap<ItemId, u32>,
    pub(crate) rotating: HashSet<VaultId>,
    pub(crate) missing_key: HashSet<VaultId>,
    pub(crate) unknown_vaults: HashSet<VaultId>,
    pub(crate) undecryptable: HashSet<ItemId>,
    // M4-09: one warning per device (the TUI also dedups per session).
    pub(crate) skew_warned: HashSet<sverb_core::model::DeviceId>,
    pub(crate) needs_login: bool,
}

impl std::fmt::Debug for Ctx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ctx")
            .field("server", &self.api.base_url())
            .field("blocked", &self.blocked.len())
            .field("rotating", &self.rotating)
            .finish_non_exhaustive()
    }
}

/// A display label for toasts: the item's `label` or `name`, else its
/// short id.
pub(crate) fn label_of(body: Option<&ItemBody>, id: ItemId) -> String {
    body.and_then(|b| b.get("label").or_else(|| b.get("name")))
        .and_then(|v| v.as_text())
        .filter(|s| !s.is_empty())
        .map_or_else(|| id.short(), ToOwned::to_owned)
}

/// Observes every stamp of `body` in the HLC; returns the first skew.
pub(crate) fn observe_body(hlc: &mut HlcClock, body: &ItemBody) -> Option<ClockSkew> {
    let mut skew = None;
    for s in body.fields.values() {
        if let Err(e) = hlc.observe_stamp(s) {
            skew.get_or_insert(e);
        }
    }
    if let Some(d) = &body.deleted
        && let Err(e) = hlc.observe_stamp(d)
    {
        skew.get_or_insert(e);
    }
    skew
}

impl Ctx {
    pub(crate) fn emit(&self, ev: SyncEvent) {
        if let Some(tx) = &self.events {
            let _ = tx.send(ev);
        }
    }

    pub(crate) fn toast(&self, level: ToastLevel, message: impl Into<String>) {
        self.emit(SyncEvent::Toast {
            level,
            message: message.into(),
        });
    }

    pub(crate) fn warn_skew(&mut self, skew: Option<ClockSkew>) {
        if let Some(s) = skew
            && self.skew_warned.insert(s.device)
        {
            tracing::warn!(device = %s.device, ahead_s = s.ahead_by.as_secs(), "clock skew");
            // M4-09: the UI turns this into "Clock skew detected on device X".
            self.emit(SyncEvent::ClockSkew {
                device: s.device.short(),
                ahead_secs: s.ahead_by.as_secs(),
            });
        }
    }

    pub(crate) fn block(&mut self, id: ItemId, reason: BlockReason) {
        self.blocked.insert(id, Blocked { reason });
    }

    /// Calls the API with an access token; on 401 refreshes once and
    /// retries. `NeedsLogin` sets the engine's needs-login state.
    pub(crate) async fn call<T, F, Fut>(&mut self, f: F) -> Result<T, SyncError>
    where
        F: Fn(ApiClient, String) -> Fut,
        Fut: Future<Output = Result<T, SyncError>>,
    {
        let res = self.call_inner(f).await;
        if matches!(res, Err(SyncError::NeedsLogin)) {
            self.needs_login = true;
        }
        res
    }

    async fn call_inner<T, F, Fut>(&self, f: F) -> Result<T, SyncError>
    where
        F: Fn(ApiClient, String) -> Fut,
        Fut: Future<Output = Result<T, SyncError>>,
    {
        let token = self.tokens.access().await?;
        match f(self.api.clone(), token.clone()).await {
            Err(e) if e.is_status(401) => {
                self.tokens.refresh_after_401(&token).await?;
                let token = self.tokens.access().await?;
                f(self.api.clone(), token).await
            }
            other => other,
        }
    }

    /// The vaults to sync.
    pub(crate) fn vaults(&self) -> Vec<VaultId> {
        self.keys
            .read()
            .vault_ids()
            .into_iter()
            .filter(|v| !self.unknown_vaults.contains(v))
            .collect()
    }

    /// `GET /v1/vaults`: rotation flags, new key versions (§13.2), and
    /// which local vaults the server knows.
    pub(crate) async fn refresh_vaults(&mut self) -> Result<(), SyncError> {
        let views = self
            .call(|api, t| async move { api.list_vaults(&t).await })
            .await?;
        let local = self.keys.read().vault_ids();
        for vault in local {
            let Some(view) = views.iter().find(|v| v.id == vault.uuid()) else {
                if self.unknown_vaults.insert(vault) {
                    tracing::warn!(%vault, "vault is not on the server; not syncing it");
                }
                continue;
            };
            self.unknown_vaults.remove(&vault);
            if view.rotation.is_some() {
                self.rotating.insert(vault);
            } else if self.rotating.remove(&vault) {
                tracing::info!(%vault, "key rotation finished; resuming pushes");
            }
            let (current, kind) = {
                let k = self.keys.read();
                (k.current_version(vault).unwrap_or(0), k.kind(vault))
            };
            if view.key_version > current && view.rotation.is_none() {
                match self.key_source.open_grant(view, view.key_version) {
                    Some(key) => {
                        let kind = kind.unwrap_or(sverb_store::VaultKind::Personal);
                        self.keys.write().insert(vault, kind, view.key_version, key);
                        let (kv, wrapped) = self.keys.read().wrap_current(vault, &self.lmk)?;
                        self.store.update_wrapped_key(vault, kv, wrapped).await?;
                        self.missing_key.remove(&vault);
                        tracing::info!(%vault, key_version = kv, "vault key updated");
                    }
                    None => {
                        if self.missing_key.insert(vault) {
                            tracing::warn!(%vault, key_version = view.key_version, "new vault key can't be opened");
                        }
                    }
                }
            } else if view.key_version <= current {
                self.missing_key.remove(&vault);
            }
        }
        Ok(())
    }

    /// One cycle: optionally the vault list, then pull, push, and pull again
    /// when something was pushed (so the cursor moves past our revisions).
    pub(crate) async fn cycle(&mut self, refresh: bool) -> Result<(), SyncError> {
        self.cycle_inner(refresh).await?;
        // M4-09: "last successful sync" for the status panel and `sverb sync --status`.
        crate::info::record_sync(&self.store).await;
        Ok(())
    }

    async fn cycle_inner(&mut self, refresh: bool) -> Result<(), SyncError> {
        if refresh {
            self.refresh_vaults().await?;
        }
        for vault in self.vaults() {
            self.pull_vault(vault).await?;
        }
        let mut pushed = false;
        for vault in self.vaults() {
            pushed |= self.push_vault(vault).await?;
        }
        if pushed {
            for vault in self.vaults() {
                self.pull_vault(vault).await?;
            }
        }
        Ok(())
    }

    /// The status after a cycle that ended with `last`.
    pub(crate) async fn status(&self, last: Option<&SyncError>) -> SyncStatus {
        if self.needs_login || matches!(last, Some(SyncError::NeedsLogin)) {
            return SyncStatus::NeedsLogin;
        }
        let pending = self.store.pending_count().await.unwrap_or(0);
        if let Some(e) = last {
            return if e.is_offline() {
                SyncStatus::Offline { pending }
            } else {
                SyncStatus::Error {
                    message: e.to_string(),
                }
            };
        }
        let mut issues = Vec::new();
        let count =
            |r: fn(&BlockReason) -> bool| self.blocked.values().filter(|b| r(&b.reason)).count();
        let read_only = count(|r| matches!(r, BlockReason::ReadOnly));
        let too_large = count(|r| matches!(r, BlockReason::TooLarge(_)));
        let conflict = count(|r| matches!(r, BlockReason::Conflict));
        let bad_local = count(|r| matches!(r, BlockReason::Undecryptable));
        let plural = |n: usize| if n == 1 { "item" } else { "items" };
        if !self.undecryptable.is_empty() || bad_local > 0 {
            let n = self.undecryptable.len() + bad_local;
            issues.push(format!("{n} {} could not be decrypted", plural(n)));
        }
        if conflict > 0 {
            issues.push(format!("{conflict} {} kept conflicting", plural(conflict)));
        }
        if too_large > 0 {
            issues.push(format!(
                "{too_large} {} too large to upload",
                plural(too_large)
            ));
        }
        if read_only > 0 {
            issues.push(format!(
                "{read_only} {} not uploaded (read-only access)",
                plural(read_only)
            ));
        }
        if !self.missing_key.is_empty() {
            issues.push("a vault key changed; sign in again to get the new key".into());
        }
        if !issues.is_empty() {
            return SyncStatus::Error {
                message: issues.join("; "),
            };
        }
        if pending > 0 && !self.rotating.is_empty() {
            return SyncStatus::Syncing;
        }
        SyncStatus::Synced
    }
}

/// A configured, not yet running engine.
#[derive(Debug)]
pub struct SyncEngine {
    ctx: Ctx,
}

/// What the TUI / CLI keeps of a running engine. Dropping it stops the engine.
#[derive(Debug)]
pub struct SyncHandle {
    cmds: mpsc::UnboundedSender<Command>,
    status: watch::Receiver<SyncStatus>,
    cancel: CancellationToken,
    task: Option<JoinHandle<()>>,
}

#[derive(Debug)]
enum Command {
    LocalChange,
    SyncNow(Option<oneshot::Sender<SyncStatus>>),
}

impl SyncEngine {
    /// An engine for the unlocked vault: `lmk` unwraps the tokens and vault
    /// keys, `hlc` is the device clock (shared with the item service so
    /// observed stamps move it forward), `events` receives [`SyncEvent`]s.
    ///
    /// # Errors
    /// [`SyncError::NotConfigured`] (no server URL), [`SyncError::NeedsLogin`]
    /// (no tokens), [`SyncError::Crypto`], [`SyncError::Store`].
    pub async fn new(
        store: Store,
        lmk: Key32,
        hlc: Arc<Mutex<HlcClock>>,
        key_source: Arc<dyn VaultKeySource>,
        config: EngineConfig,
        events: Option<mpsc::UnboundedSender<SyncEvent>>,
    ) -> Result<Self, SyncError> {
        let state = store
            .get_sync_state()
            .await?
            .ok_or(SyncError::NotConfigured("not signed in to a sync server"))?;
        let url = state
            .server_url
            .ok_or(SyncError::NotConfigured("no server URL"))?;
        let api = ApiClient::new(&url, config.tls.clone(), config.http_timeout)?;
        let tokens = Arc::new(TokenManager::load(store.clone(), lmk.clone(), api.clone()).await?);
        let rows = store.list_vaults().await?;
        let (keys, failed) = VaultKeys::load(&rows, &lmk);
        for (vault, e) in failed {
            tracing::warn!(%vault, error = %e, "vault key does not unwrap; not syncing it");
        }
        Ok(Self {
            ctx: Ctx {
                store,
                api,
                tokens,
                keys: Arc::new(RwLock::new(keys)),
                lmk,
                key_source,
                hlc,
                config,
                events,
                blocked: HashMap::new(),
                conflicts: HashMap::new(),
                rotating: HashSet::new(),
                missing_key: HashSet::new(),
                unknown_vaults: HashSet::new(),
                undecryptable: HashSet::new(),
                skew_warned: HashSet::new(),
                needs_login: false,
            },
        })
    }

    /// The token manager (test hook and M4-08).
    pub fn tokens(&self) -> &Arc<TokenManager> {
        &self.ctx.tokens
    }

    /// One full cycle (vault list, pull, push, pull) without timers or WS:
    /// `sverb sync --now`. Returns the resulting status.
    pub async fn sync_once(&mut self) -> SyncStatus {
        let res = self.ctx.cycle(true).await;
        if let Err(e) = &res {
            tracing::warn!(error = %e, "sync failed");
        }
        self.ctx.status(res.as_ref().err()).await
    }

    /// Pulls every vault (no push).
    ///
    /// # Errors
    /// The first failing request or store write.
    pub async fn pull_now(&mut self) -> Result<(), SyncError> {
        for vault in self.ctx.vaults() {
            self.ctx.pull_vault(vault).await?;
        }
        Ok(())
    }

    /// Pushes every vault's outbox (no pull first). Returns whether anything
    /// was accepted.
    ///
    /// # Errors
    /// The first failing request or store write.
    pub async fn push_now(&mut self) -> Result<bool, SyncError> {
        let mut any = false;
        for vault in self.ctx.vaults() {
            any |= self.ctx.push_vault(vault).await?;
        }
        Ok(any)
    }

    /// The status as of now (after [`Self::pull_now`] / [`Self::push_now`]).
    pub async fn status(&self) -> SyncStatus {
        self.ctx.status(None).await
    }

    /// Re-reads `GET /v1/vaults` (rotation state, new key versions).
    ///
    /// # Errors
    /// The request's error.
    pub async fn refresh_vaults(&mut self) -> Result<(), SyncError> {
        self.ctx.refresh_vaults().await
    }

    /// Runs the engine on the current runtime.
    pub fn spawn(self) -> SyncHandle {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (status_tx, status_rx) = watch::channel(SyncStatus::Syncing);
        let cancel = CancellationToken::new();
        let task = tokio::spawn(run(self.ctx, cmd_rx, status_tx, cancel.clone()));
        SyncHandle {
            cmds: cmd_tx,
            status: status_rx,
            cancel,
            task: Some(task),
        }
    }
}

impl SyncHandle {
    /// A local item was written (sets the push debounce).
    pub fn local_change(&self) {
        let _ = self.cmds.send(Command::LocalChange);
    }

    /// Runs a full cycle now and returns the status after it (`Disabled`
    /// when the engine has stopped).
    pub async fn sync_now(&self) -> SyncStatus {
        let (tx, rx) = oneshot::channel();
        if self.cmds.send(Command::SyncNow(Some(tx))).is_err() {
            return SyncStatus::Disabled;
        }
        rx.await.unwrap_or(SyncStatus::Disabled)
    }

    /// Requests a full cycle without waiting.
    pub fn request_sync(&self) {
        let _ = self.cmds.send(Command::SyncNow(None));
    }

    /// The current status.
    #[must_use]
    pub fn status(&self) -> SyncStatus {
        self.status.borrow().clone()
    }

    /// A status receiver.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<SyncStatus> {
        self.status.clone()
    }

    /// Stops the engine (vault locked, logout, quit): closes the WS and
    /// drops the keys once the current step finishes.
    pub async fn shutdown(mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }

    /// Whether the engine task has ended.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.task.as_ref().is_none_or(JoinHandle::is_finished)
    }
}

impl Drop for SyncHandle {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

fn set_status(ctx: &Ctx, tx: &watch::Sender<SyncStatus>, status: SyncStatus) {
    let changed = *tx.borrow() != status;
    tx.send_replace(status.clone());
    if changed {
        ctx.emit(SyncEvent::Status(status));
    }
}

async fn sleep_until_opt(t: Option<Instant>) {
    match t {
        Some(t) => tokio::time::sleep_until(t).await,
        None => std::future::pending().await,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Work {
    /// Vault list + pull + push.
    Full,
    /// Pull + push (WS notification, debounce).
    Quick,
}

async fn run(
    mut ctx: Ctx,
    mut cmds: mpsc::UnboundedReceiver<Command>,
    status: watch::Sender<SyncStatus>,
    cancel: CancellationToken,
) {
    let mut backoff = Backoff::new(ctx.config.retry);
    let mut retry_at: Option<Instant> = None;
    let mut push_at: Option<Instant> = None;
    let mut poll = tokio::time::interval_at(
        Instant::now() + ctx.config.poll_interval,
        ctx.config.poll_interval,
    );
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let ws_cancel = cancel.child_token();
    let (ws_tx, mut ws_rx) = mpsc::channel::<WsEvent>(64);
    let ws_task = if ctx.config.websocket {
        let mut cfg = WsConfig::for_server(ctx.api.base_url());
        cfg.tls.clone_from(&ctx.config.tls);
        let tokens = Arc::clone(&ctx.tokens);
        let c = ws_cancel.clone();
        Some(tokio::spawn(async move {
            ws::run(cfg, &*tokens, ws_tx, c).await;
        }))
    } else {
        drop(ws_tx);
        None
    };
    let mut ws_open = ctx.config.websocket;

    let mut pending_work = Some(Work::Full);
    let mut replies: Vec<oneshot::Sender<SyncStatus>> = Vec::new();

    loop {
        if let Some(work) = pending_work.take() {
            if !ctx.needs_login {
                set_status(&ctx, &status, SyncStatus::Syncing);
                let res = tokio::select! {
                    () = cancel.cancelled() => break,
                    r = ctx.cycle(work == Work::Full) => r,
                };
                match &res {
                    Ok(()) => {
                        backoff.reset();
                        retry_at = None;
                    }
                    Err(e) if e.is_offline() => {
                        let d = backoff.next_delay();
                        tracing::info!(error = %e, retry_in_ms = d.as_millis(), "sync offline");
                        retry_at = Some(Instant::now() + d);
                    }
                    Err(e) => tracing::warn!(error = %e, "sync cycle failed"),
                }
                if ctx.needs_login {
                    ws_cancel.cancel();
                }
                let st = ctx.status(res.as_ref().err()).await;
                set_status(&ctx, &status, st);
            } else {
                set_status(&ctx, &status, SyncStatus::NeedsLogin);
            }
            let st = status.borrow().clone();
            for r in replies.drain(..) {
                let _ = r.send(st.clone());
            }
        }

        tokio::select! {
            () = cancel.cancelled() => break,
            cmd = cmds.recv() => match cmd {
                None => break,
                Some(Command::LocalChange) => {
                    push_at = Some(Instant::now() + ctx.config.push_debounce);
                }
                Some(Command::SyncNow(reply)) => {
                    // A manual sync also clears per-session blocks (retry).
                    ctx.blocked.clear();
                    ctx.conflicts.clear();
                    pending_work = Some(Work::Full);
                    replies.extend(reply);
                }
            },
            () = sleep_until_opt(push_at) => {
                push_at = None;
                pending_work = Some(Work::Quick);
            }
            () = sleep_until_opt(retry_at) => {
                retry_at = None;
                pending_work = Some(Work::Full);
            }
            _ = poll.tick() => {
                pending_work = Some(Work::Full);
            }
            ev = ws_rx.recv(), if ws_open => match ev {
                None => ws_open = false,
                Some(ev) => pending_work = on_ws_event(&mut ctx, ev).await,
            },
        }
    }

    ws_cancel.cancel();
    if let Some(t) = ws_task {
        let _ = t.await;
    }
    for r in replies.drain(..) {
        let _ = r.send(SyncStatus::Disabled);
    }
}

/// What a WS event asks for.
async fn on_ws_event(ctx: &mut Ctx, ev: WsEvent) -> Option<Work> {
    match ev {
        // Catch up on anything missed while disconnected.
        WsEvent::Connected => Some(Work::Quick),
        WsEvent::Notification(ServerMsg::VaultChanged {
            vault_id,
            head_revision,
        }) => {
            let vault = VaultId::from_uuid(vault_id);
            let cursor = ctx
                .store
                .get_vault(vault)
                .await
                .ok()
                .flatten()
                .map(|v| v.sync_cursor);
            match cursor {
                Some(c) if u64::try_from(c).unwrap_or(0) < head_revision => Some(Work::Quick),
                _ => None,
            }
        }
        WsEvent::Notification(ServerMsg::VaultAccess { vault_id, change }) => {
            let vault = VaultId::from_uuid(vault_id);
            if change == AccessChange::Revoked {
                ctx.toast(
                    ToastLevel::Warn,
                    format!("Your access to vault {} was revoked", vault.short()),
                );
            }
            Some(Work::Full)
        }
        WsEvent::NeedsLogin => {
            ctx.needs_login = true;
            Some(Work::Quick)
        }
        // M4-08 (§11.2.1): the password changed on another device (or the
        // account was recovered). This device's tokens are revoked; it keeps
        // unlocking locally with the old password until the user signs in
        // with the new one (`account::login`).
        WsEvent::Notification(ServerMsg::AccountChanged { key_version }) => {
            tracing::info!(
                key_version,
                "account changed on another device; sign-in required"
            );
            ctx.needs_login = true;
            ctx.toast(
                ToastLevel::Warn,
                "Your password was changed on another device; sign in with the new password",
            );
            Some(Work::Quick)
        }
        WsEvent::Notification(_) | WsEvent::Disconnected { .. } => None,
    }
}
