//! M4-07: the sync service (feature `sync`). M4-09: wired to the UI.
//!
//! Runs one [`SyncEngine`] while the vault is unlocked (§12, §2.1):
//! `SyncEffect::Start` after unlock, `SyncEffect::Stop` on lock (the WS
//! disconnects and the engine's keys are dropped). Every committed write that
//! queues an outbox row ([`sverb_store::Store::outbox_changes`]) is a local change
//! for the push debounce. New vault keys are opened by a [`TrustedKeySource`]
//! (M5-03: grants verified against the pins).
//!
//! Engine events are forwarded as `UiEvent::Sync`. Remote changes the engine
//! applied are folded into the search index here (decrypt, `index_upsert` /
//! `index_remove`), so the reducer gets the usual `UiEvent::IndexUpdated`.
//!
//! M4-09 also runs, for the Settings section: the local state
//! ([`sverb_sync::local_info`]), devices, disconnect, team pins, and the account
//! wizard. The wizard's flows (M4-08) live here, with their secrets and their
//! randomness (the recovery-word check), never in the reducer; after every input
//! the UI gets the next [`WizardScreen`].

use std::sync::{Arc, Mutex, PoisonError};

use sverb_core::config::Config;
use sverb_store::Store;
use sverb_sync::account::{
    self as acct, AccountConfig, AccountError, DuplicateChoice, LoginRequest, LoginSession,
    PreparedRegistration, RegisterStep, RegisterWizard, RegistrationToken, Revoked, WizardEffect,
    WizardInput,
};
use sverb_sync::trust::{Trust, TrustedKeySource};
use sverb_sync::{
    EngineConfig, NoKeySource, SyncEngine, SyncError, SyncEvent, SyncHandle, SyncStatus,
    VaultKeySource, shared_hlc,
};
use tokio::sync::mpsc;
use tracing::{debug, warn};
use zeroize::Zeroizing;

use super::EventSender;
use super::vault::VaultService;
use crate::app::UiEvent;
use crate::app::sync_ui::{
    DeviceRow, SyncEffect, SyncUiEvent, TeamOp, TeamResult, WizardCmd, WizardFlow, WizardPrompt,
    WizardScreen,
};

/// Owns the running engine (if any) and the account wizard. Cheap to clone.
#[derive(Clone)]
pub struct SyncService {
    handle: Arc<Mutex<Option<SyncHandle>>>,
    vault: VaultService,
    config: Arc<Config>,
    account: AccountConfig,
    wizard: Arc<tokio::sync::Mutex<Option<Flow>>>,
}

impl std::fmt::Debug for SyncService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncService")
            .field("running", &self.slot().is_some())
            .finish_non_exhaustive()
    }
}

/// This device's name for the server: `HOSTNAME`, else a generic name.
fn device_name() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "sverb".to_owned())
}

impl SyncService {
    /// A service for `vault` with the account settings for this device.
    pub fn new(vault: VaultService, config: Arc<Config>) -> Self {
        Self::with_account(vault, config, AccountConfig::new(device_name()))
    }

    /// [`SyncService::new`] with explicit account settings (tests: cheap KSF).
    pub fn with_account(vault: VaultService, config: Arc<Config>, account: AccountConfig) -> Self {
        Self {
            handle: Arc::new(Mutex::new(None)),
            vault,
            config,
            account,
            wizard: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    fn slot(&self) -> std::sync::MutexGuard<'_, Option<SyncHandle>> {
        self.handle.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn store(&self) -> &Store {
        self.vault.store()
    }

    /// Executes a `SyncEffect`. Must be called inside a tokio runtime.
    pub fn execute(&self, effect: SyncEffect, tx: &EventSender) {
        match effect {
            SyncEffect::Start => self.start(tx),
            SyncEffect::Stop => {
                self.stop();
                let this = self.clone();
                tokio::spawn(async move { *this.wizard.lock().await = None });
            }
            SyncEffect::SyncNow => self.request_sync(),
            SyncEffect::Refresh => self.refresh(tx),
            SyncEffect::Disconnect => self.disconnect(tx),
            SyncEffect::ListDevices => self.list_devices(tx),
            SyncEffect::RevokeDevice { id } => self.revoke(id, tx),
            SyncEffect::Wizard(cmd) => self.wizard(cmd, tx),
            SyncEffect::TeamPins => self.team(None, tx),
            SyncEffect::TeamVerify {
                user,
                accept_new_key,
            } => self.team(Some((user, accept_new_key)), tx),
            // M5-01
            SyncEffect::Team(op) => self.team_op(op, tx),
        }
    }

    // M5-01: Settings → Team (orgs, members, invites, audit).
    fn team_op(&self, op: TeamOp, tx: &EventSender) {
        let Some(lmk) = self.lmk() else { return };
        let this = self.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let res = this.run_team_op(op, &lmk).await;
            let res = res.unwrap_or_else(|e| TeamResult::Failed(e.to_string()));
            let _ = tx.send(UiEvent::SyncUi(SyncUiEvent::Team(res))).await;
        });
    }

    async fn run_team_op(
        &self,
        op: TeamOp,
        lmk: &sverb_crypto::Key32,
    ) -> Result<TeamResult, AccountError> {
        use sverb_sync::account::teams;
        let (store, cfg) = (self.store(), &self.account);
        let id = |s: &str| {
            s.parse::<uuid::Uuid>()
                .map_err(|e| AccountError::Local(format!("bad id: {e}")))
        };
        Ok(match op {
            TeamOp::Load { org } => {
                let orgs = teams::list_orgs(store, lmk, cfg).await?;
                let shown = org
                    .and_then(|o| orgs.iter().find(|x| x.id.to_string() == o))
                    .or_else(|| orgs.first())
                    .map(|o| o.id);
                let members = match shown {
                    Some(o) => teams::members(store, lmk, cfg, o).await?,
                    None => Vec::new(),
                };
                TeamResult::Loaded {
                    orgs,
                    org: shown.map(|o| o.to_string()),
                    members,
                }
            }
            TeamOp::Create { name } => {
                let org = teams::create_org(store, lmk, cfg, &name).await?;
                TeamResult::Changed(format!("Created {}", org.name))
            }
            TeamOp::Invite { org, email } => {
                let role = sverb_proto::orgs::Role::Member;
                TeamResult::Invited(
                    teams::invite(store, lmk, cfg, id(&org)?, email.as_deref(), role).await?,
                )
            }
            TeamOp::Accept { link } => {
                let joined = teams::accept_invite(store, lmk, cfg, &link).await?;
                TeamResult::Changed(format!("Joined the org as {}", joined.role))
            }
            TeamOp::SetRole { org, user, role } => {
                teams::set_role(store, lmk, cfg, id(&org)?, id(&user)?, role).await?;
                TeamResult::Changed(format!("Role changed to {role}"))
            }
            TeamOp::Remove { org, user } => {
                teams::remove_member(store, lmk, cfg, id(&org)?, id(&user)?).await?;
                TeamResult::Changed("Member removed".into())
            }
            TeamOp::Audit { org } => TeamResult::Audit(
                teams::audit(store, lmk, cfg, id(&org)?, None, 50)
                    .await?
                    .events,
            ),
        })
    }

    /// Reads the local state and, when a server is set up, starts the engine for
    /// the unlocked vault. A device whose tokens were rejected reports
    /// [`SyncStatus::NeedsLogin`].
    pub fn start(&self, tx: &EventSender) {
        let Some(unlocked) = self.vault.unlocked() else {
            return;
        };
        self.stop_now();
        let store = self.store().clone();
        let lmk = unlocked.lmk().clone();
        let hlc = shared_hlc(unlocked.hlc());
        drop(unlocked);
        let engine_config = EngineConfig::from_config(&self.config);
        let this = self.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let info = match sverb_sync::local_info(&store).await {
                Ok(info) => info,
                Err(e) => {
                    warn!(error = %e, "cannot read the sync state");
                    return;
                }
            };
            let connected = info.connected();
            let _ = tx.send(UiEvent::SyncUi(SyncUiEvent::Info(info))).await;
            if !connected {
                // Local-only (§1.1): no engine, no network.
                return;
            }
            let key_source = key_source(&store, &lmk).await;
            let (ev_tx, ev_rx) = mpsc::unbounded_channel();
            match SyncEngine::new(
                store.clone(),
                lmk,
                hlc,
                key_source,
                engine_config,
                Some(ev_tx),
            )
            .await
            {
                Ok(engine) => {
                    let handle = engine.spawn();
                    // A lock may have happened while the engine was being built.
                    if this.vault.unlocked().is_none() {
                        handle.shutdown().await;
                        return;
                    }
                    let mut status = handle.subscribe();
                    let first = status.borrow_and_update().clone();
                    *this.slot() = Some(handle);
                    let _ = tx.send(UiEvent::Sync(SyncEvent::Status(first))).await;
                    tokio::spawn(local_changes(this.clone(), store));
                    forward(ev_rx, this.vault.clone(), tx).await;
                }
                Err(e) => {
                    let status = match e {
                        SyncError::NotConfigured(_) => SyncStatus::Disabled,
                        SyncError::NeedsLogin => SyncStatus::NeedsLogin,
                        other => {
                            warn!(error = %other, "sync engine did not start");
                            SyncStatus::Error {
                                message: other.to_string(),
                            }
                        }
                    };
                    let _ = tx.send(UiEvent::Sync(SyncEvent::Status(status))).await;
                }
            }
        });
    }

    /// A local item was written.
    pub fn local_change(&self) {
        if let Some(h) = self.slot().as_ref() {
            h.local_change();
        }
    }

    /// `sync_now` from the UI (palette, Settings → Sync).
    pub fn request_sync(&self) {
        if let Some(h) = self.slot().as_ref() {
            h.request_sync();
        }
    }

    /// The current status (`Disabled` when no engine runs).
    pub fn status(&self) -> SyncStatus {
        self.slot()
            .as_ref()
            .map_or(SyncStatus::Disabled, SyncHandle::status)
    }

    /// Whether an engine runs.
    pub fn is_running(&self) -> bool {
        self.slot().is_some()
    }

    fn stop_now(&self) -> Option<SyncHandle> {
        self.slot().take()
    }

    /// Stops the engine (vault locked, quit). Dropping the handle cancels the
    /// engine at once; the task finishes in the background.
    pub fn stop(&self) {
        if let Some(h) = self.stop_now() {
            debug!("sync engine stopping");
            tokio::spawn(h.shutdown());
        }
    }

    fn refresh(&self, tx: &EventSender) {
        let store = self.store().clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            match sverb_sync::local_info(&store).await {
                Ok(info) => {
                    let _ = tx.send(UiEvent::SyncUi(SyncUiEvent::Info(info))).await;
                }
                Err(e) => warn!(error = %e, "cannot read the sync state"),
            }
        });
    }

    fn lmk(&self) -> Option<sverb_crypto::Key32> {
        self.vault.unlocked().map(|v| v.lmk().clone())
    }

    fn disconnect(&self, tx: &EventSender) {
        let Some(lmk) = self.lmk() else { return };
        self.stop();
        let this = self.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let res = acct::logout(this.store(), &lmk, &this.account)
                .await
                .map(|r| {
                    let mut msg = format!(
                        "Disconnected. {} personal item(s) kept on this device",
                        r.kept_items
                    );
                    if r.shared_removed > 0 {
                        msg.push_str(&format!("; {} shared vault(s) removed", r.shared_removed));
                    }
                    if let Some(why) = r.revoke_error {
                        msg.push_str(&format!(" (the server was not told: {why})"));
                    }
                    msg
                })
                .map_err(|e| e.to_string());
            let _ = tx
                .send(UiEvent::SyncUi(SyncUiEvent::Disconnected(res)))
                .await;
        });
    }

    fn list_devices(&self, tx: &EventSender) {
        let Some(lmk) = self.lmk() else { return };
        let this = self.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let res = acct::list_devices(this.store(), &lmk, &this.account)
                .await
                .map(|list| list.iter().map(device_row).collect())
                .map_err(|e| e.to_string());
            let _ = tx.send(UiEvent::SyncUi(SyncUiEvent::Devices(res))).await;
        });
    }

    fn revoke(&self, id: String, tx: &EventSender) {
        let Some(lmk) = self.lmk() else { return };
        let this = self.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let (this_device, result) = match id.parse() {
                Err(e) => (false, Err(format!("bad device id: {e}"))),
                Ok(uuid) => {
                    match acct::revoke_device(this.store(), &lmk, &this.account, uuid).await {
                        Ok(Revoked::Other) => (false, Ok(())),
                        Ok(Revoked::ThisDevice(_)) => {
                            this.stop();
                            (true, Ok(()))
                        }
                        Err(e) => (false, Err(e.to_string())),
                    }
                }
            };
            let ev = SyncUiEvent::Revoked {
                id,
                this_device,
                result,
            };
            let _ = tx.send(UiEvent::SyncUi(ev)).await;
            if this_device {
                this.list_devices_after_logout(&tx).await;
            }
        });
    }

    async fn list_devices_after_logout(&self, tx: &EventSender) {
        let _ = tx
            .send(UiEvent::SyncUi(SyncUiEvent::Devices(Ok(Vec::new()))))
            .await;
    }

    fn team(&self, answer: Option<([u8; 16], bool)>, tx: &EventSender) {
        let store = self.store().clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let res = match answer {
                None => store.list_pins().await,
                Some((user, accept_new_key)) => {
                    use crate::views::settings::team_verify::{TeamVerifyRequest as R, execute};
                    let req = if accept_new_key {
                        R::AcceptNewKey(user)
                    } else {
                        R::MarkVerified(user)
                    };
                    execute(&store, req).await
                }
            };
            match res {
                Ok(pins) => {
                    let _ = tx.send(UiEvent::SyncUi(SyncUiEvent::TeamPins(pins))).await;
                }
                Err(e) => warn!(error = %e, "team pins"),
            }
        });
    }

    // ------------------------------------------------------------ the wizard

    fn wizard(&self, cmd: WizardCmd, tx: &EventSender) {
        let this = self.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut slot = this.wizard.lock().await;
            match cmd {
                WizardCmd::Cancel => {
                    *slot = None;
                    return;
                }
                WizardCmd::Start(flow) => {
                    *slot = Some(match flow {
                        WizardFlow::Login => Flow::Login(LoginFlow::default()),
                        WizardFlow::Register => Flow::Register(RegisterFlow::default()),
                    });
                }
                cmd => {
                    let Some(flow) = slot.as_mut() else { return };
                    // Busy screen first: server calls can take a while.
                    if let Some(busy) = flow.busy_screen(&cmd) {
                        let _ = tx.send(UiEvent::SyncUi(SyncUiEvent::Wizard(busy))).await;
                    }
                    flow.input(cmd, &this).await;
                }
            }
            if let Some(flow) = slot.as_ref() {
                let screen = flow.screen();
                let done = screen.done;
                let _ = tx.send(UiEvent::SyncUi(SyncUiEvent::Wizard(screen))).await;
                if done {
                    *slot = None;
                }
            }
        });
    }
}

/// [`TrustedKeySource`] for a signed-in account (M5-03); without account keys,
/// nothing can be opened.
async fn key_source(store: &Store, lmk: &sverb_crypto::Key32) -> Arc<dyn VaultKeySource> {
    match acct::load_account_keys(store, lmk).await {
        Ok(Some((account, keys))) => {
            let pins = match Trust::new(store.clone(), account.user_id).pins().await {
                Ok(p) => p,
                Err(e) => {
                    warn!(error = %e, "cannot read the key pins");
                    sverb_sync::trust::PinSet::default()
                }
            };
            Arc::new(TrustedKeySource::new(account.user_id, Arc::new(keys), pins))
        }
        Ok(None) => Arc::new(NoKeySource),
        Err(e) => {
            warn!(error = %e, "cannot open the account keys");
            Arc::new(NoKeySource)
        }
    }
}

fn device_row(d: &sverb_proto::auth::DeviceView) -> DeviceRow {
    DeviceRow {
        id: d.id.to_string(),
        name: d.name.clone().unwrap_or_else(|| "-".into()),
        platform: d.platform.clone().unwrap_or_else(|| "-".into()),
        created_ms: d.created_at.map(|t| t.timestamp_millis()),
        last_seen_ms: d.last_seen_at.map(|t| t.timestamp_millis()),
        current: d.current,
    }
}

/// Local writes that queued an outbox row wake the push debounce, while the
/// engine runs.
async fn local_changes(service: SyncService, store: Store) {
    let mut rx = store.outbox_changes();
    rx.mark_unchanged();
    while rx.changed().await.is_ok() {
        if !service.is_running() {
            return;
        }
        service.local_change();
    }
}

/// Forwards engine events; folds applied remote changes into the index.
async fn forward(mut rx: mpsc::UnboundedReceiver<SyncEvent>, vault: VaultService, tx: EventSender) {
    while let Some(ev) = rx.recv().await {
        if let SyncEvent::Applied { items, .. } = &ev {
            reindex(&vault, items, &tx).await;
        }
        if tx.send(UiEvent::Sync(ev)).await.is_err() {
            return;
        }
    }
}

async fn reindex(vault: &VaultService, items: &[sverb_core::model::ItemId], tx: &EventSender) {
    let Some(unlocked) = vault.unlocked() else {
        return;
    };
    for id in items {
        match vault.store().get_item(*id).await {
            Ok(Some(row)) => match unlocked.open(&row) {
                Ok(body) => vault.index_upsert(row.id, row.vault_id, &body, tx),
                Err(e) => debug!(item = %id, error = %e, "applied item not indexed"),
            },
            Ok(None) => vault.index_remove(*id, tx),
            Err(e) => warn!(item = %id, error = %e, "reading an applied item failed"),
        }
    }
}

// ---------------------------------------------------------------- flows

enum Flow {
    Register(RegisterFlow),
    Login(LoginFlow),
}

impl Flow {
    fn busy_screen(&self, cmd: &WizardCmd) -> Option<WizardScreen> {
        let mut s = self.screen();
        let busy = match self {
            Self::Register(r) => {
                matches!(cmd, WizardCmd::Submit(_))
                    && matches!(
                        r.wizard.step(),
                        RegisterStep::Password | RegisterStep::Token
                    )
                    || (r.wizard.step() == RegisterStep::ConfirmRecovery
                        && r.slot + 1 == acct::wizard::CONFIRM_WORDS)
            }
            Self::Login(l) => match l.step {
                LoginStep::Password | LoginStep::Totp => matches!(cmd, WizardCmd::Submit(_)),
                LoginStep::Adopt | LoginStep::Preview => matches!(cmd, WizardCmd::Choice('y')),
                _ => false,
            },
        };
        busy.then(|| {
            s.busy = true;
            s.prompt = None;
            s.choices.clear();
            s.error = None;
            s
        })
    }

    async fn input(&mut self, cmd: WizardCmd, svc: &SyncService) {
        match self {
            Self::Register(r) => r.input(cmd, svc).await,
            Self::Login(l) => l.input(cmd, svc).await,
        }
    }

    fn screen(&self) -> WizardScreen {
        match self {
            Self::Register(r) => r.screen(),
            Self::Login(l) => l.screen(),
        }
    }
}

fn prompt(label: &str, secret: bool) -> Option<WizardPrompt> {
    Some(WizardPrompt {
        label: label.to_owned(),
        secret,
    })
}

/// Settings → Sync → "Create an account" (§2.1), over [`RegisterWizard`].
#[derive(Default)]
struct RegisterFlow {
    wizard: RegisterWizard,
    prepared: Option<PreparedRegistration>,
    /// The confirmation word being asked (0..3).
    slot: usize,
    error: Option<String>,
}

impl RegisterFlow {
    async fn input(&mut self, cmd: WizardCmd, svc: &SyncService) {
        self.error = None;
        let effect = match (self.wizard.step(), cmd) {
            (RegisterStep::ShowRecovery, WizardCmd::Choice('y')) => {
                self.wizard.handle(WizardInput::Acknowledge(true));
                self.slot = 0;
                self.wizard.handle(WizardInput::Next)
            }
            (RegisterStep::ConfirmRecovery, WizardCmd::Choice('r')) => {
                self.slot = 0;
                self.wizard.handle(WizardInput::Back)
            }
            (RegisterStep::ConfirmRecovery, WizardCmd::Submit(text)) => {
                self.wizard.handle(WizardInput::ConfirmWord {
                    slot: self.slot,
                    text: text.expose().to_owned(),
                });
                self.slot += 1;
                if self.slot < acct::wizard::CONFIRM_WORDS {
                    return;
                }
                self.slot = 0;
                self.wizard.handle(WizardInput::Next)
            }
            (_, WizardCmd::Submit(text)) => {
                self.wizard
                    .handle(WizardInput::Text(text.expose().to_owned()));
                self.wizard.handle(WizardInput::Next)
            }
            (_, WizardCmd::Back) => self.wizard.handle(WizardInput::Back),
            _ => None,
        };
        match effect {
            Some(WizardEffect::Prepare {
                server,
                email,
                password,
            }) => {
                let res = acct::prepare_registration(
                    svc.store(),
                    &server,
                    &email,
                    &password,
                    &svc.account,
                )
                .await;
                drop(password);
                let input = match res {
                    Ok(p) => {
                        let words = p.recovery_words().iter().map(|w| (*w).to_owned()).collect();
                        self.prepared = Some(p);
                        WizardInput::Prepared(Ok(words))
                    }
                    Err(e) => WizardInput::Prepared(Err(e.to_string())),
                };
                self.wizard.handle(input);
            }
            Some(WizardEffect::Finish { token }) => {
                let Some(prepared) = &self.prepared else {
                    return;
                };
                let res = finish(svc, prepared, token.as_deref()).await;
                self.wizard.handle(WizardInput::Finished(res));
            }
            None => {}
        }
    }

    fn screen(&self) -> WizardScreen {
        let w = &self.wizard;
        let mut s = WizardScreen {
            title: "Create an account".into(),
            error: self
                .error
                .clone()
                .or_else(|| w.error().map(ToOwned::to_owned)),
            ..WizardScreen::default()
        };
        match w.step() {
            RegisterStep::Server => {
                s.body = vec!["The sync server's URL (there is no default server).".into()];
                s.prompt = prompt("Server URL", false);
            }
            RegisterStep::Email => s.prompt = prompt("Email", false),
            RegisterStep::Password => {
                s.body = vec!["Your current master password becomes the account password.".into()];
                s.prompt = prompt("Master password", true);
            }
            RegisterStep::Preparing | RegisterStep::Registering => s.busy = true,
            RegisterStep::ShowRecovery => {
                s.body
                    .push("Your recovery phrase (write it down; it is shown only now):".into());
                s.body.push(String::new());
                let words = w.recovery_words();
                for (row, chunk) in words.chunks(4).enumerate() {
                    let line: Vec<String> = chunk
                        .iter()
                        .enumerate()
                        .map(|(i, word)| format!("{:>2}. {word:<10}", row * 4 + i + 1))
                        .collect();
                    s.body.push(line.join("  "));
                }
                s.body.push(String::new());
                s.body.push(w.recovery_warning().to_owned());
                s.choices = vec![('y', "I have written it down".into())];
            }
            RegisterStep::ConfirmRecovery => {
                s.body = vec!["Type these words of your recovery phrase.".into()];
                let n = w
                    .confirm()
                    .map_or(0, |c| c.word_numbers()[self.slot.min(2)]);
                s.prompt = prompt(&format!("Word #{n}"), false);
                s.choices = vec![('r', "Show the phrase again".into())];
            }
            RegisterStep::Token => {
                s.body =
                    vec!["This server needs an invite (or its first-admin setup token).".into()];
                s.prompt = prompt("Invite or setup token", true);
            }
            RegisterStep::Done => {
                s.body = vec!["Account created. This vault now syncs.".into()];
                s.done = true;
            }
        }
        s
    }
}

/// Finish with no token, an invite, or (when an invite is refused) a setup token.
async fn finish(
    svc: &SyncService,
    prepared: &PreparedRegistration,
    token: Option<&str>,
) -> Result<(), acct::FinishError> {
    let tokens: Vec<Option<RegistrationToken>> = match token {
        None => vec![None],
        Some(t) => vec![
            Some(RegistrationToken::Invite(t.to_owned())),
            Some(RegistrationToken::Setup(t.to_owned())),
        ],
    };
    let mut last = None;
    for t in tokens {
        match acct::finish_registration(svc.store(), prepared, t.as_ref(), &svc.account).await {
            Ok(_) => return Ok(()),
            Err(AccountError::InviteRequired(m)) => last = Some(m),
            Err(e) => return Err(acct::FinishError::Other(e.to_string())),
        }
    }
    Err(acct::FinishError::NeedsToken(
        last.unwrap_or_else(|| "an invite is required".into()),
    ))
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum LoginStep {
    #[default]
    Server,
    Email,
    Password,
    Totp,
    /// "Your local master password will be changed…"
    Adopt,
    /// The import preview.
    Preview,
    Done,
}

/// Settings → Sync → "Log in to a server" (§2.2, §2.3, §2.5).
#[derive(Default)]
struct LoginFlow {
    step: LoginStep,
    server: String,
    email: String,
    password: Zeroizing<String>,
    session: Option<LoginSession>,
    error: Option<String>,
}

impl LoginFlow {
    async fn input(&mut self, cmd: WizardCmd, svc: &SyncService) {
        self.error = None;
        match (self.step, cmd) {
            (LoginStep::Server, WizardCmd::Submit(t)) => {
                let url = t.expose().trim().to_owned();
                if url.starts_with("https://") || url.starts_with("http://") {
                    self.server = url;
                    self.step = LoginStep::Email;
                } else {
                    self.error = Some("Enter the server URL (https://…)".into());
                }
            }
            (LoginStep::Email, WizardCmd::Submit(t)) => {
                let email = t.expose().trim().to_owned();
                if email.contains('@') {
                    self.email = email;
                    self.step = LoginStep::Password;
                } else {
                    self.error = Some("Enter a valid email address".into());
                }
            }
            (LoginStep::Password, WizardCmd::Submit(t)) if !t.expose().is_empty() => {
                self.password = Zeroizing::new(t.expose().to_owned());
                self.start(None, svc).await;
            }
            (LoginStep::Totp, WizardCmd::Submit(t)) => {
                let code = t.expose().trim().to_owned();
                self.start(Some(code), svc).await;
            }
            (LoginStep::Adopt, WizardCmd::Choice('y')) => self.after_adopt(svc).await,
            (LoginStep::Preview, WizardCmd::Choice(c)) => {
                let choice = match c {
                    'b' => Some(DuplicateChoice::KeepBoth),
                    'l' => Some(DuplicateChoice::KeepLocal),
                    'a' => Some(DuplicateChoice::KeepAccount),
                    'y' => None,
                    _ => return,
                };
                match (choice, self.session.as_mut()) {
                    (Some(choice), Some(s)) => s.preview_mut().set_all(choice),
                    (None, _) => self.commit(svc).await,
                    _ => {}
                }
            }
            (LoginStep::Email, WizardCmd::Back) => self.step = LoginStep::Server,
            (LoginStep::Password, WizardCmd::Back) => self.step = LoginStep::Email,
            _ => {}
        }
    }

    async fn start(&mut self, totp: Option<String>, svc: &SyncService) {
        let Some(lmk) = svc.lmk() else {
            self.error = Some("The vault is locked".into());
            return;
        };
        let req = LoginRequest {
            server_url: self.server.clone(),
            email: self.email.clone(),
            password: self.password.clone(),
            totp,
        };
        match acct::start_login(svc.store(), &lmk, &req, &svc.account).await {
            Ok(session) => {
                let differs = session.password_differs();
                self.session = Some(session);
                if differs {
                    self.step = LoginStep::Adopt;
                } else {
                    self.after_adopt(svc).await;
                }
            }
            Err(AccountError::TotpRequired) => self.step = LoginStep::Totp,
            Err(e) => {
                self.error = Some(e.to_string());
                self.step = LoginStep::Password;
            }
        }
    }

    async fn after_adopt(&mut self, svc: &SyncService) {
        if self.session.as_ref().is_some_and(LoginSession::will_import) {
            self.step = LoginStep::Preview;
        } else {
            self.commit(svc).await;
        }
    }

    async fn commit(&mut self, svc: &SyncService) {
        let Some(session) = &self.session else { return };
        match session.commit(svc.store()).await {
            Ok(_) => {
                self.password = Zeroizing::default();
                self.session = None;
                self.step = LoginStep::Done;
            }
            Err(e) => self.error = Some(e.to_string()),
        }
    }

    fn screen(&self) -> WizardScreen {
        let mut s = WizardScreen {
            title: "Log in to a server".into(),
            error: self.error.clone(),
            ..WizardScreen::default()
        };
        match self.step {
            LoginStep::Server => {
                s.body = vec!["The sync server's URL (there is no default server).".into()];
                s.prompt = prompt("Server URL", false);
            }
            LoginStep::Email => s.prompt = prompt("Email", false),
            LoginStep::Password => s.prompt = prompt("Account password", true),
            LoginStep::Totp => s.prompt = prompt("TOTP code", false),
            LoginStep::Adopt => {
                s.body = vec![format!("{}.", acct::PASSWORD_ADOPT_WARNING)];
                s.choices = vec![('y', "Continue".into())];
            }
            LoginStep::Preview => {
                if let Some(session) = &self.session {
                    let p = session.preview();
                    s.body = p.render().lines().map(ToOwned::to_owned).collect();
                    if !p.duplicates.is_empty() {
                        s.body.push(String::new());
                        s.body
                            .push("Likely duplicates: keep both, local or account copies?".into());
                    }
                    s.choices = vec![('y', format!("Import {} item(s)", p.imported_count()))];
                    if !p.duplicates.is_empty() {
                        s.choices.push(('b', "Keep both".into()));
                        s.choices.push(('l', "Keep local".into()));
                        s.choices.push(('a', "Keep account".into()));
                    }
                }
            }
            LoginStep::Done => {
                s.body = vec![
                    "Signed in.".into(),
                    "The vault locks now: unlock it with your account password to load the \
                     account vault."
                        .into(),
                ];
                s.done = true;
                s.relock = true;
            }
        }
        s
    }
}
