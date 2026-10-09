//! M5-02: shared vaults in the sync service (SPEC §13.1, §13.2): Settings →
//! Vaults requests ([`VaultOp`]) through [`VaultAdmin`], and the background
//! admin reconcile (org owners and admins without a key get `manage` from any
//! `manage` member's client, at most every [`RECONCILE_EVERY`]).

use std::time::{Duration, Instant};

use sverb_proto::orgs::Role;
use sverb_sync::account::teams;
use sverb_sync::account::vaults::{VaultAdmin, VaultAdminError};
use sverb_sync::rotation::RotationProgress;
use sverb_sync::trust::TrustError;
use tracing::{info, warn};
use uuid::Uuid;

use super::SyncService;
use crate::app::UiEvent;
use crate::app::sync_ui::VaultsResult;
use crate::app::sync_ui::{SyncUiEvent, VaultEntry, VaultMemberEntry, VaultOp};
use crate::services::EventSender;

/// How often the background reconcile runs at most.
pub(super) const RECONCILE_EVERY: Duration = Duration::from_secs(600);

fn uuid(s: &str) -> Result<Uuid, VaultAdminError> {
    s.parse()
        .map_err(|e| VaultAdminError::Invalid(format!("bad id: {e}")))
}

/// The text shown for a failure; a refused grant says why, loudly (§13.3).
fn message(e: &VaultAdminError) -> String {
    match e {
        VaultAdminError::Trust(TrustError::KeyChanged(_)) => format!(
            "Grant refused: {e}. Compare safety numbers in Settings → Team and accept the \
             new key first."
        ),
        VaultAdminError::Trust(_) => format!("Grant refused: {e}"),
        _ => e.to_string(),
    }
}

impl SyncService {
    pub(super) fn vault_op(&self, op: VaultOp, tx: &EventSender) {
        let Some(lmk) = self.lmk() else { return };
        let this = self.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let res = this
                .run_vault_op(op, &lmk, &tx)
                .await
                .unwrap_or_else(|e| VaultsResult::Failed(message(&e)));
            let _ = tx.send(UiEvent::SyncUi(SyncUiEvent::Vaults(res))).await;
        });
    }

    async fn run_vault_op(
        &self,
        op: VaultOp,
        lmk: &sverb_crypto::Key32,
        tx: &EventSender,
    ) -> Result<VaultsResult, VaultAdminError> {
        let admin = VaultAdmin::load(self.store(), lmk, &self.account).await?;
        Ok(match op {
            VaultOp::Load { vault } => self.load_vaults(&admin, lmk, vault).await?,
            VaultOp::Create { org, name } => {
                let id = admin.create(uuid(&org)?, &name).await?;
                // The new key goes to the unlocked vault; the engine pushes it.
                self.vault.adopt_new_vaults().await;
                self.request_sync();
                VaultsResult::Changed {
                    message: format!("Created the shared vault “{}”", name.trim()),
                    vault: Some(id.uuid().to_string()),
                }
            }
            VaultOp::Grant {
                vault,
                user,
                permission,
            } => {
                let v = sverb_core::model::VaultId::from_uuid(uuid(&vault)?);
                admin.grant(v, uuid(&user)?, permission).await?;
                VaultsResult::Changed {
                    message: format!("Access granted ({})", permission.as_str()),
                    vault: Some(vault),
                }
            }
            VaultOp::Revoke { vault, user } => {
                let v = sverb_core::model::VaultId::from_uuid(uuid(&vault)?);
                let me = uuid(&user)? == admin.me();
                admin.revoke(v, uuid(&user)?).await?;
                if me {
                    VaultsResult::Changed {
                        message: "You left the vault".to_owned(),
                        vault: None,
                    }
                } else {
                    // M5-04 (§13.2): the revoking client rotates the key right away.
                    info!(vault = %v, "access revoked; rotating the vault key");
                    self.rotate(&admin, &vault, tx, "Access revoked").await?
                }
            }
            // M5-04
            VaultOp::Rotate { vault } => self.rotate(&admin, &vault, tx, "").await?,
            VaultOp::Reconcile => {
                let r = admin.reconcile_admins().await?;
                let mut message = match r.granted.len() {
                    0 => "Every admin has the vault keys".to_owned(),
                    1 => "Granted one admin".to_owned(),
                    n => format!("Granted {n} admins"),
                };
                if !r.skipped.is_empty() {
                    message.push_str(&format!(
                        "; {} not granted (key not trusted)",
                        r.skipped.len()
                    ));
                }
                VaultsResult::Changed {
                    message,
                    vault: None,
                }
            }
        })
    }

    // M5-04
    /// Rotates `vault` with progress events; a failure is a
    /// [`VaultsResult::RotationFailed`] (the rotation stays resumable).
    async fn rotate(
        &self,
        admin: &VaultAdmin,
        vault: &str,
        tx: &EventSender,
        prefix: &str,
    ) -> Result<VaultsResult, VaultAdminError> {
        let v = sverb_core::model::VaultId::from_uuid(uuid(vault)?);
        let id = vault.to_owned();
        let progress_tx = tx.clone();
        let progress = move |p: RotationProgress| {
            // Progress is advisory: a full channel drops an update.
            let _ = progress_tx.try_send(UiEvent::SyncUi(SyncUiEvent::Vaults(
                VaultsResult::Rotation {
                    vault: id.clone(),
                    phase: p.phase.label().to_owned(),
                    done: p.done,
                    total: p.total,
                },
            )));
        };
        let lead = if prefix.is_empty() {
            String::new()
        } else {
            format!("{prefix}; ")
        };
        let res = admin.rotate(v, &progress).await;
        // The engine picks up the new key (and resumes paused pushes).
        self.request_sync();
        Ok(match res {
            Ok(r) => VaultsResult::RotationDone {
                message: format!(
                    "{lead}vault key rotated (version {}, {} item{})",
                    r.key_version,
                    r.items,
                    if r.items == 1 { "" } else { "s" }
                ),
                vault: vault.to_owned(),
            },
            Err(e) if e.is_busy() => VaultsResult::RotationFailed(format!(
                "{lead}another device is rotating this vault's key; try again later"
            )),
            Err(e) => {
                warn!(vault = %v, error = %e, "vault key rotation failed");
                VaultsResult::RotationFailed(format!("{lead}the key rotation failed: {e}"))
            }
        })
    }

    // M5-04
    /// The shared vaults to rotate after `user` is removed from `org` (§13.2:
    /// every vault they held a grant on that this account manages). Called before
    /// the removal; empty when leaving or without account keys.
    pub(super) async fn vaults_to_rotate(
        &self,
        lmk: &sverb_crypto::Key32,
        org: &str,
        user: &str,
    ) -> Vec<String> {
        let (Ok(org), Ok(user)) = (org.parse::<Uuid>(), user.parse::<Uuid>()) else {
            return Vec::new();
        };
        let admin = match VaultAdmin::load(self.store(), lmk, &self.account).await {
            Ok(a) if a.me() != user => a,
            _ => return Vec::new(),
        };
        match admin.vaults_to_rotate_for(org, user).await {
            Ok(v) => v.into_iter().map(|v| v.uuid().to_string()).collect(),
            Err(e) => {
                warn!(error = %e, "cannot list the vaults to rotate");
                Vec::new()
            }
        }
    }

    async fn load_vaults(
        &self,
        admin: &VaultAdmin,
        lmk: &sverb_crypto::Key32,
        shown: Option<String>,
    ) -> Result<VaultsResult, VaultAdminError> {
        let orgs = teams::list_orgs(self.store(), lmk, &self.account).await?;
        let mut vaults = Vec::new();
        for org in &orgs {
            let mut list = admin.org_vaults(org.id).await?;
            list.sort_by(|a, b| a.name.cmp(&b.name));
            for e in list {
                vaults.push(VaultEntry {
                    id: e.view.id.to_string(),
                    org_id: org.id.to_string(),
                    org_name: org.name.clone(),
                    name: e.name.clone().unwrap_or_else(|| {
                        format!("Shared {}", &e.view.id.simple().to_string()[..8])
                    }),
                    permission: e.view.permission,
                    has_key: e.view.has_key,
                });
            }
        }
        let shown = shown
            .filter(|id| vaults.iter().any(|v| &v.id == id))
            .or_else(|| vaults.first().map(|v| v.id.clone()));
        let members = match &shown {
            Some(id) => {
                let v = sverb_core::model::VaultId::from_uuid(uuid(id)?);
                match admin.members(v).await {
                    Ok(m) => m
                        .members
                        .into_iter()
                        .map(|m| VaultMemberEntry {
                            user_id: m.user_id.to_string(),
                            email: m.email.unwrap_or_else(|| m.user_id.to_string()),
                            org_role: m.org_role,
                            permission: m.permission,
                            has_key: m.has_key,
                        })
                        .collect(),
                    // A vault the account only sees as an admin, without a key.
                    Err(_) => Vec::new(),
                }
            }
            None => Vec::new(),
        };
        Ok(VaultsResult::Loaded {
            vaults,
            shown,
            members,
            admin_orgs: orgs
                .iter()
                .filter(|o| o.role >= Role::Admin)
                .map(|o| (o.id.to_string(), o.name.clone()))
                .collect(),
        })
    }

    /// After a successful sync: the §13.1 reconcile, at most every
    /// [`RECONCILE_EVERY`]. Failures are logged (the next run retries).
    pub(super) fn maybe_reconcile(&self) {
        {
            let mut last = self
                .reconciled
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if last.is_some_and(|t| t.elapsed() < RECONCILE_EVERY) {
                return;
            }
            *last = Some(Instant::now());
        }
        let Some(lmk) = self.lmk() else { return };
        let this = self.clone();
        tokio::spawn(async move {
            let admin = match VaultAdmin::load(this.store(), &lmk, &this.account).await {
                Ok(a) => a,
                // Not signed in with account keys (e.g. an old login): nothing to do.
                Err(e) => return tracing::debug!(error = %e, "no admin reconcile"),
            };
            match admin.reconcile_admins().await {
                Ok(r) if !r.granted.is_empty() || !r.skipped.is_empty() => {
                    info!(
                        granted = r.granted.len(),
                        skipped = r.skipped.len(),
                        "shared vault admin reconcile"
                    );
                }
                Ok(_) => {}
                Err(e) => warn!(error = %e, "shared vault admin reconcile failed"),
            }
        });
    }
}
