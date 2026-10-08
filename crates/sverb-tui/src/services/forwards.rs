//! M2-08: the forwards service (SPEC §9.6). Owns the [`ForwardManager`], which is the
//! session manager's forward hook: SSH sessions report their connections to it, so a
//! host's auto-start rules start when it connects and restart after a reconnect, and
//! every rule stops when its connection goes away.
//!
//! [`ForwardsService::execute`] runs the Forwards view's effects; results come back as
//! `UiEvent::Forwards`.

use std::sync::Arc;

use sverb_core::{
    error_report::ErrorReport,
    model::{Host, ItemId, ItemKind, PortForward},
};
use tracing::debug;

use super::{
    EventSender,
    sessions::SessionService,
    vault::{VaultService, items::ItemOps},
};
use crate::app::{
    ForwardsEffect, ForwardsEvent, SessionId, UiEvent,
    forwards::fwd::{ForwardManager, ForwardRule, StandalonePlan, StartError},
};

/// Executes `Effect::Forwards`. Owned by [`Services`](super::Services).
#[derive(Debug, Clone, Default)]
pub struct ForwardsService {
    manager: ForwardManager,
}

fn send(tx: &EventSender, ev: ForwardsEvent) {
    if let Err(err) = tx.try_send(UiEvent::Forwards(ev)) {
        // Refreshes are periodic: a full queue just skips one.
        debug!(%err, "forwards event dropped");
    }
}

/// Rules (with this device's authorship of their risky fields, informational since
/// M2-10) and host labels.
async fn load(ops: &ItemOps) -> Result<(Vec<ForwardRule>, Vec<(ItemId, String)>), ErrorReport> {
    let items = ops
        .list(&[ItemKind::PortForward, ItemKind::Host])
        .await
        .map_err(|e| e.report())?;
    let device = ops.vault().device_id();
    let mut rules = Vec::new();
    let mut hosts = Vec::new();
    for item in &items {
        match item.body.kind {
            ItemKind::PortForward => match PortForward::try_from(&item.body) {
                Ok(pf) => rules.push(ForwardRule::from_body(item.id, &pf, &item.body, device)),
                Err(e) => debug!(item = %item.id.short(), error = %e, "forward skipped"),
            },
            ItemKind::Host => {
                if let Ok(h) = Host::try_from(&item.body) {
                    hosts.push((item.id, h.display_label().to_owned()));
                }
            }
            _ => {}
        }
    }
    Ok((rules, hosts))
}

fn start_error(rule: ItemId, err: StartError, standalone: bool) -> ForwardsEvent {
    match err {
        StartError::NeedsApproval(values) => ForwardsEvent::NeedsApproval {
            rule,
            values,
            standalone,
        },
        // M2-10
        StartError::Blocked(values) => ForwardsEvent::Failed(ErrorReport::msg(format!(
            "The forward was blocked by approval policy ({}); it is asked again after sverb restarts",
            values
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ))),
        StartError::NotConnected => ForwardsEvent::Failed(ErrorReport::msg(
            "The host is not connected: connect it first, or press t to start the forward without a terminal",
        )),
        other => ForwardsEvent::Failed(ErrorReport::msg(format!(
            "The forward did not start: {other}"
        ))),
    }
}

impl ForwardsService {
    /// A service with an empty manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// The manager (the session manager's forward hook).
    pub fn manager(&self) -> &ForwardManager {
        &self.manager
    }

    /// Make `sessions` report its SSH connections to the manager.
    pub fn attach(&self, sessions: &SessionService) {
        sessions
            .manager()
            .set_forward_hook(Arc::new(self.manager.clone()));
    }

    fn statuses(&self, tx: &EventSender) {
        send(tx, ForwardsEvent::Status(self.manager.statuses()));
    }

    /// Run a forwards effect.
    pub fn execute(
        &self,
        op: ForwardsEffect,
        vault: Option<&VaultService>,
        sessions: Option<&mut SessionService>,
        tx: &EventSender,
    ) {
        match op {
            ForwardsEffect::Load => {
                let Some(vault) = vault.cloned() else {
                    send(
                        tx,
                        ForwardsEvent::Loaded {
                            statuses: Vec::new(),
                            hosts: Vec::new(),
                        },
                    );
                    return;
                };
                // M2-10: confirmations are the device's `local_approvals`.
                self.manager.set_approvals(vault.store().device_approvals());
                let (manager, tx) = (self.manager.clone(), tx.clone());
                tokio::spawn(async move {
                    let ev = match vault.item_ops() {
                        // Locked: nothing to show (running tunnels keep running).
                        None => ForwardsEvent::Loaded {
                            statuses: Vec::new(),
                            hosts: Vec::new(),
                        },
                        Some(ops) => match load(&ops).await {
                            Ok((rules, hosts)) => {
                                manager.set_rules(rules);
                                ForwardsEvent::Loaded {
                                    statuses: manager.statuses(),
                                    hosts,
                                }
                            }
                            Err(r) => ForwardsEvent::Failed(r),
                        },
                    };
                    let _ = tx.send(UiEvent::Forwards(ev)).await;
                });
            }
            ForwardsEffect::Refresh => self.statuses(tx),
            ForwardsEffect::Save { item, rule } => {
                let Some(vault) = vault.cloned() else {
                    send(
                        tx,
                        ForwardsEvent::Failed(ErrorReport::msg("Forwards need a vault")),
                    );
                    return;
                };
                let tx = tx.clone();
                tokio::spawn(async move {
                    let Some(ops) = vault.item_ops() else {
                        let _ = tx
                            .send(UiEvent::Forwards(ForwardsEvent::Failed(ErrorReport::msg(
                                "The vault is locked",
                            ))))
                            .await;
                        return;
                    };
                    let written = ops
                        .save(
                            ItemKind::PortForward,
                            item,
                            None,
                            move |body, clock, device| {
                                rule.apply_to(body, clock, device);
                                Ok(())
                            },
                        )
                        .await;
                    match written {
                        // The index update reloads the view.
                        Ok(w) => vault.index_upsert(w.id, w.vault, &w.body, &tx),
                        Err(e) => {
                            let r = e.report();
                            let _ = tx
                                .send(UiEvent::Forwards(ForwardsEvent::Failed(ErrorReport {
                                    short: format!("Forward not saved: {}", r.short),
                                    ..r
                                })))
                                .await;
                        }
                    }
                });
            }
            ForwardsEffect::Start(id) => {
                if let Err(err) = self.manager.start(id) {
                    send(tx, start_error(id, err, false));
                }
                self.statuses(tx);
            }
            ForwardsEffect::StartStandalone {
                rule,
                session,
                spec,
            } => {
                match self.manager.plan_standalone(rule) {
                    Ok(StandalonePlan::Connected) => {}
                    Ok(StandalonePlan::Pending(sid)) => match sessions {
                        Some(sessions) => {
                            let _ = sessions
                                .command(SessionId(sid.0), sverb_conn::SessionCmd::Reconnect);
                        }
                        None => debug!("standalone reconnect ignored: no session manager"),
                    },
                    Ok(StandalonePlan::Open { host }) => match sessions {
                        Some(sessions) => {
                            if sessions.open_tunnel(session, spec) {
                                self.manager.note_standalone_session(
                                    host,
                                    sverb_conn::SessionId(session.0),
                                );
                            }
                        }
                        None => send(
                            tx,
                            ForwardsEvent::Failed(ErrorReport::msg(
                                "cannot open a tunnel: no session manager",
                            )),
                        ),
                    },
                    Err(err) => send(tx, start_error(rule, err, true)),
                }
                self.statuses(tx);
            }
            ForwardsEffect::Stop(id) => {
                if let Some(sid) = self.manager.stop(id)
                    && let Some(sessions) = sessions
                {
                    sessions.close(SessionId(sid.0));
                }
                self.statuses(tx);
            }
            ForwardsEffect::Approve(values) => self.manager.approve(&values),
            // M2-10: remembered for this session only.
            ForwardsEffect::Deny(values) => self.manager.deny(&values),
        }
    }
}
