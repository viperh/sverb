//! M2-08: port forwards in the reducer (SPEC §9.6, §8.5, §8.1).
//!
//! - **Data:** `ForwardsEffect::Load` after unlock and on every index update (one load
//!   in flight) gives the rules and host labels; the service owns the
//!   `ForwardManager` (`services/forwards.rs`), which also auto-starts rules when their
//!   host connects and restarts them after a reconnect. While unlocked, a timer
//!   (`TimerKind::ForwardsRefresh`, every [`REFRESH_EVERY`], i.e. ≤ 2 Hz) asks for
//!   fresh statuses; the view and the status bar redraw only when they changed.
//! - **Requests** from the view: start (on the host's live connection), start without
//!   terminal (a standalone tunnel: the reducer allocates the session id, no tab is
//!   opened), stop, add / edit (the form → `ForwardsEffect::Save`), delete (confirm →
//!   `ItemEffect::Delete`).
//! - **Approval:** when the manager answers `NeedsApproval` (a non-loopback bind the
//!   first time, §9.6; a synced risky value, §17.1), a confirmation shows the exact
//!   values; "Yes" sends `Approve` and the start again. The manager remembers it, so
//!   the next start does not ask (M2-10 makes the store persistent).
//! - Locking drops the decrypted rules and stops the refresh timer (running tunnels
//!   keep running: they belong to their connections).

use std::time::Duration;

use sverb_conn::{SessionSpec, SshSpec};
use sverb_core::{
    error_report::ErrorReport,
    model::{ItemId, PortForward},
    vault::LockState,
};

use super::{App, Effect, SessionId, TimerKind, VaultEffect, hosts::ItemEffect};
use crate::{
    views::{
        DialogKind,
        dialogs::ModalDialog,
        forwards::{ForwardDialog, ForwardsRequest, approval_body},
    },
    widgets::confirm,
};

pub(crate) use sverb_conn::forward as fwd;

/// How often statuses are refreshed while unlocked (≤ 2 Hz, §9.6).
pub const REFRESH_EVERY: Duration = Duration::from_millis(500);

/// Forward requests for the forwards service (`services/forwards.rs`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ForwardsEffect {
    /// Load the rules and host labels (answered with `ForwardsEvent::Loaded`).
    Load,
    /// Fresh statuses (answered with `ForwardsEvent::Status`).
    Refresh,
    /// Create (`item: None`) or update a rule.
    Save {
        /// The item.
        item: Option<ItemId>,
        /// The rule.
        rule: PortForward,
    },
    /// Start a rule on its host's live connection.
    Start(ItemId),
    /// Start a rule on a standalone (tunnel-only) connection, opening session
    /// `session` for it unless the host already has one.
    StartStandalone {
        /// The rule.
        rule: ItemId,
        /// The session id for a new tunnel-only connection.
        session: SessionId,
        /// What to connect.
        spec: SessionSpec,
    },
    /// Stop a rule (closing its standalone connection when nothing else uses it).
    Stop(ItemId),
    /// The user confirmed these values (§9.6 / §17.1).
    Approve(Vec<fwd::RiskyValue>),
    // M2-10
    /// The user denied these values: blocked for the rest of the session (§17.1).
    Deny(Vec<fwd::RiskyValue>),
}

/// Results from the forwards service.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ForwardsEvent {
    /// Rules (with their statuses) and host labels.
    Loaded {
        /// Every rule's status.
        statuses: Vec<fwd::ForwardStatus>,
        /// Host labels by id.
        hosts: Vec<(ItemId, String)>,
    },
    /// Fresh statuses.
    Status(Vec<fwd::ForwardStatus>),
    /// Starting needs the user's confirmation of these values.
    NeedsApproval {
        /// The rule.
        rule: ItemId,
        /// What to confirm.
        values: Vec<fwd::RiskyValue>,
        /// The start was "without terminal".
        standalone: bool,
    },
    /// Something failed (load, save, start).
    Failed(ErrorReport),
}

impl App {
    // ------------------------------------------------------------ data

    /// Reload the rules (unlock, index updates). One load in flight.
    pub(crate) fn forwards_on_index(&mut self, effects: &mut Vec<Effect>) {
        if self.lock_state() == LockState::Locked && self.vault.active {
            return;
        }
        let view = &mut self.views.forwards;
        if view.loading {
            view.reload = true;
            return;
        }
        view.loading = true;
        effects.push(Effect::Forwards(ForwardsEffect::Load));
    }

    /// Locking drops the decrypted rules and stops the refresh.
    pub(crate) fn forwards_lock_transition(&mut self, was: LockState, effects: &mut Vec<Effect>) {
        let now = self.lock_state();
        if now != was && now != LockState::Unlocked {
            self.views.forwards.clear();
            effects.push(Effect::CancelTimer(TimerKind::ForwardsRefresh));
        }
    }

    fn schedule_forwards_refresh(&mut self, effects: &mut Vec<Effect>) {
        self.views.forwards.ticking = true;
        effects.push(Effect::ScheduleTimer {
            kind: TimerKind::ForwardsRefresh,
            after: REFRESH_EVERY,
        });
    }

    /// The refresh timer fired: ask for statuses and re-arm.
    pub(crate) fn on_forwards_timer(&mut self, effects: &mut Vec<Effect>) {
        self.views.forwards.ticking = false;
        if self.lock_state() == LockState::Locked && self.vault.active {
            return;
        }
        effects.push(Effect::Forwards(ForwardsEffect::Refresh));
        self.schedule_forwards_refresh(effects);
    }

    fn set_forward_statuses(&mut self, statuses: Vec<fwd::ForwardStatus>) {
        if self.views.forwards.set_statuses(statuses) {
            self.needs_redraw = true;
        }
    }

    /// A result from the forwards service.
    pub(crate) fn on_forwards(&mut self, ev: ForwardsEvent, effects: &mut Vec<Effect>) {
        match ev {
            ForwardsEvent::Loaded { statuses, hosts } => {
                self.views.forwards.loading = false;
                if self.lock_state() == LockState::Locked && self.vault.active {
                    return;
                }
                self.views.forwards.set_hosts(hosts);
                self.set_forward_statuses(statuses);
                self.needs_redraw = true;
                if !self.views.forwards.ticking {
                    self.schedule_forwards_refresh(effects);
                }
                if std::mem::take(&mut self.views.forwards.reload) {
                    self.forwards_on_index(effects);
                }
            }
            ForwardsEvent::Status(statuses) => self.set_forward_statuses(statuses),
            ForwardsEvent::NeedsApproval {
                rule,
                values,
                standalone,
            } => self.ask_forward_approval(rule, values, standalone, effects),
            ForwardsEvent::Failed(report) => {
                self.views.forwards.loading = false;
                self.push_error(&report, effects);
            }
        }
    }

    /// The confirmation for values that act locally; "Yes" approves and starts again.
    fn ask_forward_approval(
        &mut self,
        rule: ItemId,
        values: Vec<fwd::RiskyValue>,
        standalone: bool,
        effects: &mut Vec<Effect>,
    ) {
        let label = self
            .views
            .forwards
            .get(rule)
            .map(|r| r.status.rule.label.clone())
            .unwrap_or_default();
        let modal = confirm::yes_no(&format!("Start \"{label}\"?"), &approval_body(&values));
        let start = if standalone {
            match self.standalone_effect(rule) {
                Some(e) => e,
                None => return,
            }
        } else {
            Effect::Forwards(ForwardsEffect::Start(rule))
        };
        // M2-10: "No" denies for this session (not asked again until restart).
        let on_no = vec![Effect::Forwards(ForwardsEffect::Deny(values.clone()))];
        let on_yes = vec![Effect::Forwards(ForwardsEffect::Approve(values)), start];
        let route = format!("button:{}", confirm::YES);
        let no_route = format!("button:{}", confirm::NO);
        self.push_modal(
            ModalDialog::new(modal)
                .on(&route, on_yes)
                .on(&no_route, on_no),
            effects,
        );
    }

    /// `ForwardsEffect::StartStandalone` for `rule`, with a fresh session id.
    fn standalone_effect(&mut self, rule: ItemId) -> Option<Effect> {
        let row = self.views.forwards.get(rule)?;
        let host = row.status.rule.host_id;
        let label = row.host.clone();
        let spec = SshSpec {
            host: label.clone(),
            host_id: Some(host),
            label: Some(label),
            ..SshSpec::default()
        };
        let session = self.ids.session();
        Some(Effect::Forwards(ForwardsEffect::StartStandalone {
            rule,
            session,
            spec: SessionSpec::Ssh(spec),
        }))
    }

    // ------------------------------------------------------------ the view's requests

    /// Carry out the Forwards view's request (after a key).
    pub(crate) fn take_forwards_request(&mut self, effects: &mut Vec<Effect>) {
        let Some(request) = self.views.forwards.request.take() else {
            return;
        };
        match request {
            ForwardsRequest::Start(id) => effects.push(Effect::Forwards(ForwardsEffect::Start(id))),
            ForwardsRequest::StartStandalone(id) => {
                if let Some(effect) = self.standalone_effect(id) {
                    effects.push(effect);
                }
            }
            ForwardsRequest::Stop(id) => effects.push(Effect::Forwards(ForwardsEffect::Stop(id))),
            ForwardsRequest::Add => {
                let dialog = ForwardDialog::new(None, None, &self.views.forwards.hosts);
                self.push_dialog(DialogKind::Forward(dialog));
            }
            ForwardsRequest::Edit(id) => {
                let Some(row) = self.views.forwards.get(id) else {
                    return;
                };
                let r = &row.status.rule;
                let rule = PortForward {
                    label: r.label.clone(),
                    kind: r.kind,
                    host_id: r.host_id,
                    bind_addr: r.bind_addr.clone(),
                    bind_port: r.bind_port,
                    dest_host: r.dest_host.clone(),
                    dest_port: r.dest_port,
                    auto_start: r.auto_start,
                    read_only: false,
                };
                let dialog = ForwardDialog::new(Some(id), Some(&rule), &self.views.forwards.hosts);
                self.push_dialog(DialogKind::Forward(dialog));
            }
            ForwardsRequest::Delete(ids) => {
                let mut modal = confirm::delete(ids.len(), "forward");
                let names: Vec<String> = ids
                    .iter()
                    .take(5)
                    .filter_map(|id| self.views.forwards.get(*id))
                    .map(|r| r.status.rule.label.clone())
                    .collect();
                if !names.is_empty() {
                    modal.body = format!("{}. {}", names.join(", "), modal.body);
                }
                let mut deletes: Vec<Effect> = ids
                    .iter()
                    .map(|id| Effect::Forwards(ForwardsEffect::Stop(*id)))
                    .collect();
                deletes.extend(
                    ids.iter()
                        .map(|id| Effect::Vault(VaultEffect::Items(ItemEffect::Delete(*id)))),
                );
                let route = format!("button:{}", confirm::YES);
                self.push_modal(ModalDialog::new(modal).on(&route, deletes), effects);
            }
        }
    }
}

#[cfg(test)]
#[path = "forwards_tests.rs"]
mod tests;
