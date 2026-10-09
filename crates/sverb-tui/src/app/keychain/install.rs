//! M2-04: "Install key on host" in the reducer (SPEC §9.4, §6.1.7).
//!
//! - `H` on a key (or in the "generated" dialog) opens the host picker
//!   (`views/keychain/install.rs`); its answer is expanded into hosts
//!   ([`expand_targets`]) and confirmed with the exact command; `install` starts a run
//!   ([`InstallEffect::Run`], at most [`DEFAULT_CONCURRENCY`] hosts at a time) and
//!   shows the results table.
//! - The service reports [`InstallUpdate`]s: row states, and the session events of
//!   each host's dedicated connection under its own [`SessionId`] (host-key and auth
//!   prompts). Prompts open the usual dialogs, titled "Authenticating to `<host>` for:
//!   Install key"; their answers (`Effect::AuthAnswer` / `Effect::HostKeyDecision`
//!   for those ids) are rerouted to the run (`App::reroute_install_answers`).
//! - `r` re-runs the failed hosts only; `esc` closes the table and cancels what still
//!   runs.

use std::{sync::Arc, time::Duration};

use sverb_conn::{Decision, SessionEvent, ssh::exec::DEFAULT_CONCURRENCY};
use sverb_core::{config::Config, model::ItemId};

use super::keys::{ConfirmPurpose, KeychainEffect};
use crate::app::{App, Effect, SessionId, ToastLevel, VaultEffect, hosts::ItemEffect};
use crate::views::{
    DialogKind,
    dialogs::host_key::HostKeyDialog,
    keychain::{
        identity_form::IdentityDialog,
        import_dialog::{ConfirmDialog, KeychainDialog, KeychainDialogKind},
        install::{InstallPicker, InstallPlan, InstallResults, InstallTarget, expand_targets},
    },
};
use crate::widgets::{
    auth_prompt::AuthReply,
    dialog::{Button, Modal},
    results_table::{ResultsTable, RowState},
};

/// One host of a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallHost {
    /// Its row in the results table.
    pub index: usize,
    /// The host item.
    pub host: ItemId,
    /// Its label.
    pub label: String,
    /// The id its connection's prompts use.
    pub session: SessionId,
}

/// A run for the service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallJob {
    /// The run.
    pub run: u64,
    /// The command (§9.4 with markers).
    pub command: String,
    /// The hosts.
    pub hosts: Vec<InstallHost>,
    /// Per exec step (`ssh.exec_timeout_secs`).
    pub timeout: Duration,
    /// Hosts at a time.
    pub concurrency: usize,
    /// The configuration (host resolution).
    pub config: Arc<Config>,
}

/// The answer to an install connection's prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallReply {
    /// A host-key decision.
    HostKey(Decision),
    /// An auth prompt answer.
    Auth(AuthReply),
}

/// Install work for the service (`services/vault/items/install.rs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallEffect {
    /// Start a run.
    Run(Box<InstallJob>),
    /// Answer a prompt of a run's connection.
    Answer {
        /// The connection.
        session: SessionId,
        /// The answer.
        reply: InstallReply,
    },
    /// Stop a run (its connections are dropped).
    Cancel {
        /// The run.
        run: u64,
    },
}

/// Progress from the service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallUpdate {
    /// A row changed.
    Row {
        /// The run.
        run: u64,
        /// The row.
        index: usize,
        /// Its state.
        state: RowState,
        /// When done: how long it took.
        duration: Option<Duration>,
        /// Error output.
        detail: String,
    },
    /// A session event of a host's connection (prompts, state).
    Session {
        /// The run.
        run: u64,
        /// The connection.
        session: SessionId,
        /// The event.
        event: SessionEvent,
    },
}

fn items(op: InstallEffect) -> Effect {
    Effect::Vault(VaultEffect::Items(ItemEffect::Keychain(
        KeychainEffect::Install(op),
    )))
}

/// The effect that cancels `run` (the results dialog's `esc`).
pub fn cancel_effect(run: u64) -> Effect {
    items(InstallEffect::Cancel { run })
}

impl App {
    fn push_keychain_dialog(&mut self, d: KeychainDialog) {
        self.push_dialog(DialogKind::Identity(IdentityDialog::Keychain(Box::new(d))));
    }

    fn pop_top_keychain_dialog(&mut self) {
        if matches!(
            self.dialogs.last().map(|d| &d.kind),
            Some(DialogKind::Identity(IdentityDialog::Keychain(_)))
        ) {
            self.dialogs.pop();
        }
    }

    /// The open results dialog.
    fn install_results_mut(&mut self) -> Option<&mut InstallResults> {
        self.dialogs
            .iter_mut()
            .rev()
            .find_map(|d| match &mut d.kind {
                DialogKind::Identity(IdentityDialog::Keychain(k)) => match &mut k.kind {
                    KeychainDialogKind::InstallResults(r) => Some(r.as_mut()),
                    _ => None,
                },
                _ => None,
            })
    }

    /// `H`: the host picker for `key`.
    pub(crate) fn open_install_picker(&mut self, key: ItemId, effects: &mut Vec<Effect>) {
        self.needs_redraw = true;
        let catalog = self.views.keychain.identities.catalog().cloned();
        let Some(catalog) = catalog else {
            self.push_toast(
                ToastLevel::Info,
                "Hosts are still loading".to_owned(),
                effects,
            );
            return;
        };
        // A key generated a moment ago may not be in the catalog yet: its public key is
        // looked up when the picker is submitted.
        let label = catalog
            .key_details
            .get(&key)
            .map(|k| k.label.clone())
            .or_else(|| catalog.keys.get(&key).cloned())
            .unwrap_or_else(|| "key".to_owned());
        if catalog.hosts.is_empty() {
            self.push_toast(
                ToastLevel::Info,
                "No hosts to install on".to_owned(),
                effects,
            );
            return;
        }
        let picker = InstallPicker::new(key, label, &catalog, self.index().cloned());
        self.push_keychain_dialog(KeychainDialog::new(KeychainDialogKind::InstallPick(
            Box::new(picker),
        )));
    }

    /// The picker was submitted: confirm with the hosts and the command.
    pub(crate) fn on_install_pick(
        &mut self,
        key: ItemId,
        targets: &[InstallTarget],
        effects: &mut Vec<Effect>,
    ) {
        let catalog = self.views.keychain.identities.catalog().cloned();
        let Some((catalog, info)) = catalog.and_then(|c| {
            let info = c.key_details.get(&key).cloned()?;
            Some((c, info))
        }) else {
            self.push_toast(
                ToastLevel::Info,
                "The key is not loaded yet; try again in a moment".to_owned(),
                effects,
            );
            return;
        };
        let hosts = expand_targets(&catalog, targets);
        if hosts.is_empty() {
            self.push_toast(
                ToastLevel::Info,
                "The selection has no hosts".to_owned(),
                effects,
            );
            return;
        }
        let command = match sverb_conn::ssh::install_key::install_command(&info.public_key) {
            Ok(c) => c,
            Err(e) => {
                self.push_toast(ToastLevel::Error, format!("Cannot install: {e}"), effects);
                return;
            }
        };
        self.pop_top_keychain_dialog();
        let names: Vec<&str> = hosts.iter().take(8).map(|(_, l)| l.as_str()).collect();
        let more = hosts.len().saturating_sub(names.len());
        let mut body = format!(
            "Install \"{}\" on {} host(s): {}",
            info.label,
            hosts.len(),
            names.join(", ")
        );
        if more > 0 {
            body.push_str(&format!(" and {more} more"));
        }
        body.push_str(&format!(
            ".\nEach host runs (after a `uname` check for a POSIX shell):\n\n{command}"
        ));
        let plan = InstallPlan {
            key,
            key_label: info.label.clone(),
            command,
            hosts,
        };
        self.push_keychain_dialog(KeychainDialog::new(KeychainDialogKind::Confirm(
            ConfirmDialog {
                purpose: ConfirmPurpose::InstallKey(Box::new(plan)),
                modal: Modal::confirm(
                    "Install key on hosts",
                    &body,
                    vec![
                        Button::new("install", "install", 'i'),
                        Button::new("cancel", "cancel", 'n').safe(),
                    ],
                    0,
                    false,
                ),
            },
        )));
    }

    fn install_job(&mut self, run: u64, command: String, hosts: Vec<InstallHost>) -> Effect {
        for h in &hosts {
            self.views.keychain.install_sessions.insert(h.session);
        }
        items(InstallEffect::Run(Box::new(InstallJob {
            run,
            command,
            hosts,
            timeout: Duration::from_secs(u64::from(self.config.ssh.exec_timeout_secs.max(1))),
            concurrency: DEFAULT_CONCURRENCY,
            config: Arc::clone(&self.config),
        })))
    }

    /// `install` confirmed: start the run and show the results.
    pub(crate) fn start_install(&mut self, plan: InstallPlan, effects: &mut Vec<Effect>) {
        self.pop_top_keychain_dialog();
        let run = self.ids.effect().0;
        let hosts: Vec<InstallHost> = plan
            .hosts
            .iter()
            .enumerate()
            .map(|(index, (host, label))| InstallHost {
                index,
                host: *host,
                label: label.clone(),
                session: self.ids.session(),
            })
            .collect();
        let results = InstallResults {
            run,
            sessions: hosts.iter().map(|h| Some(h.session)).collect(),
            table: ResultsTable::new(
                format!("Install \"{}\"", plan.key_label),
                plan.hosts.iter().map(|(_, l)| l.clone()),
            ),
            plan,
        };
        let command = results.plan.command.clone();
        self.push_keychain_dialog(KeychainDialog::new(KeychainDialogKind::InstallResults(
            Box::new(results),
        )));
        let effect = self.install_job(run, command, hosts);
        effects.push(effect);
        self.needs_redraw = true;
    }

    /// `r`: re-run the failed hosts only.
    pub(crate) fn install_rerun(&mut self, effects: &mut Vec<Effect>) {
        let run = self.ids.effect().0;
        let Some(r) = self.install_results_mut() else {
            return;
        };
        if r.running() {
            return;
        }
        let failed = r.table.failed();
        if failed.is_empty() {
            return;
        }
        r.run = run;
        let mut picks = Vec::new();
        for (i, s) in r.sessions.iter_mut().enumerate() {
            *s = None;
            if failed.contains(&i) {
                r.table.rows[i].reset();
                picks.push((i, r.plan.hosts[i].clone()));
            }
        }
        let command = r.plan.command.clone();
        let hosts: Vec<InstallHost> = picks
            .into_iter()
            .map(|(index, (host, label))| InstallHost {
                index,
                host,
                label,
                session: self.ids.session(),
            })
            .collect();
        if let Some(r) = self.install_results_mut() {
            for h in &hosts {
                r.sessions[h.index] = Some(h.session);
            }
        }
        let effect = self.install_job(run, command, hosts);
        effects.push(effect);
        self.needs_redraw = true;
    }

    /// Progress from the service.
    pub(crate) fn on_install_update(&mut self, update: InstallUpdate, effects: &mut Vec<Effect>) {
        self.needs_redraw = true;
        match update {
            InstallUpdate::Row {
                run,
                index,
                state,
                duration,
                detail,
            } => {
                let done = !state.pending();
                let mut finished = None;
                let mut ended = None;
                if let Some(r) = self.install_results_mut().filter(|r| r.run == run)
                    && let Some(row) = r.table.rows.get_mut(index)
                {
                    row.state = state;
                    row.duration = duration;
                    row.detail = detail;
                    if done {
                        ended = r.sessions.get(index).copied().flatten();
                    }
                    if r.table.finished() {
                        finished = Some(r.table.summary());
                    }
                }
                if let Some(s) = ended {
                    self.views.keychain.install_sessions.remove(&s);
                }
                if let Some(summary) = finished {
                    self.push_toast(ToastLevel::Info, format!("Install key: {summary}"), effects);
                }
            }
            InstallUpdate::Session {
                run,
                session,
                event,
            } => self.on_install_session(run, session, event, effects),
        }
        self.reroute_install_answers(effects);
    }

    fn on_install_session(
        &mut self,
        run: u64,
        session: SessionId,
        event: SessionEvent,
        effects: &mut Vec<Effect>,
    ) {
        let label = self
            .install_results_mut()
            .filter(|r| r.run == run)
            .and_then(|r| r.row_of(session).map(|i| r.plan.hosts[i].1.clone()));
        let Some(label) = label else {
            // No table for it (closed, locked): nobody can answer.
            match event {
                SessionEvent::Prompt(_) => effects.push(items(InstallEffect::Answer {
                    session,
                    reply: InstallReply::Auth(AuthReply::Cancel),
                })),
                SessionEvent::HostKey(_) => effects.push(items(InstallEffect::Answer {
                    session,
                    reply: InstallReply::HostKey(Decision::Reject),
                })),
                _ => {}
            }
            return;
        };
        match event {
            SessionEvent::Prompt(mut prompt) => {
                prompt.title = format!("Authenticating to {label} for: Install key");
                self.auth_on_session(session, &SessionEvent::Prompt(prompt), effects);
            }
            SessionEvent::HostKey(v) => {
                self.dialogs
                    .retain(|d| !matches!(&d.kind, DialogKind::HostKey(h) if h.session == session));
                self.push_dialog(DialogKind::HostKey(HostKeyDialog::new(
                    session,
                    format!("{label} (Install key)"),
                    v,
                )));
            }
            SessionEvent::State(state) => {
                self.host_key_on_state(session, &state);
                self.auth_on_session(session, &SessionEvent::State(state), effects);
            }
            ev @ SessionEvent::PromptAccepted(_) => self.auth_on_session(session, &ev, effects),
            _ => {}
        }
    }

    /// Answers to install connections' prompts go to the run, not to a session.
    pub(crate) fn reroute_install_answers(&mut self, effects: &mut [Effect]) {
        if self.views.keychain.install_sessions.is_empty() {
            return;
        }
        for e in effects.iter_mut() {
            let rerouted = match e {
                Effect::AuthAnswer { id, reply }
                    if self.views.keychain.install_sessions.contains(id) =>
                {
                    Some(items(InstallEffect::Answer {
                        session: *id,
                        reply: InstallReply::Auth(reply.clone()),
                    }))
                }
                Effect::HostKeyDecision { id, decision }
                    if self.views.keychain.install_sessions.contains(id) =>
                {
                    Some(items(InstallEffect::Answer {
                        session: *id,
                        reply: InstallReply::HostKey(*decision),
                    }))
                }
                _ => None,
            };
            if let Some(r) = rerouted {
                *e = r;
            }
        }
    }
}
