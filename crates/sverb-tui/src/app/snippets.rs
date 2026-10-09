//! M2-09: snippets in the reducer (SPEC §9.7, §8.5, §6.1.1 step 6).
//!
//! - **Data:** `SnippetsEffect::Load` after unlock and on every index update (one load
//!   in flight) fills the Snippets view; locking drops the decrypted snippets and every
//!   snippet dialog except a running results table.
//! - **Running:** `leader e` opens the picker over the focused pane; the Snippets view's
//!   `Enter` / `p` run in the last focused pane, `r` picks hosts. Every run goes through
//!   the variable form (live, masked preview). Its answer becomes:
//!   - *Paste*: `SessionInput::PasteUnchecked` (bracketed by the session under mode
//!     2004, terminators stripped, M1-11), no trailing newline;
//!   - *Paste & execute*: `SessionInput::Raw(l1\rl2\r…)`, never bracketed;
//!   - *Exec on hosts*: the results dialog and `SnippetsEffect::Run` (at most
//!     [`DEFAULT_CONCURRENCY`] hosts at a time, built-ins per host). The runs'
//!     host-key and auth prompts open the usual dialogs ("… for: snippet `<name>`") and
//!     their answers are rerouted to the run (`App::reroute_snippet_answers`).
//!
//!   Pane runs also send a `SnippetsEffect::History` record whose command keeps secret
//!   values as `{{name}}` (M7-01 stores it; nothing is stored until then).
//! - **Startup snippets:** a snippet without unanswered variables is typed by the
//!   connection itself once the shell prints (or after 500 ms; `services/ssh.rs`). One
//!   with variables without defaults is checked when the pane connects
//!   (`SnippetsEffect::StartupCheck`); the service answers `SnippetsEvent::Startup` and
//!   the variable form opens for that pane.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use sverb_conn::{
    Decision, SessionEvent, SessionState,
    ssh::exec::{DEFAULT_CONCURRENCY, snippets::RunEvent},
};
use sverb_core::{
    config::Config,
    error_report::ErrorReport,
    model::{ItemId, RunMode, Snippet},
    snippet::{Builtins, HistoryRecord, Template, Values},
    vault::LockState,
};

use super::{
    App, Effect, SessionId, SessionInput, ToastLevel, VaultEffect, hosts::ItemEffect,
    keychain::install::InstallReply,
};
use crate::{
    views::{
        DialogKind,
        dialogs::{ModalDialog, host_key::HostKeyDialog},
        keychain::install::expand_targets,
        snippets::{
            ExecPlan, HostTargetsPicker, PaneCtx, RunRequest, RunWhere, SnippetAnswer,
            SnippetDialog, SnippetDialogKind, SnippetFormDialog, SnippetPicker, SnippetResults,
            SnippetsRequest, VarForm,
        },
    },
    widgets::{auth_prompt::AuthReply, confirm},
};

/// One host of an exec run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnippetHost {
    /// Its row.
    pub index: usize,
    /// The host item.
    pub host: ItemId,
    /// Its label.
    pub label: String,
    /// The id its connection's prompts use.
    pub session: SessionId,
}

/// An exec run for the service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnippetRunJob {
    /// The run.
    pub run: u64,
    /// The snippet.
    pub snippet: ItemId,
    /// Its name (prompt titles).
    pub name: String,
    /// The script.
    pub template: Template,
    /// The values (secrets marked).
    pub values: Values,
    /// The hosts.
    pub hosts: Vec<SnippetHost>,
    /// Per command (`ssh.exec_timeout_secs`).
    pub timeout: Duration,
    /// Hosts at a time.
    pub concurrency: usize,
    /// Host resolution.
    pub config: Arc<Config>,
}

/// Snippet work for the service (`services/snippets.rs`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SnippetsEffect {
    /// Load the snippets and tag names (`SnippetsEvent::Loaded`).
    Load,
    /// Create (`id: None`) or update a snippet.
    Save {
        /// The item.
        id: Option<ItemId>,
        /// The snippet.
        snippet: Snippet,
    },
    /// Start an exec run.
    Run(Box<SnippetRunJob>),
    /// Answer a prompt of a run's connection.
    Answer {
        /// The connection.
        session: SessionId,
        /// The answer.
        reply: InstallReply,
    },
    /// Stop a run.
    Cancel {
        /// The run.
        run: u64,
    },
    /// Write exported results to a file.
    Export {
        /// The path.
        path: String,
        /// The text.
        text: String,
    },
    /// A pane run for history (secrets as placeholders).
    History(HistoryRecord),
    /// Does `host`'s startup snippet need values? (`SnippetsEvent::Startup` if so.)
    StartupCheck {
        /// The pane.
        session: SessionId,
        /// The host.
        host: ItemId,
        /// Host resolution.
        config: Arc<Config>,
    },
}

/// Results from the snippet service.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SnippetsEvent {
    /// Snippets and tag names.
    Loaded {
        /// Every snippet.
        snippets: Vec<(ItemId, Snippet)>,
        /// Tag names.
        tags: BTreeMap<ItemId, String>,
    },
    /// A save went through.
    Saved(String),
    /// Results were written to this path.
    Exported(String),
    /// Exec-run progress.
    Run {
        /// The run.
        run: u64,
        /// What happened.
        event: RunEvent,
    },
    /// A session event of a run's connection (prompts, state).
    Session {
        /// The run.
        run: u64,
        /// The connection.
        session: SessionId,
        /// The event.
        event: SessionEvent,
    },
    /// A pane's startup snippet needs values.
    Startup {
        /// The pane.
        session: SessionId,
        /// The snippet.
        id: ItemId,
        /// It.
        snippet: Snippet,
        /// The pane's built-ins (resolved host).
        builtins: Builtins,
    },
    /// Something failed.
    Failed(ErrorReport),
}

fn fx(op: SnippetsEffect) -> Effect {
    Effect::Snippets(op)
}

impl App {
    // ------------------------------------------------------------ data

    /// Reload the snippets (unlock, index updates). One load in flight.
    pub(crate) fn snippets_on_index(&mut self, effects: &mut Vec<Effect>) {
        if self.lock_state() == LockState::Locked && self.vault.active {
            return;
        }
        let view = &mut self.views.snippets;
        if view.loading {
            view.reload = true;
            return;
        }
        view.loading = true;
        effects.push(fx(SnippetsEffect::Load));
    }

    /// Locking drops the decrypted snippets and the dialogs holding them (a results
    /// table stays: it holds no script values).
    pub(crate) fn snippets_lock_transition(&mut self, was: LockState) {
        let now = self.lock_state();
        if now != was && now != LockState::Unlocked {
            self.views.snippets.clear();
            self.dialogs.retain(|d| {
                !matches!(&d.kind, DialogKind::Snippet(s)
                    if !matches!(s.kind, SnippetDialogKind::Results(_)))
            });
        }
    }

    /// A pane connected: check its startup snippet once; a closed one is forgotten.
    pub(crate) fn snippets_on_session(
        &mut self,
        id: SessionId,
        ev: &SessionEvent,
        effects: &mut Vec<Effect>,
    ) {
        match ev {
            SessionEvent::State(SessionState::Connected { .. }) => {
                let Some(host) = self
                    .panes
                    .get(&id)
                    .and_then(|p| p.host.as_deref())
                    .and_then(|h| h.parse::<ItemId>().ok())
                else {
                    return;
                };
                if self.views.snippets.startup_checked.insert(id) {
                    effects.push(fx(SnippetsEffect::StartupCheck {
                        session: id,
                        host,
                        config: Arc::clone(&self.config),
                    }));
                }
            }
            SessionEvent::State(SessionState::Closed) => {
                self.views.snippets.startup_checked.remove(&id);
            }
            _ => {}
        }
    }

    /// A result from the snippet service.
    pub(crate) fn on_snippets(&mut self, ev: SnippetsEvent, effects: &mut Vec<Effect>) {
        self.needs_redraw = true;
        match ev {
            SnippetsEvent::Loaded { snippets, tags } => {
                self.views.snippets.loading = false;
                if self.lock_state() == LockState::Locked && self.vault.active {
                    return;
                }
                self.views.snippets.set_snippets(snippets, tags);
                if std::mem::take(&mut self.views.snippets.reload) {
                    self.snippets_on_index(effects);
                }
            }
            SnippetsEvent::Saved(name) => {
                self.push_toast(ToastLevel::Info, format!("Saved \"{name}\""), effects);
            }
            SnippetsEvent::Exported(path) => {
                self.push_toast(
                    ToastLevel::Info,
                    format!("Results saved to {path}"),
                    effects,
                );
            }
            SnippetsEvent::Run { run, event } => self.on_snippet_run(run, event, effects),
            SnippetsEvent::Session {
                run,
                session,
                event,
            } => self.on_snippet_session(run, session, event, effects),
            SnippetsEvent::Startup {
                session,
                id,
                snippet,
                builtins,
            } => {
                if !self.tabs.sessions.contains(&session) {
                    return;
                }
                let pane = PaneCtx {
                    session,
                    label: self.pane(session).label,
                    host_id: self
                        .panes
                        .get(&session)
                        .and_then(|p| p.host.as_deref())
                        .and_then(|h| h.parse().ok()),
                    builtins,
                };
                self.open_var_form(
                    id,
                    &snippet,
                    RunMode::PasteAndExecute,
                    RunWhere::Startup(pane),
                    effects,
                );
            }
            SnippetsEvent::Failed(report) => {
                self.views.snippets.loading = false;
                self.push_error(&report, effects);
            }
        }
        self.reroute_snippet_answers(effects);
    }

    // ------------------------------------------------------------ opening dialogs

    fn push_snippet_dialog(&mut self, kind: SnippetDialogKind) {
        self.push_dialog(DialogKind::Snippet(Box::new(SnippetDialog::new(kind))));
    }

    /// The pane a snippet runs in: the focused live session, else the last one.
    fn snippet_pane(&self) -> Option<PaneCtx> {
        let session = self
            .focused_session()
            .or_else(|| self.last_session.filter(|s| self.tabs.sessions.contains(s)))?;
        let info = self.pane(session);
        let host_id: Option<ItemId> = info.host.as_deref().and_then(|h| h.parse().ok());
        let summary = host_id.and_then(|h| {
            self.views
                .hosts
                .catalog()
                .and_then(|c| c.hosts.get(&h).cloned())
        });
        let builtins = match summary {
            Some(h) => Builtins {
                label: h.display_label().to_owned(),
                address: h.address.clone(),
                user: h.username.clone().unwrap_or_default(),
                date: sverb_conn::ssh::exec::snippets::today(),
            },
            None => Builtins {
                label: info.label.clone(),
                address: if host_id.is_none() && info.label == "local" {
                    "localhost".to_owned()
                } else {
                    info.label.clone()
                },
                user: sverb_conn::ssh::local_user().unwrap_or_default(),
                date: sverb_conn::ssh::exec::snippets::today(),
            },
        };
        Some(PaneCtx {
            session,
            label: info.label,
            host_id,
            builtins,
        })
    }

    /// `leader e`: the picker over the focused pane.
    pub(crate) fn open_snippet_picker(&mut self, effects: &mut Vec<Effect>) {
        self.needs_redraw = true;
        if !self.views.snippets.loaded {
            self.snippets_on_index(effects);
        }
        let entries = self
            .views
            .snippets
            .list
            .rows()
            .iter()
            .map(|r| (r.id, r.snippet.clone(), r.tags.clone()))
            .collect::<Vec<_>>();
        let mut entries = entries;
        entries.sort_by_key(|a| a.1.name.to_lowercase());
        let pane = self.snippet_pane();
        self.push_snippet_dialog(SnippetDialogKind::Picker(Box::new(SnippetPicker::new(
            entries, pane,
        ))));
    }

    fn open_var_form(
        &mut self,
        id: ItemId,
        snippet: &Snippet,
        mode: RunMode,
        target: RunWhere,
        effects: &mut Vec<Effect>,
    ) {
        match VarForm::new(id, snippet, mode, target) {
            Ok(form) => self.push_snippet_dialog(SnippetDialogKind::Vars(Box::new(form))),
            Err(e) => {
                self.push_toast(
                    ToastLevel::Error,
                    format!("\"{}\" cannot run: {e}", snippet.name),
                    effects,
                );
            }
        }
    }

    fn open_host_picker(&mut self, id: ItemId, effects: &mut Vec<Effect>) {
        let Some(snippet) = self.views.snippets.get(id).cloned() else {
            return;
        };
        let Some(catalog) = self.views.hosts.catalog().cloned() else {
            self.push_toast(
                ToastLevel::Info,
                "Hosts are still loading".to_owned(),
                effects,
            );
            return;
        };
        if catalog.hosts.is_empty() {
            self.push_toast(ToastLevel::Info, "No hosts to run on".to_owned(), effects);
            return;
        }
        self.push_snippet_dialog(SnippetDialogKind::Hosts(Box::new(HostTargetsPicker::new(
            id,
            snippet.name,
            &catalog,
        ))));
    }

    /// Run `id` in `pane` with its run mode (`mode` overrides; Exec picks hosts).
    fn run_snippet_in(
        &mut self,
        id: ItemId,
        pane: Option<PaneCtx>,
        mode: Option<RunMode>,
        effects: &mut Vec<Effect>,
    ) {
        let Some(snippet) = self.views.snippets.get(id).cloned() else {
            return;
        };
        let mode = mode.unwrap_or(snippet.run_mode);
        if mode == RunMode::Exec {
            return self.open_host_picker(id, effects);
        }
        let Some(pane) = pane else {
            self.push_toast(
                ToastLevel::Info,
                "Open a session first: snippets run in the focused pane".to_owned(),
                effects,
            );
            return;
        };
        self.open_var_form(id, &snippet, mode, RunWhere::Pane(pane), effects);
    }

    // ------------------------------------------------------------ requests & answers

    /// Carry out the Snippets view's request (after a key).
    pub(crate) fn take_snippets_request(&mut self, effects: &mut Vec<Effect>) {
        let Some(request) = self.views.snippets.request.take() else {
            return;
        };
        match request {
            SnippetsRequest::RunHere(id) => {
                let pane = self.snippet_pane();
                self.run_snippet_in(id, pane, None, effects);
            }
            SnippetsRequest::RunOnHosts(id) => self.open_host_picker(id, effects),
            SnippetsRequest::Paste(id) => {
                let pane = self.snippet_pane();
                self.run_snippet_in(id, pane, Some(RunMode::Paste), effects);
            }
            SnippetsRequest::Add => {
                let tags = self.views.snippets.tag_names.clone();
                self.push_snippet_dialog(SnippetDialogKind::Form(Box::new(
                    SnippetFormDialog::new(None, None, &tags),
                )));
            }
            SnippetsRequest::Edit(id) => {
                let Some(s) = self.views.snippets.get(id).cloned() else {
                    return;
                };
                let tags = self.views.snippets.tag_names.clone();
                self.push_snippet_dialog(SnippetDialogKind::Form(Box::new(
                    SnippetFormDialog::new(Some(id), Some(&s), &tags),
                )));
            }
            SnippetsRequest::Duplicate(id) => {
                effects.push(Effect::Vault(VaultEffect::Items(ItemEffect::Duplicate(id))));
            }
            SnippetsRequest::Delete(ids) => {
                let mut modal = confirm::delete(ids.len(), "snippet");
                let names: Vec<String> = ids
                    .iter()
                    .take(5)
                    .filter_map(|id| self.views.snippets.get(*id))
                    .map(|s| s.name.clone())
                    .collect();
                if !names.is_empty() {
                    modal.body = format!("{}. {}", names.join(", "), modal.body);
                }
                let deletes = ids
                    .iter()
                    .map(|id| Effect::Vault(VaultEffect::Items(ItemEffect::Delete(*id))))
                    .collect();
                let route = format!("button:{}", confirm::YES);
                self.push_modal(ModalDialog::new(modal).on(&route, deletes), effects);
            }
        }
    }

    /// Take the answer of the top snippet dialog (after a key).
    pub(crate) fn take_snippet_answer(&mut self, effects: &mut Vec<Effect>) {
        // M3-02: a startup snippet is typed into its own pane only (never broadcast).
        let startup = matches!(
            self.dialogs.last().map(|d| &d.kind),
            Some(DialogKind::Snippet(d)) if matches!(
                &d.kind,
                crate::views::snippets::SnippetDialogKind::Vars(f)
                    if matches!(f.target, RunWhere::Startup(_))
            )
        );
        let answer = match self.dialogs.last_mut().map(|d| &mut d.kind) {
            Some(DialogKind::Snippet(d)) => d.take_answer(),
            _ => None,
        };
        let Some(answer) = answer else {
            return;
        };
        if answer.closes() {
            self.dialogs.pop();
        }
        self.needs_redraw = true;
        match answer {
            SnippetAnswer::Picked { id, pane } => self.run_snippet_in(id, pane, None, effects),
            SnippetAnswer::Hosts { id, targets } => {
                let (Some(snippet), Some(catalog)) = (
                    self.views.snippets.get(id).cloned(),
                    self.views.hosts.catalog().cloned(),
                ) else {
                    return;
                };
                let hosts = expand_targets(&catalog, &targets);
                if hosts.is_empty() {
                    self.push_toast(
                        ToastLevel::Info,
                        "The selection has no hosts".to_owned(),
                        effects,
                    );
                    return;
                }
                self.open_var_form(id, &snippet, RunMode::Exec, RunWhere::Hosts(hosts), effects);
            }
            SnippetAnswer::Run(req) => self.run_request(req, startup, effects),
            SnippetAnswer::Save { id, snippet } => {
                effects.push(fx(SnippetsEffect::Save { id, snippet }));
            }
            SnippetAnswer::Rerun => self.snippet_rerun(effects),
            SnippetAnswer::Export { path, text, .. } => match path {
                None => {
                    effects.push(Effect::CopyToClipboard(text));
                    self.push_toast(ToastLevel::Info, "Results copied".to_owned(), effects);
                }
                Some(path) => effects.push(fx(SnippetsEffect::Export { path, text })),
            },
            SnippetAnswer::Cancel(run) => {
                effects.push(fx(SnippetsEffect::Cancel { run }));
                self.views.snippets.run_sessions.clear();
            }
        }
    }

    /// The variable form's answer: type into the pane, or start the exec run.
    fn run_request(&mut self, req: RunRequest, startup: bool, effects: &mut Vec<Effect>) {
        // M3-02: snippet runs typed into a pane follow its broadcast set (SPEC §9.8);
        // a startup snippet only goes to the pane that connected.
        let send = |app: &Self, session, input: SessionInput, effects: &mut Vec<Effect>| {
            if startup {
                effects.push(Effect::SendToSession { id: session, input });
            } else {
                app.broadcast_send(session, input, effects);
            }
        };
        match req {
            RunRequest::Paste {
                session,
                text,
                history,
            } => {
                send(self, session, SessionInput::PasteUnchecked(text), effects);
                effects.push(fx(SnippetsEffect::History(history)));
            }
            RunRequest::Execute {
                session,
                bytes,
                history,
            } => {
                send(self, session, SessionInput::Raw(bytes), effects);
                effects.push(fx(SnippetsEffect::History(history)));
            }
            RunRequest::Exec(plan) => self.start_snippet_run(plan, effects),
        }
    }

    fn snippet_job(&mut self, run: u64, plan: &ExecPlan, hosts: Vec<SnippetHost>) -> Effect {
        for h in &hosts {
            self.views.snippets.run_sessions.insert(h.session);
        }
        fx(SnippetsEffect::Run(Box::new(SnippetRunJob {
            run,
            snippet: plan.snippet,
            name: plan.name.clone(),
            template: plan.template.clone(),
            values: plan.values.clone(),
            hosts,
            timeout: Duration::from_secs(u64::from(self.config.ssh.exec_timeout_secs.max(1))),
            concurrency: DEFAULT_CONCURRENCY,
            config: Arc::clone(&self.config),
        })))
    }

    fn start_snippet_run(&mut self, plan: ExecPlan, effects: &mut Vec<Effect>) {
        let run = self.ids.effect().0;
        let hosts: Vec<SnippetHost> = plan
            .hosts
            .iter()
            .enumerate()
            .map(|(index, (host, label))| SnippetHost {
                index,
                host: *host,
                label: label.clone(),
                session: self.ids.session(),
            })
            .collect();
        let results = SnippetResults::new(
            run,
            plan.snippet,
            plan.name.clone(),
            plan.hosts.clone(),
            hosts.iter().map(|h| Some(h.session)).collect(),
        );
        self.push_snippet_dialog(SnippetDialogKind::Results(Box::new(results)));
        // The plan (with its values) lives on in the results dialog for re-runs.
        if let Some(r) = self.snippet_results_mut() {
            r.plan = Some(Box::new(plan.clone()));
        }
        let effect = self.snippet_job(run, &plan, hosts);
        effects.push(effect);
    }

    fn snippet_results_mut(&mut self) -> Option<&mut SnippetResults> {
        self.dialogs
            .iter_mut()
            .rev()
            .find_map(|d| match &mut d.kind {
                DialogKind::Snippet(s) => match &mut s.kind {
                    SnippetDialogKind::Results(r) => Some(r.as_mut()),
                    _ => None,
                },
                _ => None,
            })
    }

    /// `r`: re-run the failed hosts.
    fn snippet_rerun(&mut self, effects: &mut Vec<Effect>) {
        let run = self.ids.effect().0;
        let Some(r) = self.snippet_results_mut() else {
            return;
        };
        let Some(plan) = r.plan.clone() else {
            return;
        };
        r.run = run;
        let failed = r.reset_failed();
        let picks: Vec<(usize, ItemId, String)> = failed
            .into_iter()
            .map(|i| (i, r.hosts[i].0, r.hosts[i].1.clone()))
            .collect();
        let hosts: Vec<SnippetHost> = picks
            .into_iter()
            .map(|(index, host, label)| SnippetHost {
                index,
                host,
                label,
                session: self.ids.session(),
            })
            .collect();
        if let Some(r) = self.snippet_results_mut() {
            for h in &hosts {
                r.sessions[h.index] = Some(h.session);
            }
        }
        let effect = self.snippet_job(run, &plan, hosts);
        effects.push(effect);
    }

    fn on_snippet_run(&mut self, run: u64, event: RunEvent, effects: &mut Vec<Effect>) {
        let mut finished = None;
        let mut ended = None;
        if let Some(r) = self.snippet_results_mut().filter(|r| r.run == run) {
            match event {
                RunEvent::Started(i) => r.started(i),
                RunEvent::Finished(i, result) => {
                    ended = r.sessions.get(i).copied().flatten();
                    r.finished(i, result);
                    if !r.running() {
                        finished = Some((r.table.title.clone(), r.table.summary()));
                    }
                }
            }
        }
        if let Some(s) = ended {
            self.views.snippets.run_sessions.remove(&s);
        }
        if let Some((title, summary)) = finished {
            self.push_toast(ToastLevel::Info, format!("{title}: {summary}"), effects);
        }
    }

    fn on_snippet_session(
        &mut self,
        run: u64,
        session: SessionId,
        event: SessionEvent,
        effects: &mut Vec<Effect>,
    ) {
        let label = self
            .snippet_results_mut()
            .filter(|r| r.run == run)
            .and_then(|r| {
                r.row_of(session)
                    .map(|i| (r.hosts[i].1.clone(), r.table.title.clone()))
            });
        let Some((label, title)) = label else {
            // Nobody can answer (closed, locked).
            match event {
                SessionEvent::Prompt(_) => effects.push(fx(SnippetsEffect::Answer {
                    session,
                    reply: InstallReply::Auth(AuthReply::Cancel),
                })),
                SessionEvent::HostKey(_) => effects.push(fx(SnippetsEffect::Answer {
                    session,
                    reply: InstallReply::HostKey(Decision::Reject),
                })),
                _ => {}
            }
            return;
        };
        match event {
            SessionEvent::Prompt(mut prompt) => {
                prompt.title = format!("Authenticating to {label} for: snippet {title}");
                self.auth_on_session(session, &SessionEvent::Prompt(prompt), effects);
            }
            SessionEvent::HostKey(v) => {
                self.dialogs
                    .retain(|d| !matches!(&d.kind, DialogKind::HostKey(h) if h.session == session));
                self.push_dialog(DialogKind::HostKey(HostKeyDialog::new(
                    session,
                    format!("{label} (snippet {title})"),
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

    /// Answers to run connections' prompts go to the run, not to a session.
    pub(crate) fn reroute_snippet_answers(&mut self, effects: &mut [Effect]) {
        if self.views.snippets.run_sessions.is_empty() {
            return;
        }
        for e in effects.iter_mut() {
            let rerouted = match e {
                Effect::AuthAnswer { id, reply }
                    if self.views.snippets.run_sessions.contains(id) =>
                {
                    Some(fx(SnippetsEffect::Answer {
                        session: *id,
                        reply: InstallReply::Auth(reply.clone()),
                    }))
                }
                Effect::HostKeyDecision { id, decision }
                    if self.views.snippets.run_sessions.contains(id) =>
                {
                    Some(fx(SnippetsEffect::Answer {
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

#[cfg(test)]
#[path = "snippets_tests.rs"]
mod tests;
