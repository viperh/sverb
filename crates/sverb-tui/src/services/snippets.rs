//! The snippet service (SPEC §9.7).
//!
//! - `Load` / `Save` / `Export` / `StartupCheck` go through the vault's item service.
//! - `Run` works on at most `job.concurrency` hosts at a time
//!   (`sverb_conn::ssh::exec::snippets::run_on_hosts`) with the TUI's SSH connector;
//!   each host gets a dedicated connection whose host-key and auth prompts go to the UI
//!   under the row's session id (`SnippetsEvent::Session`); answers come back as
//!   `SnippetsEffect::Answer`. `Cancel` aborts the run.
//!   secret value: secrets are `{{name}}` placeholders).
//!
//! Nothing here logs commands or values.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, LazyLock, Mutex, PoisonError},
};

use sverb_conn::{
    EventSink, SessionCmd, SessionEvent, SessionId as ConnSessionId, SessionState, SshSpec,
    ssh::{
        HostResolver as _,
        exec::{
            ExecPrompts,
            snippets::{HostExecutor, RunJob, RunTarget, SshExecutor, run_on_hosts, today},
        },
    },
};
use sverb_core::{
    error_report::ErrorReport,
    model::{ItemKind, Snippet, Tag},
    snippet::{HistorySink, NoHistory, Startup},
};
use tokio::sync::mpsc;
use tracing::debug;

use super::{EventSender, vault::VaultService};
use crate::app::{
    SessionId, UiEvent,
    keychain::install::InstallReply,
    snippets::{SnippetRunJob, SnippetsEffect, SnippetsEvent},
};

/// Connections waiting for prompt answers.
static ANSWERS: LazyLock<Mutex<HashMap<SessionId, mpsc::Sender<SessionCmd>>>> =
    LazyLock::new(Mutex::default);
/// Runs in progress.
static RUNS: LazyLock<Mutex<HashMap<u64, tokio::task::AbortHandle>>> =
    LazyLock::new(Mutex::default);

fn send(tx: &EventSender, ev: SnippetsEvent) {
    let ev = UiEvent::Snippets(ev);
    if let Err(mpsc::error::TrySendError::Full(ev)) = tx.try_send(ev) {
        let tx = tx.clone();
        tokio::spawn(async move {
            let _ = tx.send(ev).await;
        });
    }
}

fn failed(tx: &EventSender, msg: impl Into<String>) {
    send(tx, SnippetsEvent::Failed(ErrorReport::msg(msg.into())));
}

/// Execute a snippet effect.
pub fn execute(vault: Option<&VaultService>, op: SnippetsEffect, tx: &EventSender) {
    match op {
        SnippetsEffect::Answer { session, reply } => return answer(session, reply),
        SnippetsEffect::Cancel { run } => {
            if let Some(task) = RUNS
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&run)
            {
                task.abort();
            }
            return;
        }
        SnippetsEffect::History(record) => return NoHistory.record(record),
        SnippetsEffect::Export { path, text } => {
            let tx = tx.clone();
            tokio::spawn(async move {
                match tokio::fs::write(&path, text).await {
                    Ok(()) => send(&tx, SnippetsEvent::Exported(path)),
                    Err(e) => failed(&tx, format!("Could not write {path}: {e}")),
                }
            });
            return;
        }
        _ => {}
    }
    let Some(vault) = vault.cloned() else {
        failed(tx, "Snippets need a vault");
        return;
    };
    let tx = tx.clone();
    match op {
        SnippetsEffect::Run(job) => start(vault, *job, tx),
        SnippetsEffect::Load => {
            tokio::spawn(async move {
                let Some(ops) = vault.item_ops() else {
                    return failed(&tx, "The vault is locked");
                };
                match ops.list(&[ItemKind::Snippet, ItemKind::Tag]).await {
                    Ok(items) => {
                        let mut snippets = Vec::new();
                        let mut tags = BTreeMap::new();
                        for i in items {
                            match i.body.kind {
                                ItemKind::Snippet => {
                                    if let Ok(s) = Snippet::try_from(&i.body) {
                                        snippets.push((i.id, s));
                                    }
                                }
                                ItemKind::Tag => {
                                    if let Ok(t) = Tag::try_from(&i.body) {
                                        tags.insert(i.id, t.name);
                                    }
                                }
                                _ => {}
                            }
                        }
                        send(&tx, SnippetsEvent::Loaded { snippets, tags });
                    }
                    Err(e) => failed(&tx, e.to_string()),
                }
            });
        }
        SnippetsEffect::Save { id, snippet } => {
            tokio::spawn(async move {
                let Some(ops) = vault.item_ops() else {
                    return failed(&tx, "The vault is locked");
                };
                let name = snippet.name.clone();
                let written = ops
                    .save(ItemKind::Snippet, id, None, move |body, clock, device| {
                        snippet.apply_to(body, clock, device);
                        Ok(())
                    })
                    .await;
                match written {
                    Ok(_) => send(&tx, SnippetsEvent::Saved(name)),
                    Err(e) => send(&tx, SnippetsEvent::Failed(e.report())),
                }
            });
        }
        SnippetsEffect::StartupCheck {
            session,
            host,
            config,
        } => {
            tokio::spawn(async move {
                let resolver = super::ssh::VaultHostResolver::new(Some(vault.clone()), config);
                let spec = SshSpec {
                    host_id: Some(host),
                    ..SshSpec::default()
                };
                let Ok(target) = resolver.resolve(&spec).await else {
                    return;
                };
                let Some(id) = target.startup_snippet_id else {
                    return;
                };
                let Some(ops) = vault.item_ops() else {
                    return;
                };
                let Ok(Some(item)) = ops.load(id).await else {
                    return;
                };
                let Ok(snippet) = Snippet::try_from(&item.body) else {
                    return;
                };
                let builtins = super::ssh::startup_builtins(&target);
                match sverb_core::snippet::startup(&snippet, &builtins) {
                    Startup::NeedsValues(_) => send(
                        &tx,
                        SnippetsEvent::Startup {
                            session,
                            id,
                            snippet,
                            builtins,
                        },
                    ),
                    Startup::Invalid(e) => {
                        failed(&tx, format!("Startup snippet \"{}\": {e}", snippet.name));
                    }
                    // Typed by the connection itself (`services/ssh.rs`).
                    Startup::Ready(_) => {}
                }
            });
        }
        // Handled above.
        SnippetsEffect::Answer { .. }
        | SnippetsEffect::Cancel { .. }
        | SnippetsEffect::History(_)
        | SnippetsEffect::Export { .. } => {}
    }
}

fn answer(session: SessionId, reply: InstallReply) {
    let cmd = match reply {
        InstallReply::HostKey(d) => SessionCmd::HostKeyDecision(d),
        InstallReply::Auth(r) => SessionCmd::AuthAnswer(r.into_answer()),
    };
    let sender = ANSWERS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&session)
        .cloned();
    match sender {
        Some(s) if s.try_send(cmd).is_ok() => {}
        _ => debug!(
            session = session.0,
            "answer for a finished snippet connection"
        ),
    }
}

/// Forwards a run connection's prompts to the UI.
struct Forward {
    run: u64,
    tx: EventSender,
}

impl EventSink for Forward {
    fn send(&self, id: ConnSessionId, ev: SessionEvent) {
        if matches!(
            ev,
            SessionEvent::HostKey(_)
                | SessionEvent::Prompt(_)
                | SessionEvent::PromptAccepted(_)
                | SessionEvent::State(_)
        ) {
            send(
                &self.tx,
                SnippetsEvent::Session {
                    run: self.run,
                    session: SessionId(id.0),
                    event: ev,
                },
            );
        }
    }
}

/// Removes the answer route when the host is done (or the run is aborted).
struct Route(SessionId);

impl Drop for Route {
    fn drop(&mut self) {
        ANSWERS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.0);
    }
}

fn start(vault: VaultService, job: SnippetRunJob, tx: EventSender) {
    let run = job.run;
    let connector = Arc::new(super::ssh::ssh_connector_with_events(
        Some(vault),
        Arc::clone(&job.config),
        Some(tx.clone()),
    ));
    let sessions: HashMap<usize, SessionId> =
        job.hosts.iter().map(|h| (h.index, h.session)).collect();
    let routes: Arc<Mutex<Vec<Route>>> = Arc::default();
    let (tx_p, routes_p) = (tx.clone(), Arc::clone(&routes));
    let executor = SshExecutor::new(connector)
        .with_prompts(Arc::new(move |t: &RunTarget| {
            let session = sessions.get(&t.index).copied().unwrap_or(SessionId(0));
            let (answer_tx, answers) = mpsc::channel(4);
            ANSWERS
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(session, answer_tx);
            routes_p
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(Route(session));
            ExecPrompts {
                id: ConnSessionId(session.0),
                events: Arc::new(Forward {
                    run,
                    tx: tx_p.clone(),
                }),
                answers,
            }
        }))
        .on_connected({
            let tx = tx.clone();
            let sessions: HashMap<usize, SessionId> =
                job.hosts.iter().map(|h| (h.index, h.session)).collect();
            Arc::new(move |t: &RunTarget| {
                // The connection no longer prompts: close its dialogs.
                if let Some(s) = sessions.get(&t.index) {
                    send(
                        &tx,
                        SnippetsEvent::Session {
                            run,
                            session: *s,
                            event: SessionEvent::State(SessionState::Closed),
                        },
                    );
                }
            })
        });
    let executor: Arc<dyn HostExecutor> = Arc::new(executor);
    let targets: Vec<RunTarget> = job
        .hosts
        .iter()
        .map(|h| RunTarget {
            index: h.index,
            host_id: Some(h.host),
            label: h.label.clone(),
        })
        .collect();
    let run_job = Arc::new(RunJob {
        snippet: Some(job.snippet),
        template: job.template,
        values: job.values,
        date: today(),
        timeout: job.timeout,
    });
    let concurrency = job.concurrency;
    let tx2 = tx.clone();
    let task = tokio::spawn(async move {
        let _routes = routes;
        run_on_hosts(
            executor,
            run_job,
            targets,
            concurrency,
            Arc::new(move |event| send(&tx2, SnippetsEvent::Run { run, event })),
        )
        .await;
        RUNS.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&run);
    });
    RUNS.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(run, task.abort_handle());
}
