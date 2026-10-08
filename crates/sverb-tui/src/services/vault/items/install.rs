//! M2-04: install-key runs (SPEC §9.4) for the TUI.
//!
//! A run works on at most `job.concurrency` hosts at a time. Each host gets a
//! dedicated connection (`sverb_conn::ssh::SshConnection`, the TUI's SSH connector:
//! vault host resolution, known hosts, the auth chain), then `uname` and the install
//! command. Progress goes back as `VaultEvent::Keychain` with
//! `KeychainOutcome::Install`: row states, and the connection's session events
//! (host-key and auth prompts) under the host's session id. Prompt answers come in as
//! `InstallEffect::Answer` and are passed to the waiting connection; `Cancel` aborts
//! the run (dropping its connections).

use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, Mutex, PoisonError},
    time::Instant,
};

use sverb_conn::{
    EventSink, SessionCmd, SessionEvent, SessionId as ConnSessionId, SshSpec,
    ssh::{
        exec::{ExecPrompts, SshConnection, connect_error_text, for_each_concurrent},
        install_key::{InstallOutcome, install_on},
    },
};
use tokio::sync::mpsc;
use tracing::debug;

use super::super::VaultService;
use crate::app::keychain::install::{
    InstallEffect, InstallHost, InstallJob, InstallReply, InstallUpdate,
};
use crate::app::keychain::keys::{KeychainEvent, KeychainOutcome};
use crate::app::{SessionId, UiEvent, VaultEvent};
use crate::services::EventSender;
use crate::widgets::results_table::RowState;

/// Connections waiting for prompt answers.
static ANSWERS: LazyLock<Mutex<HashMap<SessionId, mpsc::Sender<SessionCmd>>>> =
    LazyLock::new(Mutex::default);
/// Runs in progress.
static RUNS: LazyLock<Mutex<HashMap<u64, tokio::task::AbortHandle>>> =
    LazyLock::new(Mutex::default);

fn send(tx: &EventSender, update: InstallUpdate) {
    let ev = UiEvent::Vault(VaultEvent::Keychain(KeychainEvent {
        token: 0,
        outcome: KeychainOutcome::Install(update),
    }));
    if let Err(mpsc::error::TrySendError::Full(ev)) = tx.try_send(ev) {
        let tx = tx.clone();
        tokio::spawn(async move {
            let _ = tx.send(ev).await;
        });
    }
}

/// Forwards a connection's session events to the UI.
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
                InstallUpdate::Session {
                    run: self.run,
                    session: SessionId(id.0),
                    event: ev,
                },
            );
        }
    }
}

/// Execute an install effect.
pub fn execute(service: &VaultService, op: InstallEffect, tx: &EventSender) {
    match op {
        InstallEffect::Run(job) => start(service.clone(), *job, tx.clone()),
        InstallEffect::Answer { session, reply } => {
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
                Some(s) => {
                    if s.try_send(cmd).is_err() {
                        debug!(
                            session = session.0,
                            "install connection no longer waits for an answer"
                        );
                    }
                }
                None => debug!(
                    session = session.0,
                    "answer for a finished install connection"
                ),
            }
        }
        InstallEffect::Cancel { run } => {
            if let Some(task) = RUNS
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&run)
            {
                task.abort();
            }
        }
    }
}

fn start(service: VaultService, job: InstallJob, tx: EventSender) {
    let run = job.run;
    let connector = Arc::new(crate::services::ssh::ssh_connector_with_events(
        Some(service),
        Arc::clone(&job.config),
        Some(tx.clone()),
    ));
    let job = Arc::new(job);
    let tx2 = tx.clone();
    let task = tokio::spawn(async move {
        let hosts = job.hosts.clone();
        for_each_concurrent(hosts, job.concurrency, |h| {
            let (connector, job, tx) = (Arc::clone(&connector), Arc::clone(&job), tx2.clone());
            async move { one_host(&connector, &job, h, &tx).await }
        })
        .await;
        RUNS.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&run);
    });
    RUNS.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(run, task.abort_handle());
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

async fn one_host(
    connector: &sverb_conn::SshConnector,
    job: &InstallJob,
    h: InstallHost,
    tx: &EventSender,
) {
    let started = Instant::now();
    let row = |state: RowState, detail: String, done: bool| InstallUpdate::Row {
        run: job.run,
        index: h.index,
        state,
        duration: done.then(|| started.elapsed()),
        detail,
    };
    send(
        tx,
        row(
            RowState::Running("connecting".to_owned()),
            String::new(),
            false,
        ),
    );
    let (answer_tx, answers) = mpsc::channel(4);
    ANSWERS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(h.session, answer_tx);
    let _route = Route(h.session);
    let spec = SshSpec {
        host: h.label.clone(),
        host_id: Some(h.host),
        label: Some(h.label.clone()),
        ..SshSpec::default()
    };
    let prompts = ExecPrompts {
        id: ConnSessionId(h.session.0),
        events: Arc::new(Forward {
            run: job.run,
            tx: tx.clone(),
        }),
        answers,
    };
    let opened = SshConnection::open(connector, &spec, prompts).await;
    // The connection no longer prompts: close its dialogs.
    send(
        tx,
        InstallUpdate::Session {
            run: job.run,
            session: h.session,
            event: SessionEvent::State(sverb_conn::SessionState::Closed),
        },
    );
    let conn = match opened {
        Ok(conn) => conn,
        Err(err) => {
            let text = connect_error_text(&err);
            let detail = err.report.map(|r| r.chain.join("\n")).unwrap_or_default();
            send(
                tx,
                row(RowState::Failed(format!("error: {text}")), detail, true),
            );
            return;
        }
    };
    send(
        tx,
        row(
            RowState::Running("installing".to_owned()),
            String::new(),
            false,
        ),
    );
    let outcome = install_on(&conn, &job.command, job.timeout).await;
    conn.close().await;
    let (state, detail) = match &outcome {
        InstallOutcome::Installed => (RowState::Ok(outcome.text()), String::new()),
        InstallOutcome::AlreadyPresent => (RowState::Notice(outcome.text()), String::new()),
        InstallOutcome::Unsupported => (RowState::Failed(outcome.text()), String::new()),
        InstallOutcome::Failed { detail, .. } => (RowState::Failed(outcome.text()), detail.clone()),
    };
    send(tx, row(state, detail, true));
}
