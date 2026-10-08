//! M2-09: multi-host snippet runs over exec channels (SPEC §9.7, §16).
//!
//! [`run_on_hosts`] runs one [`RunJob`] (a parsed template and the user's values) on
//! many [`RunTarget`]s, at most `concurrency` at a time ([`DEFAULT_CONCURRENCY`]),
//! through a [`HostExecutor`]. Results come back in target order; progress goes to a
//! callback ([`RunEvent`]) as hosts start and finish.
//!
//! [`SshExecutor`] is the real executor: a dedicated connection per host
//! ([`SshConnection::open`]), then the command rendered **for that host**: the
//! built-ins (`host.label`, `host.address`, `host.user`) come from the resolved target,
//! so inherited users and identities are what `{{host.user}}` sees. Each run is
//! recorded to the [`HistorySink`] with secrets as `{{name}}` placeholders. Neither the
//! command nor values are logged.

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use sverb_core::{
    model::ItemId,
    snippet::{
        Builtins, HostRunResult, RenderStyle, Template, Values,
        history::{HistorySink, NoHistory, record_run},
    },
};

use super::{
    DEFAULT_CONCURRENCY, ExecOpts, ExecPrompts, ExecResult, SshConnection, connect_error_text,
    exec, for_each_concurrent,
};
use crate::{session::SshSpec, ssh::SshConnector};

/// One host of a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunTarget {
    /// Position in the run (results-table row).
    pub index: usize,
    /// The host item (`None`: an unsaved target, resolved from `label`).
    pub host_id: Option<ItemId>,
    /// The host label.
    pub label: String,
}

/// What runs everywhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunJob {
    /// The snippet (for history).
    pub snippet: Option<ItemId>,
    /// The parsed script.
    pub template: Template,
    /// The values (defaults filled in; secrets marked).
    pub values: Values,
    /// `{{date}}` (`YYYY-MM-DD`).
    pub date: String,
    /// Per command.
    pub timeout: Duration,
}

/// Progress of a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunEvent {
    /// The host got a slot.
    Started(usize),
    /// The host is done.
    Finished(usize, HostRunResult),
}

/// Runs a job on one host.
#[async_trait]
pub trait HostExecutor: Send + Sync {
    /// Connect, render, execute; never fails (errors are in the result).
    async fn run(&self, target: &RunTarget, job: &RunJob) -> HostRunResult;
}

/// Today's local date, `YYYY-MM-DD` (`{{date}}`).
pub fn today() -> String {
    chrono::Local::now().format("%Y-%m-%d").to_string()
}

/// An exec result as a run result.
pub fn from_exec(label: &str, r: ExecResult) -> HostRunResult {
    HostRunResult {
        host: label.to_owned(),
        exit: r.exit,
        signal: r.signal,
        stdout: r.stdout.to_vec(),
        stderr: r.stderr.to_vec(),
        truncated: r.truncated,
        duration: r.duration,
        error: None,
    }
}

/// Run `job` on `targets`, at most `concurrency` (≥ 1) at a time; results in target
/// order.
pub async fn run_on_hosts(
    executor: Arc<dyn HostExecutor>,
    job: Arc<RunJob>,
    targets: Vec<RunTarget>,
    concurrency: usize,
    on_event: Arc<dyn Fn(RunEvent) + Send + Sync>,
) -> Vec<HostRunResult> {
    let slots: Arc<parking_lot::Mutex<Vec<Option<HostRunResult>>>> =
        Arc::new(parking_lot::Mutex::new(vec![None; targets.len()]));
    let order: Vec<(usize, String)> = targets
        .iter()
        .enumerate()
        .map(|(i, t)| (i, t.label.clone()))
        .collect();
    let items: Vec<(usize, RunTarget)> = targets.into_iter().enumerate().collect();
    for_each_concurrent(items, concurrency.max(1), |(slot, target)| {
        let (executor, job, on_event, slots) = (
            Arc::clone(&executor),
            Arc::clone(&job),
            Arc::clone(&on_event),
            Arc::clone(&slots),
        );
        async move {
            on_event(RunEvent::Started(target.index));
            let result = executor.run(&target, &job).await;
            on_event(RunEvent::Finished(target.index, result.clone()));
            slots.lock()[slot] = Some(result);
        }
    })
    .await;
    let mut slots = slots.lock();
    order
        .into_iter()
        .map(|(i, label)| {
            slots[i]
                .take()
                .unwrap_or_else(|| HostRunResult::failed(label, "not run", Duration::ZERO))
        })
        .collect()
}

/// Called with a host once its connection attempt is over.
pub type ConnectedHook = Arc<dyn Fn(&RunTarget) + Send + Sync>;

/// Makes the prompt channel of one host's connection.
pub type PromptsFor = Arc<dyn Fn(&RunTarget) -> ExecPrompts + Send + Sync>;

/// The real executor: a dedicated SSH connection per host.
#[derive(Clone)]
pub struct SshExecutor {
    connector: Arc<SshConnector>,
    prompts: PromptsFor,
    history: Arc<dyn HistorySink>,
    /// Called once the connection is closed (prompt dialogs can go).
    connected: Option<ConnectedHook>,
}

impl std::fmt::Debug for SshExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshExecutor").finish_non_exhaustive()
    }
}

impl SshExecutor {
    /// Connect through `connector`; host-key and auth prompts are refused.
    pub fn new(connector: Arc<SshConnector>) -> Self {
        Self {
            connector,
            prompts: Arc::new(|_| ExecPrompts::none()),
            history: Arc::new(NoHistory),
            connected: None,
        }
    }

    /// Where each connection's prompts go.
    #[must_use]
    pub fn with_prompts(mut self, prompts: PromptsFor) -> Self {
        self.prompts = prompts;
        self
    }

    /// Where runs are recorded.
    #[must_use]
    pub fn with_history(mut self, history: Arc<dyn HistorySink>) -> Self {
        self.history = history;
        self
    }

    /// Called when a host's connection attempt is over (its prompts are done).
    #[must_use]
    pub fn on_connected(mut self, f: ConnectedHook) -> Self {
        self.connected = Some(f);
        self
    }
}

#[async_trait]
impl HostExecutor for SshExecutor {
    async fn run(&self, target: &RunTarget, job: &RunJob) -> HostRunResult {
        let started = Instant::now();
        let spec = SshSpec {
            host: target.label.clone(),
            host_id: target.host_id,
            label: Some(target.label.clone()),
            ..SshSpec::default()
        };
        let opened = SshConnection::open(&self.connector, &spec, (self.prompts)(target)).await;
        if let Some(f) = &self.connected {
            f(target);
        }
        let conn = match opened {
            Ok(conn) => conn,
            Err(err) => {
                return HostRunResult::failed(
                    &target.label,
                    connect_error_text(&err),
                    started.elapsed(),
                );
            }
        };
        let t = conn.target();
        let builtins = Builtins {
            label: t.label.clone(),
            address: t.address.clone(),
            user: t.username.clone(),
            date: job.date.clone(),
        };
        let command = match job
            .template
            .render(&job.values, &builtins, RenderStyle::Final)
        {
            Ok(c) => c,
            Err(e) => {
                conn.close().await;
                return HostRunResult::failed(&target.label, e.to_string(), started.elapsed());
            }
        };
        record_run(
            self.history.as_ref(),
            &job.template,
            &job.values,
            &builtins,
            target.host_id,
            job.snippet,
        );
        let result = exec(&conn, &command, ExecOpts::with_timeout(job.timeout)).await;
        conn.close().await;
        match result {
            Ok(r) => from_exec(&target.label, r),
            Err(e) => HostRunResult::failed(&target.label, e.to_string(), started.elapsed()),
        }
    }
}

/// Counts how many runs are in flight (tests and diagnostics).
#[derive(Debug, Default)]
pub struct InFlight {
    now: AtomicUsize,
    max: AtomicUsize,
}

impl InFlight {
    /// A run started.
    pub fn enter(&self) {
        let n = self.now.fetch_add(1, Ordering::SeqCst) + 1;
        self.max.fetch_max(n, Ordering::SeqCst);
    }

    /// A run ended.
    pub fn leave(&self) {
        self.now.fetch_sub(1, Ordering::SeqCst);
    }

    /// The most at once.
    pub fn max(&self) -> usize {
        self.max.load(Ordering::SeqCst)
    }
}

/// The default concurrency of snippet runs.
pub const SNIPPET_CONCURRENCY: usize = DEFAULT_CONCURRENCY;

#[cfg(all(unix, test))]
#[path = "snippets_tests.rs"]
mod tests;
