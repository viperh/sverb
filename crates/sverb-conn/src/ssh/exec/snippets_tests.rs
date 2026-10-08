//! M2-09: snippet runs: T-05 (paste encoding), T-09 (loopback variant), T-10.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use sverb_core::snippet::{
    Builtins, HistoryRecord, HistorySink, HostRunResult, RenderStyle, RunStatus, Summary, Template,
    Values, paste_execute_bytes, paste_text, results,
};
use sverb_term::{input::paste::encode_paste, modes::TermModes};

use super::*;
use crate::ssh::{
    InsecureAcceptAnyHostKey, SshConnector,
    exec_testing::{ExecResolver, ExecServerOpts, TempHome, start_exec_server},
};

fn job(script: &str, values: Values) -> Arc<RunJob> {
    Arc::new(RunJob {
        snippet: None,
        template: Template::parse(script).unwrap(),
        values,
        date: "2026-10-08".into(),
        timeout: Duration::from_secs(10),
    })
}

fn targets(labels: &[&str]) -> Vec<RunTarget> {
    labels
        .iter()
        .enumerate()
        .map(|(index, l)| RunTarget {
            index,
            host_id: None,
            label: (*l).to_owned(),
        })
        .collect()
}

/// Renders per host and "runs" it: exit 1 when the command contains `fail`.
struct Fake {
    flight: InFlight,
    seen: Mutex<Vec<String>>,
}

#[async_trait]
impl HostExecutor for Fake {
    async fn run(&self, target: &RunTarget, job: &RunJob) -> HostRunResult {
        self.flight.enter();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let b = Builtins {
            label: target.label.clone(),
            date: job.date.clone(),
            ..Builtins::default()
        };
        let cmd = job
            .template
            .render(&job.values, &b, RenderStyle::Final)
            .unwrap();
        self.seen.lock().unwrap().push(cmd.clone());
        self.flight.leave();
        HostRunResult {
            host: target.label.clone(),
            exit: Some(u32::from(cmd.contains("fail"))),
            stdout: cmd.into_bytes(),
            ..HostRunResult::default()
        }
    }
}

// T-10
#[tokio::test(start_paused = true)]
async fn t10_default_concurrency_is_10() {
    let fake = Arc::new(Fake {
        flight: InFlight::default(),
        seen: Mutex::default(),
    });
    let labels: Vec<String> = (0..30).map(|i| format!("h{i}")).collect();
    let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
    let events = Arc::new(Mutex::new(Vec::new()));
    let ev2 = Arc::clone(&events);
    let out = run_on_hosts(
        fake.clone(),
        job("echo {{host.label}}", Values::new()),
        targets(&refs),
        SNIPPET_CONCURRENCY,
        Arc::new(move |e| ev2.lock().unwrap().push(e)),
    )
    .await;
    assert_eq!(SNIPPET_CONCURRENCY, 10);
    assert_eq!(fake.flight.max(), 10);
    assert_eq!(out.len(), 30);
    // Target order, each with its own built-ins.
    for (i, r) in out.iter().enumerate() {
        assert_eq!(r.host, format!("h{i}"));
        assert_eq!(r.stdout, format!("echo h{i}").into_bytes());
    }
    let events = events.lock().unwrap();
    assert_eq!(events.len(), 60);
    assert!(matches!(events[0], RunEvent::Started(_)));
}

#[tokio::test(start_paused = true)]
async fn concurrency_limit_is_respected() {
    let fake = Arc::new(Fake {
        flight: InFlight::default(),
        seen: Mutex::default(),
    });
    let out = run_on_hosts(
        fake.clone(),
        job("x", Values::new()),
        targets(&["a", "b", "c", "d", "e"]),
        2,
        Arc::new(|_| {}),
    )
    .await;
    assert_eq!(fake.flight.max(), 2);
    assert_eq!(out.len(), 5);
}

// T-05
#[test]
fn t05_paste_encoding() {
    let text = paste_text("echo a\necho b\n");
    let on = TermModes {
        bracketed_paste: true,
        ..TermModes::default()
    };
    let off = TermModes::default();
    assert_eq!(
        &encode_paste(&text, &on)[..],
        b"\x1b[200~echo a\necho b\x1b[201~"
    );
    assert_eq!(&encode_paste(&text, &off)[..], b"echo a\recho b");
    // Terminators inside the text are stripped (M1-11).
    let evil = paste_text("a\x1b[201~rm -rf /\n");
    assert_eq!(
        &encode_paste(&evil, &on)[..],
        b"\x1b[200~arm -rf /\x1b[201~"
    );
}

// T-06 (bytes go out raw: the session's paste encoder is not involved)
#[test]
fn t06_paste_execute_never_bracketed() {
    let bytes = paste_execute_bytes("l1\nl2\nl3");
    assert_eq!(bytes, b"l1\rl2\rl3\r");
    assert!(!bytes.windows(6).any(|w| w == b"\x1b[200~"));
}

#[derive(Default)]
struct Sink(Mutex<Vec<HistoryRecord>>);

impl HistorySink for Sink {
    fn record(&self, record: HistoryRecord) {
        self.0.lock().unwrap().push(record);
    }
}

// T-09 (loopback variant of the Docker e2e): three hosts, one fails.
#[tokio::test]
async fn t09_exec_on_three_hosts_loopback() {
    let home = TempHome::new();
    let (addr, seen) = start_exec_server(ExecServerOpts {
        home: home.0.clone(),
        posix: true,
    })
    .await;
    let connector = Arc::new(
        SshConnector::new(Arc::new(ExecResolver::password(addr)))
            .with_verifier(Arc::new(InsecureAcceptAnyHostKey::insecure_for_testing())),
    );
    let sink = Arc::new(Sink::default());
    let executor = Arc::new(SshExecutor::new(connector).with_history(sink.clone()));
    const CANARY: &str = "CANARY-tok-77";
    let values = Values::new().with("token", CANARY, true);
    let out = run_on_hosts(
        executor,
        job(
            "echo {{host.label}}@{{host.user}} {{date}}; : {{token|q}}; test {{host.label}} != web-2",
            values,
        ),
        targets(&["web-1", "web-2", "web-3"]),
        SNIPPET_CONCURRENCY,
        Arc::new(|_| {}),
    )
    .await;
    let statuses: Vec<RunStatus> = out.iter().map(HostRunResult::status).collect();
    assert_eq!(
        statuses,
        vec![RunStatus::Ok, RunStatus::Exit(1), RunStatus::Ok]
    );
    assert_eq!(out[0].stdout, b"web-1@sverb 2026-10-08\n");
    assert_eq!(out[1].stdout, b"web-2@sverb 2026-10-08\n");
    assert_eq!(results::summarize(&out), Summary::Partial);
    // The server ran the real value; history only saw the placeholder.
    assert!(seen.lock().commands.iter().all(|c| c.contains(CANARY)));
    let records = sink.0.lock().unwrap();
    assert_eq!(records.len(), 3);
    assert!(records.iter().all(|r| !r.command.contains(CANARY)));
    assert!(records[0].command.contains(": {{token}};"));
    // Exports of this run.
    let json = results::to_json(&out);
    assert_eq!(json["data"][1]["exit"], 1);
    assert_eq!(json["data"][0]["stdout"], "web-1@sverb 2026-10-08\n");
    let md = results::to_markdown("check", &out);
    assert!(md.contains("| web-2 | exit 1 | 1 |"), "{md}");
}

#[tokio::test]
async fn unreachable_host_is_an_error_row() {
    // Nothing listens on this port (bound then dropped).
    let addr = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let connector = Arc::new(
        SshConnector::new(Arc::new(ExecResolver::password(addr)))
            .with_verifier(Arc::new(InsecureAcceptAnyHostKey::insecure_for_testing())),
    );
    let out = run_on_hosts(
        Arc::new(SshExecutor::new(connector)),
        job("true", Values::new()),
        targets(&["gone"]),
        SNIPPET_CONCURRENCY,
        Arc::new(|_| {}),
    )
    .await;
    assert!(matches!(out[0].status(), RunStatus::Error(_)), "{out:?}");
    assert_eq!(results::summarize(&out), Summary::AllFailed);
}

// T-08 (loopback, real time): the startup snippet (Paste & execute text from
// `sverb_core::snippet::startup`) is typed once the first output arrives, or after
// `STARTUP_DELAY` (500 ms) when the shell prints nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t08_startup_snippet_after_output_or_delay() {
    use crate::{
        OpenOptions, SessionEvent, SessionManager, SessionState, TransportKind,
        ssh::{
            HostResolver, SshError, SshTarget,
            channel::STARTUP_DELAY,
            testing::{TestResolver, start_server},
        },
    };
    use sverb_core::{
        model::{RunMode, Snippet},
        snippet::startup,
    };

    #[derive(Debug)]
    struct WithStartup(TestResolver);
    #[async_trait]
    impl HostResolver for WithStartup {
        async fn resolve(&self, spec: &crate::SshSpec) -> Result<SshTarget, SshError> {
            let mut host = self.0.resolve(spec).await?;
            let snippet = Snippet {
                name: "init".into(),
                script: "echo {{host.user}}\nid {{who:me}}\n".into(),
                description: None,
                tags: Vec::new(),
                variables: Vec::new(),
                run_mode: RunMode::Paste,
                read_only: false,
            };
            let b = Builtins {
                label: host.label.clone(),
                address: host.address.clone(),
                user: host.username.clone(),
                date: today(),
            };
            host.startup_input = startup(&snippet, &b).ready();
            Ok(host)
        }
    }

    for quiet in [false, true] {
        let (addr, seen) = start_server().await;
        seen.lock().quiet_shell = quiet;
        let connector = SshConnector::new(Arc::new(WithStartup(TestResolver {
            addr,
            password: "secret",
            edit: |_| {},
        })))
        .with_verifier(Arc::new(InsecureAcceptAnyHostKey::insecure_for_testing()));
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mgr = SessionManager::new(tx);
        mgr.register_connector(TransportKind::Ssh, Arc::new(connector));
        let _handle = mgr
            .open_with(
                crate::SessionSpec::Ssh(crate::SshSpec {
                    host: "ignored".into(),
                    port: 22,
                    ..crate::SshSpec::default()
                }),
                OpenOptions {
                    cols: 80,
                    rows: 24,
                    ..OpenOptions::default()
                },
            )
            .unwrap();
        let connected = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let (_, ev) = rx.recv().await.unwrap();
                if matches!(ev, SessionEvent::State(SessionState::Connected { .. })) {
                    return std::time::Instant::now();
                }
            }
        })
        .await
        .expect("connects");
        let typed = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if !seen.lock().input.is_empty() {
                    return std::time::Instant::now();
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("startup input typed");
        // Give the second line time to arrive.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(seen.lock().input, b"echo sverb\rid me\r", "quiet={quiet}");
        let waited = typed.duration_since(connected);
        if quiet {
            assert!(
                waited >= STARTUP_DELAY - Duration::from_millis(150),
                "{waited:?}"
            );
        } else {
            assert!(
                waited < STARTUP_DELAY - Duration::from_millis(100),
                "{waited:?}"
            );
        }
        mgr.shutdown(Duration::from_secs(2)).await;
    }
}
