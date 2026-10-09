//! session), the Snippets view's requests, exec runs and their prompts, the startup
//! snippet form (reducer half; the timing is `sverb-conn`'s T-08).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use sverb_conn::{SessionEvent, SessionState, ssh::exec::snippets::RunEvent};
use sverb_core::{
    model::{ItemId, RunMode, Snippet, VarDef},
    snippet::{Builtins, HostRunResult},
};

use super::{SnippetsEffect, SnippetsEvent};
use crate::app::{Config, Effect, InputEvent, SessionId, SessionInput, UiEvent};
use crate::testing::AppHarness;
use crate::views::{DialogKind, Section, snippets::SnippetDialogKind};
use crate::widgets::terminal_pane::PaneInfo;

const RESTART: ItemId = ItemId::from_bytes([1; 16]);
const UPTIME: ItemId = ItemId::from_bytes([2; 16]);

fn snippet(name: &str, script: &str, mode: RunMode, variables: Vec<VarDef>) -> Snippet {
    Snippet {
        name: name.into(),
        script: script.into(),
        description: None,
        tags: Vec::new(),
        variables,
        run_mode: mode,
        read_only: false,
    }
}

fn loaded() -> UiEvent {
    UiEvent::Snippets(SnippetsEvent::Loaded {
        snippets: vec![
            (
                RESTART,
                snippet(
                    "restart",
                    "systemctl restart {{svc}}\necho {{host.label}}",
                    RunMode::PasteAndExecute,
                    vec![VarDef {
                        name: "svc".into(),
                        default: None,
                        secret: false,
                    }],
                ),
            ),
            (UPTIME, snippet("uptime", "uptime", RunMode::Paste, vec![])),
        ],
        tags: BTreeMap::new(),
    })
}

fn harness() -> AppHarness {
    let mut h = AppHarness::new(Config::default()).with_live_session();
    h.app_mut().panes.insert(
        SessionId(1),
        PaneInfo {
            label: "web-1".into(),
            ..PaneInfo::default()
        },
    );
    h.send(loaded());
    h.take_effects();
    h
}

fn type_text(h: &mut AppHarness, text: &str) {
    for c in text.chars() {
        h.send(UiEvent::Input(InputEvent::Key(KeyEvent::new(
            KeyCode::Char(c),
            KeyModifiers::NONE,
        ))));
    }
}

fn press(h: &mut AppHarness, code: KeyCode) {
    h.send(UiEvent::Input(InputEvent::Key(KeyEvent::new(
        code,
        KeyModifiers::NONE,
    ))));
}

fn top_snippet_dialog(h: &AppHarness) -> Option<&SnippetDialogKind> {
    match h.app().dialogs().last().map(|d| &d.kind) {
        Some(DialogKind::Snippet(d)) => Some(&d.kind),
        _ => None,
    }
}

fn sent(effects: &[Effect]) -> Vec<(SessionId, SessionInput)> {
    effects
        .iter()
        .filter_map(|e| match e {
            Effect::SendToSession { id, input } => Some((*id, input.clone())),
            _ => None,
        })
        .collect()
}

#[test]
fn t07_leader_e_picker_vars_and_send() {
    let mut h = harness();
    h.keys("ctrl-\\ e");
    assert!(
        matches!(top_snippet_dialog(&h), Some(SnippetDialogKind::Picker(_))),
        "{:?}",
        h.app().dialogs()
    );
    // Insert mode: typed keys filter the picker, they do not reach the session.
    type_text(&mut h, "rest");
    assert!(sent(h.effects()).is_empty());
    let screen = h.render(120, 30);
    assert!(screen.contains("systemctl restart {{svc}}"), "{screen}");
    press(&mut h, KeyCode::Enter);
    assert!(
        matches!(top_snippet_dialog(&h), Some(SnippetDialogKind::Vars(_))),
        "{:?}",
        h.app().dialogs()
    );
    // Enter without a value is refused.
    press(&mut h, KeyCode::Enter);
    assert!(matches!(
        top_snippet_dialog(&h),
        Some(SnippetDialogKind::Vars(_))
    ));
    type_text(&mut h, "nginx");
    assert!(h.render(120, 30).contains("echo web-1"));
    h.take_effects();
    press(&mut h, KeyCode::Enter);
    assert!(h.app().dialogs().is_empty());
    let effects = h.take_effects();
    assert_eq!(
        sent(&effects),
        vec![(
            SessionId(1),
            SessionInput::Raw(b"systemctl restart nginx\recho web-1\r".to_vec())
        )]
    );
    assert!(effects.iter().any(|e| matches!(
        e,
        Effect::Snippets(SnippetsEffect::History(r)) if r.snippet == Some(RESTART)
    )));
}

#[test]
fn paste_mode_sends_unchecked_paste() {
    let mut h = harness();
    h.keys("ctrl-\\ e");
    type_text(&mut h, "upt");
    press(&mut h, KeyCode::Enter);
    h.take_effects();
    press(&mut h, KeyCode::Enter);
    assert_eq!(
        sent(&h.take_effects()),
        vec![(SessionId(1), SessionInput::PasteUnchecked("uptime".into()))]
    );
}

#[test]
fn view_requests_and_exec_run() {
    let mut h = harness();
    h.app_mut().open_section(Section::Snippets);
    let effects = h
        .app_mut()
        .handle(UiEvent::IndexUpdated(std::sync::Arc::new(
            sverb_core::search::IndexSnapshot::default(),
        )));
    assert!(effects.contains(&Effect::Snippets(SnippetsEffect::Load)));
    h.send(loaded());
    // `a` opens the editor.
    press(&mut h, KeyCode::Char('a'));
    assert!(matches!(
        top_snippet_dialog(&h),
        Some(SnippetDialogKind::Form(_))
    ));
    h.app_mut().dialogs.clear();
    // `d` asks before deleting.
    press(&mut h, KeyCode::Char('d'));
    assert!(matches!(
        h.app().dialogs().last().map(|d| &d.kind),
        Some(DialogKind::Modal(_))
    ));
    h.app_mut().dialogs.clear();

    // An exec plan answered by the variable form starts a run with a results table.
    let plan = crate::views::snippets::ExecPlan {
        snippet: UPTIME,
        name: "uptime".into(),
        template: sverb_core::snippet::Template::parse("uptime").unwrap(),
        values: sverb_core::snippet::Values::new(),
        hosts: vec![(ItemId::new(), "a".into()), (ItemId::new(), "b".into())],
    };
    let mut effects = Vec::new();
    h.app_mut().start_snippet_run(plan, &mut effects);
    let Some(Effect::Snippets(SnippetsEffect::Run(job))) = effects.pop() else {
        panic!("{effects:?}")
    };
    assert_eq!(job.concurrency, 10);
    assert_eq!(job.hosts.len(), 2);
    let run = job.run;
    // A prompt of a run connection opens the auth dialog; its answer goes to the run.
    let s0 = job.hosts[0].session;
    h.send(UiEvent::Snippets(SnippetsEvent::Run {
        run,
        event: RunEvent::Started(0),
    }));
    h.send(UiEvent::Snippets(SnippetsEvent::Run {
        run,
        event: RunEvent::Finished(
            0,
            HostRunResult {
                host: "a".into(),
                exit: Some(0),
                ..HostRunResult::default()
            },
        ),
    }));
    h.send(UiEvent::Snippets(SnippetsEvent::Run {
        run,
        event: RunEvent::Finished(
            1,
            HostRunResult {
                host: "b".into(),
                exit: Some(4),
                ..HostRunResult::default()
            },
        ),
    }));
    let Some(SnippetDialogKind::Results(r)) = top_snippet_dialog(&h) else {
        panic!()
    };
    assert_eq!(r.table.summary(), "1 ok · 1 failed");
    assert!(!h.app().views.snippets.run_sessions.contains(&s0));
    // `r` re-runs the failed host only.
    h.take_effects();
    press(&mut h, KeyCode::Char('r'));
    let effects = h.take_effects();
    let Some(Effect::Snippets(SnippetsEffect::Run(job))) = effects
        .iter()
        .find(|e| matches!(e, Effect::Snippets(SnippetsEffect::Run(_))))
    else {
        panic!("{effects:?}")
    };
    assert_eq!(job.hosts.len(), 1);
    assert_eq!(job.hosts[0].index, 1);
    // Esc while running cancels the run.
    press(&mut h, KeyCode::Esc);
    assert!(
        h.take_effects()
            .contains(&Effect::Snippets(SnippetsEffect::Cancel { run: job.run }))
    );
    assert!(h.app().dialogs().is_empty());
}

// T-08 (reducer half): a connected pane is checked once; a snippet needing values opens
// the form for that pane, and its answer is typed Paste & execute.
#[test]
fn t08_startup_snippet_form() {
    let mut h = harness();
    let host = ItemId::new();
    h.app_mut().panes.insert(
        SessionId(1),
        PaneInfo {
            label: "web-1".into(),
            host: Some(host.to_string()),
            ..PaneInfo::default()
        },
    );
    let checks = |effects: &[Effect]| {
        effects
            .iter()
            .filter(|e| matches!(e, Effect::Snippets(SnippetsEffect::StartupCheck { .. })))
            .count()
    };
    let connected = SessionEvent::State(SessionState::Connected { since: h.now() });
    h.send(UiEvent::Session(SessionId(1), connected.clone()));
    h.send(UiEvent::Session(SessionId(1), connected));
    assert_eq!(checks(h.effects()), 1, "checked once per session");
    h.send(UiEvent::Snippets(SnippetsEvent::Startup {
        session: SessionId(1),
        id: RESTART,
        snippet: snippet(
            "init",
            "export TOKEN={{token}}",
            RunMode::Paste,
            vec![VarDef {
                name: "token".into(),
                default: None,
                secret: true,
            }],
        ),
        builtins: Builtins::default(),
    }));
    assert!(matches!(
        top_snippet_dialog(&h),
        Some(SnippetDialogKind::Vars(_))
    ));
    type_text(&mut h, "s3cr3t");
    assert!(!h.render(100, 30).contains("s3cr3t"));
    h.take_effects();
    press(&mut h, KeyCode::Enter);
    let effects = h.take_effects();
    assert_eq!(
        sent(&effects),
        vec![(
            SessionId(1),
            SessionInput::Raw(b"export TOKEN=s3cr3t\r".to_vec())
        )]
    );
    let history = effects.iter().find_map(|e| match e {
        Effect::Snippets(SnippetsEffect::History(r)) => Some(r.command.clone()),
        _ => None,
    });
    assert_eq!(history.as_deref(), Some("export TOKEN={{token}}"));
}

/// A saved snippet reaches the view and the `leader e` picker through the index
/// update that follows the write, also when a load is already in flight.
#[test]
fn index_update_reloads_list_and_picker() {
    const DF: ItemId = ItemId::from_bytes([3; 16]);
    let mut h = harness();
    h.app_mut().open_section(Section::Snippets);
    let index = || UiEvent::IndexUpdated(std::sync::Arc::new(Default::default()));
    let loads = |effects: &[Effect]| {
        effects
            .iter()
            .filter(|e| matches!(e, Effect::Snippets(SnippetsEffect::Load)))
            .count()
    };
    h.send(index());
    assert_eq!(loads(&h.take_effects()), 1);
    // The save's index update arrives while that load runs: one more load after it.
    h.send(index());
    assert_eq!(loads(&h.take_effects()), 0);
    h.send(loaded());
    assert_eq!(loads(&h.take_effects()), 1);
    let UiEvent::Snippets(SnippetsEvent::Loaded { mut snippets, tags }) = loaded() else {
        unreachable!()
    };
    snippets.push((DF, snippet("disk", "df -h", RunMode::Paste, vec![])));
    h.send(UiEvent::Snippets(SnippetsEvent::Loaded { snippets, tags }));
    assert_eq!(loads(&h.take_effects()), 0);
    assert_eq!(
        h.app().views.snippets.get(DF).map(|s| s.name.as_str()),
        Some("disk")
    );
    assert!(h.render(120, 30).contains("disk"));
    h.keys("ctrl-\\ e");
    let Some(SnippetDialogKind::Picker(p)) = top_snippet_dialog(&h) else {
        panic!("{:?}", h.app().dialogs())
    };
    assert!(p.entries.iter().any(|(id, _)| *id == DF));
}
