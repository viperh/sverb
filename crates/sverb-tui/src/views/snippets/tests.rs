//! The Snippets view and dialogs (T-04 masking in the UI, T-07 at the dialog
//! level, results and export, the editor's "add variables?" prompt).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::time::Duration;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use sverb_core::{
    model::{ItemId, RunMode, Snippet, VarDef},
    snippet::{Builtins, HostRunResult},
};

use super::*;
use crate::app::{Config, SessionId, state::IdGen};
use crate::views::ViewCx;
use crate::widgets::test_util::{self, draw_with, text};

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

fn pane() -> PaneCtx {
    PaneCtx {
        session: SessionId(42),
        label: "web-1".into(),
        host_id: Some(ItemId::new()),
        builtins: Builtins {
            label: "web-1".into(),
            address: "10.0.0.1".into(),
            user: "root".into(),
            date: "2026-10-08".into(),
        },
    }
}

/// Feed one key; returns (answer, closed). Answering dialogs stay open: the reducer pops them.
fn press(d: &mut SnippetDialog, code: KeyCode) -> (Option<SnippetAnswer>, bool) {
    press_mods(d, code, KeyModifiers::NONE)
}

fn press_mods(
    d: &mut SnippetDialog,
    code: KeyCode,
    mods: KeyModifiers,
) -> (Option<SnippetAnswer>, bool) {
    let config = Config::default();
    let (mut effects, mut pending, mut ids) = (Vec::new(), BTreeMap::new(), IdGen::default());
    let mut cx = ViewCx::new(&config, &mut effects, &mut pending, &mut ids);
    d.handle(&ViewEvent::Key(KeyEvent::new(code, mods)), &mut cx);
    let closed = cx.close_requested();
    (d.take_answer(), closed)
}

fn type_in(d: &mut SnippetDialog, s: &str) {
    for c in s.chars() {
        press(d, KeyCode::Char(c));
    }
}

fn render(d: &SnippetDialog, w: u16, h: u16) -> String {
    text(&draw_with(w, h, false, |f, cx| d.render(f, f.area(), cx)))
}

// T-07 (dialog level; the reducer test is in `app/snippets_tests.rs`)
#[test]
fn t07_picker_filter_preview_vars_and_bytes() {
    let restart = snippet(
        "restart service",
        "sudo systemctl restart {{svc}}\nsystemctl status {{svc}} # {{host.label}}",
        RunMode::PasteAndExecute,
        vec![VarDef {
            name: "svc".into(),
            default: Some("nginx".into()),
            secret: false,
        }],
    );
    let (a, b, c) = (ItemId::new(), ItemId::new(), ItemId::new());
    let mut d = SnippetDialog::new(SnippetDialogKind::Picker(Box::new(SnippetPicker::new(
        vec![
            (
                a,
                snippet("disk usage", "df -h", RunMode::Paste, vec![]),
                vec![],
            ),
            (b, restart.clone(), vec!["ops".into()]),
            (
                c,
                snippet("uptime", "uptime", RunMode::Exec, vec![]),
                vec![],
            ),
        ],
        Some(pane()),
    ))));
    let screen = render(&d, 120, 30);
    assert!(screen.contains("disk usage"), "{screen}");
    // Fuzzy filter: "rst" matches "restart service" only.
    type_in(&mut d, "rst");
    let SnippetDialogKind::Picker(p) = &d.kind else {
        panic!()
    };
    assert_eq!(p.visible.len(), 1);
    assert_eq!(p.current().unwrap().0, b);
    let screen = render(&d, 120, 30);
    assert!(screen.contains("Preview"), "{screen}");
    assert!(
        screen.contains("sudo systemctl restart {{svc}}"),
        "{screen}"
    );
    // `#ops` also matches through the tag.
    for _ in 0..3 {
        press(&mut d, KeyCode::Backspace);
    }
    type_in(&mut d, "#ops");
    let (answer, closed) = press(&mut d, KeyCode::Enter);
    assert!(!closed, "the reducer pops it");
    let Some(SnippetAnswer::Picked { id, pane: Some(p) }) = answer else {
        panic!("{answer:?}")
    };
    assert_eq!(id, b);

    // The variable form: default prefilled, live preview, Enter runs.
    let form = VarForm::new(id, &restart, restart.run_mode, RunWhere::Pane(p)).unwrap();
    let mut d = SnippetDialog::new(SnippetDialogKind::Vars(Box::new(form)));
    let screen = render(&d, 100, 30);
    assert!(screen.contains("sudo systemctl restart nginx"), "{screen}");
    press_mods(&mut d, KeyCode::Char('u'), KeyModifiers::CONTROL);
    type_in(&mut d, "redis");
    let screen = render(&d, 100, 30);
    assert!(
        screen.contains("systemctl status redis # web-1"),
        "{screen}"
    );
    let (answer, closed) = press(&mut d, KeyCode::Enter);
    assert!(!closed, "the reducer pops it");
    let Some(SnippetAnswer::Run(RunRequest::Execute {
        session,
        bytes,
        history,
    })) = answer
    else {
        panic!("{answer:?}")
    };
    assert_eq!(session, SessionId(42));
    assert_eq!(
        bytes,
        b"sudo systemctl restart redis\rsystemctl status redis # web-1\r"
    );
    assert_eq!(history.snippet, Some(b));
}

#[test]
fn paste_mode_has_no_trailing_newline() {
    let s = snippet("ls", "ls -la\n", RunMode::Paste, vec![]);
    let form = VarForm::new(ItemId::new(), &s, s.run_mode, RunWhere::Pane(pane())).unwrap();
    let RunRequest::Paste { text, session, .. } = form.submit().unwrap() else {
        panic!()
    };
    assert_eq!((text.as_str(), session), ("ls -la", SessionId(42)));
    // Exec-mode snippets typed into a pane run like Paste & execute.
    let s = snippet("up", "uptime", RunMode::Exec, vec![]);
    let form = VarForm::new(ItemId::new(), &s, s.run_mode, RunWhere::Pane(pane())).unwrap();
    assert!(matches!(
        form.submit().unwrap(),
        RunRequest::Execute { ref bytes, .. } if bytes == b"uptime\r"
    ));
}

// T-04 (UI side): secrets are masked in the form, the preview and history.
#[test]
fn t04_secret_masked_in_form_and_preview() {
    const CANARY: &str = "CANARY-ui-55";
    let s = snippet(
        "login",
        "login --user {{user:admin}} --password {{pw}}",
        RunMode::PasteAndExecute,
        vec![VarDef {
            name: "pw".into(),
            default: None,
            secret: true,
        }],
    );
    let form = VarForm::new(ItemId::new(), &s, s.run_mode, RunWhere::Pane(pane())).unwrap();
    let mut d = SnippetDialog::new(SnippetDialogKind::Vars(Box::new(form)));
    // Missing value: Enter refuses.
    let (answer, closed) = press(&mut d, KeyCode::Enter);
    assert!(answer.is_none() && !closed);
    assert!(render(&d, 100, 30).contains("Enter a value for pw"));
    type_in(&mut d, CANARY);
    let screen = render(&d, 100, 30);
    assert!(!screen.contains(CANARY), "{screen}");
    assert!(screen.contains("--password ••••"), "{screen}");
    assert!(!format!("{d:?}").contains(CANARY));
    let (answer, _) = press(&mut d, KeyCode::Enter);
    let Some(SnippetAnswer::Run(RunRequest::Execute { bytes, history, .. })) = answer else {
        panic!()
    };
    assert!(String::from_utf8(bytes).unwrap().contains(CANARY));
    assert_eq!(history.command, "login --user admin --password {{pw}}");
}

#[test]
fn view_keys_make_requests() {
    let mut view = SnippetsView::default();
    let (a, tag) = (ItemId::new(), ItemId::new());
    let mut s = snippet("deploy", "echo {{x}}", RunMode::Exec, vec![]);
    s.tags = vec![tag];
    view.set_snippets(
        vec![(a, s)],
        [(tag, "web".to_owned())].into_iter().collect(),
    );
    for (code, want) in [
        (KeyCode::Enter, SnippetsRequest::RunHere(a)),
        (KeyCode::Char('r'), SnippetsRequest::RunOnHosts(a)),
        (KeyCode::Char('p'), SnippetsRequest::Paste(a)),
        (KeyCode::Char('a'), SnippetsRequest::Add),
        (KeyCode::Char('e'), SnippetsRequest::Edit(a)),
        (KeyCode::Char('y'), SnippetsRequest::Duplicate(a)),
        (KeyCode::Char('d'), SnippetsRequest::Delete(vec![a])),
    ] {
        test_util::key(&mut view, code, KeyModifiers::NONE);
        assert_eq!(view.request.take(), Some(want));
    }
    assert_eq!(view.list.rows()[0].tags, vec!["web"]);
    let buf = test_util::draw(&view, 100, 10, false);
    let screen = text(&buf);
    assert!(screen.contains("deploy"), "{screen}");
    assert!(screen.contains("#web"), "{screen}");
    // Detail pane: script with the variable highlighted.
    let screen = text(&draw_with(60, 12, false, |f, cx| {
        view.render_detail(f, f.area(), cx);
    }));
    assert!(screen.contains("echo {{x}}"), "{screen}");
    assert!(screen.contains("Variables:  x"), "{screen}");
    view.clear();
    assert!(view.list.rows().is_empty());
}

#[test]
fn results_rows_and_export() {
    let (h1, h2) = (ItemId::new(), ItemId::new());
    let mut r = SnippetResults::new(
        7,
        ItemId::new(),
        "uptime".into(),
        vec![(h1, "web-1".into()), (h2, "web-2".into())],
        vec![Some(SessionId(1)), Some(SessionId(2))],
    );
    assert!(r.running());
    r.started(0);
    r.finished(
        0,
        HostRunResult {
            host: "web-1".into(),
            exit: Some(0),
            stdout: b"up\n".to_vec(),
            duration: Duration::from_millis(1200),
            ..HostRunResult::default()
        },
    );
    r.finished(
        1,
        HostRunResult {
            host: "web-2".into(),
            exit: Some(2),
            stderr: b"boom\n".to_vec(),
            truncated: true,
            duration: Duration::from_millis(300),
            ..HostRunResult::default()
        },
    );
    assert!(!r.running());
    assert_eq!(r.table.summary(), "1 ok · 1 failed");
    assert_eq!(r.table.rows[1].state.text(), "exit 2");
    assert!(r.table.rows[1].truncated);
    assert_eq!(r.table.rows[1].detail, "stderr:\nboom");
    assert_eq!(r.row_of(SessionId(2)), Some(1));
    let mut d = SnippetDialog::new(SnippetDialogKind::Results(Box::new(r)));
    let screen = render(&d, 100, 20);
    assert!(screen.contains("web-2"), "{screen}");
    // x j c: JSON to the clipboard.
    press(&mut d, KeyCode::Char('x'));
    press(&mut d, KeyCode::Char('j'));
    let (answer, closed) = press(&mut d, KeyCode::Char('c'));
    assert!(!closed);
    let Some(SnippetAnswer::Export { json, path, text }) = answer else {
        panic!()
    };
    assert!(json && path.is_none());
    assert!(
        text.starts_with(r#"{"version":1,"data":[{"host":"web-1","exit":0"#),
        "{text}"
    );
    // x m f <path> Enter: Markdown to a file.
    press(&mut d, KeyCode::Char('x'));
    press(&mut d, KeyCode::Char('m'));
    press(&mut d, KeyCode::Char('f'));
    press_mods(&mut d, KeyCode::Char('u'), KeyModifiers::CONTROL);
    type_in(&mut d, "/tmp/out.md");
    let (answer, _) = press(&mut d, KeyCode::Enter);
    let Some(SnippetAnswer::Export { json, path, text }) = answer else {
        panic!()
    };
    assert!(!json);
    assert_eq!(path.as_deref(), Some("/tmp/out.md"));
    assert!(
        text.contains("| web-2 | exit 2 | 2 | 0.3s | yes |"),
        "{text}"
    );
    // r re-runs the failed rows.
    let (answer, _) = press(&mut d, KeyCode::Char('r'));
    assert_eq!(answer, Some(SnippetAnswer::Rerun));
    let SnippetDialogKind::Results(r) = &mut d.kind else {
        panic!()
    };
    assert_eq!(r.reset_failed(), vec![1]);
    assert!(r.running());
    // Esc while running cancels.
    let (answer, closed) = press(&mut d, KeyCode::Esc);
    assert!(!closed, "the reducer pops it");
    assert_eq!(answer, Some(SnippetAnswer::Cancel(7)));
}

#[test]
fn editor_asks_before_adding_variables() {
    let mut d = SnippetDialog::new(SnippetDialogKind::Form(Box::new(SnippetFormDialog::new(
        None,
        Some(&snippet(
            "deploy",
            "deploy {{env:staging}} {{token}}",
            RunMode::Exec,
            vec![VarDef {
                name: "token".into(),
                default: None,
                secret: true,
            }],
        )),
        &BTreeMap::new(),
    ))));
    let screen = render(&d, 100, 40);
    assert!(screen.contains("New snippet"), "{screen}");
    // Save (ctrl-s): `env` is used but not declared → the prompt.
    let (answer, _) = press_mods(&mut d, KeyCode::Char('s'), KeyModifiers::CONTROL);
    assert!(answer.is_none());
    let SnippetDialogKind::Form(f) = &d.kind else {
        panic!()
    };
    assert!(f.confirm.is_some(), "no prompt");
    assert!(render(&d, 100, 40).contains("Add variables?"));
    let (answer, closed) = press(&mut d, KeyCode::Char('y'));
    assert!(!closed, "the reducer pops it");
    let Some(SnippetAnswer::Save { id: None, snippet }) = answer else {
        panic!("{answer:?}")
    };
    let vars: Vec<(&str, Option<&str>, bool)> = snippet
        .variables
        .iter()
        .map(|v| (v.name.as_str(), v.default.as_deref(), v.secret))
        .collect();
    assert_eq!(
        vars,
        vec![("token", None, true), ("env", Some("staging"), false)]
    );
    assert_eq!(snippet.run_mode, RunMode::Exec);
}

#[test]
fn host_picker_answers_targets() {
    let catalog = crate::views::hosts::catalog::HostCatalog::default();
    let mut d = SnippetDialog::new(SnippetDialogKind::Hosts(Box::new(HostTargetsPicker::new(
        ItemId::new(),
        "x".into(),
        &catalog,
    ))));
    // Nothing to pick: Enter does nothing.
    let (answer, closed) = press(&mut d, KeyCode::Enter);
    assert!(answer.is_none() && !closed);
    assert!(render(&d, 80, 20).contains("no hosts, groups or tags match"));
}

#[test]
fn dialogs_render_at_any_size() {
    let s = snippet("a", "echo {{x}}", RunMode::Paste, vec![]);
    let dialogs = vec![
        SnippetDialog::new(SnippetDialogKind::Picker(Box::new(SnippetPicker::new(
            vec![(ItemId::new(), s.clone(), vec![])],
            None,
        )))),
        SnippetDialog::new(SnippetDialogKind::Vars(Box::new(
            VarForm::new(ItemId::new(), &s, RunMode::Paste, RunWhere::Pane(pane())).unwrap(),
        ))),
        SnippetDialog::new(SnippetDialogKind::Form(Box::new(SnippetFormDialog::new(
            Some(ItemId::new()),
            Some(&s),
            &BTreeMap::new(),
        )))),
        SnippetDialog::new(SnippetDialogKind::Results(Box::new(SnippetResults::new(
            1,
            ItemId::new(),
            "t".into(),
            vec![(ItemId::new(), "h".into())],
            vec![None],
        )))),
    ];
    for d in &dialogs {
        for (w, h) in [(0, 0), (1, 1), (10, 3), (40, 10), (200, 60)] {
            let _ = render(d, w, h);
        }
    }
    let view = SnippetsView::default();
    for (w, h) in [(0, 0), (1, 1), (30, 5)] {
        let _ = test_util::draw(&view, w, h, true);
    }
    // A script that does not parse cannot be run.
    let bad = snippet("b", "{{oops", RunMode::Paste, vec![]);
    assert!(VarForm::new(ItemId::new(), &bad, RunMode::Paste, RunWhere::Pane(pane())).is_err());
}
