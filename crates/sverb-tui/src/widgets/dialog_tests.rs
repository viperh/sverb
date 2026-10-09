#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use pretty_assertions::assert_eq;

use super::{
    confirm,
    dialog::{Button, Modal, ModalAnswer},
    test_util::{assert_no_color, draw_with, text},
};
use crate::{
    app::{Config, Effect},
    testing::AppHarness,
    views::{DialogKind, dialogs::ModalDialog},
};

fn press(modal: &mut Modal, code: KeyCode) -> Option<ModalAnswer> {
    modal.handle_key(&KeyEvent::new(code, KeyModifiers::NONE))
}

fn accept_reject() -> Modal {
    Modal::confirm(
        "Unknown host key",
        "The server's ED25519 key is SHA256:abc. Trust it?",
        vec![
            Button::new("accept", "Accept", 'a'),
            Button::new("once", "Accept once", 'o'),
            Button::new("reject", "Reject", 'r').safe(),
        ],
        0,
        false,
    )
}

#[test]
fn t18_dialog_captures_all_keys() {
    let mut h = AppHarness::new(Config::default());
    h.resize(80, 24);
    h.app_mut().seed_three_hosts();
    h.modal(ModalDialog::new(accept_reject()));
    // `j` would move the Hosts list, `q` would quit, `?` would open help.
    h.keys("j j q ?");
    assert_eq!(h.app().views().hosts.list.cursor(), 0);
    assert!(h.effects().is_empty(), "{:?}", h.effects());
    assert_eq!(h.app().dialogs().len(), 1);
    // Stacked dialogs: the top one gets the keys first.
    h.modal(ModalDialog::new(Modal::info("Note", "on top")));
    h.keys("enter");
    assert_eq!(h.app().dialogs().len(), 1);
    assert!(matches!(h.app().dialogs()[0].kind, DialogKind::Modal(_)));
    h.keys("esc");
    assert!(h.app().dialogs().is_empty());
    h.keys("j");
    assert_eq!(
        h.app().views().hosts.list.cursor(),
        1,
        "keys reach the view again"
    );
}

#[test]
fn t19_mnemonics_and_danger_default() {
    let mut m = accept_reject();
    assert_eq!(
        m.handle_key(&KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE)),
        Some(ModalAnswer::Button("reject".into()))
    );
    let mut m = accept_reject();
    assert_eq!(
        m.handle_key(&KeyEvent::new(KeyCode::Char('O'), KeyModifiers::SHIFT)),
        Some(ModalAnswer::Button("once".into())),
        "mnemonics ignore case"
    );
    // Tab / arrows move the focus; Enter presses the focused button.
    let mut m = accept_reject();
    press(&mut m, KeyCode::Tab);
    press(&mut m, KeyCode::Right);
    assert_eq!(m.focused_button(), Some("reject"));
    press(&mut m, KeyCode::Left);
    assert_eq!(
        press(&mut m, KeyCode::Enter),
        Some(ModalAnswer::Button("once".into()))
    );
    assert_eq!(
        press(&mut accept_reject(), KeyCode::Esc),
        Some(ModalAnswer::Cancelled)
    );

    // Danger: Enter answers the safe button even though `default` points at Delete.
    let mut d = confirm::delete(3, "host");
    assert_eq!(d.title, "Delete 3 hosts?");
    assert_eq!(d.focused_button(), Some(confirm::NO));
    assert_eq!(
        press(&mut d, KeyCode::Enter),
        Some(ModalAnswer::Button(confirm::NO.into()))
    );
    let mut d = confirm::delete(1, "host");
    assert_eq!(
        d.handle_key(&KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE)),
        Some(ModalAnswer::Button(confirm::YES.into()))
    );
    // Ctrl/Alt chords are not mnemonics.
    let mut m = accept_reject();
    assert_eq!(
        m.handle_key(&KeyEvent::new(KeyCode::Char('a'), KeyModifiers::CONTROL)),
        None
    );

    // In the app: the answer's effects run and the dialog closes.
    let mut h = AppHarness::new(Config::default());
    h.modal(
        ModalDialog::new(confirm::delete(2, "host"))
            .on("button:yes", vec![Effect::Quit { code: 3 }]),
    );
    h.keys("enter");
    assert!(h.effects().is_empty(), "Enter is safe");
    assert!(h.app().dialogs().is_empty());
    h.modal(
        ModalDialog::new(confirm::delete(2, "host"))
            .on("button:yes", vec![Effect::Quit { code: 3 }]),
    );
    h.keys("d");
    assert_eq!(h.effects(), &[Effect::Quit { code: 3 }]);
}

#[test]
fn t20_timeout_counts_down_and_fires() {
    let mut m = accept_reject().with_timeout(
        Duration::from_secs(120),
        ModalAnswer::Button("reject".into()),
    );
    let screen = text(&draw_with(80, 24, false, |f, cx| m.render(f, f.area(), cx)));
    assert!(screen.contains("120 s left"), "{screen}");
    for _ in 0..119 {
        assert_eq!(m.tick(Duration::from_secs(1)), None);
    }
    let screen = text(&draw_with(80, 24, false, |f, cx| m.render(f, f.area(), cx)));
    assert!(screen.contains("1 s left"), "{screen}");
    assert_eq!(
        m.tick(Duration::from_secs(1)),
        Some(ModalAnswer::Button("reject".into()))
    );

    // In the app, on the virtual clock.
    let mut h = AppHarness::new(Config::default());
    h.resize(80, 24);
    h.modal(
        ModalDialog::new(
            accept_reject().with_timeout(Duration::from_secs(120), ModalAnswer::TimedOut),
        )
        .on("timed-out", vec![Effect::Quit { code: 7 }]),
    );
    h.advance(60_000);
    assert_eq!(h.app().dialogs().len(), 1);
    assert!(h.render(80, 24).contains("60 s left"));
    h.advance(59_000);
    assert_eq!(h.app().dialogs().len(), 1);
    h.advance(1_000);
    assert!(h.app().dialogs().is_empty());
    assert!(h.effects().contains(&Effect::Quit { code: 7 }));
    // A dialog answered before its timeout leaves only a stale tick behind.
    let mut h = AppHarness::new(Config::default());
    h.modal(
        ModalDialog::new(
            accept_reject().with_timeout(Duration::from_secs(5), ModalAnswer::TimedOut),
        )
        .on("timed-out", vec![Effect::Quit { code: 7 }]),
    );
    h.keys("r");
    h.advance(10_000);
    assert!(!h.effects().contains(&Effect::Quit { code: 7 }));
}

fn all_dialogs() -> Vec<(&'static str, Modal)> {
    let mut prompt = Modal::prompt(
        "Password",
        "Password for deploy@10.0.0.5",
        "Password:",
        true,
    );
    prompt.paste("s3cret");
    let mut text_prompt = Modal::prompt("Rename tab", "", "Name:", false);
    text_prompt.paste("prod shell");
    vec![
        (
            "confirm",
            accept_reject().with_timeout(Duration::from_secs(120), ModalAnswer::TimedOut),
        ),
        ("danger", confirm::delete(3, "host")),
        ("prompt_secret", prompt),
        ("prompt_text", text_prompt),
        (
            "choice",
            Modal::choice(
                "Connect all",
                "Open 3 hosts as:",
                vec!["New tabs".into(), "Splits in one tab".into()],
            ),
        ),
        (
            "progress",
            Modal::progress("Connecting", "Connecting to prod-web-1…", true),
        ),
        (
            "info",
            Modal::info(
                "Copied",
                "ssh -p 2222 deploy@10.0.0.5 was copied to the clipboard. A long sentence that has to wrap inside the dialog because it is wider than eighty percent of the screen.",
            ),
        ),
    ]
}

#[test]
fn t21_every_dialog_type_snapshots() {
    for (name, modal) in all_dialogs() {
        let color = draw_with(80, 24, false, |f, cx| modal.render(f, f.area(), cx));
        let mono = draw_with(80, 24, true, |f, cx| modal.render(f, f.area(), cx));
        assert_no_color(&mono);
        let screen = text(&color);
        assert_eq!(screen, text(&mono), "{name}: same text with NO_COLOR");
        assert!(
            !screen.contains("s3cret"),
            "{name}: secret prompts stay masked"
        );
        // Max 80% of the width.
        let widest = screen
            .lines()
            .map(|l| l.trim().chars().count())
            .max()
            .unwrap();
        assert!(widest <= 64, "{name}: {widest} cells wide");
        insta::assert_snapshot!(format!("t21_{name}_80x24"), screen);
    }
}

#[test]
fn prompt_dialog_is_insert_mode() {
    use crate::app::Mode;
    let mut h = AppHarness::new(Config::default()).with_sessions(1);
    h.modal(
        ModalDialog::new(Modal::prompt("Rename tab", "", "Name:", false))
            .on("cancelled", vec![Effect::Quit { code: 9 }]),
    );
    assert_eq!(h.app().mode(), Mode::Insert);
    // `q` and `?` are text here, not Quit/Help.
    h.keys("q ?");
    let DialogKind::Modal(m) = &h.app().dialogs()[0].kind else {
        panic!()
    };
    let crate::widgets::dialog::ModalKind::Prompt { input, .. } = &m.modal.kind else {
        panic!()
    };
    assert!(matches!(input, crate::widgets::dialog::PromptInput::Text(t) if t.text() == "q?"));
    assert!(h.effects().is_empty());
    h.keys("esc");
    assert_eq!(h.effects(), &[Effect::Quit { code: 9 }]);
    assert_eq!(h.app().mode(), Mode::Normal);
}
