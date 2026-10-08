//! M1-04 reducer tests: T-10 (auto-lock), T-11 (lock overlay), T-12 (disconnect on
//! lock), plus startup, backoff and recovery flows.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use super::*;
use crate::app::{Config, SessionId, SessionInput, UiEvent};
use crate::testing::AppHarness;

fn unlocked_harness(config: Config) -> AppHarness {
    let mut h = AppHarness::new(config);
    let app = h.app().clone().with_vault();
    *h.app_mut() = app;
    h.send(UiEvent::Vault(VaultEvent::Status(VaultStatusInfo {
        initialized: true,
        ..VaultStatusInfo::default()
    })));
    h.send(UiEvent::Vault(VaultEvent::Unlocked {
        via_keyring: false,
        note: None,
    }));
    assert_eq!(h.app().lock_state(), LockState::Unlocked);
    h.take_effects();
    h
}

fn config_with(f: impl FnOnce(&mut Config)) -> Config {
    let mut c = Config::default();
    f(&mut c);
    c
}

fn has_lock(effects: &[Effect]) -> bool {
    effects.contains(&Effect::Vault(VaultEffect::Lock))
}

fn sends_to_session(effects: &[Effect]) -> bool {
    effects
        .iter()
        .any(|e| matches!(e, Effect::SendToSession { .. }))
}

// T-10
#[test]
fn t10_auto_lock_after_idle_minutes() {
    let mut h = unlocked_harness(config_with(|c| c.general.auto_lock_minutes = 1));
    // Unlock armed the timer (the harness recorded it before take_effects).
    h.advance(59_000);
    assert_eq!(h.app().lock_state(), LockState::Unlocked);
    h.advance(1_000);
    assert!(has_lock(h.effects()), "{:?}", h.effects());
    assert_eq!(h.app().lock_state(), LockState::Locked);
}

// T-10
#[test]
fn t10_input_resets_the_idle_timer() {
    let mut h = unlocked_harness(config_with(|c| c.general.auto_lock_minutes = 1));
    h.advance(59_000);
    h.keys("j");
    let effects = h.take_effects();
    assert!(effects.contains(&Effect::ScheduleTimer {
        kind: TimerKind::AutoLockCheck,
        after: Duration::from_secs(60),
    }));
    h.advance(59_000);
    assert!(!has_lock(h.effects()));
    assert_eq!(h.app().lock_state(), LockState::Unlocked);
    h.advance(1_000);
    assert!(has_lock(h.effects()));
}

// T-10
#[test]
fn t10_zero_never_locks() {
    let mut h = unlocked_harness(config_with(|c| c.general.auto_lock_minutes = 0));
    h.keys("j");
    h.advance(24 * 3600 * 1000);
    assert!(!has_lock(h.effects()));
    assert!(!h.effects().iter().any(|e| matches!(
        e,
        Effect::ScheduleTimer {
            kind: TimerKind::AutoLockCheck,
            ..
        }
    )));
    assert_eq!(h.app().lock_state(), LockState::Unlocked);
}

// T-11
#[test]
fn t11_locked_session_gets_no_input_and_overlay_renders() {
    let mut h = unlocked_harness(Config::default());
    h.app_mut().focus_session(SessionId(1));
    h.keys("x");
    assert!(
        sends_to_session(&h.take_effects()),
        "unlocked: keys reach the session"
    );

    // leader ctrl-l locks.
    h.keys("ctrl-\\ ctrl-l");
    assert!(has_lock(h.effects()));
    assert_eq!(h.app().lock_state(), LockState::Locked);
    h.take_effects();

    h.keys("a b ctrl-c enter");
    h.send(UiEvent::Input(InputEvent::Paste("rm -rf /".into())));
    assert!(!sends_to_session(h.effects()), "{:?}", h.effects());
    // The prompt got the keys (enter submitted `ab`).
    assert!(h.effects().iter().any(|e| matches!(
        e,
        Effect::Vault(VaultEffect::Unlock(UnlockRequest::Password(p))) if p.expose() == "ab"
    )));
    insta::assert_snapshot!("t11_lock_overlay_80x24", h.render(80, 24));

    h.send(UiEvent::Vault(VaultEvent::Unlocked {
        via_keyring: false,
        note: None,
    }));
    h.take_effects();
    h.keys("y");
    assert_eq!(
        h.take_effects()
            .into_iter()
            .filter(|e| matches!(e, Effect::SendToSession { .. }))
            .collect::<Vec<_>>(),
        [Effect::SendToSession {
            id: SessionId(1),
            input: SessionInput::Key(KeyChord::parse_sequence("y").unwrap()[0]),
        }]
    );
}

// T-11: `leader q` still quits while locked; other leader keys do nothing.
#[test]
fn t11_leader_q_quits_while_locked() {
    let mut h = unlocked_harness(Config::default());
    h.app_mut().focus_session(SessionId(1));
    h.keys("ctrl-\\ ctrl-l");
    h.take_effects();
    h.keys("ctrl-\\ x");
    assert!(!h.effects().iter().any(|e| matches!(e, Effect::Quit { .. })));
    h.keys("ctrl-\\ q");
    assert!(h.effects().contains(&Effect::Quit { code: 0 }));
}

// T-12
#[test]
fn t12_lock_disconnects_sessions_when_configured() {
    let mut h = unlocked_harness(config_with(|c| c.general.lock_disconnects_sessions = true));
    h.app_mut().focus_session(SessionId(1));
    h.app_mut().focus_session(SessionId(2));
    h.keys("ctrl-\\ ctrl-l");
    let closed: Vec<_> = h
        .effects()
        .iter()
        .filter_map(|e| match e {
            Effect::CloseSession(id) => Some(*id),
            _ => None,
        })
        .collect();
    assert_eq!(closed, [SessionId(1), SessionId(2)]);

    // Default: sessions stay connected behind the overlay.
    let mut h = unlocked_harness(Config::default());
    h.app_mut().focus_session(SessionId(1));
    h.keys("ctrl-\\ ctrl-l");
    assert!(
        !h.effects()
            .iter()
            .any(|e| matches!(e, Effect::CloseSession(_)))
    );
}

#[test]
fn startup_first_run_then_launch_after_unlock() {
    let mut h = AppHarness::new(Config::default());
    let app = h.app().clone().with_vault();
    *h.app_mut() = app;
    // M3-03: `--workspace` no longer toasts; `join` still does (until M6-03).
    h.send(UiEvent::Launch(crate::app::LaunchIntent::Join("l".into())));
    assert!(h.app().toasts().is_empty(), "launch waits for unlock");
    h.send(UiEvent::Vault(VaultEvent::Status(VaultStatusInfo {
        initialized: false,
        keyring_available: true,
        ..VaultStatusInfo::default()
    })));
    assert!(matches!(h.app().vault_screen(), VaultScreen::FirstRun(f) if f.keyring_available));
    insta::assert_snapshot!("first_run_80x24", h.render(80, 24));
    let pw = "correct horse battery staple violin";
    for c in pw.chars() {
        h.send(UiEvent::Input(InputEvent::Key(KeyEvent::from(
            crossterm::event::KeyCode::Char(c),
        ))));
    }
    h.keys("tab");
    for c in pw.chars() {
        h.send(UiEvent::Input(InputEvent::Key(KeyEvent::from(
            crossterm::event::KeyCode::Char(c),
        ))));
    }
    h.keys("tab space enter");
    assert!(h.effects().iter().any(|e| matches!(
        e,
        Effect::Vault(VaultEffect::Initialize { password, keyring: true }) if password.expose() == pw
    )));
    assert_eq!(h.app().lock_state(), LockState::Unlocking);
    h.send(UiEvent::Vault(VaultEvent::Unlocked {
        via_keyring: false,
        note: None,
    }));
    assert_eq!(h.app().lock_state(), LockState::Unlocked);
    assert_eq!(h.app().toasts().len(), 1, "the deferred launch ran");
}

#[test]
fn keyring_first_then_fallback_to_prompt() {
    let mut h = AppHarness::new(Config::default());
    let app = h.app().clone().with_vault();
    *h.app_mut() = app;
    h.send(UiEvent::Vault(VaultEvent::Status(VaultStatusInfo {
        initialized: true,
        keyring_enabled: true,
        ..VaultStatusInfo::default()
    })));
    assert!(
        h.effects()
            .contains(&Effect::Vault(VaultEffect::Unlock(UnlockRequest::Keyring)))
    );
    h.send(UiEvent::Vault(VaultEvent::UnlockFailed(
        UnlockFailure::Keyring("the keyring entry is missing".into()),
    )));
    assert_eq!(h.app().lock_state(), LockState::Locked);
    assert!(matches!(h.app().vault_screen(), VaultScreen::Unlock(f) if f.busy.is_none()));
    assert!(
        h.app().toasts()[0]
            .message
            .contains("Keyring unlock failed")
    );
}

#[test]
fn backoff_countdown_disables_input() {
    let mut h = unlocked_harness(Config::default());
    h.keys("ctrl-\\ ctrl-l a enter");
    h.send(UiEvent::Vault(VaultEvent::UnlockFailed(
        UnlockFailure::WrongPassword {
            failures: 6,
            retry_after: Some(Duration::from_secs(2)),
        },
    )));
    let VaultScreen::Unlock(form) = h.app().vault_screen() else {
        panic!("prompt expected")
    };
    assert_eq!(form.countdown, Some(2));
    assert!(
        form.error
            .as_deref()
            .is_some_and(|e| e.contains("6 failed"))
    );
    h.take_effects();
    h.keys("b enter");
    assert!(!h.effects().iter().any(|e| matches!(e, Effect::Vault(_))));
    h.advance(2_000);
    let VaultScreen::Unlock(form) = h.app().vault_screen() else {
        panic!("prompt expected")
    };
    assert_eq!(form.countdown, None);
    h.keys("b enter");
    assert!(
        h.effects()
            .iter()
            .any(|e| matches!(e, Effect::Vault(VaultEffect::Unlock(_))))
    );
}

#[test]
fn keyring_recovery_opens_the_new_password_form() {
    let mut h = AppHarness::new(Config::default());
    let app = h.app().clone().with_vault();
    *h.app_mut() = app;
    h.send(UiEvent::Vault(VaultEvent::Status(VaultStatusInfo {
        initialized: true,
        keyring_enabled: true,
        ..VaultStatusInfo::default()
    })));
    h.send(UiEvent::Vault(VaultEvent::UnlockFailed(
        UnlockFailure::Keyring("x".into()),
    )));
    h.take_effects();
    h.keys("ctrl-r");
    assert!(
        h.effects()
            .contains(&Effect::Vault(VaultEffect::Unlock(UnlockRequest::Keyring)))
    );
    h.send(UiEvent::Vault(VaultEvent::Unlocked {
        via_keyring: true,
        note: None,
    }));
    assert!(
        matches!(h.app().vault_screen(), VaultScreen::ChangePassword(f) if f.current.is_none())
    );
}

#[test]
fn lock_discards_forms_and_toasts_after_unlock() {
    let mut h = unlocked_harness(Config::default());
    h.app_mut().push_dialog(DialogKind::HostForm(
        crate::views::hosts::form::HostFormDialog::blank(),
    ));
    h.keys("x");
    h.keys("ctrl-\\ ctrl-l");
    assert!(h.app().dialogs().is_empty());
    h.send(UiEvent::Vault(VaultEvent::Unlocked {
        via_keyring: false,
        note: None,
    }));
    assert!(
        h.app()
            .toasts()
            .iter()
            .any(|t| t.message == DISCARDED_FORMS)
    );
}

#[test]
fn without_a_vault_service_nothing_changes() {
    let mut h = AppHarness::new(Config::default());
    h.keys("j");
    assert!(
        h.effects().is_empty()
            || !h.effects().iter().any(|e| matches!(
                e,
                Effect::ScheduleTimer {
                    kind: TimerKind::AutoLockCheck,
                    ..
                }
            ))
    );
    assert_eq!(h.app().lock_state(), LockState::Unlocked);
    h.keys("ctrl-\\ ctrl-l");
    assert!(!has_lock(h.effects()));
}

#[test]
fn password_never_appears_in_debug_output() {
    let p = VaultPassword::from("hunter2");
    let e = Effect::Vault(VaultEffect::Unlock(UnlockRequest::Password(p)));
    assert!(!format!("{e:?}").contains("hunter2"));
    let mut h = unlocked_harness(Config::default());
    h.keys("ctrl-\\ ctrl-l h u n t e r");
    assert!(!format!("{:?}", h.app()).contains("hunter"));
}
