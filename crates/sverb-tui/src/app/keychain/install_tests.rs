//! M2-04 reducer tests: install key on host — picker → confirm → run → results
//! (T-10: statuses rendered, `r` re-runs failed hosts only), prompts attributed to the
//! run and answered to it, `esc` cancels.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{sync::Arc, time::Duration};

use sverb_conn::{AuthPrompt, PromptKind, PromptLine, SessionEvent};

use super::install::{InstallEffect, InstallReply, InstallUpdate};
use super::keys::{KeychainEffect, KeychainEvent, KeychainOutcome};
use crate::app::hosts::ItemEffect;
use crate::app::{Config, Effect, SessionId, UiEvent, VaultEffect, VaultEvent};
use crate::testing::AppHarness;
use crate::views::keychain::import_dialog::KeychainDialogKind;
use crate::views::keychain::{
    identity_form::IdentityDialog,
    install::InstallTarget,
    tests::{CACHE, DB1, PROD, add_sample_keys, id, sample},
};
use crate::views::{DialogKind, Section};
use crate::widgets::auth_prompt::AuthReply;
use crate::widgets::results_table::RowState;

fn keychain() -> AppHarness {
    let mut h = AppHarness::new(Config::default());
    let (index, mut cat) = sample();
    add_sample_keys(&mut cat);
    let cat = Arc::new(cat);
    h.send(UiEvent::IndexUpdated(index));
    h.take_effects();
    let app = h.app_mut();
    app.views.keychain.set_catalog(Arc::clone(&cat));
    app.views.hosts.set_catalog(cat);
    app.open_section(Section::Keychain);
    h
}

fn top(h: &AppHarness) -> Option<&KeychainDialogKind> {
    match &h.app().dialogs().last()?.kind {
        DialogKind::Identity(IdentityDialog::Keychain(d)) => Some(&d.kind),
        _ => None,
    }
}

fn install_ops(effects: &[Effect]) -> Vec<InstallEffect> {
    effects
        .iter()
        .filter_map(|e| match e {
            Effect::Vault(VaultEffect::Items(ItemEffect::Keychain(KeychainEffect::Install(
                op,
            )))) => Some(op.clone()),
            _ => None,
        })
        .collect()
}

fn update(h: &mut AppHarness, u: InstallUpdate) {
    h.send(UiEvent::Vault(VaultEvent::Keychain(KeychainEvent {
        token: 0,
        outcome: KeychainOutcome::Install(u),
    })));
}

fn row(run: u64, index: usize, state: RowState) -> InstallUpdate {
    InstallUpdate::Row {
        run,
        index,
        state,
        duration: Some(Duration::from_millis(1200)),
        detail: "mkdir: Permission denied".into(),
    }
}

/// Pick group "prod" (→ db-1) and host "cache", confirm; returns the run's effect.
fn start(h: &mut AppHarness) -> (u64, Vec<(usize, String, SessionId)>) {
    h.keys("H");
    let Some(KeychainDialogKind::InstallPick(p)) = top(h) else {
        panic!("{:?}", h.app().dialogs().last());
    };
    // Groups first, then tags, then hosts by label.
    assert_eq!(p.entries[0].target, InstallTarget::Group(id(PROD)));
    let cache = p
        .entries
        .iter()
        .position(|e| e.target == InstallTarget::Host(id(CACHE)))
        .unwrap();
    h.keys("space");
    for _ in 0..cache {
        h.keys("down");
    }
    h.keys("space enter");
    let screen = h.render(160, 48);
    assert!(screen.contains("umask 077"), "{screen}");
    assert!(screen.contains("2 host(s): cache, db-1"), "{screen}");
    h.take_effects();
    h.keys("i");
    let ops = install_ops(&h.take_effects());
    let [InstallEffect::Run(job)] = ops.as_slice() else {
        panic!("{ops:?}");
    };
    assert!(job.command.starts_with("umask 077; mkdir -p ~/.ssh"));
    assert_eq!(job.concurrency, 10);
    assert!(matches!(
        top(h),
        Some(KeychainDialogKind::InstallResults(_))
    ));
    (
        job.run,
        job.hosts
            .iter()
            .map(|x| (x.index, x.label.clone(), x.session))
            .collect(),
    )
}

/// T-10: statuses render; `r` re-runs the failed hosts only.
#[test]
fn t10_results_and_rerun_failed() {
    let mut h = keychain();
    let (run, hosts) = start(&mut h);
    assert_eq!(
        hosts.iter().map(|x| x.1.as_str()).collect::<Vec<_>>(),
        ["cache", "db-1"]
    );
    let screen = h.render(160, 48);
    assert!(screen.contains("queued"), "{screen}");
    // `r` does nothing while running.
    h.keys("r");
    assert!(install_ops(&h.take_effects()).is_empty());

    update(&mut h, row(run, 0, RowState::Ok("installed".into())));
    update(
        &mut h,
        row(run, 1, RowState::Failed("error: Permission denied".into())),
    );
    let screen = h.render(160, 48);
    assert!(screen.contains("installed"), "{screen}");
    assert!(screen.contains("error: Permission denied"), "{screen}");
    assert!(screen.contains("1 ok · 1 failed"), "{screen}");

    h.take_effects();
    h.keys("r");
    let ops = install_ops(&h.take_effects());
    let [InstallEffect::Run(job)] = ops.as_slice() else {
        panic!("{ops:?}");
    };
    assert_ne!(job.run, run);
    assert_eq!(job.hosts.len(), 1);
    assert_eq!(job.hosts[0].index, 1);
    assert_eq!(job.hosts[0].host, id(DB1));
    let Some(KeychainDialogKind::InstallResults(r)) = top(&h) else {
        panic!();
    };
    assert_eq!(r.table.rows[0].state, RowState::Ok("installed".into()));
    assert_eq!(r.table.rows[1].state, RowState::Queued);
    // Stale updates of the first run are ignored.
    update(&mut h, row(run, 1, RowState::Ok("installed".into())));
    let Some(KeychainDialogKind::InstallResults(r)) = top(&h) else {
        panic!();
    };
    assert_eq!(r.table.rows[1].state, RowState::Queued);
    // An already-present answer for the re-run.
    update(
        &mut h,
        row(job.run, 1, RowState::Notice("already present".into())),
    );
    assert!(h.render(160, 48).contains("already present"));
}

/// Prompts are attributed to the run and answered to it (not to a session).
#[test]
fn prompts_go_to_the_run() {
    let mut h = keychain();
    let (run, hosts) = start(&mut h);
    let (_, _, session) = hosts[1].clone();
    let prompt = AuthPrompt::new(
        PromptKind::Password {
            host: Some(id(DB1)),
        },
        "Authenticate to db-1".into(),
        vec![PromptLine {
            text: "Password:".into(),
            echo: false,
        }],
    );
    update(
        &mut h,
        InstallUpdate::Session {
            run,
            session,
            event: SessionEvent::Prompt(prompt),
        },
    );
    let screen = h.render(160, 48);
    assert!(
        screen.contains("Authenticating to db-1 for: Install key"),
        "{screen}"
    );
    h.take_effects();
    h.keys("p w enter");
    let effects = h.take_effects();
    assert!(
        !effects
            .iter()
            .any(|e| matches!(e, Effect::AuthAnswer { .. })),
        "{effects:?}"
    );
    let ops = install_ops(&effects);
    assert!(
        matches!(
            ops.as_slice(),
            [InstallEffect::Answer { session: s, reply: InstallReply::Auth(AuthReply::Responses(r)) }]
                if *s == session && r.len() == 1
        ),
        "{ops:?}"
    );
}

/// `esc` closes the table and cancels a run in progress.
#[test]
fn esc_cancels_a_running_install() {
    let mut h = keychain();
    let (run, _) = start(&mut h);
    h.keys("esc");
    assert!(top(&h).is_none());
    let ops = install_ops(&h.take_effects());
    assert!(
        matches!(ops.as_slice(), [InstallEffect::Cancel { run: r }] if *r == run),
        "{ops:?}"
    );
    // A late prompt for the closed run is cancelled at once.
    update(
        &mut h,
        InstallUpdate::Session {
            run,
            session: SessionId(999),
            event: SessionEvent::Prompt(AuthPrompt::new(
                PromptKind::Password { host: None },
                "x".into(),
                Vec::new(),
            )),
        },
    );
    let ops = install_ops(&h.take_effects());
    assert!(
        matches!(
            ops.as_slice(),
            [InstallEffect::Answer {
                reply: InstallReply::Auth(AuthReply::Cancel),
                ..
            }]
        ),
        "{ops:?}"
    );
}
