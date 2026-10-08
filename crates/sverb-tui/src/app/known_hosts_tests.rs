//! M1-15 reducer tests: the unknown-key modal (T-10), the changed-key screen (T-11),
//! prompts closing with the session, and the Known Hosts view (list, delete, edit,
//! import / export prompts, lock).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use sverb_conn::{
    Decision, DisconnectReason, SessionEvent, SessionState, Verification, session::HostKeyDetails,
};
use sverb_core::{
    known_hosts::randomart,
    model::{ItemId, KnownHost, KnownHostMarker, UnixMillis},
};

use super::{KnownHostsEffect, KnownHostsEvent};
use crate::app::{
    Config, Effect, Mode, SessionId, ToastLevel, UiEvent, VaultEffect, hosts::ItemEffect,
};
use crate::testing::AppHarness;
use crate::views::{DialogKind, Section, dialogs::host_key::HostKeyStage};

const SESSION: SessionId = SessionId(7);

fn verification(changed: bool) -> Verification {
    Verification {
        hop: 1,
        of: 1,
        host: "web.example.com:22".into(),
        fingerprint: "SHA256:uYxmMoF3aflKiV/iuu80yjcxVbhqOX/6YopX8ub8Jko".into(),
        changed,
        details: HostKeyDetails {
            hostname: "web.example.com".into(),
            port: 22,
            key_type: "ssh-ed25519".into(),
            randomart: randomart(&[0x5a; 32], "ED25519", 256),
            old_fingerprints: if changed {
                vec!["SHA256:OLDOLDOLD".into()]
            } else {
                Vec::new()
            },
            note: None,
        },
    }
}

fn ask(h: &mut AppHarness, changed: bool) {
    h.send(UiEvent::Session(
        SESSION,
        SessionEvent::HostKey(verification(changed)),
    ));
    assert!(
        matches!(
            h.app().dialogs().last().map(|d| &d.kind),
            Some(DialogKind::HostKey(_))
        ),
        "{:?}",
        h.app().dialogs()
    );
}

fn decisions(effects: &[Effect]) -> Vec<Decision> {
    effects
        .iter()
        .filter_map(|e| match e {
            Effect::HostKeyDecision { id, decision } if *id == SESSION => Some(*decision),
            _ => None,
        })
        .collect()
}

fn host_key_open(h: &AppHarness) -> bool {
    h.app()
        .dialogs()
        .iter()
        .any(|d| matches!(d.kind, DialogKind::HostKey(_)))
}

/// T-10: `a` → accept & save (the verifier's store saves the item), `o` → accept for
/// this connection only, `r` / `Esc` → reject. Each closes the modal.
#[test]
fn t10_unknown_key_modal() {
    for (keys, want) in [
        ("a", Decision::AcceptAndSave),
        ("o", Decision::AcceptOnce),
        ("r", Decision::Reject),
        ("esc", Decision::Reject),
    ] {
        let mut h = AppHarness::new(Config::default());
        ask(&mut h, false);
        // Unrelated keys do nothing.
        h.keys("x q");
        assert!(decisions(h.effects()).is_empty());
        assert!(host_key_open(&h));
        h.keys(keys);
        assert_eq!(decisions(h.effects()), [want], "{keys}");
        assert!(!host_key_open(&h), "{keys}: the modal closes");
    }
}

#[test]
fn t10_unknown_modal_shows_fingerprint_and_randomart() {
    let mut h = AppHarness::new(Config::default());
    ask(&mut h, false);
    let screen = h.render(100, 40);
    assert!(screen.contains("Unknown host key"), "{screen}");
    assert!(
        screen.contains("SHA256:uYxmMoF3aflKiV/iuu80yjcxVbhqOX/6YopX8ub8Jko"),
        "{screen}"
    );
    assert!(screen.contains("ssh-ed25519"), "{screen}");
    assert!(screen.contains("+--[ED25519 256]--+"), "{screen}");
    assert!(screen.contains("+----[SHA256]-----+"), "{screen}");
    assert!(screen.contains("ccept & save"), "{screen}");
    assert!(
        screen.contains("nce") && screen.contains("eject"),
        "{screen}"
    );
}

/// T-11: only reject acts; `R` opens the prompt; a wrong host name stays blocked; the
/// exact host name replaces (accept & save).
#[test]
fn t11_changed_key_screen() {
    let mut h = AppHarness::new(Config::default());
    ask(&mut h, true);
    let screen = h.render(100, 40);
    assert!(
        screen.contains("WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED"),
        "{screen}"
    );
    assert!(screen.contains("SHA256:OLDOLDOLD"), "{screen}");
    assert!(screen.contains("SHA256:uYxmMoF3afl"), "{screen}");

    // Accept keys are inactive.
    h.keys("a o enter");
    assert!(decisions(h.effects()).is_empty());
    assert!(host_key_open(&h));

    // `R` → the host name prompt (Insert mode).
    h.keys("R");
    let stage = |h: &AppHarness| match &h.app().dialogs().last().unwrap().kind {
        DialogKind::HostKey(d) => d.stage.clone(),
        other => panic!("{other:?}"),
    };
    assert!(matches!(stage(&h), HostKeyStage::ConfirmReplace { .. }));
    assert_eq!(h.app().mode(), Mode::Insert);
    assert!(
        h.render(100, 40)
            .contains("type the host name (web.example.com)")
    );

    // A wrong host name: still blocked.
    h.keys("w e b enter");
    assert!(decisions(h.effects()).is_empty());
    assert!(matches!(
        stage(&h),
        HostKeyStage::ConfirmReplace { mismatch: true, .. }
    ));
    assert!(h.render(100, 40).contains("not the host name"));

    // Esc goes back to the warning; R again starts empty.
    h.keys("esc");
    assert!(matches!(stage(&h), HostKeyStage::Ask));
    assert!(decisions(h.effects()).is_empty());
    h.keys("R");
    let typed = "web.example.com"
        .chars()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    h.keys(&typed);
    h.keys("enter");
    assert_eq!(decisions(h.effects()), [Decision::AcceptAndSave]);
    assert!(!host_key_open(&h));

    // Reject from the warning.
    let mut h = AppHarness::new(Config::default());
    ask(&mut h, true);
    h.keys("r");
    assert_eq!(decisions(h.effects()), [Decision::Reject]);
}

/// The session stops waiting (120 s timeout, closed): its prompt closes. Another
/// session's prompt stays.
#[test]
fn prompt_closes_with_the_session() {
    let mut h = AppHarness::new(Config::default());
    ask(&mut h, false);
    h.send(UiEvent::Session(
        SessionId(99),
        SessionEvent::State(SessionState::Closed),
    ));
    assert!(host_key_open(&h));
    h.send(UiEvent::Session(
        SESSION,
        SessionEvent::State(SessionState::Disconnected {
            reason: DisconnectReason::HostKey,
            at: h.now(),
        }),
    ));
    assert!(!host_key_open(&h));
    assert!(decisions(h.effects()).is_empty());
}

#[test]
fn saves_toast() {
    let mut h = AppHarness::new(Config::default());
    h.send(UiEvent::KnownHosts(KnownHostsEvent::Saved {
        host: "[db]:2222".into(),
        auto: true,
    }));
    assert!(
        h.app()
            .toasts()
            .iter()
            .any(|t| t.level == ToastLevel::Success
                && t.message == "Added host key for [db]:2222 (accept-new)")
    );
}

// ---------------------------------------------------------------- the view

const ED: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIBhYxpK5M9dWWLkngJsG1h11alcrHTyZO7bn447uw5it";

fn entries() -> Vec<(ItemId, KnownHost)> {
    let e = |pattern: &str, marker, comment: Option<&str>| KnownHost {
        host_pattern: pattern.into(),
        key_type: "ssh-ed25519".into(),
        public_key: ED.into(),
        added_at: UnixMillis(1_791_331_200_000),
        comment: comment.map(Into::into),
        marker,
        read_only: false,
    };
    vec![
        (
            ItemId::from_bytes([1; 16]),
            e("web.example.com", KnownHostMarker::None, None),
        ),
        (
            ItemId::from_bytes([2; 16]),
            e(
                "|1|TiLoG1eC3mmpBNtvUXd6mbrVn8Y=|gOIVmUZAweBiA2FDlKYdy6QlUmA=",
                KnownHostMarker::None,
                Some("laptop"),
            ),
        ),
        (
            ItemId::from_bytes([3; 16]),
            e("*.test", KnownHostMarker::CertAuthority, Some("ca")),
        ),
    ]
}

fn known_view() -> AppHarness {
    let mut h = AppHarness::new(Config::default());
    h.app_mut().open_section(Section::Known);
    let effects = h
        .app_mut()
        .handle(UiEvent::IndexUpdated(std::sync::Arc::new(
            sverb_core::search::IndexSnapshot::default(),
        )));
    assert!(
        effects.contains(&Effect::KnownHosts(KnownHostsEffect::Load)),
        "{effects:?}"
    );
    h.send(UiEvent::KnownHosts(KnownHostsEvent::Loaded(entries())));
    h
}

#[test]
fn view_lists_entries_with_fingerprints() {
    let h = known_view();
    let screen = h.render(220, 30);
    assert!(screen.contains("web.example.com"), "{screen}");
    assert!(screen.contains("(hashed) laptop"), "{screen}");
    // The list shows hashed patterns as `(hashed)` plus the comment; the detail pane
    // shows the whole field.
    assert!(screen.contains("› (hashed) laptop"), "{screen}");
    assert!(screen.contains("@cert-authority"), "{screen}");
    assert!(screen.contains("SHA256:uYxmMoF3"), "{screen}");
    assert!(screen.contains("2026-10-07"), "{screen}");
    // The detail pane: the full fingerprint and the randomart.
    assert!(
        screen.contains("SHA256:uYxmMoF3aflKiV/iuu80yjcxVbhqOX/6YopX8ub8Jko"),
        "{screen}"
    );
    assert!(screen.contains("[ED25519 256]"), "{screen}");
}

#[test]
fn view_delete_edit_import_export() {
    let mut h = known_view();
    // Delete asks first, then deletes the item.
    h.keys("d");
    assert!(
        h.take_effects()
            .iter()
            .all(|e| !matches!(e, Effect::Vault(_)))
    );
    h.keys("d");
    let deletes: Vec<_> = h
        .take_effects()
        .into_iter()
        .filter(|e| matches!(e, Effect::Vault(VaultEffect::Items(ItemEffect::Delete(_)))))
        .collect();
    assert_eq!(deletes.len(), 1, "{deletes:?}");

    // Edit: the comment.
    h.keys("e");
    assert!(matches!(
        h.app().dialogs().last().unwrap().kind,
        DialogKind::KnownHosts(_)
    ));
    h.keys("tab x y ctrl-s");
    let saves: Vec<_> = h
        .take_effects()
        .into_iter()
        .filter_map(|e| match e {
            Effect::KnownHosts(KnownHostsEffect::Save { item, entry }) => Some((item, entry)),
            _ => None,
        })
        .collect();
    assert_eq!(saves.len(), 1, "{:?}", h.app().dialogs());
    // The first row (sorted by host): the hashed entry, comment "laptop".
    assert_eq!(saves[0].0, Some(ItemId::from_bytes([2; 16])));
    assert_eq!(saves[0].1.comment.as_deref(), Some("laptopxy"));
    assert!(saves[0].1.host_pattern.starts_with("|1|"));
    assert!(h.app().dialogs().is_empty());

    // Export and import ask for a path (defaults filled in).
    h.keys("x enter");
    assert!(
        h.take_effects()
            .contains(&Effect::KnownHosts(KnownHostsEffect::Export {
                path: "~/sverb_known_hosts".into()
            }))
    );
    // M2-11: import opens the import wizard (known_hosts source); Enter runs the dry run.
    h.keys("I enter");
    assert!(h.take_effects().iter().any(|e| matches!(
        e,
        Effect::Import(crate::views::import_wizard::ImportEffect::Preview { request, .. })
            if request.source == crate::views::import_wizard::WizardSource::KnownHosts
                && request.path == "~/.ssh/known_hosts"
    )));
}

#[test]
fn view_clears_on_lock() {
    let mut h = AppHarness::new(Config::default());
    *h.app_mut() =
        std::mem::replace(h.app_mut(), crate::app::App::new(Default::default())).with_vault();
    h.send(UiEvent::KnownHosts(KnownHostsEvent::Loaded(entries())));
    // Locked: the loaded list is dropped, not shown.
    assert!(h.app().views().known_hosts.list.rows().is_empty());
}
