//! M2-08 reducer tests: the Forwards view (load, list, live refresh at ≤ 2 Hz, status
//! bar), its requests (start, start without terminal, stop, add, delete) and the
//! non-loopback bind confirmation (T-18).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use sverb_conn::SessionSpec;
use sverb_core::model::{ForwardKind, ItemId};

use super::{ForwardsEffect, ForwardsEvent, REFRESH_EVERY, fwd};
use crate::app::{Config, Effect, TimerKind, UiEvent, VaultEffect, hosts::ItemEffect};
use crate::testing::AppHarness;
use crate::views::{DialogKind, Section};

const HOST: ItemId = ItemId::from_bytes([9; 16]);

fn status(id: u8, label: &str, bind: &str, state: fwd::ForwardState) -> fwd::ForwardStatus {
    fwd::ForwardStatus {
        rule: fwd::ForwardRule {
            id: ItemId::from_bytes([id; 16]),
            label: label.into(),
            kind: ForwardKind::Local,
            host_id: HOST,
            bind_addr: bind.into(),
            bind_port: 5432,
            dest_host: Some("db".into()),
            dest_port: Some(5432),
            auto_start: false,
            typed_here: true,
        },
        state,
        port: Some(5432),
        active: 0,
        bytes_in: 0,
        bytes_out: 0,
        refused: 0,
        total: 0,
        standalone: false,
    }
}

fn loaded(statuses: Vec<fwd::ForwardStatus>) -> UiEvent {
    UiEvent::Forwards(ForwardsEvent::Loaded {
        statuses,
        hosts: vec![(HOST, "prod".into())],
    })
}

fn forwards_view(statuses: Vec<fwd::ForwardStatus>) -> AppHarness {
    let mut h = AppHarness::new(Config::default());
    h.app_mut().open_section(Section::Forwards);
    let effects = h
        .app_mut()
        .handle(UiEvent::IndexUpdated(std::sync::Arc::new(
            sverb_core::search::IndexSnapshot::default(),
        )));
    assert!(
        effects.contains(&Effect::Forwards(ForwardsEffect::Load)),
        "{effects:?}"
    );
    h.send(loaded(statuses));
    h
}

fn forward_effects(effects: Vec<Effect>) -> Vec<ForwardsEffect> {
    effects
        .into_iter()
        .filter_map(|e| match e {
            Effect::Forwards(f) => Some(f),
            _ => None,
        })
        .collect()
}

#[test]
fn view_lists_rules_and_refreshes_at_2hz() {
    let mut h = forwards_view(vec![status(
        1,
        "db tunnel",
        "127.0.0.1",
        fwd::ForwardState::Stopped,
    )]);
    let screen = h.render(200, 30);
    assert!(screen.contains("db tunnel"), "{screen}");
    assert!(screen.contains("127.0.0.1:5432 → db:5432"), "{screen}");
    assert!(screen.contains("stopped"), "{screen}");
    assert!(screen.contains("prod"), "{screen}");
    // The refresh timer: one Refresh per 500 ms.
    h.take_effects();
    h.advance(REFRESH_EVERY.as_millis() as u64);
    assert_eq!(forward_effects(h.take_effects()), [ForwardsEffect::Refresh],);
    h.advance(REFRESH_EVERY.as_millis() as u64 * 2);
    assert_eq!(forward_effects(h.take_effects()).len(), 2);

    // Live status: listening, connections, bytes; the status bar summarizes.
    let mut live = status(1, "db tunnel", "127.0.0.1", fwd::ForwardState::Listening);
    live.active = fwd::MAX_CHANNELS;
    live.bytes_in = 1_200_000;
    h.send(UiEvent::Forwards(ForwardsEvent::Status(vec![live])));
    let screen = h.render(200, 30);
    assert!(screen.contains("listening"), "{screen}");
    assert!(screen.contains("256/256"), "{screen}");
    assert!(screen.contains("1.2 MB"), "{screen}");
    assert!(screen.contains("⇄ L:5432→db:5432"), "{screen}");
    // An unchanged status does not ask for a redraw.
    h.app_mut().mark_drawn();
    let same = h.app().views().forwards.statuses();
    h.send(UiEvent::Forwards(ForwardsEvent::Status(same)));
    assert!(!h.app().needs_redraw());
}

#[test]
fn start_stop_standalone_add_delete() {
    let mut h = forwards_view(vec![status(
        1,
        "db",
        "127.0.0.1",
        fwd::ForwardState::Stopped,
    )]);
    let id = ItemId::from_bytes([1; 16]);
    h.take_effects();
    h.keys("enter");
    assert_eq!(
        forward_effects(h.take_effects()),
        [ForwardsEffect::Start(id)]
    );
    // Start without terminal: a fresh session id, the host's spec, no tab.
    h.keys("t");
    let effects = forward_effects(h.take_effects());
    let [ForwardsEffect::StartStandalone { rule, spec, .. }] = effects.as_slice() else {
        panic!("{effects:?}")
    };
    assert_eq!(*rule, id);
    let SessionSpec::Ssh(spec) = spec else {
        panic!()
    };
    assert_eq!(spec.host_id, Some(HOST));
    assert!(h.app().tabs().sessions.is_empty(), "no tab for a tunnel");

    h.send(UiEvent::Forwards(ForwardsEvent::Status(vec![status(
        1,
        "db",
        "127.0.0.1",
        fwd::ForwardState::Listening,
    )])));
    h.keys("x");
    assert_eq!(
        forward_effects(h.take_effects()),
        [ForwardsEffect::Stop(id)]
    );

    // Add opens the form.
    h.keys("a");
    assert!(matches!(
        h.app().dialogs().last().map(|d| &d.kind),
        Some(DialogKind::Forward(_))
    ));
    h.keys("esc");
    assert!(h.app().dialogs().is_empty());

    // Delete asks, then stops and deletes.
    h.keys("d");
    assert!(forward_effects(h.take_effects()).is_empty());
    h.keys("d");
    let effects = h.take_effects();
    assert!(effects.contains(&Effect::Forwards(ForwardsEffect::Stop(id))));
    assert!(effects.contains(&Effect::Vault(VaultEffect::Items(ItemEffect::Delete(id)))));
}

/// T-18: a non-loopback bind asks for confirmation the first time only. The manager
/// answers the first start with `NeedsApproval`; "Yes" approves and starts; the next
/// start goes straight through (the manager no longer asks, see
/// `sverb-conn` `forward::tests::lifecycle_and_approval`).
#[test]
fn t18_non_loopback_bind_confirmed_first_time_only() {
    let mut h = forwards_view(vec![status(
        2,
        "wide",
        "0.0.0.0",
        fwd::ForwardState::Stopped,
    )]);
    let id = ItemId::from_bytes([2; 16]);
    let manager = fwd::ForwardManager::new();
    let rule = h
        .app()
        .views()
        .forwards
        .get(id)
        .unwrap()
        .status
        .rule
        .clone();
    manager.set_rules([rule]);

    // First start: the manager needs the confirmation.
    h.take_effects();
    h.keys("enter");
    assert_eq!(
        forward_effects(h.take_effects()),
        [ForwardsEffect::Start(id)]
    );
    let Err(fwd::StartError::NeedsApproval(values)) = manager.start(id) else {
        panic!()
    };
    h.send(UiEvent::Forwards(ForwardsEvent::NeedsApproval {
        rule: id,
        values: values.clone(),
        standalone: false,
    }));
    let Some(DialogKind::Modal(m)) = h.app().dialogs().last().map(|d| &d.kind) else {
        panic!("{:?}", h.app().dialogs())
    };
    assert!(m.modal.body.contains("0.0.0.0:5432"), "{}", m.modal.body);
    h.keys("y");
    let effects = forward_effects(h.take_effects());
    assert_eq!(
        effects,
        [ForwardsEffect::Approve(values), ForwardsEffect::Start(id)]
    );
    for e in effects {
        if let ForwardsEffect::Approve(v) = e {
            manager.approve(&v);
        }
    }
    // Second start: no question.
    assert!(manager.pending_approval(id).is_empty());
    h.keys("enter");
    assert_eq!(
        forward_effects(h.take_effects()),
        [ForwardsEffect::Start(id)]
    );
    assert!(h.app().dialogs().is_empty());
    // M2-10: "No" denies (for this session); with nothing to deny it is empty.
    h.send(UiEvent::Forwards(ForwardsEvent::NeedsApproval {
        rule: id,
        values: Vec::new(),
        standalone: false,
    }));
    h.keys("n");
    assert_eq!(
        forward_effects(h.take_effects()),
        [ForwardsEffect::Deny(Vec::new())]
    );
}

/// M2-10 T-10 (reducer + manager): "No" denies the values for the session; the next
/// start is blocked without a dialog; a fresh manager (a new start of sverb) asks
/// again.
#[test]
fn m2_10_deny_blocks_for_the_session() {
    let mut h = forwards_view(vec![status(
        2,
        "wide",
        "0.0.0.0",
        fwd::ForwardState::Stopped,
    )]);
    let id = ItemId::from_bytes([2; 16]);
    let rule = h
        .app()
        .views()
        .forwards
        .get(id)
        .unwrap()
        .status
        .rule
        .clone();
    let manager = fwd::ForwardManager::new();
    manager.set_rules([rule.clone()]);
    let Err(fwd::StartError::NeedsApproval(values)) = manager.start(id) else {
        panic!()
    };
    h.take_effects();
    h.send(UiEvent::Forwards(ForwardsEvent::NeedsApproval {
        rule: id,
        values: values.clone(),
        standalone: false,
    }));
    h.keys("n");
    let effects = forward_effects(h.take_effects());
    assert_eq!(effects, [ForwardsEffect::Deny(values.clone())]);
    manager.deny(&values);
    assert!(matches!(
        manager.start(id),
        Err(fwd::StartError::Blocked(_))
    ));
    let restarted = fwd::ForwardManager::new();
    restarted.set_rules([rule]);
    assert!(matches!(
        restarted.start(id),
        Err(fwd::StartError::NeedsApproval(_))
    ));
}

#[test]
fn lock_drops_rules_and_stops_the_refresh() {
    let mut h = AppHarness::new(Config::default());
    *h.app_mut() =
        std::mem::replace(h.app_mut(), crate::app::App::new(Default::default())).with_vault();
    h.send(loaded(vec![status(
        1,
        "db",
        "127.0.0.1",
        fwd::ForwardState::Stopped,
    )]));
    // Locked: nothing is shown and no refresh is scheduled.
    assert!(h.app().views().forwards.list.rows().is_empty());
    assert!(!h.take_effects().iter().any(|e| matches!(
        e,
        Effect::ScheduleTimer {
            kind: TimerKind::ForwardsRefresh,
            ..
        }
    )));
}
