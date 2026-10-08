//! M4-09 reducer and snapshot tests: local-only vs synced bars and Settings pages
//! (T-01, T-02), palette gating (T-03), the devices revoke flow (T-05), the
//! lifecycle effects, the clock-skew toast and the account wizard dialog.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use pretty_assertions::assert_eq;
use sverb_core::model::VaultId;
use sverb_store::VaultKind;
use sverb_sync::{LocalSyncInfo, SyncEvent, SyncStatus, VaultPending};

use super::sync::SyncUiEvent;
use super::sync_ui::{DeviceRow, SyncEffect, WizardCmd, WizardFlow, WizardPrompt, WizardScreen};
use super::*;
use crate::keymap::action::ActionName;
use crate::testing::AppHarness;
use crate::views::{
    DialogKind, Section,
    settings::{NOT_CONNECTED, SettingsPage},
};

fn harness() -> AppHarness {
    let mut h = AppHarness::new(Config::default());
    // Fixed UTC for the snapshots.
    h.app_mut().views.settings.utc_offset_secs = Some(0);
    h
}

fn local_only() -> LocalSyncInfo {
    LocalSyncInfo::default()
}

fn synced_info() -> LocalSyncInfo {
    LocalSyncInfo {
        server_url: Some("https://sync.example.test".into()),
        signed_in: true,
        email: Some("me@example.test".into()),
        last_sync_ms: Some(1_791_460_800_000),
        pending: vec![VaultPending {
            vault: VaultId::from_bytes([1; 16]),
            kind: Some(VaultKind::Personal),
            pending: 3,
        }],
    }
}

fn sync_effects(h: &mut AppHarness) -> Vec<SyncEffect> {
    h.take_effects()
        .into_iter()
        .filter_map(|e| match e {
            Effect::Sync(s) => Some(s),
            _ => None,
        })
        .collect()
}

fn top_line(h: &AppHarness) -> String {
    h.render(100, 30)
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned()
}

fn settings(h: &mut AppHarness) -> String {
    h.app_mut().open_section(Section::Settings);
    h.render(100, 30)
}

// T-01: local-only: no indicator, Settings → Sync says "Not connected · Connect to a
// server", with buttons leading to the wizards.
#[test]
fn t01_local_only_hides_sync() {
    let mut h = harness();
    h.send(UiEvent::SyncUi(SyncUiEvent::Info(local_only())));
    h.send(UiEvent::Sync(SyncEvent::Status(SyncStatus::Disabled)));
    assert!(!h.app().sync_ui().connected());
    assert_eq!(h.app().sync_ui().indicator(), None);
    let top = top_line(&h);
    assert!(!top.contains("synced") && !top.contains("offline"), "{top}");
    let screen = settings(&mut h);
    assert!(screen.contains(NOT_CONNECTED), "{screen}");
    assert!(screen.contains("Log in to a server"), "{screen}");
    assert!(!screen.contains("Devices"), "no Devices page: {screen}");
    insta::assert_snapshot!("t01_local_only_settings", screen);

    // Enter opens the login wizard, `n` the registration.
    h.app_mut().shell.region = crate::views::Region::Main;
    h.take_effects();
    h.keys("enter");
    assert!(matches!(
        h.app().dialogs().last().map(|d| &d.kind),
        Some(DialogKind::AccountWizard(w)) if w.flow == WizardFlow::Login
    ));
    assert_eq!(
        sync_effects(&mut h),
        [SyncEffect::Wizard(WizardCmd::Start(WizardFlow::Login))]
    );
}

// T-02: synced mode, each status.
#[test]
fn t02_synced_states() {
    let mut h = harness();
    h.send(UiEvent::SyncUi(SyncUiEvent::Info(synced_info())));
    let cases = [
        (SyncStatus::Synced, "⟳ synced"),
        (SyncStatus::Syncing, "syncing"),
        (SyncStatus::Offline { pending: 3 }, "offline (3 pending)"),
        (
            SyncStatus::Error {
                message: "1 item too large to upload".into(),
            },
            "error",
        ),
    ];
    for (status, text) in cases {
        h.send(UiEvent::Sync(SyncEvent::Status(status.clone())));
        assert!(h.app().sync_ui().connected());
        let top = top_line(&h);
        assert!(top.trim_end().ends_with(text), "{status:?}: {top}");
        let snap = format!("{status:?}")
            .split(|c: char| !c.is_alphanumeric())
            .next()
            .unwrap_or_default()
            .to_lowercase();
        insta::assert_snapshot!(format!("t02_top_bar_{snap}"), top);
    }
    // The details panel: server, account, last sync, pending, errors.
    let screen = settings(&mut h);
    for want in [
        "https://sync.example.test",
        "me@example.test",
        "2026-10-08 12:00",
        "Personal: 3",
        "1 item too large to upload",
        "[s] Sync now",
        "[d] Disconnect",
    ] {
        assert!(screen.contains(want), "{want}: {screen}");
    }
    insta::assert_snapshot!("t02_sync_page", screen);
}

// T-02: a settled status re-reads the pending counts / last sync.
#[test]
fn settled_status_refreshes_the_info() {
    let mut h = harness();
    h.send(UiEvent::SyncUi(SyncUiEvent::Info(synced_info())));
    h.take_effects();
    h.send(UiEvent::Sync(SyncEvent::Status(SyncStatus::Syncing)));
    assert!(sync_effects(&mut h).is_empty());
    h.send(UiEvent::Sync(SyncEvent::Status(SyncStatus::Synced)));
    assert_eq!(sync_effects(&mut h), [SyncEffect::Refresh]);
}

// T-03: team, share and sync actions are disabled in local-only mode.
#[test]
fn t03_team_and_share_actions_need_a_server() {
    let mut h = harness().with_live_session();
    let gated = [
        ActionName::SharePane,
        ActionName::TeamKeys,
        ActionName::SyncStatus,
        ActionName::SyncNow,
        ActionName::Devices,
    ];
    h.send(UiEvent::SyncUi(SyncUiEvent::Info(local_only())));
    for a in gated {
        assert!(!h.app().action_enabled(a), "{a} enabled in local-only mode");
    }
    h.send(UiEvent::SyncUi(SyncUiEvent::Info(synced_info())));
    for a in gated {
        assert!(h.app().action_enabled(a), "{a} disabled while synced");
    }
}

fn device(id: &str, current: bool) -> DeviceRow {
    DeviceRow {
        id: id.into(),
        name: if current { "laptop" } else { "phone" }.into(),
        platform: "linux".into(),
        created_ms: Some(1_791_460_800_000),
        last_seen_ms: None,
        current,
    }
}

// T-05: Settings → Devices: revoke asks, then sends the effect; revoking this
// device logs out (the info refresh shows local-only).
#[test]
fn t05_devices_revoke_flow() {
    let mut h = harness();
    h.send(UiEvent::SyncUi(SyncUiEvent::Info(synced_info())));
    h.send(UiEvent::Sync(SyncEvent::Status(SyncStatus::Synced)));
    h.take_effects();
    let mut effects = Vec::new();
    h.app_mut()
        .open_sync_page(SettingsPage::Devices, &mut effects);
    assert_eq!(effects, [Effect::Sync(SyncEffect::ListDevices)]);
    assert!(h.app().views.settings.panel.devices.loading);
    h.send(UiEvent::SyncUi(SyncUiEvent::Devices(Ok(vec![
        device("d-me", true),
        device("d-phone", false),
    ]))));
    let screen = h.render(100, 30);
    assert!(screen.contains("this device"), "{screen}");
    insta::assert_snapshot!("t05_devices_page", screen);

    // Revoke the phone: a confirmation, then the effect.
    h.keys("j x");
    assert!(matches!(
        h.app().dialogs().last().map(|d| &d.kind),
        Some(DialogKind::Modal(_))
    ));
    h.take_effects();
    h.keys("r");
    assert_eq!(
        sync_effects(&mut h),
        [SyncEffect::RevokeDevice {
            id: "d-phone".into()
        }]
    );
    h.send(UiEvent::SyncUi(SyncUiEvent::Revoked {
        id: "d-phone".into(),
        this_device: false,
        result: Ok(()),
    }));
    assert_eq!(h.app().views.settings.panel.devices.rows.len(), 1);

    // Revoke this device: logged out, back to local-only.
    h.keys("x r");
    assert_eq!(
        sync_effects(&mut h),
        [SyncEffect::RevokeDevice { id: "d-me".into() }]
    );
    h.send(UiEvent::SyncUi(SyncUiEvent::Revoked {
        id: "d-me".into(),
        this_device: true,
        result: Ok(()),
    }));
    assert_eq!(sync_effects(&mut h), [SyncEffect::Refresh]);
    assert!(
        h.app()
            .toasts()
            .iter()
            .any(|t| t.message.contains("logged out"))
    );
    h.send(UiEvent::SyncUi(SyncUiEvent::Info(local_only())));
    assert!(!h.app().sync_ui().connected());
    assert_eq!(h.app().views.settings.page, SettingsPage::Sync);
    assert!(h.render(100, 30).contains(NOT_CONNECTED));
}

// Unlock starts the engine, lock stops it.
#[test]
fn lock_transitions_start_and_stop_sync() {
    let mut h = harness();
    let mut effects = Vec::new();
    h.app_mut()
        .sync_lock_transition(sverb_core::vault::LockState::Locked, &mut effects);
    assert_eq!(effects, [Effect::Sync(SyncEffect::Start)]);
    h.app_mut().vault.lock = sverb_core::vault::LockState::Locked;
    let mut effects = Vec::new();
    h.app_mut()
        .sync_lock_transition(sverb_core::vault::LockState::Unlocked, &mut effects);
    assert_eq!(effects, [Effect::Sync(SyncEffect::Stop)]);
}

// "Clock skew detected on device X": once per device per session.
#[test]
fn clock_skew_toast_once_per_device() {
    let mut h = harness();
    for device in ["ab12", "ab12", "cd34", "ab12"] {
        h.send(UiEvent::Sync(SyncEvent::ClockSkew {
            device: device.into(),
            ahead_secs: 600,
        }));
    }
    let toasts: Vec<_> = h.app().toasts().iter().map(|t| t.message.clone()).collect();
    assert_eq!(
        toasts,
        [
            "Clock skew detected on device ab12",
            "Clock skew detected on device cd34"
        ]
    );
}

// The wizard dialog: typing, submit, choices, done → relock.
#[test]
fn wizard_dialog_round_trip() {
    let mut h = harness();
    h.send(UiEvent::SyncUi(SyncUiEvent::Info(local_only())));
    let mut effects = Vec::new();
    h.app_mut()
        .open_account_wizard(WizardFlow::Login, &mut effects);
    h.send(UiEvent::SyncUi(SyncUiEvent::Wizard(WizardScreen {
        title: "Log in to a server".into(),
        prompt: Some(WizardPrompt {
            label: "Account password".into(),
            secret: true,
        }),
        ..WizardScreen::default()
    })));
    h.take_effects();
    h.keys("p w");
    let screen = h.render(100, 30);
    assert!(screen.contains("Account password: ••"), "{screen}");
    assert!(!screen.contains("pw"), "masked: {screen}");
    h.keys("enter");
    let effs = sync_effects(&mut h);
    assert!(
        matches!(&effs[..], [SyncEffect::Wizard(WizardCmd::Submit(pw))] if pw.expose() == "pw"),
        "{effs:?}"
    );
    // A choice screen.
    h.send(UiEvent::SyncUi(SyncUiEvent::Wizard(WizardScreen {
        title: "Log in to a server".into(),
        body: vec!["Your local master password will be changed.".into()],
        choices: vec![('y', "Continue".into())],
        ..WizardScreen::default()
    })));
    h.keys("y");
    assert_eq!(
        sync_effects(&mut h),
        [SyncEffect::Wizard(WizardCmd::Choice('y'))]
    );
    // Done with relock: the dialog closes and the vault locks.
    h.app_mut().vault.active = true;
    h.send(UiEvent::SyncUi(SyncUiEvent::Wizard(WizardScreen {
        title: "Log in to a server".into(),
        done: true,
        relock: true,
        ..WizardScreen::default()
    })));
    h.keys("enter");
    assert!(h.app().dialogs().is_empty());
    assert_eq!(h.app().lock_state(), sverb_core::vault::LockState::Locked);
    let effs = h.take_effects();
    assert!(
        effs.contains(&Effect::Sync(SyncEffect::Refresh)),
        "{effs:?}"
    );
    assert!(effs.contains(&Effect::Sync(SyncEffect::Stop)), "{effs:?}");

    // Esc cancels a flow.
    let mut effects = Vec::new();
    h.app_mut().vault.lock = sverb_core::vault::LockState::Unlocked;
    h.app_mut()
        .open_account_wizard(WizardFlow::Register, &mut effects);
    h.take_effects();
    h.keys("esc");
    assert!(h.app().dialogs().is_empty());
    assert_eq!(
        sync_effects(&mut h),
        [SyncEffect::Wizard(WizardCmd::Cancel)]
    );
}

// The palette's "Sync status" opens Settings → Sync; "Sync now" asks the engine.
#[test]
fn sync_actions() {
    let mut h = harness();
    h.send(UiEvent::SyncUi(SyncUiEvent::Info(synced_info())));
    h.take_effects();
    let mut effects = Vec::new();
    assert!(
        h.app_mut()
            .apply_sync_action(ActionName::SyncNow, &mut effects)
    );
    assert_eq!(effects, [Effect::Sync(SyncEffect::SyncNow)]);
    let mut effects = Vec::new();
    assert!(
        h.app_mut()
            .apply_sync_action(ActionName::SyncStatus, &mut effects)
    );
    assert_eq!(h.app().shell.section, Section::Settings);
    assert_eq!(h.app().views.settings.page, SettingsPage::Sync);
    assert!(
        !h.app_mut()
            .apply_sync_action(ActionName::Quit, &mut effects)
    );
}

// M5-01 T-08: the Team page only exists in synced mode; an invite copies the link
// and says so; the page's keys send the org requests.
#[test]
fn t08_team_page() {
    use super::sync::TeamResult;
    use super::sync_ui::TeamOp;
    use sverb_proto::orgs::{InviteCreated, MemberView, OrgView, Role};

    let mut h = harness();
    h.send(UiEvent::SyncUi(SyncUiEvent::Info(local_only())));
    assert_eq!(h.app().views.settings.pages(), [SettingsPage::Sync]);
    assert!(!h.app().action_enabled(ActionName::TeamKeys));

    h.send(UiEvent::SyncUi(SyncUiEvent::Info(synced_info())));
    h.take_effects();
    let mut effects = Vec::new();
    h.app_mut().open_sync_page(SettingsPage::Team, &mut effects);
    assert!(effects.contains(&Effect::Sync(SyncEffect::TeamPins)));
    assert!(effects.contains(&Effect::Sync(SyncEffect::Team(TeamOp::Load { org: None }))));
    // Not in an org yet.
    h.send(UiEvent::SyncUi(SyncUiEvent::Team(TeamResult::Loaded {
        orgs: vec![],
        org: None,
        members: vec![],
    })));
    assert!(h.render(100, 30).contains("You are not in any org"));

    let org_id = "0190f000-0000-7000-8000-000000000001".parse().unwrap();
    let me = "0190f000-0000-7000-8000-000000000002".parse().unwrap();
    h.send(UiEvent::SyncUi(SyncUiEvent::Team(TeamResult::Loaded {
        orgs: vec![OrgView {
            id: org_id,
            name: "Acme".into(),
            role: Role::Owner,
            created_at: None,
        }],
        org: Some(org_id.to_string()),
        members: vec![MemberView {
            user_id: me,
            email: "me@example.test".into(),
            role: Role::Owner,
        }],
    })));
    let screen = h.render(100, 30);
    assert!(
        screen.contains("Acme") && screen.contains("me@example.test"),
        "{screen}"
    );
    insta::assert_snapshot!("t08_team_page", screen);

    // `i`, an email, Enter: the invite request (Insert mode while typing).
    h.app_mut().shell.region = crate::views::Region::Main;
    h.take_effects();
    h.keys("i");
    assert_eq!(h.app().mode(), Mode::Insert);
    for c in "bob@example.test".chars() {
        h.keys(&c.to_string());
    }
    h.keys("enter");
    assert_eq!(
        sync_effects(&mut h),
        [SyncEffect::Team(TeamOp::Invite {
            org: org_id.to_string(),
            email: Some("bob@example.test".into()),
        })]
    );
    // The result: link copied, toast.
    let link = "https://sync.example.test/invite/tok".to_owned();
    h.send(UiEvent::SyncUi(SyncUiEvent::Team(TeamResult::Invited(
        InviteCreated {
            id: me,
            org_id,
            email: Some("bob@example.test".into()),
            role: Role::Member,
            expires_at: chrono::DateTime::from_timestamp(0, 0).unwrap(),
            link: Some(link.clone()),
            emailed: false,
        },
    ))));
    assert!(h.effects().contains(&Effect::CopyToClipboard(link)));
    assert!(
        h.app()
            .toasts()
            .iter()
            .any(|t| t.message.contains("link copied to the clipboard")),
        "{:?}",
        h.app().toasts()
    );
}
