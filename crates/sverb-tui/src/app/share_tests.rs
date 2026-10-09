//! Terminal sharing in the reducer: the start dialog, approvals, the viewers
//! panel and the `⚠ shared · …` badge, viewer panes from `sverb join` and the
//! palette (reducer side), and letterboxing / clipping of the host's screen
//! (drawing side).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use pretty_assertions::assert_eq;
use ratatui::{Terminal, backend::TestBackend};
use sverb_conn::SharedEmulator;
use sverb_crypto::share::{ShareKey, ShareLink};
use sverb_proto::share::ShareMode;

use super::share::{ShareEffect, ShareEvent, ViewerInfo, ViewerStatus};
use super::*;
use crate::testing::{AppHarness, buffer_to_string};
use crate::views::DialogKind;
use crate::views::share::ShareDialog;
use crate::widgets::terminal_pane::tests::new_emulator;

const LEADER: &str = "ctrl-\\";
const HOST: SessionId = SessionId(1);

fn harness() -> AppHarness {
    let mut h = AppHarness::new(Config::default());
    h.resize(80, 24);
    h.take_effects();
    h
}

fn leader(h: &mut AppHarness, key: &str) {
    h.keys(&format!("{LEADER} {key}"));
}

fn share_effects(h: &mut AppHarness) -> Vec<ShareEffect> {
    h.take_effects()
        .into_iter()
        .filter_map(|e| match e {
            Effect::Share(s) => Some(s),
            _ => None,
        })
        .collect()
}

fn top_share(h: &AppHarness) -> Option<&ShareDialog> {
    match &h.app().dialogs().last()?.kind {
        DialogKind::Share(d) => Some(d),
        _ => None,
    }
}

/// Draw with emulators for the given sessions.
fn draw(app: &App, w: u16, h: u16, emus: &[(SessionId, SharedEmulator)]) -> String {
    let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
    let source = |id: SessionId| {
        emus.iter()
            .find(|(s, _)| *s == id)
            .map(|(_, e)| Arc::clone(e))
    };
    terminal
        .draw(|f| {
            app.render_with_panes(f, &source);
        })
        .unwrap();
    buffer_to_string(terminal.backend().buffer())
}

fn link() -> String {
    ShareLink::new("sync.example.test", [7; 16], ShareKey::from_bytes([9; 32]))
        .unwrap()
        .to_sverb_link()
}

fn viewer(id: u32, name: &str) -> ViewerInfo {
    ViewerInfo {
        id,
        name: Some(name.to_owned()),
        account: None,
        ip_hint: Some("198.51.100.0/24".to_owned()),
        control: false,
    }
}

/// A host pane that is being shared (as after the start dialog and `Started`).
fn shared(h: &mut AppHarness, mode: ShareMode) {
    h.app_mut().focus_session(HOST);
    h.app_mut().set_pane_label(HOST, "web-1");
    h.app_mut().share.hosts.insert(
        HOST,
        super::share::HostShare {
            mode,
            link: None,
            expires: None,
            viewers: Vec::new(),
        },
    );
    h.send(UiEvent::Share(ShareEvent::Started {
        session: HOST,
        link: link(),
        web_link: "https://sync.example.test/s/x#k".into(),
        expires: "14:32".into(),
        mode,
    }));
}

// ------------------------------------------------------------------ host

#[test]
fn share_needs_a_server_and_a_pane() {
    let mut h = harness();
    leader(&mut h, "S");
    assert!(
        h.app()
            .toasts()
            .iter()
            .any(|t| t.message.contains("Focus a terminal pane"))
    );
    h.app_mut().focus_session(HOST);
    leader(&mut h, "S");
    // Local-only (or a build without sync): no dialog, a hint instead.
    assert!(top_share(&h).is_none());
    assert!(
        h.app()
            .toasts()
            .iter()
            .any(|t| t.message.contains("Sharing needs a sverb server"))
    );
}

#[cfg(feature = "sync")]
#[test]
fn start_dialog_chooses_mode_expiry_and_options() {
    use super::share::ShareStartOptions;
    use super::sync::SyncUiEvent;
    let mut h = harness();
    h.send(UiEvent::SyncUi(SyncUiEvent::Info(
        sverb_sync::LocalSyncInfo {
            server_url: Some("https://sync.example.test".into()),
            signed_in: true,
            ..sverb_sync::LocalSyncInfo::default()
        },
    )));
    assert!(h.app().sync_ui().connected());
    h.app_mut().focus_session(HOST);
    h.app_mut().set_pane_label(HOST, "web-1");
    h.take_effects();
    leader(&mut h, "S");
    assert!(matches!(top_share(&h), Some(ShareDialog::Start(_))));
    insta::assert_snapshot!("t11_start_dialog_80x24", h.render(80, 24));
    // Control mode, 4 h, skip approval (with its warning).
    h.keys("right down right right down down space");
    let screen = h.render(80, 24);
    assert!(screen.contains("Anyone with the link"), "{screen}");
    h.keys("enter");
    assert!(top_share(&h).is_none());
    assert_eq!(
        share_effects(&mut h),
        [ShareEffect::Start {
            session: HOST,
            options: ShareStartOptions {
                mode: ShareMode::Control,
                expiry: 3,
                require_account: false,
                skip_approval: true,
            }
        }]
    );
    // `Esc` cancels without sharing.
    h.app_mut().share.hosts.clear();
    leader(&mut h, "S");
    h.keys("esc");
    assert!(top_share(&h).is_none());
    assert!(share_effects(&mut h).is_empty());
}

// The banner on a shared pane, in both modes.
#[test]
fn t11_shared_badge() {
    for (mode, name) in [(ShareMode::View, "view"), (ShareMode::Control, "control")] {
        let mut h = harness();
        shared(&mut h, mode);
        // The link went to the clipboard and the viewers panel opened.
        assert!(
            h.effects()
                .iter()
                .any(|e| matches!(e, Effect::CopyToClipboard(l) if l.starts_with("sverb://join/")))
        );
        assert!(matches!(top_share(&h), Some(ShareDialog::Viewers(_))));
        h.keys("esc");
        assert!(top_share(&h).is_none());
        h.advance(5_000); // the toast fades
        let emu = new_emulator(78, 22, b"$ make test");
        let screen = draw(h.app(), 80, 24, &[(HOST, emu)]);
        assert!(screen.contains(&format!("⚠ shared · {name}")), "{screen}");
        insta::assert_snapshot!(format!("t11_badge_{name}_80x24"), screen);
        // Sharing ends: the badge goes.
        h.send(UiEvent::Share(ShareEvent::Ended {
            session: HOST,
            reason: "stopped by the host".into(),
        }));
        let emu = new_emulator(78, 22, b"$ make test");
        assert!(!draw(h.app(), 80, 24, &[(HOST, emu)]).contains("⚠ shared"));
    }
}

// Approval modal and the viewers panel's actions.
#[test]
fn t11_approval_and_viewers_panel() {
    let mut h = harness();
    shared(&mut h, ShareMode::Control);
    h.keys("esc");
    h.advance(5_000);
    h.take_effects();

    // A viewer asks: the approval modal.
    h.send(UiEvent::Share(ShareEvent::ApprovalNeeded {
        session: HOST,
        viewer: viewer(3, "bob"),
    }));
    assert!(matches!(top_share(&h), Some(ShareDialog::Approve(_))));
    insta::assert_snapshot!("t11_approve_80x24", h.render(80, 24));
    h.keys("a");
    assert!(top_share(&h).is_none());
    assert_eq!(
        share_effects(&mut h),
        [ShareEffect::Approve {
            session: HOST,
            viewer: 3
        }]
    );
    // Another one is denied (Esc denies too).
    h.send(UiEvent::Share(ShareEvent::ApprovalNeeded {
        session: HOST,
        viewer: viewer(4, "mallory"),
    }));
    h.keys("esc");
    assert_eq!(
        share_effects(&mut h),
        [ShareEffect::Deny {
            session: HOST,
            viewer: 4
        }]
    );
    // A viewer that leaves before the host answers takes its modal with it.
    h.send(UiEvent::Share(ShareEvent::ApprovalNeeded {
        session: HOST,
        viewer: viewer(5, "eve"),
    }));
    h.send(UiEvent::Share(ShareEvent::ViewerLeft {
        session: HOST,
        viewer: 5,
        reason: "left".into(),
    }));
    assert!(top_share(&h).is_none());

    h.send(UiEvent::Share(ShareEvent::ViewerJoined {
        session: HOST,
        viewer: viewer(3, "bob"),
    }));
    h.send(UiEvent::Share(ShareEvent::ViewerJoined {
        session: HOST,
        viewer: ViewerInfo {
            name: None,
            ip_hint: None,
            ..viewer(6, "")
        },
    }));
    h.take_effects();
    // `leader S` on the shared pane: the viewers panel.
    leader(&mut h, "S");
    assert!(matches!(top_share(&h), Some(ShareDialog::Viewers(_))));
    // Grant control to bob.
    h.keys("c");
    assert_eq!(
        share_effects(&mut h),
        [ShareEffect::SetControl {
            session: HOST,
            viewer: 3,
            granted: true
        }]
    );
    h.send(UiEvent::Share(ShareEvent::ControlChanged {
        session: HOST,
        viewer: 3,
        granted: true,
    }));
    h.advance(5_000); // the "is viewing" toasts fade
    insta::assert_snapshot!("t11_viewers_panel_80x24", h.render(80, 24));
    // Revoke.
    h.keys("c");
    assert_eq!(
        share_effects(&mut h),
        [ShareEffect::SetControl {
            session: HOST,
            viewer: 3,
            granted: false
        }]
    );
    // Copy the link, kick the anonymous viewer.
    h.keys("y down k");
    let effects = h.take_effects();
    assert!(
        effects
            .iter()
            .any(|e| matches!(e, Effect::CopyToClipboard(l) if l == &link()))
    );
    assert!(effects.contains(&Effect::Share(ShareEffect::Kick {
        session: HOST,
        viewer: 6
    })));
    h.send(UiEvent::Share(ShareEvent::ViewerLeft {
        session: HOST,
        viewer: 6,
        reason: "kicked".into(),
    }));
    let Some(ShareDialog::Viewers(p)) = top_share(&h) else {
        panic!("panel closed");
    };
    assert_eq!(p.viewers.len(), 1);
    // Stop sharing: the panel closes.
    h.keys("s");
    assert!(top_share(&h).is_none());
    assert_eq!(share_effects(&mut h), [ShareEffect::Stop { session: HOST }]);
}

#[test]
fn view_mode_panel_has_no_control_toggle() {
    let mut h = harness();
    shared(&mut h, ShareMode::View);
    h.send(UiEvent::Share(ShareEvent::ViewerJoined {
        session: HOST,
        viewer: viewer(3, "bob"),
    }));
    h.take_effects();
    h.keys("c");
    assert!(share_effects(&mut h).is_empty());
    assert!(!h.render(80, 24).contains("c control"));
}

#[test]
fn start_failure_and_wrong_key_toast() {
    let mut h = harness();
    h.app_mut().focus_session(HOST);
    h.app_mut().share.hosts.insert(
        HOST,
        super::share::HostShare {
            mode: ShareMode::View,
            link: None,
            expires: None,
            viewers: Vec::new(),
        },
    );
    h.send(UiEvent::Share(ShareEvent::StartFailed {
        session: HOST,
        error: "this device is not signed in to a server".into(),
    }));
    assert!(h.app().share_ui().hosts.is_empty());
    assert!(
        h.app()
            .toasts()
            .iter()
            .any(|t| t.level == ToastLevel::Error && t.message.contains("not signed in"))
    );
    shared(&mut h, ShareMode::View);
    h.keys("esc");
    h.send(UiEvent::Share(ShareEvent::ViewerRejected {
        session: HOST,
        viewer: 9,
    }));
    // No approval modal for a wrong key.
    assert!(top_share(&h).is_none());
    assert!(
        h.app()
            .toasts()
            .iter()
            .any(|t| t.message.contains("wrong link key"))
    );
}

// ------------------------------------------------------------------ viewer

fn joined(h: &mut AppHarness) -> SessionId {
    h.send(UiEvent::Launch(LaunchIntent::Join(link())));
    let id = h.app().focused_session().expect("a viewer pane");
    assert!(h.app().share_ui().viewers.contains_key(&id));
    id
}

// T-12 (reducer side): `sverb join <link>` opens a viewer tab and asks the service.
#[test]
fn t12_join_opens_a_viewer_tab() {
    let mut h = harness();
    let before = h.app().tabs().list.len();
    let id = joined(&mut h);
    assert_eq!(h.app().tabs().list.len(), before + 1);
    assert_eq!(
        share_effects(&mut h),
        [ShareEffect::Join { id, link: link() }]
    );
    assert_eq!(h.app().pane(id).label, "joining shared session…");
    // The link (with its key) never shows up in Debug output.
    let dbg = format!("{:?}", ShareEffect::Join { id, link: link() });
    assert!(!dbg.contains("sverb://"), "{dbg}");
    // A link that doesn't parse: a warning, no tab.
    h.send(UiEvent::Launch(LaunchIntent::Join(
        "sverb://join/nope".into(),
    )));
    assert_eq!(h.app().tabs().list.len(), before + 1);
    assert!(
        h.app()
            .toasts()
            .iter()
            .any(|t| t.message.contains("Not a usable share link"))
    );
}

#[test]
fn palette_paste_joins() {
    let mut h = harness();
    leader(&mut h, "p");
    h.send(UiEvent::Input(InputEvent::Paste(link())));
    h.keys("enter");
    let id = h.app().focused_session().unwrap();
    assert!(h.app().share_ui().viewers.contains_key(&id));
    assert!(matches!(
        share_effects(&mut h).as_slice(),
        [ShareEffect::Join { id: j, .. }] if *j == id
    ));
}

#[test]
fn viewer_pane_status_input_and_resizes() {
    let mut h = harness();
    let id = joined(&mut h);
    let status = |h: &mut AppHarness, status| {
        h.send(UiEvent::Share(ShareEvent::Viewer { id, status }));
    };
    status(
        &mut h,
        ViewerStatus::Joined {
            mode: ShareMode::Control,
        },
    );
    status(&mut h, ViewerStatus::Waiting);
    assert_eq!(
        h.app().pane(id).label,
        "shared session · waiting for host approval…"
    );
    status(
        &mut h,
        ViewerStatus::Live {
            cols: 100,
            rows: 30,
        },
    );
    assert_eq!(h.app().pane(id).label, "viewing shared session (read-only)");
    h.take_effects();

    // View only: typed keys don't leave the pane (only the leader works).
    h.keys("l s enter");
    let effects = h.take_effects();
    assert!(
        !effects
            .iter()
            .any(|e| matches!(e, Effect::SendToSession { .. } | Effect::Share(_))),
        "{effects:?}"
    );
    // Control granted: keys go to the share, encoded by the service.
    status(&mut h, ViewerStatus::Control(true));
    assert_eq!(h.app().pane(id).label, "viewing shared session (control)");
    h.take_effects();
    h.keys("x");
    assert!(matches!(
        share_effects(&mut h).as_slice(),
        [ShareEffect::Input { id: j, input: SessionInput::Key(_) }] if *j == id
    ));

    // The pane keeps the host's size: layout resizes are dropped.
    h.resize(120, 40);
    h.advance(200);
    let effects = h.take_effects();
    assert!(
        !effects
            .iter()
            .any(|e| matches!(e, Effect::ResizeSession { id: r, .. } if *r == id)),
        "{effects:?}"
    );
    // Splitting can't duplicate a viewer pane.
    leader(&mut h, "-");
    assert!(
        h.app()
            .toasts()
            .iter()
            .any(|t| t.message.contains("can't be duplicated"))
    );
    // `leader S` on a viewer pane doesn't share it.
    leader(&mut h, "S");
    assert!(top_share(&h).is_none());

    status(
        &mut h,
        ViewerStatus::Ended {
            reason: "the session ended".into(),
        },
    );
    assert_eq!(h.app().pane(id).label, "share ended (the session ended)");
}

#[test]
fn unavailable_closes_the_viewer_pane() {
    let mut h = harness();
    let id = joined(&mut h);
    h.take_effects();
    h.send(UiEvent::Share(ShareEvent::Unavailable {
        id: Some(id),
        message: "Terminal sharing is not available in this build".into(),
    }));
    assert!(h.effects().contains(&Effect::CloseSession(id)));
    assert!(!h.app().tabs().sessions.contains(&id));
    assert!(!h.app().share_ui().viewers.contains_key(&id));
}

// T-07 (drawing side): the host's screen is centered in a larger pane and clipped in
// a smaller one; nothing breaks.
#[test]
fn t07_viewer_letterbox_and_clip() {
    let mut h = harness();
    let id = joined(&mut h);
    h.send(UiEvent::Share(ShareEvent::Viewer {
        id,
        status: ViewerStatus::Live { cols: 20, rows: 4 },
    }));
    let emu = new_emulator(20, 4, b"top-left\r\n\r\n\r\nlast row   [end]");
    let big = draw(h.app(), 80, 24, &[(id, Arc::clone(&emu))]);
    insta::assert_snapshot!("t07_letterbox_80x24", big);
    // The first host row starts well inside the pane (centered), not at its edge.
    let row = big.lines().find(|l| l.contains("top-left")).unwrap();
    assert!(row.find("top-left").unwrap() > 20, "{row}");

    // A pane smaller than the host's screen clips it (top-left kept).
    let emu = new_emulator(120, 40, b"top-left corner");
    let small = draw(h.app(), 40, 12, &[(id, emu)]);
    assert!(small.contains("top-left"), "{small}");
    // Degenerate sizes don't panic.
    let emu = new_emulator(120, 40, b"x");
    for (w, hh) in [(1, 1), (3, 3), (10, 2)] {
        let _ = draw(h.app(), w, hh, &[(id, Arc::clone(&emu))]);
    }
}
