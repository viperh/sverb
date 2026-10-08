//! M1-16 reducer and rendering tests (T-03, T-04, T-08 reducer variant, T-09).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{buffer::Buffer, layout::Rect};
use sverb_conn::session::actor::backoff::MAX_ATTEMPTS;
use sverb_conn::{DisconnectReason, SessionEvent, SessionState, SshSessionInfo};
use sverb_core::error_report::ErrorReport;
use sverb_term::ColorDepth;

use super::DISCONNECTED_HINT;
use crate::app::{
    App, Config, Effect, Focus, InputEvent, Mode, SessionId, TimerFired, TimerKind, UiEvent,
};
use crate::theme::Theme;
use crate::views::{DialogId, DialogKind};
use crate::widgets::terminal_pane::{PaneInfo, PaneOverlay, TerminalPane, tests::new_emulator};

/// A timestamp for state events (the reducer never reads the clock itself).
fn at() -> std::time::Instant {
    use std::time::Instant as Clock;
    Clock::now()
}

const ID: SessionId = SessionId(7);

fn app(auto: bool) -> App {
    let mut config = Config::default();
    config.ssh.auto_reconnect = auto;
    let mut app = App::new(Arc::new(config));
    app.handle(UiEvent::Input(InputEvent::Resize {
        cols: 100,
        rows: 30,
    }));
    app.focus_session(ID);
    app.set_pane_label(ID, "web-1");
    // An SSH session that connected.
    app.handle(UiEvent::Session(
        ID,
        SessionEvent::SshInfo(SshSessionInfo::default()),
    ));
    state(&mut app, SessionState::Connected { since: at() });
    assert_eq!(app.mode(), Mode::Terminal);
    app
}

fn state(app: &mut App, s: SessionState) -> Vec<Effect> {
    app.handle(UiEvent::Session(ID, SessionEvent::State(s)))
}

fn drop_with(app: &mut App, reason: DisconnectReason) -> Vec<Effect> {
    state(app, SessionState::Disconnected { reason, at: at() })
}

fn press(app: &mut App, code: KeyCode) -> Vec<Effect> {
    app.handle(UiEvent::Input(InputEvent::Key(KeyEvent::new(
        code,
        KeyModifiers::NONE,
    ))))
}

fn leader(app: &mut App, key: char) -> Vec<Effect> {
    let l = app.keymap().leader().to_key_event();
    let mut effects = app.handle(UiEvent::Input(InputEvent::Key(l)));
    effects.extend(press(app, KeyCode::Char(key)));
    effects
}

fn tick(app: &mut App, id: DialogId) -> Vec<Effect> {
    app.handle(UiEvent::Timer(TimerFired {
        kind: TimerKind::DialogTick(id),
        at: at(),
    }))
}

/// The countdown's pending tick: (timer id, delay ms).
fn scheduled_tick(effects: &[Effect]) -> Option<(DialogId, u128)> {
    effects.iter().find_map(|e| match e {
        Effect::ScheduleTimer {
            kind: TimerKind::DialogTick(id),
            after,
        } => Some((*id, after.as_millis())),
        _ => None,
    })
}

/// Tick the countdown to its end; returns every effect on the way.
fn run_countdown(app: &mut App, first: &[Effect]) -> Vec<Effect> {
    let mut all = Vec::new();
    let mut next = scheduled_tick(first);
    let mut guard = 0;
    while let Some((id, _)) = next {
        let effects = tick(app, id);
        next = scheduled_tick(&effects);
        all.extend(effects);
        guard += 1;
        assert!(guard < 100, "countdown never ends");
    }
    all
}

fn leaks(effects: &[Effect]) -> bool {
    effects.iter().any(|e| {
        matches!(
            e,
            Effect::SendToSession { .. } | Effect::CloseSession(_) | Effect::ReconnectSession(_)
        )
    })
}

// T-03: banner keys.
#[test]
fn t03_banner_keys() {
    let mut app = app(false);
    app.handle(UiEvent::Session(
        ID,
        SessionEvent::Error(ErrorReport {
            short: "Connection lost (no response for 30 s)".into(),
            chain: vec!["keepalive timeout".into()],
        }),
    ));
    let effects = drop_with(&mut app, DisconnectReason::Timeout);
    assert!(scheduled_tick(&effects).is_none(), "auto-reconnect is off");
    assert_eq!(
        app.pane(ID).overlay,
        PaneOverlay::Disconnected {
            reason: DisconnectReason::Timeout.message(),
            gave_up: None,
        }
    );
    assert_eq!(
        app.mode(),
        Mode::Normal,
        "a dead pane takes no terminal input"
    );

    // Plain letters (K-06): swallowed, with a hint.
    for c in ['c', 'd', 'r', 'l', 'x', 'q'] {
        let effects = press(&mut app, KeyCode::Char(c));
        assert!(!leaks(&effects), "{c}: {effects:?}");
        assert!(
            !effects.iter().any(|e| matches!(e, Effect::Quit { .. })),
            "{c}"
        );
    }
    assert!(app.toasts().iter().any(|t| t.message == DISCONNECTED_HINT));
    assert!(app.tabs().sessions.contains(&ID));

    // `leader i`: the error chain.
    leader(&mut app, 'i');
    let shown = app.dialogs().iter().any(|d| {
        matches!(&d.kind, DialogKind::Modal(m)
            if m.modal.body.contains("keepalive timeout") && m.modal.body.contains("web-1"))
    });
    assert!(shown, "{:?}", app.dialogs());
    press(&mut app, KeyCode::Esc);
    while !app.dialogs().is_empty() {
        press(&mut app, KeyCode::Esc);
    }
    app.focus_session(ID);

    // `Enter`: reconnect; nothing reaches the session until it is connected.
    let effects = press(&mut app, KeyCode::Enter);
    assert!(
        effects.contains(&Effect::ReconnectSession(ID)),
        "{effects:?}"
    );
    assert!(matches!(
        app.pane(ID).overlay,
        PaneOverlay::Connecting { .. }
    ));
    let effects = press(&mut app, KeyCode::Char('l'));
    assert!(!leaks(&effects), "{effects:?}");
    state(&mut app, SessionState::Resolving);
    state(&mut app, SessionState::Connected { since: at() });
    assert_eq!(app.pane(ID).overlay, PaneOverlay::None);
    assert_eq!(app.mode(), Mode::Terminal);
    let effects = press(&mut app, KeyCode::Char('l'));
    assert!(
        effects
            .iter()
            .any(|e| matches!(e, Effect::SendToSession { id, .. } if *id == ID))
    );

    // `leader x`: close.
    drop_with(&mut app, DisconnectReason::Closed);
    let effects = leader(&mut app, 'x');
    assert!(effects.contains(&Effect::CloseSession(ID)), "{effects:?}");
    assert!(!app.tabs().sessions.contains(&ID));
    assert_eq!(app.focus, Focus::Hosts);
}

// An SSH exit is the calmer footer, and `Enter` reconnects.
#[test]
fn ssh_exit_shows_the_footer_and_enter_reconnects() {
    let mut app = app(true);
    let effects = drop_with(&mut app, DisconnectReason::Exited(3));
    assert!(
        scheduled_tick(&effects).is_none(),
        "no auto-reconnect after an exit"
    );
    assert_eq!(
        app.pane(ID).overlay,
        PaneOverlay::Exited {
            code: Some(3),
            remote: true
        }
    );
    for c in ['x', 'r', 'c'] {
        assert!(!leaks(&press(&mut app, KeyCode::Char(c))), "{c}");
    }
    let effects = press(&mut app, KeyCode::Enter);
    assert!(effects.contains(&Effect::ReconnectSession(ID)));
    assert!(!leaks(&press(&mut app, KeyCode::Char('a'))));
    state(&mut app, SessionState::Connected { since: at() });
    assert_eq!(app.mode(), Mode::Terminal);
}

// T-02 (UI side): no countdown after HostKey or Auth, even with auto-reconnect on.
#[test]
fn no_countdown_for_hostkey_or_auth() {
    for reason in [DisconnectReason::HostKey, DisconnectReason::Auth] {
        let mut app = app(true);
        let effects = drop_with(&mut app, reason);
        assert!(scheduled_tick(&effects).is_none(), "{reason:?}");
        assert!(matches!(
            app.pane(ID).overlay,
            PaneOverlay::Disconnected { gave_up: None, .. }
        ));
    }
}

// Auto-reconnect: a countdown, then `ReconnectSession`; success resets it.
#[test]
fn auto_reconnect_counts_down_then_reconnects() {
    let mut app = app(true);
    let effects = drop_with(&mut app, DisconnectReason::Timeout);
    let (_, first_ms) = scheduled_tick(&effects).expect("countdown");
    assert!(first_ms <= 1000);
    let PaneOverlay::Reconnecting {
        in_secs,
        attempt,
        of,
    } = app.pane(ID).overlay
    else {
        panic!("{:?}", app.pane(ID).overlay)
    };
    // The first delay is 1 s ±20% jitter (0.8–1.2 s), shown rounded up: 1 or 2 s.
    assert!((1..=2).contains(&in_secs), "in_secs = {in_secs}");
    assert_eq!((attempt, of), (1, MAX_ATTEMPTS));
    assert_eq!(app.mode(), Mode::Normal);
    let effects = run_countdown(&mut app, &effects);
    assert!(
        effects.contains(&Effect::ReconnectSession(ID)),
        "{effects:?}"
    );
    state(&mut app, SessionState::Resolving);
    state(&mut app, SessionState::Connected { since: at() });
    assert_eq!(app.pane(ID).overlay, PaneOverlay::None);
    assert_eq!(app.pane(ID).reconnect.attempt, 0);
}

// A host's `auto_reconnect` can't be checked without a catalog here; the global key
// decides for unsaved targets, and a local pane never auto-reconnects.
#[test]
fn local_panes_never_auto_reconnect() {
    let mut config = Config::default();
    config.ssh.auto_reconnect = true;
    let mut app = App::new(Arc::new(config));
    app.focus_session(ID);
    state(&mut app, SessionState::Connected { since: at() });
    let effects = drop_with(&mut app, DisconnectReason::Connect);
    assert!(scheduled_tick(&effects).is_none());
    assert!(matches!(
        app.pane(ID).overlay,
        PaneOverlay::Disconnected { .. }
    ));
}

// T-08 (reducer, virtual time): ten failed attempts, then "gave up after 10 attempts".
#[test]
fn t08_gives_up_after_ten_attempts() {
    let mut app = app(true);
    let mut effects = drop_with(&mut app, DisconnectReason::Timeout);
    let mut reconnects = 0;
    let mut total_ms: u128 = 0;
    while let Some((_, first)) = scheduled_tick(&effects) {
        total_ms += first;
        let ticks = run_countdown(&mut app, &effects);
        total_ms += ticks
            .iter()
            .filter_map(|e| match e {
                Effect::ScheduleTimer {
                    kind: TimerKind::DialogTick(_),
                    after,
                } => Some(after.as_millis()),
                _ => None,
            })
            .sum::<u128>();
        assert!(ticks.contains(&Effect::ReconnectSession(ID)));
        reconnects += 1;
        // The attempt fails again (the container stays down).
        state(&mut app, SessionState::Resolving);
        effects = drop_with(&mut app, DisconnectReason::Connect);
    }
    assert_eq!(reconnects, MAX_ATTEMPTS);
    // 1+2+4+8+16+30·5 = 181 s, ±20%.
    assert!(
        (144_800..=217_200).contains(&total_ms),
        "total backoff {total_ms} ms"
    );
    assert_eq!(
        app.pane(ID).overlay,
        PaneOverlay::Disconnected {
            reason: DisconnectReason::Connect.message(),
            gave_up: Some(MAX_ATTEMPTS),
        }
    );
    let text = render_text(&app.pane(ID), 80, 24);
    assert!(text.contains("gave up after 10 attempts"), "{text}");
    // Enter still reconnects by hand.
    let effects = press(&mut app, KeyCode::Enter);
    assert!(effects.contains(&Effect::ReconnectSession(ID)));
}

// T-09: `Esc` cancels the countdown; a plain `c` does nothing; `Enter` is "now".
#[test]
fn t09_cancel_countdown() {
    let mut app = app(true);
    let effects = drop_with(&mut app, DisconnectReason::Timeout);
    let (tick_id, _) = scheduled_tick(&effects).unwrap();

    let effects = press(&mut app, KeyCode::Char('c'));
    assert!(!leaks(&effects), "{effects:?}");
    assert!(matches!(
        app.pane(ID).overlay,
        PaneOverlay::Reconnecting { .. }
    ));

    let effects = press(&mut app, KeyCode::Esc);
    assert!(
        effects.contains(&Effect::CancelTimer(TimerKind::DialogTick(tick_id))),
        "{effects:?}"
    );
    assert!(matches!(
        app.pane(ID).overlay,
        PaneOverlay::Disconnected { gave_up: None, .. }
    ));
    // A stale tick does nothing.
    let effects = tick(&mut app, tick_id);
    assert!(!leaks(&effects), "{effects:?}");
    assert!(scheduled_tick(&effects).is_none());

    // `Enter` now (from a fresh countdown).
    let mut app = self::app(true);
    drop_with(&mut app, DisconnectReason::Closed);
    let effects = press(&mut app, KeyCode::Enter);
    assert!(effects.contains(&Effect::ReconnectSession(ID)));
    assert!(
        effects
            .iter()
            .any(|e| matches!(e, Effect::CancelTimer(TimerKind::DialogTick(_))))
    );
    // `leader x` during a countdown closes; a late tick reconnects nothing.
    state(&mut app, SessionState::Resolving);
    let effects = drop_with(&mut app, DisconnectReason::Closed);
    let (tick_id, _) = scheduled_tick(&effects).unwrap();
    let effects = leader(&mut app, 'x');
    assert!(effects.contains(&Effect::CloseSession(ID)), "{effects:?}");
    state(&mut app, SessionState::Closed);
    for _ in 0..5 {
        let effects = tick(&mut app, tick_id);
        assert!(!leaks(&effects), "{effects:?}");
    }
}

// ------------------------------------------------------------------- T-04

fn render(info: &PaneInfo, w: u16, h: u16) -> Buffer {
    let theme = Theme::default();
    let emu = new_emulator(
        w - 2,
        h - 2,
        b"$ tail -f /var/log/syslog\r\nOct  8 10:00:01 web-1 CRON[42]: job ran\r\n",
    );
    let area = Rect::new(0, 0, w, h);
    let mut buf = Buffer::empty(area);
    TerminalPane {
        info,
        theme: &theme,
        focused: true,
        scheme: None,
        depth: ColorDepth::TrueColor,
        use_osc_title: false,
        leader: "^g".to_owned(),
    }
    .render(area, &mut buf, Some(&emu));
    buf
}

fn render_text(info: &PaneInfo, w: u16, h: u16) -> String {
    let buf = render(info, w, h);
    let mut s = String::new();
    for y in 0..h {
        for x in 0..w {
            s.push_str(buf[(x, y)].symbol());
        }
        s.push('\n');
    }
    s
}

fn pane(overlay: PaneOverlay) -> PaneInfo {
    PaneInfo {
        label: "web-1".to_owned(),
        overlay,
        ..PaneInfo::default()
    }
}

// T-04: the banner for a keepalive timeout at 80×24 (content stays visible above it).
#[test]
fn t04_banner_timeout_80x24() {
    let text = render_text(
        &pane(PaneOverlay::Disconnected {
            reason: DisconnectReason::Timeout.message(),
            gave_up: None,
        }),
        80,
        24,
    );
    assert!(text.contains("CRON[42]"), "content visible");
    insta::assert_snapshot!("t04_banner_timeout_80x24", text);
}

// T-04: the countdown banner at 80×24.
#[test]
fn t04_countdown_80x24() {
    let text = render_text(
        &pane(PaneOverlay::Reconnecting {
            in_secs: 4,
            attempt: 3,
            of: MAX_ATTEMPTS,
        }),
        80,
        24,
    );
    assert!(text.contains("Reconnecting in 4 s (attempt 3/10)"));
    insta::assert_snapshot!("t04_countdown_80x24", text);
}

// T-04: the Exited footer (SSH and local) at 80×24.
#[test]
fn t04_exited_footer_80x24() {
    let text = render_text(
        &pane(PaneOverlay::Exited {
            code: Some(0),
            remote: true,
        }),
        80,
        24,
    );
    assert!(text.contains("Session ended (exit 0) — [Enter] reconnect · ^g x close"));
    assert!(!text.contains("Disconnected"), "no banner for an exit");
    insta::assert_snapshot!("t04_exited_footer_80x24", text);
    let local = render_text(
        &pane(PaneOverlay::Exited {
            code: Some(130),
            remote: false,
        }),
        80,
        24,
    );
    assert!(local.contains("Process exited (code 130) — [Enter] restart · ^g x close"));
}

// M2-05
/// A jump chain's `Connecting { hop, of }` shows per-hop progress in the pane (names
/// come from the catalog; without one, the hop numbers) and clears once connected. A
/// single-hop connection shows nothing new.
#[test]
fn m2_05_jump_progress_overlay() {
    let mut app = app(false);
    drop_with(&mut app, DisconnectReason::Connect);
    state(&mut app, SessionState::Resolving);
    state(&mut app, SessionState::Connecting { hop: 1, of: 2 });
    assert_eq!(
        app.pane(ID).overlay,
        PaneOverlay::Connecting {
            frame: 0,
            detail: "connecting (hop 1/2)".into()
        }
    );
    state(&mut app, SessionState::Connecting { hop: 2, of: 2 });
    assert!(matches!(
        &app.pane(ID).overlay,
        PaneOverlay::Connecting { detail, .. } if detail == "connecting (hop 2/2)"
    ));
    state(&mut app, SessionState::Connected { since: at() });
    assert_eq!(app.pane(ID).overlay, PaneOverlay::None);
}
