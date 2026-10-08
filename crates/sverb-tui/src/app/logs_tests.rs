//! M3-06 reducer tests: the Logs view (T-06, T-07, T-08, T-09) and its wiring.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use pretty_assertions::assert_eq;
use sverb_conn::{LocalSpec, SessionSpec, SshSpec};
use sverb_core::{
    config::Config,
    model::{ConnLog, ConnResult, ItemId, UnixMillis},
};
use sverb_term::recording::{Event, EventKind, Header, Recording};

use super::*;
use crate::{
    app::{Mode, UiEvent},
    testing::AppHarness,
    views::{DialogKind, logs::ResultFilter},
};

/// 2026-10-07 12:34 UTC.
const T0: i64 = 1_791_376_440_000;
const MIN: i64 = 60_000;

fn id(n: u8) -> ItemId {
    let mut b = [0_u8; 16];
    b[6] = 0x70;
    b[15] = n;
    ItemId::from_bytes(b)
}

fn entry(
    n: u8,
    label: &str,
    target: Option<&str>,
    started_min: i64,
    secs: Option<i64>,
    result: Option<ConnResult>,
) -> LogEntry {
    let started = T0 + started_min * MIN;
    let error_detail = match &result {
        Some(ConnResult::AuthFailed) => Some(vec![
            "Permission denied".to_owned(),
            "tried: publickey, password".to_owned(),
        ]),
        Some(ConnResult::NetworkError(m)) => Some(vec![m.clone()]),
        _ => None,
    };
    LogEntry {
        id: id(n),
        log: ConnLog {
            host_id: target.map(|_| id(100 + n)),
            started_at: UnixMillis(started),
            ended_at: secs.map(|s| UnixMillis(started + s * 1000)),
            result,
            bytes_in: u64::from(n) * 123_456,
            bytes_out: u64::from(n) * 789,
            label: label.to_owned(),
            target: target.map(str::to_owned),
            error_detail,
            ..ConnLog::default()
        },
        recording: (n % 2 == 1).then(|| PathBuf::from(format!("/tmp/rec-{n}.cast.sv"))),
    }
}

fn mixed() -> Vec<LogEntry> {
    vec![
        entry(
            1,
            "web-1",
            Some("deploy@10.0.0.5:22"),
            0,
            Some(3720),
            Some(ConnResult::Ok),
        ),
        entry(
            2,
            "db",
            Some("root@db.example:22"),
            5,
            Some(2),
            Some(ConnResult::AuthFailed),
        ),
        entry(3, "local", None, 10, Some(45), Some(ConnResult::Ok)),
        entry(
            4,
            "bastion",
            Some("bastion.example:2222"),
            15,
            Some(15),
            Some(ConnResult::NetworkError(
                "Connection refused or timed out".into(),
            )),
        ),
        entry(
            5,
            "web-2",
            Some("web-2.example:22"),
            20,
            Some(1),
            Some(ConnResult::HostKeyRejected),
        ),
        entry(6, "web-1", Some("deploy@10.0.0.5:22"), 25, None, None),
    ]
}

/// The Logs section open, with `entries` loaded and times in UTC.
fn harness(entries: Vec<LogEntry>) -> AppHarness {
    let mut h = AppHarness::new(Config::default());
    h.resize(160, 48);
    h.app_mut().open_section(Section::Logs);
    h.app_mut().views.logs.utc_offset_secs = Some(0);
    h.send(UiEvent::ConnLog(ConnLogEvent::Loaded(entries)));
    h
}

fn visible_labels(h: &AppHarness) -> Vec<String> {
    h.app()
        .logs()
        .visible()
        .iter()
        .map(|e| format!("{}#{}", e.host(), e.id.as_bytes()[15]))
        .collect()
}

/// T-06: `r` cycles all → ok → failed; `/` filters by host (fuzzy).
#[test]
fn t06_filter_by_result_and_host() {
    let mut h = harness(mixed());
    assert_eq!(
        visible_labels(&h),
        [
            "web-1#6",
            "web-2#5",
            "bastion#4",
            "local#3",
            "db#2",
            "web-1#1"
        ],
        "newest first"
    );
    h.keys("r");
    assert_eq!(h.app().logs().result_filter, ResultFilter::Ok);
    assert_eq!(visible_labels(&h), ["local#3", "web-1#1"]);
    h.keys("r");
    assert_eq!(visible_labels(&h), ["web-2#5", "bastion#4", "db#2"]);
    h.keys("r");
    assert_eq!(h.app().logs().result_filter, ResultFilter::All);

    // `/` edits the host filter in Insert mode: `q` is typed, not quit.
    h.keys("/");
    assert_eq!(h.app().mode(), Mode::Insert);
    h.keys("w b");
    assert_eq!(visible_labels(&h), ["web-1#6", "web-2#5", "web-1#1"]);
    h.keys("enter");
    assert_eq!(h.app().mode(), Mode::Normal);
    // Both filters at once.
    h.keys("r");
    assert_eq!(visible_labels(&h), ["web-1#1"]);
    h.keys("r");
    assert_eq!(visible_labels(&h), ["web-2#5"]);
    // The target matches too.
    h.keys("r / backspace backspace 1 0 . 0");
    assert_eq!(visible_labels(&h), ["web-1#6", "web-1#1"]);
    // Esc while editing clears the filter.
    h.keys("esc");
    assert_eq!(h.app().logs().host_filter, "");
    assert_eq!(visible_labels(&h).len(), 6);
    assert!(!h.effects().iter().any(|e| matches!(e, Effect::Quit { .. })));
}

/// T-07: reconnect opens a new session for the entry's host.
#[test]
fn t07_reconnect_opens_a_session() {
    let mut h = harness(mixed());
    // The newest entry (web-1, SSH).
    h.keys("enter");
    let opened: Vec<_> = h
        .effects()
        .iter()
        .filter_map(|e| match e {
            Effect::OpenSession { id, spec, .. } => Some((*id, spec.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(
        opened,
        [(
            SessionId(1),
            SessionSpec::Ssh(SshSpec {
                host: "10.0.0.5".into(),
                port: 22,
                user: Some("deploy".into()),
                ..SshSpec::default()
            })
        )]
    );
    assert_eq!(h.app().mode(), Mode::Terminal, "the new pane has focus");

    // A local entry opens a local shell.
    let mut h = harness(mixed());
    h.keys("j j j enter");
    assert_eq!(h.app().logs().selected, Some(id(3)));
    assert!(h.effects().iter().any(|e| matches!(
        e,
        Effect::OpenSession { spec: SessionSpec::Local(l), .. } if *l == LocalSpec::default()
    )));
}

#[test]
fn targets_parse() {
    assert_eq!(
        parse_target("bastion.example:2222"),
        Some(SshSpec {
            host: "bastion.example".into(),
            port: 2222,
            user: None,
            ..SshSpec::default()
        })
    );
    assert_eq!(
        parse_target("me@[::1]:2200"),
        Some(SshSpec {
            host: "::1".into(),
            port: 2200,
            user: Some("me".into()),
            ..SshSpec::default()
        })
    );
    assert_eq!(parse_target("host").map(|s| s.port), Some(22));
    assert_eq!(parse_target("@host"), None);
    assert_eq!(parse_target("h:notaport"), None);
}

/// T-08: delete asks about the recording; "also delete" passes it on.
#[test]
fn t08_delete_with_recording() {
    let mut h = harness(mixed());
    // web-1 #1 (oldest) has a recording.
    h.keys("G d");
    let Some(DialogKind::Logs(LogsDialog::Delete(d))) = h.app().dialogs().last().map(|d| &d.kind)
    else {
        panic!("no delete dialog: {:?}", h.app().dialogs());
    };
    assert_eq!(d.ids, [id(1)]);
    assert!(d.has_recording);
    assert!(h.render(160, 48).contains("y delete with its recording"));
    h.take_effects();
    h.keys("y");
    assert_eq!(
        h.effects(),
        [Effect::Logs(LogsEffect::Delete {
            ids: vec![id(1)],
            delete_recordings: true
        })]
    );
    assert!(h.app().dialogs().is_empty());
    h.send(UiEvent::ConnLog(ConnLogEvent::Removed(vec![id(1)])));
    assert!(h.app().logs().get(id(1)).is_none());

    // `k` keeps the recording (web-2 #5 has one); `n` cancels.
    h.keys("g j d");
    h.take_effects();
    h.keys("k");
    assert_eq!(
        h.effects(),
        [Effect::Logs(LogsEffect::Delete {
            ids: vec![id(5)],
            delete_recordings: false
        })]
    );
    h.keys("d");
    h.take_effects();
    h.keys("n");
    assert!(h.effects().is_empty());
    assert!(h.app().dialogs().is_empty());
}

#[test]
fn clear_older_asks_for_days() {
    let mut h = harness(mixed());
    h.keys("D");
    let Some(DialogKind::Logs(LogsDialog::Clear(c))) = h.app().dialogs().last().map(|d| &d.kind)
    else {
        panic!("no clear dialog");
    };
    assert_eq!(c.days, "90", "logs.retention_days");
    h.take_effects();
    h.keys("backspace backspace 7 tab enter");
    assert_eq!(
        h.effects(),
        [Effect::Logs(LogsEffect::ClearOlderThan {
            days: 7,
            delete_recordings: true
        })]
    );
}

/// T-09: the Logs view at 160×48 with mixed results.
#[test]
fn t09_snapshot_160x48() {
    let mut h = harness(mixed());
    h.keys("j");
    insta::assert_snapshot!("t09_logs_160x48", h.render(160, 48));
}

#[test]
fn details_export_and_replay() {
    let mut h = harness(mixed());
    // db: auth failure with a detail chain.
    h.keys("j j j j i");
    let screen = h.render(160, 48);
    assert!(screen.contains("Permission denied"), "{screen}");
    assert!(
        screen.contains("caused by: tried: publickey, password"),
        "{screen}"
    );
    h.keys("esc");
    assert!(h.app().dialogs().is_empty());

    // No recording: export and replay say so.
    h.take_effects();
    h.keys("p");
    assert!(
        h.app()
            .toasts()
            .iter()
            .any(|t| t.message.contains("no recording"))
    );
    assert!(!h.effects().iter().any(|e| matches!(e, Effect::Logs(_))));

    // web-2 #5 has one: export asks for a path, replay asks the service.
    h.keys("k k k e");
    let Some(DialogKind::Logs(LogsDialog::Export(x))) = h.app().dialogs().last().map(|d| &d.kind)
    else {
        panic!("no export dialog");
    };
    assert_eq!(x.path, "sverb-web-2-20261007-125400.cast");
    h.take_effects();
    h.keys("enter");
    assert_eq!(
        h.effects(),
        [Effect::Logs(LogsEffect::Export {
            src: PathBuf::from("/tmp/rec-5.cast.sv"),
            dst: "sverb-web-2-20261007-125400.cast".into()
        })]
    );
    h.take_effects();
    h.keys("p");
    assert_eq!(
        h.effects(),
        [Effect::Logs(LogsEffect::OpenReplay {
            id: id(5),
            path: PathBuf::from("/tmp/rec-5.cast.sv"),
            label: "web-2".into()
        })]
    );

    // The decrypted recording opens the player, which ticks on timers.
    let recording = Recording {
        header: Header::new(40, 5),
        events: vec![
            Event::new(std::time::Duration::ZERO, EventKind::Output, "hello"),
            Event::new(
                std::time::Duration::from_secs(1),
                EventKind::Output,
                " world",
            ),
        ],
        incomplete: false,
    };
    h.send(UiEvent::ConnLog(ConnLogEvent::Replay {
        id: id(5),
        label: "web-2".into(),
        recording: Box::new(recording),
    }));
    assert!(matches!(
        h.app().dialogs().last().map(|d| &d.kind),
        Some(DialogKind::Logs(LogsDialog::Replay(_)))
    ));
    h.advance(10);
    assert!(h.render(160, 48).contains("hello"));
    assert!(!h.render(160, 48).contains("hello world"));
    h.advance(1500);
    assert!(h.render(160, 48).contains("hello world"));
    // `q` closes the player (not the app).
    h.take_effects();
    h.keys("q");
    assert!(h.app().dialogs().is_empty());
    assert!(!h.effects().iter().any(|e| matches!(e, Effect::Quit { .. })));
}

/// The banner's `leader i` (M1-16) lands on the session's entry.
#[test]
fn show_conn_log_selects_the_sessions_entry() {
    let mut h = AppHarness::new(Config::default());
    let session = SessionId(9);
    h.app_mut().focus_session(session);
    h.send(UiEvent::ConnLog(ConnLogEvent::Started {
        session,
        id: id(2),
    }));
    h.app_mut().views.logs.result_filter = ResultFilter::Ok;
    assert!(h.app_mut().show_conn_log(session));
    assert_eq!(h.app().shell().section, Section::Logs);
    assert_eq!(h.app().mode(), Mode::Normal);
    // The list arrives later: the entry is selected and the filter that hid it is reset.
    h.send(UiEvent::ConnLog(ConnLogEvent::Loaded(mixed())));
    assert_eq!(h.app().logs().selected, Some(id(2)));
    assert_eq!(h.app().logs().result_filter, ResultFilter::All);
    assert!(!h.app_mut().show_conn_log(SessionId(77)));
}

/// Unlock runs maintenance (and arms the daily timer); lock drops the list.
#[test]
fn unlock_maintains_and_lock_forgets() {
    let mut config = Config::default();
    config.logs.sync = true;
    config.recording.retention_days = 30;
    config.general.auto_lock_minutes = 0;
    let mut h = AppHarness::new(config);
    h.app_mut().vault.active = true;
    h.app_mut().vault.lock = LockState::Locked;
    // Locked: the list is ignored.
    h.send(UiEvent::ConnLog(ConnLogEvent::Loaded(mixed())));
    assert!(!h.app().logs().loaded);
    h.send(UiEvent::Vault(crate::app::VaultEvent::Unlocked {
        via_keyring: false,
        note: None,
    }));
    let fx = h.take_effects();
    assert!(fx.contains(&Effect::Logs(LogsEffect::SetSync(true))));
    assert!(fx.contains(&Effect::Logs(LogsEffect::Maintain {
        logs_retention_days: 90,
        recording_retention_days: 30
    })));
    assert!(fx.contains(&Effect::ScheduleTimer {
        kind: TimerKind::LogsMaintenance,
        after: MAINTENANCE_EVERY
    }));
    h.send(UiEvent::ConnLog(ConnLogEvent::Loaded(mixed())));
    assert_eq!(h.app().logs().entries.len(), 6);
    // A day later it runs again.
    h.advance(MAINTENANCE_EVERY.as_millis().try_into().unwrap());
    assert!(
        h.effects()
            .iter()
            .any(|e| matches!(e, Effect::Logs(LogsEffect::Maintain { .. })))
    );
    h.send(UiEvent::Vault(crate::app::VaultEvent::LockRequested));
    assert!(h.app().logs().entries.is_empty());
    assert!(!h.app().logs().loaded);
}
