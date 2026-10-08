//! M2-10 tests: classification (T-01), hashing (T-02), group provenance (T-08),
//! remote change (T-05, unit level), session denial (T-10, unit level) and the
//! values typed in a save (T-03, unit level).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use super::*;
use crate::model::{DeviceId, HlcClock, HostDefaults, VaultId};
use crate::resolve::{GlobalDefaults, LookupTable, Settings, Target, resolve_settings};

fn id(b: u8) -> ItemId {
    ItemId::from_bytes([b; 16])
}

const HOST: u8 = 1;
const GROUP: u8 = 2;
const DEFAULTS: u8 = 3;

fn host_items(forwards: &[(ItemId, PortForward)]) -> HostItems<'_> {
    HostItems {
        host_id: Some(id(HOST)),
        vault_defaults: Some(id(DEFAULTS)),
        forwards,
    }
}

/// Resolve `host` (in group `GROUP` with `group` defaults; vault defaults `vault`).
fn resolve_with(host: &Host, group: HostDefaults, vault: Option<HostDefaults>) -> ResolvedHost {
    let mut table = LookupTable::default();
    let v = VaultId::from_bytes([9; 16]);
    table.insert_group(
        id(GROUP),
        v,
        &Group {
            name: "prod".into(),
            defaults: group,
            ..Group::default()
        },
    );
    table.mark_live(id(GROUP));
    let vault = vault.map(|d| Settings::from_defaults(&d));
    let target = Target {
        group_id: Some(id(GROUP)),
        ..Target::of(host)
    };
    resolve_settings(
        &target,
        &Settings::from_host(host),
        &table,
        vault.as_ref(),
        &GlobalDefaults::default(),
    )
}

fn rule(kind: ForwardKind, bind: &str, dest: Option<&str>) -> PortForward {
    PortForward {
        label: "r".into(),
        kind,
        host_id: id(HOST),
        bind_addr: bind.into(),
        bind_port: 8080,
        dest_host: dest.map(Into::into),
        dest_port: dest.map(|_| 5432),
        auto_start: false,
        read_only: false,
    }
}

fn with_proxy(proxy: Proxy) -> Host {
    Host {
        address: "db.example".into(),
        proxy: Some(proxy),
        ..Host::default()
    }
}

fn agent(source: AgentSource) -> Host {
    Host {
        address: "db.example".into(),
        agent_forwarding: Some(true),
        agent_source: Some(source),
        ..Host::default()
    }
}

// T-01
#[test]
fn t01_classification() {
    let none = HostItems::default();
    let r = |h: &Host| resolve_with(h, HostDefaults::default(), None);
    // ProxyCommand → needs; SOCKS → no.
    let cmd = r(&with_proxy(Proxy::Command("ssh -W %h:%p bastion".into())));
    let acts = local_actions(&cmd, &host_items(&[]));
    assert_eq!(
        acts,
        [LocalAction::new(
            id(HOST),
            ActionKind::ProxyCommand,
            "ssh -W %h:%p bastion"
        )]
    );
    let socks = r(&with_proxy(Proxy::Socks5 {
        addr: "proxy:1080".into(),
        auth: None,
    }));
    assert!(local_actions(&socks, &host_items(&[])).is_empty());

    // Forwards.
    let cases: [(ForwardKind, &str, Option<&str>, Option<&str>); 7] = [
        (ForwardKind::Remote, "*", Some("127.0.0.1"), None),
        (
            ForwardKind::Remote,
            "*",
            Some("10.0.0.5"),
            Some("10.0.0.5:5432"),
        ),
        (
            ForwardKind::Local,
            "0.0.0.0",
            Some("db"),
            Some("0.0.0.0:8080"),
        ),
        (ForwardKind::Local, "127.0.0.2", Some("db"), None),
        (ForwardKind::Local, "::1", Some("db"), None),
        (
            ForwardKind::Dynamic,
            "fe80::1",
            None,
            Some("[fe80::1]:8080"),
        ),
        (ForwardKind::Local, "localhost", Some("db"), None),
    ];
    for (kind, bind, dest, expected) in cases {
        let got = forward_actions(id(7), &rule(kind, bind, dest));
        assert_eq!(
            got.first().map(|a| a.value.as_str()),
            expected,
            "{kind:?} {bind} {dest:?}"
        );
    }
    assert_eq!(
        forward_actions(id(7), &rule(ForwardKind::Remote, "*", Some("10.0.0.5")))[0].kind,
        ActionKind::ForwardDest
    );

    // Agent forwarding: builtin → no, system / both → needs.
    for (source, needs) in [
        (AgentSource::Builtin, false),
        (AgentSource::System, true),
        (AgentSource::Both, true),
    ] {
        let acts = local_actions(&r(&agent(source)), &host_items(&[]));
        assert_eq!(!acts.is_empty(), needs, "{source:?}");
        if needs {
            assert_eq!(acts[0].field(), AGENT_FIELD);
            assert_eq!(acts[0].value, source.as_wire());
        }
    }
    // Forwarding off with a system source: nothing acts.
    let mut off = agent(AgentSource::System);
    off.agent_forwarding = Some(false);
    assert!(local_actions(&r(&off), &host_items(&[])).is_empty());
    // An unsaved host (no item): nothing to key, nothing stored.
    assert!(local_actions(&cmd, &none).is_empty());
}

// T-02
#[test]
fn t02_changed_value_hash() {
    let a = LocalAction::new(id(1), ActionKind::ProxyCommand, "nc %h %p");
    let mut rows = HashMap::new();
    assert_eq!(status_of(&a, &rows), ApprovalStatus::NeedsApproval);
    rows.insert((id(1), PROXY_COMMAND_FIELD.to_owned()), a.hash());
    assert_eq!(status_of(&a, &rows), ApprovalStatus::Approved);
    let changed = LocalAction::new(id(1), ActionKind::ProxyCommand, "nc evil %p");
    assert_eq!(
        status_of(&changed, &rows),
        ApprovalStatus::ChangedSinceApproval
    );
    assert_eq!(
        ApprovalStatus::ChangedSinceApproval.to_string(),
        "changed since approval"
    );
    assert_eq!(value_sha256("x"), value_sha256("x"));
    assert_ne!(value_sha256("x"), value_sha256("x "));
}

// T-08
#[test]
fn t08_group_proxy_keyed_by_group() {
    let host = Host {
        address: "db.example".into(),
        ..Host::default()
    };
    let resolved = resolve_with(
        &host,
        HostDefaults {
            proxy: Some(Proxy::Command("ssh -W %h:%p bastion".into())),
            ..HostDefaults::default()
        },
        None,
    );
    let acts = local_actions(&resolved, &host_items(&[]));
    assert_eq!(acts.len(), 1);
    assert_eq!(acts[0].item_id, id(GROUP));
    // An approval of the host item does not cover it; one of the group does.
    let mut rows = HashMap::new();
    rows.insert((id(HOST), PROXY_COMMAND_FIELD.to_owned()), acts[0].hash());
    assert_eq!(
        requires_approval(&resolved, &host_items(&[]), &rows).len(),
        1
    );
    rows.insert((id(GROUP), PROXY_COMMAND_FIELD.to_owned()), acts[0].hash());
    assert!(requires_approval(&resolved, &host_items(&[]), &rows).is_empty());

    // Vault defaults: keyed by the vault-defaults group item.
    let resolved = resolve_with(
        &host,
        HostDefaults::default(),
        Some(HostDefaults {
            proxy: Some(Proxy::Command("corkscrew p 8080 %h %p".into())),
            ..HostDefaults::default()
        }),
    );
    assert_eq!(
        local_actions(&resolved, &host_items(&[]))[0].item_id,
        id(DEFAULTS)
    );
}

#[test]
fn agent_keys_source_and_forwarding_items() {
    // Forwarding enabled by the group, source set on the host: both items.
    let host = Host {
        address: "db.example".into(),
        agent_source: Some(AgentSource::System),
        ..Host::default()
    };
    let resolved = resolve_with(
        &host,
        HostDefaults {
            agent_forwarding: Some(true),
            ..HostDefaults::default()
        },
        None,
    );
    let items: Vec<_> = local_actions(&resolved, &host_items(&[]))
        .into_iter()
        .map(|a| a.item_id)
        .collect();
    assert_eq!(items, [id(HOST), id(GROUP)]);
}

#[test]
fn forwards_are_included() {
    let fw = [(id(20), rule(ForwardKind::Local, "0.0.0.0", Some("db")))];
    let resolved = resolve_with(
        &Host {
            address: "x".into(),
            ..Host::default()
        },
        HostDefaults::default(),
        None,
    );
    let pending = requires_approval(&resolved, &host_items(&fw), &HashMap::new());
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].action.item_id, id(20));
    assert_eq!(pending[0].status, ApprovalStatus::NeedsApproval);
}

// T-05 (unit): approved, then changed remotely → asked again.
#[test]
fn t05_remote_change_asks_again() {
    let approvals = DeviceApprovals::new();
    let a = LocalAction::new(id(1), ActionKind::ProxyCommand, "nc %h %p");
    assert_eq!(
        approvals.decide_action(&a),
        Decision::Ask(ApprovalStatus::NeedsApproval)
    );
    approvals.approve_action(&a);
    assert_eq!(approvals.decide_action(&a), Decision::Allow);
    let changed = LocalAction::new(id(1), ActionKind::ProxyCommand, "nc evil %p");
    assert_eq!(
        approvals.decide_action(&changed),
        Decision::Ask(ApprovalStatus::ChangedSinceApproval)
    );
}

#[derive(Debug, Default)]
struct RecordingSink(parking_lot::Mutex<Vec<(ItemId, String, Option<ValueHash>)>>);

impl ApprovalSink for RecordingSink {
    fn approved(&self, item: ItemId, field: &str, hash: ValueHash) {
        self.0.lock().push((item, field.to_owned(), Some(hash)));
    }
    fn revoked(&self, item: ItemId, field: &str) {
        self.0.lock().push((item, field.to_owned(), None));
    }
}

// T-10 (unit): deny → blocked for the session, asked again after a restart.
#[test]
fn t10_deny_is_session_only() {
    let sink = Arc::new(RecordingSink::default());
    let session = DeviceApprovals::with_sink(sink.clone());
    let a = LocalAction::new(id(1), ActionKind::SystemAgent, "system");
    session.deny_action(&a);
    assert_eq!(session.decide_action(&a), Decision::Blocked);
    assert!(sink.0.lock().is_empty(), "a denial is never persisted");
    // A new process loads the same (empty) rows: asks again.
    let restarted = DeviceApprovals::with_sink(sink.clone());
    restarted.load(session.rows());
    assert_eq!(
        restarted.decide_action(&a),
        Decision::Ask(ApprovalStatus::NeedsApproval)
    );
    // Approving clears the denial and persists.
    session.approve_action(&a);
    assert_eq!(session.decide_action(&a), Decision::Allow);
    assert_eq!(
        sink.0.lock().as_slice(),
        [(id(1), AGENT_FIELD.to_owned(), Some(a.hash()))]
    );
    session.revoke(id(1), AGENT_FIELD);
    assert_eq!(
        session.decide_action(&a),
        Decision::Ask(ApprovalStatus::NeedsApproval)
    );
    assert_eq!(sink.0.lock().len(), 2);
}

// T-03 (unit): the values typed in a save are the changed ones.
#[test]
fn t03_typed_actions_are_the_changed_values() {
    let mut clock = HlcClock::default();
    let dev = DeviceId::from_bytes([1; 16]);
    let mut body = ItemBody::new(ItemKind::Host, 1);
    let mut host = with_proxy(Proxy::Command("nc %h %p".into()));
    host.apply_to(&mut body, &mut clock, dev);
    // New item: the command is typed here.
    let typed = typed_actions(id(HOST), None, &body);
    assert_eq!(typed.len(), 1);
    assert_eq!(typed[0].value, "nc %h %p");
    // Editing the label only: the (possibly synced) command is not re-approved.
    let before = body.clone();
    host.label = "db".into();
    host.apply_to(&mut body, &mut clock, dev);
    assert!(typed_actions(id(HOST), Some(&before), &body).is_empty());
    // Changing the command: typed.
    let before = body.clone();
    host.proxy = Some(Proxy::Command("nc -X 5 %h %p".into()));
    host.agent_source = Some(AgentSource::Both);
    host.apply_to(&mut body, &mut clock, dev);
    let typed = typed_actions(id(HOST), Some(&before), &body);
    assert_eq!(typed.len(), 2);
    assert!(
        typed
            .iter()
            .any(|a| a.kind == ActionKind::SystemAgent && a.value == "both")
    );

    // Forward body.
    let mut fbody = ItemBody::new(ItemKind::PortForward, 1);
    rule(ForwardKind::Local, "0.0.0.0", Some("db")).apply_to(&mut fbody, &mut clock, dev);
    assert_eq!(typed_actions(id(5), None, &fbody)[0].value, "0.0.0.0:8080");
}

#[test]
fn messages() {
    let a = LocalAction::new(id(1), ActionKind::ProxyCommand, "ssh -W %h:%p bastion");
    assert_eq!(
        a.question(),
        "This host runs a local command: `ssh -W %h:%p bastion`. Allow?"
    );
    assert_eq!(
        a.headless_message("db"),
        "host \"db\" uses a local command that has not been approved on this device. \
         Run: sverb approve db"
    );
    assert_eq!(
        ActionKind::from_field("dest_host"),
        Some(ActionKind::ForwardDest)
    );
}
