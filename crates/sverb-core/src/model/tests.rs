//! Cross-module tests for the item model.

use std::time::Duration;

use ciborium::Value;
use proptest::prelude::*;

use super::*;
use crate::secret::SecretString;

const T0: Duration = Duration::from_secs(1_800_000_000);

fn dev(b: u8) -> DeviceId {
    DeviceId::from_bytes([b; 16])
}

fn id(b: u8) -> ItemId {
    ItemId::from_bytes([b; 16])
}

fn clock() -> (ManualClock, HlcClock) {
    let pc = ManualClock::new(T0);
    (pc.clone(), HlcClock::new(pc))
}

fn at(secs: u64) -> Hlc {
    Hlc::from_duration(T0 + Duration::from_secs(secs))
}

fn stamp_of(body: &ItemBody, field: &str) -> Option<(Hlc, DeviceId)> {
    body.get_stamped(field).map(Stamped::stamp)
}

#[test]
fn stamped_ties_break_on_device() {
    let a = Stamped::new(Value::from(1), at(1), dev(1));
    let b = Stamped::new(Value::from(2), at(1), dev(2));
    assert!(b.is_newer_than(&a));
    assert!(!a.is_newer_than(&b));
    assert_eq!(a.cmp_stamp(&b), std::cmp::Ordering::Less);
    // Deterministic: the answer doesn't depend on argument order or values.
    let c = Stamped::new(Value::from(99), at(1), dev(1));
    assert_eq!(c.cmp_stamp(&b), a.cmp_stamp(&b));
    // HLC dominates the device.
    let d = Stamped::new(Value::from(3), at(2), dev(0));
    assert!(d.is_newer_than(&b));
}

#[test]
fn set_stamps_and_skips_equal_values() {
    let (pc, mut clock) = clock();
    let mut body = ItemBody::new(ItemKind::Host, 1);
    assert!(body.set("port", 22_u16, &mut clock, dev(1)));
    let first = stamp_of(&body, "port");
    pc.advance(Duration::from_secs(1));
    assert!(!body.set("port", 22_u16, &mut clock, dev(1)));
    assert_eq!(stamp_of(&body, "port"), first);
    assert!(body.set("port", 2222_u16, &mut clock, dev(1)));
    let second = stamp_of(&body, "port");
    assert!(second > first);
}

#[test]
fn tombstone_rule_and_resurrection() {
    let mut body = ItemBody::new(ItemKind::Host, 1);
    body.fields.insert(
        "address".into(),
        Stamped::new(Value::from("a.example"), at(3), dev(1)),
    );
    body.deleted = Some(Stamped::new(true, at(5), dev(1)));
    assert!(body.is_deleted());
    body.fields.insert(
        "port".into(),
        Stamped::new(Value::from(2222), at(7), dev(2)),
    );
    assert!(!body.is_deleted());
    assert_eq!(body.max_field_hlc(), Some(at(7)));
    assert_eq!(body.max_hlc(), Some(at(7)));
    // A `false` tombstone never deletes.
    body.deleted = Some(Stamped::new(false, at(9), dev(1)));
    assert!(!body.is_deleted());
}

#[test]
fn unknown_fields_survive_view_round_trip() -> Result<(), ViewError> {
    let (_, mut clock) = clock();
    let mut body = ItemBody::new(ItemKind::Host, 1);
    body.set("address", "a.example", &mut clock, dev(1));
    body.set("port", 22_u16, &mut clock, dev(1));
    body.fields.insert(
        "future_field".into(),
        Stamped::new(Value::from("from the future"), at(1), dev(7)),
    );
    let before = body.clone();

    let mut host = Host::try_from(&body)?;
    host.port = Some(2200);
    host.apply_to(&mut body, &mut clock, dev(1));

    assert_eq!(
        body.get_stamped("future_field"),
        before.get_stamped("future_field")
    );
    assert_eq!(body.get("port"), Some(&Value::from(2200)));
    // Nothing but `port` changed.
    for (k, v) in &before.fields {
        if k != "port" {
            assert_eq!(body.get_stamped(k), Some(v), "{k}");
        }
    }
    assert_eq!(body.fields.len(), before.fields.len());
    Ok(())
}

#[test]
fn applying_an_unchanged_view_creates_no_stamps() -> Result<(), ViewError> {
    let (_, mut clock) = clock();
    let mut body = ItemBody::new(ItemKind::Host, 1);
    body.set("address", "a.example", &mut clock, dev(1));
    let before = body.clone();
    Host::try_from(&body)?.apply_to(&mut body, &mut clock, dev(1));
    assert_eq!(body, before);
    Ok(())
}

#[test]
fn proxy_is_flattened_and_sub_fields_stamp_independently() -> Result<(), ViewError> {
    let (pc, mut clock) = clock();
    let mut body = ItemBody::new(ItemKind::Host, 1);
    let host = Host {
        address: "a.example".into(),
        proxy: Some(Proxy::Socks5 {
            addr: "proxy:1080".into(),
            auth: Some(ProxyAuth {
                user: "u".into(),
                password: Some(SecretString::from("pw")),
            }),
        }),
        ..Host::default()
    };
    host.apply_to(&mut body, &mut clock, dev(1));
    assert_eq!(body.get("proxy.kind"), Some(&Value::from("socks5")));
    assert_eq!(body.get("proxy.addr"), Some(&Value::from("proxy:1080")));
    assert_eq!(body.get("proxy.auth.user"), Some(&Value::from("u")));
    assert_eq!(body.get("proxy.auth.password"), Some(&Value::from("pw")));
    assert!(!body.contains("proxy.command"));
    assert!(!body.contains("proxy"));

    let before = body.clone();
    pc.advance(Duration::from_secs(1));
    let mut host = Host::try_from(&body)?;
    if let Some(Proxy::Socks5 { addr, .. }) = &mut host.proxy {
        *addr = "proxy2:1080".into();
    }
    host.apply_to(&mut body, &mut clock, dev(1));
    for (k, v) in &before.fields {
        if k == "proxy.addr" {
            assert!(body.get_stamped(k).is_some_and(|n| n.is_newer_than(v)));
        } else {
            assert_eq!(body.get_stamped(k), Some(v), "{k}");
        }
    }

    // Switching to a command clears the socks sub-fields with explicit Nulls.
    let mut host = Host::try_from(&body)?;
    host.proxy = Some(Proxy::Command("nc %h %p".into()));
    host.apply_to(&mut body, &mut clock, dev(1));
    assert_eq!(body.get("proxy.addr"), None);
    assert!(body.contains("proxy.addr"));
    let back = Host::try_from(&body)?;
    assert!(matches!(back.proxy, Some(Proxy::Command(ref c)) if c == "nc %h %p"));
    Ok(())
}

fn value_strategy() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::from),
        any::<u64>().prop_map(Value::from),
        any::<f64>()
            .prop_filter("no NaN", |f| !f.is_nan())
            .prop_map(Value::Float),
        ".{0,12}".prop_map(Value::Text),
        proptest::collection::vec(any::<u8>(), 0..20).prop_map(Value::Bytes),
    ];
    leaf.prop_recursive(3, 24, 4, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            proptest::collection::vec(("[a-z]{1,4}".prop_map(Value::Text), inner), 0..4)
                .prop_map(Value::Map),
        ]
    })
}

fn stamped<T: std::fmt::Debug>(v: impl Strategy<Value = T>) -> impl Strategy<Value = Stamped<T>> {
    (v, any::<u64>(), any::<[u8; 16]>())
        .prop_map(|(value, h, d)| Stamped::new(value, Hlc::from_u64(h), DeviceId::from_bytes(d)))
}

fn body_strategy() -> impl Strategy<Value = ItemBody> {
    (
        proptest::sample::select(ItemKind::ALL.to_vec()),
        any::<u16>(),
        proptest::collection::btree_map("[a-z_.]{1,12}", stamped(value_strategy()), 0..8),
        proptest::option::of(stamped(any::<bool>())),
    )
        .prop_map(|(kind, schema_version, fields, deleted)| ItemBody {
            kind,
            schema_version,
            fields,
            deleted,
        })
}

proptest! {
    #[test]
    fn cbor_round_trip_is_lossless_and_deterministic(body in body_strategy()) {
        let bytes = body.to_cbor().map_err(|e| TestCaseError::fail(e.to_string()))?;
        let back = ItemBody::from_cbor(&bytes).map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert_eq!(&back, &body);
        let again = back.to_cbor().map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert_eq!(again, bytes);
    }
}

#[test]
fn cbor_bytes_feed_seal_item() -> Result<(), Box<dyn std::error::Error>> {
    let (_, mut clock) = clock();
    let mut body = ItemBody::new(ItemKind::Host, 1);
    body.set("address", "a.example", &mut clock, dev(1));
    let bytes = body.to_cbor()?;
    let vk = sverb_crypto::Key32::from_bytes([7_u8; 32]);
    let item = id(1);
    let vault = VaultId::from_bytes([2; 16]);
    let env = sverb_crypto::envelope::seal_item_with_nonce(
        &vk,
        vault.as_bytes(),
        item.as_bytes(),
        1,
        &bytes,
        &sverb_crypto::Nonce24::from_bytes([3; 24]),
    )?;
    let plain = sverb_crypto::envelope::open_item(
        |v| (v == 1).then_some(&vk),
        vault.as_bytes(),
        item.as_bytes(),
        &env,
    )?;
    assert_eq!(ItemBody::from_cbor(&plain)?, body);
    Ok(())
}

#[test]
fn newer_schema_yields_read_only_views() -> Result<(), ViewError> {
    let mut body = ItemBody::new(ItemKind::Host, 99);
    body.fields.insert(
        "address".into(),
        Stamped::new(Value::from("a.example"), at(1), dev(1)),
    );
    assert!(Host::try_from(&body)?.read_only);
    body.schema_version = 1;
    assert!(!Host::try_from(&body)?.read_only);
    assert!(Tag::try_from(&ItemBody::new(ItemKind::Tag, 99))?.read_only);
    Ok(())
}

#[test]
fn wrong_field_types_are_reported() {
    let mut body = ItemBody::new(ItemKind::Host, 1);
    body.fields.insert(
        "port".into(),
        Stamped::new(Value::from("twenty-two"), at(1), dev(1)),
    );
    assert_eq!(
        Host::try_from(&body).err(),
        Some(ViewError::FieldTypeError {
            field: "port".into()
        })
    );
    // Out of range for u16.
    body.fields.insert(
        "port".into(),
        Stamped::new(Value::from(70_000), at(1), dev(1)),
    );
    assert!(matches!(
        Host::try_from(&body),
        Err(ViewError::FieldTypeError { .. })
    ));
    assert!(matches!(
        Tag::try_from(&body),
        Err(ViewError::WrongKind {
            expected: ItemKind::Tag,
            found: ItemKind::Host
        })
    ));
}

#[test]
fn secrets_are_typed_and_redacted() -> Result<(), ViewError> {
    let (_, mut clock) = clock();
    let mut body = ItemBody::new(ItemKind::Host, 1);
    body.set("address", "a.example", &mut clock, dev(1));
    body.set("password", "CANARY-7f3a", &mut clock, dev(1));
    let host = Host::try_from(&body)?;
    let pw: Option<&SecretString> = host.password.as_ref();
    assert_eq!(pw.map(|p| p.expose()), Some("CANARY-7f3a"));
    let dbg = format!("{host:?}");
    assert!(!dbg.contains("CANARY"), "{dbg}");
    assert!(!format!("{body:?}").contains("CANARY"));
    Ok(())
}

#[test]
fn unset_beats_older_value() {
    let pc = ManualClock::new(T0 + Duration::from_secs(3));
    let mut clock = HlcClock::new(pc.clone());
    let mut body = ItemBody::new(ItemKind::Host, 1);
    body.set("port", 2222_u16, &mut clock, dev(1));
    let set_stamp = body.get_stamped("port").map(|s| s.hlc);
    pc.set(T0 + Duration::from_secs(5));
    assert!(body.unset("port", &mut clock, dev(1)));
    assert_eq!(body.get("port"), None);
    assert!(body.contains("port"));
    let unset_stamp = body.get_stamped("port").map(|s| s.hlc);
    assert!(unset_stamp > set_stamp);
    assert_eq!(
        unset_stamp.map(|h| h.physical()),
        Some(T0 + Duration::from_secs(5))
    );
    // Unsetting again is a no-op.
    assert!(!body.unset("port", &mut clock, dev(1)));
}

#[test]
fn host_label_falls_back_to_address() {
    let host = Host {
        address: "a.example".into(),
        ..Host::default()
    };
    assert_eq!(host.display_label(), "a.example");
    assert_eq!(host.port_or_default(), 22);
}

#[test]
fn group_defaults_use_dotted_keys() -> Result<(), ViewError> {
    let (_, mut clock) = clock();
    let mut body = ItemBody::new(ItemKind::Group, 1);
    let group = Group {
        name: "prod".into(),
        parent_id: Some(id(9)),
        defaults: HostDefaults {
            port: Some(2222),
            env: Some(vec![("A".into(), "1".into())]),
            algorithms: Some(AlgoOverrides {
                kex: Some(vec!["diffie-hellman-group14-sha1".into()]),
                ..AlgoOverrides::default()
            }),
            ..HostDefaults::default()
        },
        icon: None,
        read_only: false,
        is_vault_defaults: false,
    };
    group.apply_to(&mut body, &mut clock, dev(1));
    assert_eq!(body.get("defaults.port"), Some(&Value::from(2222)));
    assert!(body.get("defaults.algorithms.kex").is_some());
    assert!(!body.contains("defaults.algorithms.mac"));
    let back = Group::try_from(&body)?;
    assert_eq!(back.name, "prod");
    assert_eq!(back.parent_id, Some(id(9)));
    assert_eq!(back.defaults.port, Some(2222));
    assert_eq!(back.defaults.env, Some(vec![("A".into(), "1".into())]));
    assert_eq!(back.defaults.algorithms, group.defaults.algorithms);
    Ok(())
}

#[test]
fn every_view_round_trips() -> Result<(), ViewError> {
    let (_, mut clock) = clock();
    let d = dev(1);

    // Host, all fields.
    let mut b = ItemBody::new(ItemKind::Host, 1);
    let host = Host {
        label: "web".into(),
        address: "a.example".into(),
        port: Some(2222),
        group_id: Some(id(2)),
        tags: vec![id(3), id(4)],
        identity_id: Some(id(5)),
        username: Some("root".into()),
        password: Some(SecretString::from("pw")),
        key_id: Some(id(6)),
        jump_chain: vec![id(7)],
        proxy: Some(Proxy::Http {
            addr: "p:8080".into(),
            auth: None,
        }),
        agent_forwarding: Some(false),
        agent_source: Some(AgentSource::Both),
        env: vec![("LANG".into(), "C".into())],
        startup_snippet_id: Some(id(8)),
        keepalive_secs: Some(30),
        charset: Some("latin1".into()),
        backspace: Some(Backspace::CtrlH),
        color_scheme: Some("dark".into()),
        port_forwards: vec![id(9)],
        notes: Some("# hi".into()),
        pinned: true,
        algorithms: None,
        request_pty_for_exec: Some(true),
        record_sessions: Some(true),
        auto_reconnect: Some(false),
        read_only: false,
        explicit_empty: ExplicitEmpty::default(),
    };
    host.apply_to(&mut b, &mut clock, d);
    assert_eq!(b.get("record_sessions"), Some(&Value::Bool(true)));
    assert_eq!(b.get("auto_reconnect"), Some(&Value::Bool(false)));
    assert_eq!(b.get("backspace"), Some(&Value::from("ctrl-h")));
    assert_eq!(b.get("agent_forwarding"), Some(&Value::Bool(false)));
    let back = Host::try_from(&b)?;
    assert_eq!(format!("{back:?}"), format!("{host:?}"));
    let before = b.clone();
    back.apply_to(&mut b, &mut clock, d);
    assert_eq!(b, before);

    // Identity
    let mut b = ItemBody::new(ItemKind::Identity, 1);
    let v = Identity {
        label: "me".into(),
        username: "me".into(),
        password: None,
        key_id: Some(id(1)),
        read_only: false,
    };
    v.apply_to(&mut b, &mut clock, d);
    assert_eq!(format!("{:?}", Identity::try_from(&b)?), format!("{v:?}"));

    // Key
    let mut b = ItemBody::new(ItemKind::Key, 1);
    let v = Key {
        label: "k".into(),
        algorithm: KeyAlgorithm::EcdsaP256,
        private_key: SecretString::from("-----BEGIN OPENSSH PRIVATE KEY-----"),
        public_key: "ecdsa-sha2-nistp256 AAAA".into(),
        passphrase: Some(SecretString::from("pp")),
        certificate_ids: vec![id(2)],
        agent_forwardable: false,
        confirm_on_use: true,
        read_only: false,
    };
    v.apply_to(&mut b, &mut clock, d);
    assert_eq!(b.get("algorithm"), Some(&Value::from("ecdsa-p256")));
    let back = Key::try_from(&b)?;
    assert_eq!(
        back.private_key.expose(),
        "-----BEGIN OPENSSH PRIVATE KEY-----"
    );
    assert_eq!(back.passphrase.as_ref().map(|p| p.expose()), Some("pp"));
    assert_eq!(back.algorithm, KeyAlgorithm::EcdsaP256);
    assert!(back.confirm_on_use && !back.agent_forwardable);
    assert!(!format!("{back:?}").contains("BEGIN"));

    // Certificate
    let mut b = ItemBody::new(ItemKind::Certificate, 1);
    let v = Certificate {
        label: "c".into(),
        cert: "ssh-ed25519-cert-v01@openssh.com AAAA".into(),
        key_id: Some(id(1)),
        read_only: false,
    };
    v.apply_to(&mut b, &mut clock, d);
    assert_eq!(Certificate::try_from(&b)?, v);

    // KnownHost
    let mut b = ItemBody::new(ItemKind::KnownHost, 1);
    let v = KnownHost {
        host_pattern: "[a.example]:2222".into(),
        key_type: "ssh-ed25519".into(),
        public_key: "AAAA".into(),
        added_at: UnixMillis(1_700_000_000_000),
        comment: None,
        marker: KnownHostMarker::CertAuthority,
        read_only: false,
    };
    v.apply_to(&mut b, &mut clock, d);
    assert_eq!(b.get("marker"), Some(&Value::from("cert-authority")));
    assert_eq!(KnownHost::try_from(&b)?, v);

    // PortForward
    let mut b = ItemBody::new(ItemKind::PortForward, 1);
    let v = PortForward {
        label: "db".into(),
        kind: ForwardKind::Local,
        host_id: id(1),
        bind_addr: DEFAULT_BIND_ADDR.into(),
        bind_port: 5432,
        dest_host: Some("db.internal".into()),
        dest_port: Some(5432),
        auto_start: true,
        read_only: false,
    };
    v.apply_to(&mut b, &mut clock, d);
    assert_eq!(PortForward::try_from(&b)?, v);
    let empty = ItemBody::new(ItemKind::PortForward, 1);
    assert!(matches!(
        PortForward::try_from(&empty),
        Err(ViewError::MissingField { .. })
    ));

    // Snippet
    let mut b = ItemBody::new(ItemKind::Snippet, 1);
    let v = Snippet {
        name: "deploy".into(),
        script: "make {{target:all}}".into(),
        description: Some("d".into()),
        tags: vec![id(1)],
        variables: vec![VarDef {
            name: "target".into(),
            default: Some("all".into()),
            secret: false,
        }],
        run_mode: RunMode::PasteAndExecute,
        read_only: false,
    };
    v.apply_to(&mut b, &mut clock, d);
    assert_eq!(b.get("run_mode"), Some(&Value::from("paste-and-execute")));
    assert_eq!(Snippet::try_from(&b)?, v);

    // Workspace
    let mut b = ItemBody::new(ItemKind::Workspace, 1);
    let v = Workspace {
        name: "ops".into(),
        layout: Some(Value::Map(vec![(Value::from("leaf"), Value::from(id(1)))])),
        broadcast_groups: vec![Value::Array(vec![Value::from(0), Value::from(1)])],
        read_only: false,
    };
    v.apply_to(&mut b, &mut clock, d);
    assert_eq!(Workspace::try_from(&b)?, v);

    // Tag
    let mut b = ItemBody::new(ItemKind::Tag, 1);
    let v = Tag {
        name: "prod".into(),
        color: Some("#ff0000".into()),
        read_only: false,
    };
    v.apply_to(&mut b, &mut clock, d);
    assert_eq!(Tag::try_from(&b)?, v);

    // HistoryEntry
    let mut b = ItemBody::new(ItemKind::HistoryEntry, 1);
    let v = HistoryEntry {
        command: "ls".into(),
        host_id: Some(id(1)),
        executed_at: UnixMillis(5),
        exit_code: Some(-1),
        verified: true,
        read_only: false,
    };
    v.apply_to(&mut b, &mut clock, d);
    assert_eq!(HistoryEntry::try_from(&b)?, v);
    // An unverified (heuristic) entry round-trips too.
    let v = HistoryEntry {
        verified: false,
        ..v
    };
    v.apply_to(&mut b, &mut clock, d);
    assert_eq!(HistoryEntry::try_from(&b)?, v);

    // ConnLog
    let mut b = ItemBody::new(ItemKind::ConnLog, 1);
    let v = ConnLog {
        // Optional host, label, target and error detail (spec additions).
        host_id: Some(id(1)),
        started_at: UnixMillis(1),
        ended_at: Some(UnixMillis(2)),
        result: Some(ConnResult::NetworkError("reset".into())),
        bytes_in: 10,
        bytes_out: 0,
        read_only: false,
        label: "web-1".into(),
        target: Some("deploy@10.0.0.5:2222".into()),
        error_detail: Some(vec!["Connection reset".into(), "os error 104".into()]),
    };
    v.apply_to(&mut b, &mut clock, d);
    assert_eq!(b.get("result.kind"), Some(&Value::from("network-error")));
    assert_eq!(ConnLog::try_from(&b)?, v);
    assert_eq!(v.duration(), Some(std::time::Duration::from_millis(1)));
    assert!(v.is_failure());
    // A local shell's entry has no host; an open entry is no failure.
    let mut b = ItemBody::new(ItemKind::ConnLog, 1);
    let local = ConnLog {
        label: "local".into(),
        started_at: UnixMillis(7),
        ..ConnLog::default()
    };
    local.apply_to(&mut b, &mut clock, d);
    assert_eq!(b.get("host_id"), None);
    assert_eq!(ConnLog::try_from(&b)?, local);
    assert!(!local.is_failure());
    assert_eq!(local.duration(), None);
    Ok(())
}

#[test]
fn record_sessions_resolves_host_then_groups_then_global() -> Result<(), ViewError> {
    use crate::model::resolve_record_sessions;
    let host = Host::default();
    let unset = HostDefaults::default();
    let on = HostDefaults {
        record_sessions: Some(true),
        ..HostDefaults::default()
    };
    let off = HostDefaults {
        record_sessions: Some(false),
        ..HostDefaults::default()
    };
    // Nothing set: the global flag.
    assert!(!resolve_record_sessions(&host, [&unset], false));
    assert!(resolve_record_sessions(&host, [&unset], true));
    // The nearest group that sets it wins.
    assert!(resolve_record_sessions(&host, [&unset, &on, &off], false));
    assert!(!resolve_record_sessions(&host, [&off, &on], true));
    // The host's own value wins over everything.
    let host = Host {
        record_sessions: Some(false),
        ..Host::default()
    };
    assert!(!resolve_record_sessions(&host, [&on], true));
    // Round trip through a group's defaults.
    let (_, mut clock) = clock();
    let mut body = ItemBody::new(ItemKind::Group, 1);
    on.write(&mut body, "defaults.", &mut clock, dev(1));
    assert_eq!(
        body.get("defaults.record_sessions"),
        Some(&Value::Bool(true))
    );
    let back = HostDefaults::read(&body, "defaults.")?;
    assert_eq!(back.record_sessions, Some(true));
    Ok(())
}
