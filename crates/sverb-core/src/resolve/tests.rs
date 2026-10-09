//! property test against a naive reference.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use proptest::prelude::*;

use super::*;
use crate::model::{DeviceId, ExplicitEmpty, HlcClock, ItemBody, ItemKind};

fn id(b: u8) -> ItemId {
    ItemId::from_bytes([b; 16])
}

const ROOT: u8 = 1;
const PROD: u8 = 2;
const WEB: u8 = 3;
const IDENT: u8 = 10;
const KEY: u8 = 11;
const JUMP: u8 = 12;

/// A host in group `web` → `prod` → `root`, an identity with a password and a key.
struct World {
    host: Host,
    table: LookupTable,
    vault: Option<Settings>,
    globals: GlobalDefaults,
}

impl World {
    fn new() -> Self {
        let mut table = LookupTable::default();
        let group = |name: &str, parent: Option<u8>| GroupNode {
            name: name.to_owned(),
            parent_id: parent.map(id),
            icon: None,
            defaults: Settings::default(),
        };
        table.groups.insert(id(ROOT), group("root", None));
        table.groups.insert(id(PROD), group("prod", Some(ROOT)));
        table.groups.insert(id(WEB), group("web", Some(PROD)));
        table.identities.insert(
            id(IDENT),
            IdentityNode {
                label: "deploy".into(),
                username: "deploy".into(),
                has_password: true,
                key_id: Some(id(KEY)),
            },
        );
        for b in [ROOT, PROD, WEB, IDENT, KEY, JUMP] {
            table.mark_live(id(b));
        }
        Self {
            host: Host {
                address: "a.example".into(),
                group_id: Some(id(WEB)),
                ..Host::default()
            },
            table,
            vault: None,
            globals: GlobalDefaults {
                keepalive_secs: 15,
                color_scheme: "solarized".into(),
                record_sessions: false,
                auto_reconnect: false,
            },
        }
    }

    fn group(&mut self, b: u8) -> &mut Settings {
        &mut self
            .table
            .groups
            .get_mut(&id(b))
            .expect("fixture group")
            .defaults
    }

    fn vault(&mut self) -> &mut Settings {
        self.vault.get_or_insert_with(Settings::default)
    }

    fn resolve(&self) -> ResolvedHost {
        resolve_settings(
            &Target::of(&self.host),
            &Settings::from_host(&self.host),
            &self.table,
            self.vault.as_ref(),
            &self.globals,
        )
    }
}

fn group_src(b: u8) -> Source {
    let name = match b {
        ROOT => "root",
        PROD => "prod",
        _ => "web",
    };
    Source::Group {
        id: id(b),
        name: name.into(),
    }
}

struct Row {
    name: &'static str,
    setup: fn(&mut World),
    key: SettingKey,
    value: Option<&'static str>,
    source: Source,
}

fn rows() -> Vec<Row> {
    vec![
        Row {
            name: "port on host",
            setup: |w| {
                w.host.port = Some(2222);
                w.group(WEB).port = Some(1);
            },
            key: SettingKey::Port,
            value: Some("2222"),
            source: Source::Host,
        },
        Row {
            name: "port on group only",
            setup: |w| w.group(WEB).port = Some(2200),
            key: SettingKey::Port,
            value: Some("2200"),
            source: group_src(WEB),
        },
        Row {
            name: "port on grandparent only",
            setup: |w| w.group(ROOT).port = Some(2300),
            key: SettingKey::Port,
            value: Some("2300"),
            source: group_src(ROOT),
        },
        Row {
            name: "nearest group wins",
            setup: |w| {
                w.group(ROOT).port = Some(2300);
                w.group(PROD).port = Some(2400);
            },
            key: SettingKey::Port,
            value: Some("2400"),
            source: group_src(PROD),
        },
        Row {
            name: "port unset everywhere",
            setup: |_| {},
            key: SettingKey::Port,
            value: Some("22"),
            source: Source::BuiltinDefault,
        },
        Row {
            name: "keepalive unset everywhere → global config",
            setup: |_| {},
            key: SettingKey::KeepaliveSecs,
            value: Some("15"),
            source: Source::GlobalConfig,
        },
        Row {
            name: "vault default beats global",
            setup: |w| w.vault().keepalive_secs = Some(60),
            key: SettingKey::KeepaliveSecs,
            value: Some("60"),
            source: Source::VaultDefaults,
        },
        Row {
            name: "group beats vault default",
            setup: |w| {
                w.vault().keepalive_secs = Some(60);
                w.group(ROOT).keepalive_secs = Some(5);
            },
            key: SettingKey::KeepaliveSecs,
            value: Some("5"),
            source: group_src(ROOT),
        },
        Row {
            name: "identity on group + inline username on host → username from host",
            setup: |w| {
                w.group(PROD).identity_id = Some(id(IDENT));
                w.host.username = Some("root".into());
            },
            key: SettingKey::Username,
            value: Some("root"),
            source: Source::Host,
        },
        Row {
            name: "identity on group + inline username on host → password from group identity",
            setup: |w| {
                w.group(PROD).identity_id = Some(id(IDENT));
                w.host.username = Some("root".into());
            },
            key: SettingKey::Password,
            value: Some("••••••"),
            source: group_src(PROD),
        },
        Row {
            name: "identity on group → key from identity",
            setup: |w| w.group(PROD).identity_id = Some(id(IDENT)),
            key: SettingKey::KeyId,
            value: Some("0b0b0b0b"),
            source: group_src(PROD),
        },
        Row {
            name: "identity's user at group level",
            setup: |w| w.group(WEB).identity_id = Some(id(IDENT)),
            key: SettingKey::Username,
            value: Some("deploy"),
            source: group_src(WEB),
        },
        Row {
            name: "inline group username beats identity of a farther group",
            setup: |w| {
                w.group(ROOT).identity_id = Some(id(IDENT));
                w.group(PROD).username = Some("ops".into());
            },
            key: SettingKey::Username,
            value: Some("ops"),
            source: group_src(PROD),
        },
        Row {
            name: "deleted group reference resolves as no group",
            setup: |w| {
                w.host.group_id = Some(id(99));
                w.group(WEB).port = Some(2200);
            },
            key: SettingKey::Port,
            value: Some("22"),
            source: Source::BuiltinDefault,
        },
        Row {
            name: "deleted identity on host falls through to the group's",
            setup: |w| {
                w.host.identity_id = Some(id(98));
                w.group(WEB).username = Some("web".into());
            },
            key: SettingKey::Username,
            value: Some("web"),
            source: group_src(WEB),
        },
        Row {
            name: "deleted key on host → none",
            setup: |w| w.host.key_id = Some(id(97)),
            key: SettingKey::KeyId,
            value: None,
            source: Source::BuiltinDefault,
        },
        Row {
            name: "env set on host as empty → empty (not inherited)",
            setup: |w| {
                w.host.explicit_empty = ExplicitEmpty {
                    env: true,
                    ..ExplicitEmpty::default()
                };
                w.group(WEB).env = Some(vec![("A".into(), "1".into())]);
            },
            key: SettingKey::Env,
            value: None,
            source: Source::Host,
        },
        Row {
            name: "env absent → inherited",
            setup: |w| w.group(WEB).env = Some(vec![("A".into(), "1".into())]),
            key: SettingKey::Env,
            value: Some("1 variable(s)"),
            source: group_src(WEB),
        },
        Row {
            name: "jump chain from the parent",
            setup: |w| w.group(PROD).jump_chain = Some(vec![id(JUMP), id(96)]),
            key: SettingKey::JumpChain,
            value: Some("1 hop(s)"),
            source: group_src(PROD),
        },
        Row {
            name: "charset default",
            setup: |_| {},
            key: SettingKey::Charset,
            value: Some("UTF-8"),
            source: Source::BuiltinDefault,
        },
        Row {
            name: "color scheme from config",
            setup: |_| {},
            key: SettingKey::ColorScheme,
            value: Some("solarized"),
            source: Source::GlobalConfig,
        },
        Row {
            name: "record_sessions from a group",
            setup: |w| w.group(ROOT).record_sessions = Some(true),
            key: SettingKey::RecordSessions,
            value: Some("yes"),
            source: group_src(ROOT),
        },
        Row {
            name: "auto_reconnect from config",
            setup: |_| {},
            key: SettingKey::AutoReconnect,
            value: Some("no"),
            source: Source::GlobalConfig,
        },
        Row {
            name: "auto_reconnect from a group",
            setup: |w| w.group(ROOT).auto_reconnect = Some(true),
            key: SettingKey::AutoReconnect,
            value: Some("yes"),
            source: group_src(ROOT),
        },
        Row {
            name: "vault default username",
            setup: |w| w.vault().username = Some("admin".into()),
            key: SettingKey::Username,
            value: Some("admin"),
            source: Source::VaultDefaults,
        },
    ]
}

#[test]
fn resolution_table() {
    let rows = rows();
    assert!(rows.len() >= 15);
    for row in rows {
        let mut w = World::new();
        (row.setup)(&mut w);
        let r = w.resolve();
        assert_eq!(
            r.display(row.key).as_deref(),
            row.value,
            "value: {}",
            row.name
        );
        // Provenance for every row.
        assert_eq!(r.source(row.key), &row.source, "source: {}", row.name);
    }
}

#[test]
fn details_of_the_table() {
    // Password origin names the identity; warnings list missing references.
    let mut w = World::new();
    w.group(PROD).identity_id = Some(id(IDENT));
    let r = w.resolve();
    assert_eq!(
        r.password,
        Some(SecretOrigin {
            source: group_src(PROD),
            identity: Some(id(IDENT)),
        })
    );
    assert_eq!(r.group_chain, vec![id(WEB), id(PROD), id(ROOT)]);
    assert!(r.inherits_from(id(PROD)));
    assert!(!r.inherits_from(id(WEB)));

    let mut w = World::new();
    w.host.group_id = Some(id(99));
    let r = w.resolve();
    assert!(r.missing_group());
    assert_eq!(r.group_id, None);
    assert_eq!(r.warnings, vec![ResolveWarning::MissingGroup(id(99))]);

    let mut w = World::new();
    w.group(PROD).jump_chain = Some(vec![id(JUMP), id(96)]);
    let r = w.resolve();
    assert_eq!(r.jump_chain, vec![id(JUMP)]);
    assert_eq!(r.warnings, vec![ResolveWarning::MissingItem(id(96))]);
}

#[test]
fn group_cycle_terminates() {
    let mut w = World::new();
    // Corrupt store: root's parent is web (web → prod → root → web …).
    w.table.groups.get_mut(&id(ROOT)).expect("root").parent_id = Some(id(WEB));
    w.group(ROOT).port = Some(2300);
    w.group(WEB).keepalive_secs = Some(9);
    let r = w.resolve();
    assert_eq!(r.port, 2300);
    assert_eq!(r.keepalive_secs, 9);
    assert_eq!(r.group_chain, vec![id(WEB), id(PROD), id(ROOT)]);
    assert_eq!(r.warnings, vec![ResolveWarning::GroupCycle(id(WEB))]);

    // A self-parented group.
    let mut w = World::new();
    w.table.groups.get_mut(&id(WEB)).expect("web").parent_id = Some(id(WEB));
    let r = w.resolve();
    assert_eq!(r.group_chain, vec![id(WEB)]);
}

#[test]
fn depth_limit() {
    let mut table = LookupTable::default();
    for i in 0..100u8 {
        table.groups.insert(
            id(i),
            GroupNode {
                name: format!("g{i}"),
                parent_id: Some(id(i + 1)),
                ..GroupNode::default()
            },
        );
    }
    let host = Host {
        group_id: Some(id(0)),
        ..Host::default()
    };
    let r = resolve_settings(
        &Target::of(&host),
        &Settings::from_host(&host),
        &table,
        None,
        &GlobalDefaults::default(),
    );
    assert_eq!(r.group_chain.len(), MAX_GROUP_DEPTH);
    assert!(r.warnings.contains(&ResolveWarning::DepthLimit));
}

#[test]
fn explicit_empty_lists_round_trip() -> Result<(), crate::model::ViewError> {
    let mut clock = HlcClock::default();
    let dev = DeviceId::from_bytes([1; 16]);
    let mut body = ItemBody::new(ItemKind::Host, 1);
    let mut host = Host {
        address: "a".into(),
        ..Host::default()
    };
    host.apply_to(&mut body, &mut clock, dev);
    assert!(!body.contains("env"));
    host.explicit_empty.env = true;
    host.apply_to(&mut body, &mut clock, dev);
    let back = Host::try_from(&body)?;
    assert!(back.explicit_empty.env);
    assert!(!back.explicit_empty.jump_chain);
    assert_eq!(Settings::from_host(&back).env, Some(Vec::new()));
    // Back to "inherit": the key is cleared.
    host.explicit_empty.env = false;
    host.apply_to(&mut body, &mut clock, dev);
    let back = Host::try_from(&body)?;
    assert!(!back.explicit_empty.env);
    assert_eq!(Settings::from_host(&back).env, None);
    Ok(())
}

#[test]
fn resolve_reads_the_config() {
    let mut config = Config::default();
    config.ssh.keepalive_secs = 42;
    let host = Host {
        address: "a".into(),
        ..Host::default()
    };
    let r = resolve(&host, &LookupTable::default(), None, &config);
    assert_eq!(r.keepalive_secs, 42);
    assert_eq!(r.source(SettingKey::KeepaliveSecs), &Source::GlobalConfig);
    assert_eq!(r.address, "a");
}

#[test]
fn vault_defaults_items_go_to_their_vault() {
    let mut t = LookupTable::default();
    let vault = VaultId::from_bytes([5; 16]);
    let mut g = Group {
        name: "defaults".into(),
        is_vault_defaults: true,
        ..Group::default()
    };
    g.defaults.port = Some(2022);
    t.insert_group(id(50), vault, &g);
    assert!(t.groups.is_empty());
    assert_eq!(t.defaults_of(vault).and_then(|s| s.port), Some(2022));
    assert_eq!(t.vault_defaults_items.get(&vault), Some(&id(50)));
}

// ---------------------------------------------------------------- T-04

#[derive(Debug, Clone)]
struct Fields {
    port: Option<u16>,
    keepalive: Option<u32>,
    user: Option<String>,
    env: Option<Vec<(String, String)>>,
}

fn fields() -> impl Strategy<Value = Fields> {
    (
        proptest::option::of(1u16..100),
        proptest::option::of(0u32..100),
        proptest::option::of("[a-c]{1,2}"),
        proptest::option::of(proptest::collection::vec(("[A-B]", "[0-1]"), 0..2)),
    )
        .prop_map(|(port, keepalive, user, env)| Fields {
            port,
            keepalive,
            user,
            env,
        })
}

fn settings(f: &Fields) -> Settings {
    Settings {
        port: f.port,
        keepalive_secs: f.keepalive,
        username: f.user.clone(),
        env: f.env.clone(),
        ..Settings::default()
    }
}

/// `(parent index (< own index) or none, fields)` per group: a forest of depth ≤ 6.
/// Groups (parent index, fields), the host's group index, its fields, the vault's.
type WorldValue = (
    Vec<(Option<usize>, Fields)>,
    Option<usize>,
    Fields,
    Option<Fields>,
);

fn world() -> impl Strategy<Value = WorldValue> {
    proptest::collection::vec((proptest::option::of(0usize..6), fields()), 1..7).prop_flat_map(
        |groups| {
            let n = groups.len();
            (
                Just(groups),
                proptest::option::of(0..n + 1), // n: a missing group
                fields(),
                proptest::option::of(fields()),
            )
        },
    )
}

/// The obvious recursive definition, one field at a time.
fn naive<T: Clone>(
    host: &Fields,
    group: Option<usize>,
    groups: &[(Option<usize>, Fields)],
    vault: Option<&Fields>,
    get: &dyn Fn(&Fields) -> Option<T>,
) -> Option<(T, Option<usize>, bool)> {
    if let Some(v) = get(host) {
        return Some((v, None, false));
    }
    fn walk<T>(
        g: Option<usize>,
        groups: &[(Option<usize>, Fields)],
        get: &dyn Fn(&Fields) -> Option<T>,
    ) -> Option<(T, usize)> {
        let g = g?;
        let (parent, f) = groups.get(g)?;
        get(f)
            .map(|v| (v, g))
            .or_else(|| walk(parent.filter(|p| *p < g), groups, get))
    }
    if let Some((v, g)) = walk(group, groups, get) {
        return Some((v, Some(g), false));
    }
    vault.and_then(get).map(|v| (v, None, true))
}

proptest! {
    #[test]
    fn matches_the_naive_reference((groups, host_group, host, vault) in world()) {
        let gid = |i: usize| id(100 + u8::try_from(i).unwrap_or(0));
        let mut table = LookupTable::default();
        for (i, (parent, f)) in groups.iter().enumerate() {
            table.groups.insert(gid(i), GroupNode {
                name: format!("g{i}"),
                parent_id: parent.filter(|p| *p < i).map(gid),
                icon: None,
                defaults: settings(f),
            });
        }
        let own = settings(&host);
        let target = Target { group_id: host_group.map(gid), ..Target::default() };
        let vault_s = vault.as_ref().map(settings);
        let globals = GlobalDefaults::default();
        let r = resolve_settings(&target, &own, &table, vault_s.as_ref(), &globals);
        let src = |found: Option<(Option<usize>, bool)>, fallback: Source| match found {
            None => fallback,
            Some((None, false)) => Source::Host,
            Some((None, true)) => Source::VaultDefaults,
            Some((Some(g), _)) => Source::Group { id: gid(g), name: format!("g{g}") },
        };

        let port = naive(&host, host_group, &groups, vault.as_ref(), &|f| f.port);
        prop_assert_eq!(r.port, port.as_ref().map_or(22, |p| p.0));
        prop_assert_eq!(r.source(SettingKey::Port), &src(port.map(|p| (p.1, p.2)), Source::BuiltinDefault));

        let ka = naive(&host, host_group, &groups, vault.as_ref(), &|f| f.keepalive);
        prop_assert_eq!(r.keepalive_secs, ka.as_ref().map_or(globals.keepalive_secs, |p| p.0));
        prop_assert_eq!(r.source(SettingKey::KeepaliveSecs), &src(ka.map(|p| (p.1, p.2)), Source::GlobalConfig));

        let user = naive(&host, host_group, &groups, vault.as_ref(), &|f| f.user.clone());
        prop_assert_eq!(&r.username, &user.as_ref().map(|p| p.0.clone()));
        prop_assert_eq!(r.source(SettingKey::Username), &src(user.map(|p| (p.1, p.2)), Source::BuiltinDefault));

        let env = naive(&host, host_group, &groups, vault.as_ref(), &|f| f.env.clone());
        prop_assert_eq!(&r.env, &env.as_ref().map(|p| p.0.clone()).unwrap_or_default());
        prop_assert_eq!(r.source(SettingKey::Env), &src(env.map(|p| (p.1, p.2)), Source::BuiltinDefault));

        prop_assert_eq!(r.missing_group(), host_group == Some(groups.len()));
    }
}

#[test]
fn password_origin_reads_the_right_secret() {
    use crate::secret::SecretString;
    let ident = Identity {
        label: "ops".into(),
        username: "ops".into(),
        password: Some(SecretString::from("from-identity")),
        key_id: None,
        read_only: false,
    };
    let mut group = Group {
        name: "prod".into(),
        ..Group::default()
    };
    group.defaults.password = Some(SecretString::from("from-group"));
    let host = Host {
        password: Some(SecretString::from("inline")),
        ..Host::default()
    };
    let read = |o: SecretOrigin| {
        password_for(
            &o,
            &host,
            |g| (g == id(PROD)).then_some(&group),
            |i| (i == id(IDENT)).then_some(&ident),
            None,
        )
        .map(|s| s.expose().to_owned())
    };
    assert_eq!(
        read(SecretOrigin {
            source: Source::Host,
            identity: None
        })
        .as_deref(),
        Some("inline")
    );
    assert_eq!(
        read(SecretOrigin {
            source: group_src(PROD),
            identity: None
        })
        .as_deref(),
        Some("from-group")
    );
    assert_eq!(
        read(SecretOrigin {
            source: group_src(PROD),
            identity: Some(id(IDENT))
        })
        .as_deref(),
        Some("from-identity")
    );
    assert_eq!(
        read(SecretOrigin {
            source: Source::VaultDefaults,
            identity: None
        }),
        None
    );
}
