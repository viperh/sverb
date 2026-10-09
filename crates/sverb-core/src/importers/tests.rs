use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::backup::{self as bk, BackupError, BackupItem, BackupPayload, BackupVault};
use super::preview::{ExistingItem, ItemWrite, WriteAction, classify, materialize};
use super::ssh_config::{DEFAULTS_GROUP, SshConfigOptions, parse_file, parse_str};
use super::*;
use crate::exporters;
use crate::model::{
    DeviceId, ForwardKind, Group, HlcClock, Host, ItemBody, ItemId, ItemKind, ManualClock,
    PortForward, Proxy, Tag, VaultId, current_schema,
};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn ssh_fixture(name: &str) -> ImportPlan {
    let dir = fixtures().join("ssh_config");
    let path = if name == "include" {
        dir.join("include/config")
    } else {
        dir.join(name)
    };
    let opts = SshConfigOptions::in_dir(path.parent().unwrap_or(&dir));
    match parse_file(&path, &opts) {
        Ok(p) => p,
        Err(e) => panic!("{name}: {e}"),
    }
}

fn host<'a>(plan: &'a ImportPlan, label: &str) -> &'a HostDraft {
    plan.items
        .iter()
        .find_map(|i| match &i.draft {
            Draft::Host(h) if h.label == label => Some(&**h),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no host {label} in\n{}", plan.render_table()))
}

fn group_ref(plan: &ImportPlan, name: &str) -> Option<PlanRef> {
    plan.items
        .iter()
        .position(|i| matches!(&i.draft, Draft::Group(g) if g.name == name))
}

fn clock() -> HlcClock {
    HlcClock::new(ManualClock::new(Duration::from_secs(1_800_000_000)))
}

fn dev(b: u8) -> DeviceId {
    DeviceId::from_bytes([b; 16])
}

fn vault() -> VaultId {
    VaultId::from_bytes([7; 16])
}

fn seq_ids() -> impl FnMut() -> ItemId {
    let mut n = 0u8;
    move || {
        n += 1;
        ItemId::from_bytes([n; 16])
    }
}

// ------------------------------------------------------------------ T-01

#[test]
fn t01_fixture_snapshots() {
    for name in [
        "basic",
        "wildcard",
        "include",
        "proxyjump",
        "forwards",
        "match_block",
        "quoting",
        "weird_whitespace",
    ] {
        let plan = ssh_fixture(name);
        insta::assert_snapshot!(format!("ssh_config_{name}"), plan.render_table());
    }
}

#[test]
fn basic_mapping() {
    let plan = ssh_fixture("basic");
    let web = host(&plan, "web");
    assert_eq!(web.address, "web.example.com");
    assert_eq!(web.port, Some(2222));
    assert_eq!(web.username.as_deref(), Some("deploy"));
    assert_eq!(web.identity_files, ["~/.ssh/id_ed25519"]);
    assert_eq!(web.agent_forwarding, Some(true));
    assert_eq!(web.keepalive_secs, Some(30));
    assert_eq!(
        web.env,
        [
            ("LANG".to_owned(), "C.UTF-8".to_owned()),
            ("TZ".to_owned(), "UTC".to_owned())
        ]
    );
    // `Host a b` → two hosts; %h → the alias.
    assert_eq!(host(&plan, "db").address, "db.internal.example.com");
    assert_eq!(
        host(&plan, "db-replica").address,
        "db-replica.internal.example.com"
    );
    assert_eq!(host(&plan, "plain").address, "plain");
    assert_eq!(plan.identity_files(), ["~/.ssh/id_ed25519"]);
}

// ------------------------------------------------------------------ T-02

#[test]
fn t02_first_match_wins() {
    let plan = parse_str(
        "Host web\n  User a\nHost *\n  User b\n",
        &SshConfigOptions::in_dir("/nonexistent"),
    );
    let web = host(&plan, "web");
    assert_eq!(web.username.as_deref(), Some("a"));
    // `Host *` first: its value wins over the later host block.
    let plan = parse_str(
        "Host *\n  User b\nHost web\n  User a\n",
        &SshConfigOptions::in_dir("/nonexistent"),
    );
    let web = host(&plan, "web");
    // The host inherits `b` from "Imported defaults" (nothing stored on the host).
    assert_eq!(web.username, None);
    assert_eq!(web.group, group_ref(&plan, DEFAULTS_GROUP));
    let Some(Draft::Group(g)) = group_ref(&plan, DEFAULTS_GROUP).map(|r| &plan.items[r].draft)
    else {
        panic!("no defaults group");
    };
    assert_eq!(g.defaults.username.as_deref(), Some("b"));
}

// ------------------------------------------------------------------ T-03

#[test]
fn t03_include_glob_and_cycle() {
    let plan = ssh_fixture("include");
    for alias in ["first", "second", "main", "from-a", "from-b"] {
        let _ = host(&plan, alias);
    }
    assert_eq!(host(&plan, "first").address, "first.example.com");
    assert_eq!(host(&plan, "second").username.as_deref(), Some("included"));
    assert!(
        plan.warnings
            .iter()
            .any(|w| w.contains("Include cycle detected")),
        "{:?}",
        plan.warnings
    );
    // Glob order: 10-first before 20-second.
    let pos = |l: &str| plan.items.iter().position(|i| i.label == l);
    assert!(pos("first") < pos("second"));
}

#[test]
fn t03_include_depth_limit() {
    let dir = std::env::temp_dir().join(format!("sverb-m2-11-depth-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
    for i in 0..20 {
        let text = format!("Include f{}\nHost h{i}\n", i + 1);
        std::fs::write(dir.join(format!("f{i}")), text).unwrap_or_else(|e| panic!("{e}"));
    }
    let plan = parse_file(&dir.join("f0"), &SshConfigOptions::in_dir(&dir))
        .unwrap_or_else(|e| panic!("{e}"));
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        plan.warnings.iter().any(|w| w.contains("deeper than 16")),
        "{:?}",
        plan.warnings
    );
    let hosts = plan
        .items
        .iter()
        .filter(|i| i.kind == ItemKind::Host)
        .count();
    assert_eq!(hosts, 17); // f0 … f16
}

// ------------------------------------------------------------------ T-04

#[test]
fn t04_wildcard_group_defaults() {
    let plan = ssh_fixture("wildcard");
    let prod = group_ref(&plan, "*.prod").unwrap_or_else(|| panic!("{}", plan.render_table()));
    let defaults = group_ref(&plan, DEFAULTS_GROUP);
    let Draft::Group(g) = &plan.items[prod].draft else {
        panic!("not a group");
    };
    assert_eq!(g.defaults.username.as_deref(), Some("deploy"));
    assert_eq!(g.defaults.keepalive_secs, Some(60));
    assert_eq!(g.parent, defaults);
    // Members: the matching aliases.
    let web = host(&plan, "web.prod");
    assert_eq!(web.group, Some(prod));
    assert_eq!(web.username.as_deref(), Some("alice")); // own value differs
    let api = host(&plan, "api.prod");
    assert_eq!(api.group, Some(prod));
    assert_eq!(api.username, None); // inherits deploy
    assert_eq!(api.port, Some(2200));
    let laptop = host(&plan, "laptop");
    assert_eq!(laptop.group, defaults);
    assert_eq!(laptop.username, None); // inherits fallback
    // The negated block is not a group, its value lands on the hosts.
    assert!(
        plan.skipped
            .iter()
            .any(|s| s.reason.contains("Host !jump *") && s.reason.contains("negated")),
        "{:?}",
        plan.skipped
    );
    assert_eq!(laptop.agent_forwarding, Some(false));

    let plan = parse_str(
        "Host !x *\n  User u\n",
        &SshConfigOptions::in_dir("/nonexistent"),
    );
    assert!(plan.items.is_empty());
    assert_eq!(plan.skipped.len(), 1);
    assert!(plan.skipped[0].reason.contains("negated"));
}

// ------------------------------------------------------------------ T-05

#[test]
fn t05_proxyjump_chain() {
    let plan = ssh_fixture("proxyjump");
    let target = host(&plan, "target");
    let labels: Vec<&str> = target
        .jump_chain
        .iter()
        .map(|r| plan.label_of(*r))
        .collect();
    assert_eq!(labels, ["user@bastion:2222", "inner"]);
    let hop = host(&plan, "user@bastion:2222");
    assert_eq!(hop.address, "bastion");
    assert_eq!(hop.port, Some(2222));
    assert_eq!(hop.username.as_deref(), Some("user"));
    // `inner` is linked, not duplicated.
    assert_eq!(plan.items.iter().filter(|i| i.label == "inner").count(), 1);
    let uri = host(&plan, "via-uri");
    let hop = host(&plan, plan.label_of(uri.jump_chain[0]));
    assert_eq!(
        (hop.address.as_str(), hop.port, hop.username.as_deref()),
        ("gw.example.com", Some(2022), Some("ops"))
    );
    assert_eq!(
        host(&plan, "cmd").proxy_command.as_deref(),
        Some("ssh -W %h:%p bastion.example.com")
    );
    let direct = host(&plan, "direct");
    assert!(direct.jump_chain.is_empty());
}

// ------------------------------------------------------------------ T-06

#[test]
fn t06_forwards() {
    let plan = parse_str(
        "Host t\n  LocalForward 5432 db:5432\n  RemoteForward 0 localhost:80\n  DynamicForward 1080\n",
        &SshConfigOptions::in_dir("/nonexistent"),
    );
    let rules: Vec<&ForwardDraft> = plan
        .items
        .iter()
        .filter_map(|i| match &i.draft {
            Draft::Forward(f) => Some(f),
            _ => None,
        })
        .collect();
    assert_eq!(rules.len(), 3);
    assert_eq!(rules[0].kind, ForwardKind::Local);
    assert_eq!(
        (
            rules[0].bind_port,
            rules[0].dest_host.as_deref(),
            rules[0].dest_port
        ),
        (5432, Some("db"), Some(5432))
    );
    assert_eq!(rules[1].kind, ForwardKind::Remote);
    assert_eq!(
        (
            rules[1].bind_port,
            rules[1].dest_host.as_deref(),
            rules[1].dest_port
        ),
        (0, Some("localhost"), Some(80))
    );
    assert_eq!(rules[2].kind, ForwardKind::Dynamic);
    assert_eq!(
        (rules[2].bind_port, rules[2].dest_host.as_deref()),
        (1080, None)
    );
    assert_eq!(host(&plan, "t").forwards.len(), 3);
}

// ------------------------------------------------------------------ T-07

#[test]
fn t07_unsupported_summary() {
    let plan = ssh_fixture("weird_whitespace");
    let summary: Vec<&String> = plan
        .warnings
        .iter()
        .filter(|w| w.starts_with("Unsupported keywords skipped"))
        .collect();
    assert_eq!(summary.len(), 1, "{:?}", plan.warnings);
    assert!(summary[0].contains("Compression (2)"), "{}", summary[0]);
    assert!(
        summary[0].contains("StrictHostKeyChecking (1)"),
        "{}",
        summary[0]
    );
    let tabs = host(&plan, "tabs");
    assert_eq!(tabs.address, "tabs.example.com");
    assert_eq!(tabs.username.as_deref(), Some("bob"));
}

#[test]
fn match_blocks_are_skipped() {
    let plan = ssh_fixture("match_block");
    assert_eq!(host(&plan, "b").username.as_deref(), Some("bob"));
    assert!(
        plan.skipped
            .iter()
            .any(|s| s.reason.starts_with("Match host b"))
    );
}

// ------------------------------------------------------------------ T-08

#[test]
fn t08_csv() {
    let text = std::fs::read_to_string(fixtures().join("csv/hosts.csv")).unwrap_or_default();
    let plan = csv::parse(&text).unwrap_or_else(|e| panic!("{e}"));
    insta::assert_snapshot!("csv_hosts", plan.render_table());
    let web = host(&plan, "Web");
    assert_eq!(web.username.as_deref(), Some("alice"));
    let tags: Vec<&str> = web.tags.iter().map(|t| plan.label_of(*t)).collect();
    assert_eq!(tags, ["prod", "web"]);
    let db = host(&plan, "DB, primary");
    assert_eq!(db.port, Some(5432));
    let tags: Vec<&str> = db.tags.iter().map(|t| plan.label_of(*t)).collect();
    assert_eq!(tags, ["prod", "db"]);
    // Group path Prod/Web: two levels, Prod shared.
    let web_group = web.group.map(|g| &plan.items[g]);
    let Some(Draft::Group(g)) = web_group.map(|i| &i.draft) else {
        panic!("no group");
    };
    assert_eq!(g.name, "Web");
    assert_eq!(g.parent.map(|p| plan.label_of(p)), Some("Prod"));
    assert_eq!(
        plan.items
            .iter()
            .filter(|i| i.kind == ItemKind::Group && i.label == "Prod")
            .count(),
        1
    );
    assert!(
        plan.skipped
            .iter()
            .any(|s| s.source_line.as_deref() == Some("line 4") && s.reason.contains("port"))
    );
    assert!(
        plan.skipped
            .iter()
            .any(|s| s.source_line.as_deref() == Some("line 6") && s.reason.contains("address"))
    );
    assert!(plan.warnings.iter().any(|w| w.contains("notes")));
    assert_eq!(host(&plan, "10.0.0.9").address, "10.0.0.9");

    let bad = std::fs::read_to_string(fixtures().join("csv/no_address.csv")).unwrap_or_default();
    assert!(matches!(csv::parse(&bad), Err(ImportError::Format(_))));
}

// ------------------------------------------------------------------ known_hosts

#[test]
fn known_hosts_import() {
    let text =
        std::fs::read_to_string(fixtures().join("known_hosts/known_hosts")).unwrap_or_default();
    let mut plan = known_hosts::parse(&text);
    assert_eq!(plan.items.len(), 4);
    assert!(
        plan.items
            .iter()
            .any(|i| matches!(&i.draft, Draft::KnownHost(k) if k.host_pattern.starts_with("|1|")))
    );
    assert_eq!(plan.skipped.len(), 2); // the repeated line and the broken one
    // One already in the vault → duplicate.
    let mut c = clock();
    let Draft::KnownHost(first) = plan.items[0].draft.clone() else {
        panic!("not a known host");
    };
    let mut body = ItemBody::new(ItemKind::KnownHost, current_schema(ItemKind::KnownHost));
    first.apply_to(&mut body, &mut c, dev(1));
    let existing = Existing::new(
        [ExistingItem {
            id: ItemId::from_bytes([9; 16]),
            vault: vault(),
            body,
        }],
        vault(),
    );
    classify(&mut plan, &existing, None);
    assert_eq!(plan.counts().duplicate, 1);
    assert_eq!(plan.counts().new, 3);
}

// ------------------------------------------------------------------ T-09

fn existing_host(c: &mut HlcClock, h: &Host) -> ExistingItem {
    let mut body = ItemBody::new(ItemKind::Host, current_schema(ItemKind::Host));
    h.apply_to(&mut body, c, dev(1));
    ExistingItem {
        id: ItemId::from_bytes([42; 16]),
        vault: vault(),
        body,
    }
}

#[test]
fn t09_duplicate_and_conflict() {
    let mut c = clock();
    let opts = SshConfigOptions::in_dir("/nonexistent");
    let same = Host {
        label: "web".to_owned(),
        address: "web.example.com".to_owned(),
        port: Some(2222),
        username: Some("deploy".to_owned()),
        ..Host::default()
    };
    let existing = Existing::new([existing_host(&mut c, &same)], vault());
    let mut plan = parse_str(
        "Host web\n HostName web.example.com\n Port 2222\n User deploy\n",
        &opts,
    );
    classify(&mut plan, &existing, None);
    assert_eq!(
        plan.items[0].status,
        PlanStatus::Duplicate(ItemId::from_bytes([42; 16]))
    );

    let mut plan = parse_str(
        "Host www\n HostName web.example.com\n Port 2222\n User deploy\n",
        &opts,
    );
    classify(&mut plan, &existing, None);
    let PlanStatus::Conflict(id, diffs) = &plan.items[0].status else {
        panic!("expected a conflict: {:?}", plan.items[0].status);
    };
    assert_eq!(*id, ItemId::from_bytes([42; 16]));
    assert_eq!(
        diffs,
        &[FieldDiff {
            field: "label".to_owned(),
            existing: "web".to_owned(),
            imported: "www".to_owned(),
        }]
    );
    assert!(plan.render_table().contains("~ label: web -> www"));

    // Another user → new.
    let mut plan = parse_str(
        "Host web\n HostName web.example.com\n Port 2222\n User root\n",
        &opts,
    );
    classify(&mut plan, &existing, None);
    assert_eq!(plan.items[0].status, PlanStatus::New);
}

#[test]
fn conflict_policies() {
    let mut c = clock();
    let opts = SshConfigOptions::in_dir("/nonexistent");
    let old = Host {
        label: "web".to_owned(),
        address: "web.example.com".to_owned(),
        notes: Some("keep me".to_owned()),
        ..Host::default()
    };
    let existing = Existing::new([existing_host(&mut c, &old)], vault());
    let mut plan = parse_str(
        "Host www\n HostName web.example.com\n ServerAliveInterval 5\n",
        &opts,
    );
    classify(&mut plan, &existing, None);
    let run = |policy| {
        let mut c = clock();
        let o = ApplyOptions {
            vault: Some(vault()),
            policy,
            ..ApplyOptions::default()
        };
        materialize(&plan, &existing, &o, &mut c, dev(2), &mut seq_ids())
            .unwrap_or_else(|e| panic!("{e}"))
    };
    assert!(run(ConflictPolicy::Skip).writes.is_empty());
    let w = run(ConflictPolicy::Overwrite);
    assert_eq!(w.writes.len(), 1);
    assert_eq!(w.writes[0].action, WriteAction::Update);
    assert_eq!(w.writes[0].id, ItemId::from_bytes([42; 16]));
    let h = Host::try_from(&w.writes[0].body).unwrap_or_default();
    assert_eq!(h.label, "www");
    assert_eq!(h.keepalive_secs, Some(5));
    assert_eq!(h.notes.as_deref(), Some("keep me"));
    let w = run(ConflictPolicy::KeepBoth);
    assert_eq!(w.writes[0].action, WriteAction::Create);
    assert_ne!(w.writes[0].id, ItemId::from_bytes([42; 16]));
}

// ------------------------------------------------------------------ materialize

fn written<'a>(w: &'a [ItemWrite], kind: ItemKind, label: &str) -> &'a ItemWrite {
    w.iter()
        .find(|w| w.body.kind == kind && preview::body_label(&w.body) == label)
        .unwrap_or_else(|| panic!("no {kind} {label}"))
}

#[test]
fn materialize_links_references() {
    let mut plan = ssh_fixture("wildcard");
    let target_group = ItemId::from_bytes([77; 16]);
    let existing = Existing::new([], vault());
    classify(&mut plan, &existing, Some(target_group));
    let mut c = clock();
    let key = ItemId::from_bytes([88; 16]);
    let opts = ApplyOptions {
        vault: Some(vault()),
        group: Some(target_group),
        ..ApplyOptions::default()
    };
    let w = materialize(&plan, &existing, &opts, &mut c, dev(3), &mut seq_ids())
        .unwrap_or_else(|e| panic!("{e}"));
    let _ = key;
    let defaults = written(&w.writes, ItemKind::Group, DEFAULTS_GROUP);
    let prod = written(&w.writes, ItemKind::Group, "*.prod");
    let g = Group::try_from(&prod.body).unwrap_or_default();
    assert_eq!(g.parent_id, Some(defaults.id));
    assert_eq!(g.defaults.username.as_deref(), Some("deploy"));
    let dg = Group::try_from(&defaults.body).unwrap_or_default();
    assert_eq!(dg.parent_id, Some(target_group));
    let web =
        Host::try_from(&written(&w.writes, ItemKind::Host, "web.prod").body).unwrap_or_default();
    assert_eq!(web.group_id, Some(prod.id));
    assert!(w.writes.iter().all(|x| x.vault == vault()));

    // Forwards and jump chains point at the new ids; auto_start is on.
    let mut plan = ssh_fixture("forwards");
    classify(&mut plan, &existing, None);
    let w = materialize(&plan, &existing, &opts, &mut c, dev(3), &mut seq_ids())
        .unwrap_or_else(|e| panic!("{e}"));
    let t = written(&w.writes, ItemKind::Host, "tunnels");
    let host = Host::try_from(&t.body).unwrap_or_default();
    assert_eq!(host.port_forwards.len(), 4);
    for f in w
        .writes
        .iter()
        .filter(|x| x.body.kind == ItemKind::PortForward)
    {
        let rule = PortForward::try_from(&f.body).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(rule.host_id, t.id);
        assert!(rule.auto_start);
        assert!(host.port_forwards.contains(&f.id));
    }
    // The non-loopback bind is approved at confirmation.
    assert!(
        w.approvals
            .iter()
            .any(|a| a.field == "bind_addr" && a.value == "0.0.0.0:8080")
    );
}

// ------------------------------------------------------------------ T-17 (core part)

#[test]
fn t17_proxy_command_approval_notes() {
    let mut plan = ssh_fixture("proxyjump");
    let existing = Existing::new([], vault());
    classify(&mut plan, &existing, None);
    let mut c = clock();
    let opts = ApplyOptions {
        vault: Some(vault()),
        ..ApplyOptions::default()
    };
    let w = materialize(&plan, &existing, &opts, &mut c, dev(3), &mut seq_ids())
        .unwrap_or_else(|e| panic!("{e}"));
    let cmd = written(&w.writes, ItemKind::Host, "cmd");
    assert_eq!(
        w.approvals,
        [ApprovalNote {
            item_id: cmd.id,
            field: "proxy.command".to_owned(),
            value: "ssh -W %h:%p bastion.example.com".to_owned(),
        }]
    );
    let h = Host::try_from(&cmd.body).unwrap_or_default();
    assert!(matches!(h.proxy, Some(Proxy::Command(_))));
    // The jump chain is ordered and linked.
    let target =
        Host::try_from(&written(&w.writes, ItemKind::Host, "target").body).unwrap_or_default();
    let bastion = written(&w.writes, ItemKind::Host, "user@bastion:2222");
    let inner = written(&w.writes, ItemKind::Host, "inner");
    assert_eq!(target.jump_chain, [bastion.id, inner.id]);
}

// ------------------------------------------------------------------ backups (T-11 core)

const PW: &str = "correct horse battery staple 42";
const M_KIB: u32 = sverb_crypto::kdf::Argon2Params::MIN_M_KIB;

fn sample_payload() -> BackupPayload {
    let mut c = clock();
    let mut h = ItemBody::new(ItemKind::Host, current_schema(ItemKind::Host));
    Host {
        label: "db".to_owned(),
        address: "db.example.com".to_owned(),
        password: Some(crate::secret::SecretString::from("CANARY-secret")),
        ..Host::default()
    }
    .apply_to(&mut h, &mut c, dev(5));
    let mut t = ItemBody::new(ItemKind::Tag, current_schema(ItemKind::Tag));
    Tag {
        name: "prod".to_owned(),
        ..Tag::default()
    }
    .apply_to(&mut t, &mut c, dev(5));
    BackupPayload {
        vaults: vec![BackupVault {
            id: vault(),
            name: "Personal".to_owned(),
            kind: "personal".to_owned(),
            defaults: None,
        }],
        items: vec![
            BackupItem {
                id: ItemId::from_bytes([1; 16]),
                vault: vault(),
                body: h,
            },
            BackupItem {
                id: ItemId::from_bytes([2; 16]),
                vault: vault(),
                body: t,
            },
        ],
    }
}

fn encrypt(p: &BackupPayload) -> String {
    exporters::backup::encrypt(p, PW, M_KIB, 1, 1, crate::model::UnixMillis(0))
        .unwrap_or_else(|e| panic!("{e}"))
}

#[test]
fn t11_backup_roundtrip_core() {
    let payload = sample_payload();
    let text = encrypt(&payload);
    assert!(!text.contains("CANARY"));
    let back = bk::decrypt(&text, PW).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(back, payload);
    // Restore into an empty vault: same ids, identical bodies (stamps included).
    let mut plan = bk::plan(&back);
    let existing = Existing::new([], vault());
    classify(&mut plan, &existing, None);
    assert_eq!(plan.counts().new, 2);
    let mut c = clock();
    let opts = ApplyOptions {
        vault: Some(vault()),
        ..ApplyOptions::default()
    };
    let w = materialize(&plan, &existing, &opts, &mut c, dev(9), &mut seq_ids())
        .unwrap_or_else(|e| panic!("{e}"));
    let got: BTreeMap<ItemId, &ItemBody> = w.writes.iter().map(|x| (x.id, &x.body)).collect();
    for item in &payload.items {
        assert_eq!(got.get(&item.id), Some(&&item.body));
    }
    // Importing again: everything is a duplicate.
    let existing = Existing::new(
        payload.items.iter().map(|i| ExistingItem {
            id: i.id,
            vault: vault(),
            body: i.body.clone(),
        }),
        vault(),
    );
    let mut plan = bk::plan(&back);
    classify(&mut plan, &existing, None);
    assert_eq!(plan.counts().duplicate, 2);
}

#[test]
fn t12_backup_errors() {
    let text = encrypt(&sample_payload());
    let wrong = bk::decrypt(&text, "not the password at all");
    assert_eq!(wrong, Err(BackupError::Decrypt));
    assert!(
        BackupError::Decrypt
            .to_string()
            .contains("wrong export password"),
        "a clear message"
    );
    // Tampered ciphertext → auth error.
    let mut file: bk::BackupFile = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{e}"));
    let mut ct = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(&file.ciphertext_b64)
            .unwrap_or_default()
    };
    ct[3] ^= 0x40;
    file.ciphertext_b64 = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(&ct)
    };
    let tampered = serde_json::to_string(&file).unwrap_or_default();
    assert_eq!(bk::decrypt(&tampered, PW), Err(BackupError::Decrypt));
    // A newer version → unsupported.
    let newer = text.replace("\"version\": 1", "\"version\": 2");
    assert_eq!(
        bk::decrypt(&newer, PW),
        Err(BackupError::UnsupportedVersion(2))
    );
    assert!(matches!(
        bk::decrypt("{}", PW),
        Err(BackupError::NotABackup(_))
    ));
    // Weak export passwords are refused.
    assert!(exporters::backup::check_password("password").is_err());
    assert!(exporters::backup::check_password(PW).is_ok());
}

// ------------------------------------------------------------------ T-13

#[test]
fn t13_ssh_config_export() {
    let a = ItemId::from_bytes([1; 16]);
    let b = ItemId::from_bytes([2; 16]);
    let g = ItemId::from_bytes([3; 16]);
    let mut groups = BTreeMap::new();
    groups.insert(
        g,
        Group {
            name: "prod".to_owned(),
            defaults: crate::model::HostDefaults {
                username: Some("deploy".to_owned()),
                keepalive_secs: Some(30),
                ..Default::default()
            },
            ..Group::default()
        },
    );
    let data = exporters::ssh_config::SshConfigExport {
        hosts: vec![
            (
                a,
                Host {
                    label: "bastion host".to_owned(),
                    address: "bastion.example.com".to_owned(),
                    port: Some(2222),
                    password: Some(crate::secret::SecretString::from("CANARY-password")),
                    ..Host::default()
                },
            ),
            (
                b,
                Host {
                    label: "db".to_owned(),
                    address: "10.0.0.5".to_owned(),
                    group_id: Some(g),
                    jump_chain: vec![a],
                    proxy: None,
                    agent_forwarding: Some(true),
                    env: vec![("GREETING".to_owned(), "hello world".to_owned())],
                    key_id: Some(ItemId::from_bytes([9; 16])),
                    ..Host::default()
                },
            ),
        ],
        groups,
        forwards: vec![PortForward {
            label: "pg".to_owned(),
            kind: ForwardKind::Local,
            host_id: b,
            bind_addr: "127.0.0.1".to_owned(),
            bind_port: 5432,
            dest_host: Some("localhost".to_owned()),
            dest_port: Some(5432),
            auto_start: true,
            read_only: false,
        }],
        key_paths: BTreeMap::new(),
    };
    let text = exporters::ssh_config::export(&data);
    assert!(text.contains(exporters::SECRETS_WARNING));
    assert!(!text.contains("CANARY"));
    insta::assert_snapshot!("ssh_config_export", text);
    // The export parses back.
    let plan = parse_str(&text, &SshConfigOptions::in_dir("/nonexistent"));
    let db = host(&plan, "db");
    assert_eq!(db.username.as_deref(), Some("deploy"));
    assert_eq!(
        db.jump_chain
            .iter()
            .map(|r| plan.label_of(*r))
            .collect::<Vec<_>>(),
        ["bastion-host"]
    );
}

#[test]
fn csv_export_roundtrip() {
    let rows = vec![exporters::csv::CsvRow {
        label: "DB, primary".to_owned(),
        address: "db.example.com".to_owned(),
        port: Some(5432),
        username: Some("pg".to_owned()),
        group: Some("Prod/DB".to_owned()),
        tags: vec!["prod".to_owned(), "db".to_owned()],
    }];
    let text = exporters::csv::export(&rows).unwrap_or_default();
    assert!(text.starts_with("label,address,port,username,group,tags\n"));
    let plan = csv::parse(&text).unwrap_or_else(|e| panic!("{e}"));
    let h = host(&plan, "DB, primary");
    assert_eq!(h.port, Some(5432));
    assert_eq!(h.tags.len(), 2);
}

#[test]
fn t14_write_file_mode_and_refusal() {
    let dir = std::env::temp_dir().join(format!("sverb-m2-11-mode-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
    let f = dir.join("out");
    exporters::write_file(&f, b"one", false).unwrap_or_else(|e| panic!("{e}"));
    let again = exporters::write_file(&f, b"two", false);
    assert_eq!(
        again.map_err(|e| e.kind()),
        Err(std::io::ErrorKind::AlreadyExists)
    );
    assert_eq!(std::fs::read(&f).unwrap_or_default(), b"one");
    exporters::write_file(&f, b"two", true).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(std::fs::read(&f).unwrap_or_default(), b"two");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&f)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0);
        assert_eq!(mode, 0o600);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------ robustness

#[test]
fn parser_never_panics_on_garbage() {
    for text in [
        "",
        "=",
        "Host",
        "Host \"",
        "Port 99999999",
        "Host *\nProxyJump ,,,",
        "Host a\nLocalForward [::1",
        "Host a\nHostName %",
        "Host [\nUser x",
        "\u{feff}Host a\n",
    ] {
        let _ = super::ssh_config::parse_str_no_include(text).render_table();
    }
}

proptest::proptest! {
    // T-16 (in-tree half): the fuzz target's body on random config-like text.
    #[test]
    fn ssh_config_parser_never_panics(text in "(?s)((Host|Match|User|Port|ProxyJump|LocalForward|HostName|Include|SetEnv|IdentityFile|=|\"|'|#|%h|%|\\*|!|,|:|\\[|\\]|/|@| |\t|\n|[a-z0-9.])){0,200}") {
        let plan = super::ssh_config::parse_str_no_include(&text);
        let _ = plan.render_table();
    }

    #[test]
    fn csv_parser_never_panics(text in "(?s)((address|label|port|group|tags|,|\"|;|\\||/|\n|[a-z0-9. ])){0,200}") {
        let _ = csv::parse(&text);
    }
}

// The `backup_decrypt` fuzz target's body (`bk::fuzz_backup_decrypt`), on a real
// backup file, on a real authenticated plaintext (zstd + CBOR), and on random bytes.
#[test]
fn backup_decrypt_fuzz_body_seeds() {
    let payload = sample_payload();
    bk::fuzz_backup_decrypt(encrypt(&payload).as_bytes());
    let mut cbor = Vec::new();
    ciborium::into_writer(&payload, &mut cbor).unwrap_or_else(|e| panic!("{e}"));
    let compressed = zstd::encode_all(cbor.as_slice(), 3).unwrap_or_else(|e| panic!("{e}"));
    bk::fuzz_backup_decrypt(&compressed);
    // Truncations of both never panic either.
    for cut in [0, 1, 7, compressed.len() / 2, compressed.len() - 1] {
        bk::fuzz_backup_decrypt(&compressed[..cut]);
    }
}

proptest::proptest! {
    #[test]
    fn backup_decrypt_fuzz_body_never_panics(data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..1024)) {
        bk::fuzz_backup_decrypt(&data);
    }
}
