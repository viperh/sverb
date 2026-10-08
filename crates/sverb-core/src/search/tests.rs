//! M1-05 unit tests (T-01 … T-11).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;

use ciborium::Value;
use pretty_assertions::assert_eq;

use super::*;
use crate::host_arg::MatchKind;
use crate::model::{DeviceId, HlcClock, ItemBody, ItemId, ItemKind, VaultId};

/// Builds bodies and an index.
struct Fx {
    clock: HlcClock,
    device: DeviceId,
    vault: VaultId,
    team: VaultId,
    items: Vec<(ItemId, VaultId, ItemBody)>,
}

impl Fx {
    fn new() -> Self {
        Self {
            clock: HlcClock::default(),
            device: DeviceId::new(),
            vault: VaultId::new(),
            team: VaultId::new(),
            items: Vec::new(),
        }
    }

    fn body(&mut self, kind: ItemKind, fields: &[(&str, Value)]) -> ItemBody {
        let mut body = ItemBody::new(kind, 1);
        for (k, v) in fields {
            body.set(k, v.clone(), &mut self.clock, self.device);
        }
        body
    }

    fn add(&mut self, kind: ItemKind, fields: &[(&str, Value)]) -> ItemId {
        let vault = self.vault;
        self.add_in(vault, kind, fields)
    }

    fn add_in(&mut self, vault: VaultId, kind: ItemKind, fields: &[(&str, Value)]) -> ItemId {
        let id = ItemId::new();
        let body = self.body(kind, fields);
        self.items.push((id, vault, body));
        id
    }

    fn tag(&mut self, name: &str) -> ItemId {
        self.add(ItemKind::Tag, &[("name", t(name))])
    }

    fn host(&mut self, label: &str, address: &str, tags: &[ItemId]) -> ItemId {
        self.add(
            ItemKind::Host,
            &[
                ("label", t(label)),
                ("address", t(address)),
                ("tags", idv(tags)),
            ],
        )
    }

    fn index(&self) -> ItemIndex {
        let mut index = ItemIndex::build(self.items.iter().map(|(i, v, b)| (*i, *v, b)));
        index.set_vault_name(self.vault, "Personal");
        index.set_vault_name(self.team, "Team Infra");
        index
    }
}

fn t(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn idv(ids: &[ItemId]) -> Value {
    Value::Array(
        ids.iter()
            .map(|i| Value::Bytes(i.as_bytes().to_vec()))
            .collect(),
    )
}

fn ids(snap: &IndexSnapshot, q: &str, scope: Scope) -> Vec<ItemId> {
    snap.query(&Query::parse(q), scope)
        .into_iter()
        .map(|h| h.item_id)
        .collect()
}

fn labels(snap: &IndexSnapshot, q: &str, scope: Scope) -> Vec<String> {
    ids(snap, q, scope)
        .into_iter()
        .map(|id| snap.get(id).unwrap().display_label().to_owned())
        .collect()
}

#[test]
fn query_parsing() {
    let q = Query::parse(r#"web #Prod  @team kind:hosts "db primary" #eu kind:nope "open"#);
    assert_eq!(q.terms, vec!["web"]);
    assert_eq!(q.phrases, vec!["db primary", "open"]);
    assert_eq!(q.tags, vec!["prod", "eu"]);
    assert_eq!(q.vaults, vec!["team"]);
    assert_eq!(q.kinds, vec![ItemKind::Host]);
    assert!(q.unknown_kind);
    assert!(Query::parse("  # @ ").is_empty());
    assert_eq!(parse_kind("port_forwards"), Some(ItemKind::PortForward));
    assert_eq!(parse_kind("Snippet"), Some(ItemKind::Snippet));
}

// T-01
#[test]
fn t01_fuzzy_basic() {
    let mut fx = Fx::new();
    fx.host("prod-web-1", "10.0.0.1", &[]);
    fx.host("prod-db", "10.0.0.2", &[]);
    fx.host("staging-web", "10.0.0.3", &[]);
    let snap = fx.index().snapshot();
    let got = labels(&snap, "pw1", Scope::Hosts);
    assert_eq!(got.first().map(String::as_str), Some("prod-web-1"));
    assert_eq!(labels(&snap, "zzz", Scope::Hosts), Vec::<String>::new());
    // Empty query: everything, alphabetical.
    assert_eq!(
        labels(&snap, "", Scope::Hosts),
        vec!["prod-db", "prod-web-1", "staging-web"]
    );
}

// T-02
#[test]
fn t02_tag_filter() {
    let mut fx = Fx::new();
    let prod = fx.tag("Prod");
    let dev = fx.tag("dev");
    fx.host("web-a", "a", &[prod]);
    fx.host("web-b", "b", &[dev]);
    fx.host("db-a", "c", &[prod]);
    let snap = fx.index().snapshot();
    assert_eq!(labels(&snap, "#prod web", Scope::Hosts), vec!["web-a"]);
    assert_eq!(labels(&snap, "#PROD", Scope::Hosts), vec!["db-a", "web-a"]);
    assert_eq!(
        labels(&snap, "#pro", Scope::Hosts),
        Vec::<String>::new(),
        "exact tag"
    );
}

// T-03
#[test]
fn t03_multiple_tags_and() {
    let mut fx = Fx::new();
    let prod = fx.tag("prod");
    let eu = fx.tag("eu");
    fx.host("h1", "a", &[prod, eu]);
    fx.host("h2", "b", &[prod]);
    fx.host("h3", "c", &[eu]);
    let snap = fx.index().snapshot();
    assert_eq!(labels(&snap, "#prod #eu", Scope::Hosts), vec!["h1"]);
}

// T-04
#[test]
fn t04_vault_filter() {
    let mut fx = Fx::new();
    let team = fx.team;
    fx.host("mine", "a", &[]);
    fx.add_in(
        team,
        ItemKind::Host,
        &[("label", t("shared")), ("address", t("b"))],
    );
    let snap = fx.index().snapshot();
    assert_eq!(labels(&snap, "@team", Scope::Hosts), vec!["shared"]);
    assert_eq!(labels(&snap, "@Pers", Scope::Hosts), vec!["mine"]);
    assert_eq!(
        labels(&snap, "@infra", Scope::Hosts),
        Vec::<String>::new(),
        "prefix"
    );
    assert_eq!(snap.vault_name(team), Some("Team Infra"));
}

// T-05
#[test]
fn t05_quoted_phrase_is_substring() {
    let mut fx = Fx::new();
    fx.host("db-primary", "a", &[]);
    fx.host("db-x-primary", "b", &[]);
    let snap = fx.index().snapshot();
    assert_eq!(
        labels(&snap, "\"db-primary\"", Scope::Hosts),
        vec!["db-primary"]
    );
    assert_eq!(
        labels(&snap, "db-primary", Scope::Hosts).len(),
        2,
        "fuzzy matches both"
    );
}

// T-06
#[test]
fn t06_ordering_pinned_frecency_alpha() {
    let mut fx = Fx::new();
    let b = fx.host("b-host", "x", &[]);
    let a = fx.host("a-host", "x", &[]);
    let c = fx.host("c-host", "x", &[]);
    let pinned = fx.add(
        ItemKind::Host,
        &[
            ("label", t("z-host")),
            ("address", t("x")),
            ("pinned", Value::Bool(true)),
        ],
    );
    let mut index = fx.index();
    let snap = index.snapshot();
    // Equal scores (no text): pinned, then alphabetical.
    assert_eq!(ids(&snap, "", Scope::Hosts), vec![pinned, a, b, c]);
    // Frecency beats alphabetical, not pinned.
    index.set_frecency(HashMap::from([(c, 3.0), (b, 1.0)]));
    let snap = index.snapshot();
    assert_eq!(ids(&snap, "", Scope::Hosts), vec![pinned, c, b, a]);
    // Same ordering for a query whose scores tie ("host" scores alike on all four).
    let hits = snap.query(&Query::parse("host"), Scope::Hosts);
    assert!(hits.windows(2).all(|w| w[0].score == w[1].score));
    assert_eq!(
        hits.iter().map(|h| h.item_id).collect::<Vec<_>>(),
        vec![pinned, c, b, a]
    );
    // An explicit lookup overrides the snapshot's frecency.
    let lookup = HashMap::from([(a, 9.0)]);
    let ordered: Vec<_> = snap
        .ordered(Scope::Hosts, &lookup)
        .iter()
        .map(|e| e.item_id)
        .collect();
    assert_eq!(ordered, vec![pinned, a, b, c]);
}

// T-07
#[test]
fn t07_no_secrets_indexed() {
    let mut fx = Fx::new();
    fx.add(
        ItemKind::Host,
        &[
            ("label", t("canary-host")),
            ("address", t("h")),
            ("password", t("CANARY-PW")),
            ("proxy.kind", t("socks5")),
            ("proxy.auth.user", t("u")),
            ("proxy.auth.password", t("CANARY-PROXY")),
        ],
    );
    let var = Value::Map(vec![
        (t("name"), t("token")),
        (t("default"), t("CANARY-VAR")),
        (t("secret"), Value::Bool(true)),
    ]);
    fx.add(
        ItemKind::Snippet,
        &[
            ("name", t("deploy")),
            ("script", t("echo {{token}}")),
            ("variables", Value::Array(vec![var])),
        ],
    );
    fx.add(
        ItemKind::Key,
        &[
            ("label", t("k")),
            ("algorithm", t("ed25519")),
            ("private_key", t("CANARY-KEY")),
            ("passphrase", t("CANARY-PASS")),
        ],
    );
    fx.add(
        ItemKind::Identity,
        &[
            ("label", t("ops")),
            ("username", t("root")),
            ("password", t("CANARY-ID")),
        ],
    );
    let snap = fx.index().snapshot();
    assert_eq!(snap.len(), 4);
    for e in snap.entries() {
        for s in [
            &e.search_text,
            &e.body_text,
            &e.label,
            &e.address,
            &e.user,
            &e.group_path,
        ] {
            assert!(!s.contains("CANARY"), "{:?} leaks a secret", e.kind);
        }
    }
    for q in [
        "CANARY",
        "\"CANARY\"",
        "canary-pw",
        "\"CANARY-VAR\"",
        "CANARY-KEY",
        "CANARY-ID",
    ] {
        let hits = ids(&snap, q, Scope::Palette);
        // Only the host's *label* may match "canary".
        for id in hits {
            assert_eq!(
                snap.get(id).unwrap().display_label(),
                "canary-host",
                "query {q}"
            );
        }
    }
    assert!(ids(&snap, "\"CANARY-VAR\"", Scope::Palette).is_empty());
    assert!(ids(&snap, "\"CANARY-PW\"", Scope::Palette).is_empty());
    // Snippet bodies are searchable in the Snippets view and the palette only.
    assert_eq!(labels(&snap, "\"echo\"", Scope::Snippets), vec!["deploy"]);
    assert_eq!(labels(&snap, "\"echo\"", Scope::Palette), vec!["deploy"]);
    assert!(ids(&snap, "\"echo\"", Scope::All).is_empty());
    assert!(ids(&snap, "\"echo\"", Scope::Hosts).is_empty());
    // Variable names are searchable, their defaults are not.
    assert_eq!(labels(&snap, "token", Scope::Snippets), vec!["deploy"]);
}

// T-08
#[test]
fn t08_incremental_tag_and_group_rename() {
    let mut fx = Fx::new();
    let prod = fx.tag("prod");
    let eu = fx.add(ItemKind::Group, &[("name", t("eu"))]);
    let web = fx.add(
        ItemKind::Group,
        &[
            ("name", t("web")),
            ("parent_id", Value::Bytes(eu.as_bytes().to_vec())),
        ],
    );
    let h1 = fx.host("h1", "a", &[prod]);
    let h2 = fx.host("h2", "b", &[prod]);
    let h3 = fx.add(
        ItemKind::Host,
        &[
            ("label", t("h3")),
            ("address", t("c")),
            ("group_id", Value::Bytes(web.as_bytes().to_vec())),
        ],
    );
    let vault = fx.vault;
    let mut index = fx.index();
    let snap = index.snapshot();
    assert_eq!(&*snap.get(h3).unwrap().group_path, "eu / web");
    assert_eq!(&*snap.get(web).unwrap().group_path, "eu");
    let before = snap.version();

    // Rename tag prod -> production.
    let renamed = fx.body(ItemKind::Tag, &[("name", t("production"))]);
    index.upsert(prod, vault, &renamed);
    let snap2 = index.snapshot();
    assert!(snap2.version() > before);
    for h in [h1, h2] {
        assert_eq!(
            snap2
                .get(h)
                .unwrap()
                .tags
                .iter()
                .map(|t| t.as_str())
                .collect::<Vec<_>>(),
            vec!["production"]
        );
    }
    let mut got = ids(&snap2, "#production", Scope::Hosts);
    got.sort();
    let mut want = vec![h1, h2];
    want.sort();
    assert_eq!(got, want);
    assert!(ids(&snap2, "#prod", Scope::Hosts).is_empty());
    // The old snapshot is unchanged (immutable).
    assert_eq!(ids(&snap, "#prod", Scope::Hosts).len(), 2);

    // Rename the ancestor group: the grandchild host's path follows.
    let eu2 = fx.body(ItemKind::Group, &[("name", t("europe"))]);
    index.upsert(eu, vault, &eu2);
    let snap3 = index.snapshot();
    assert_eq!(&*snap3.get(h3).unwrap().group_path, "europe / web");
    assert_eq!(labels(&snap3, "\"europe\"", Scope::Hosts), vec!["h3"]);

    // Deleting the tag item drops its name from the hosts.
    index.remove(prod);
    let snap4 = index.snapshot();
    assert!(snap4.get(h1).unwrap().tags.is_empty());

    // A group cycle does not hang.
    let cyc = fx.body(
        ItemKind::Group,
        &[
            ("name", t("europe")),
            ("parent_id", Value::Bytes(web.as_bytes().to_vec())),
        ],
    );
    index.upsert(eu, vault, &cyc);
    assert!(index.snapshot().get(h3).is_some());
}

// T-09
#[test]
fn t09_deleted_items_are_removed() {
    let mut fx = Fx::new();
    let gone = fx.host("gone", "a", &[]);
    let stays = fx.host("stays", "b", &[]);
    // A body that is already deleted at build time is not indexed.
    let mut dead = fx.body(ItemKind::Host, &[("label", t("dead")), ("address", t("c"))]);
    dead.delete(&mut fx.clock, fx.device);
    let dead_id = ItemId::new();
    fx.items.push((dead_id, fx.vault, dead));
    let vault = fx.vault;
    let mut index = fx.index();
    assert_eq!(index.len(), 2);
    assert!(index.get(dead_id).is_none());

    let mut body = fx.body(ItemKind::Host, &[("label", t("gone")), ("address", t("a"))]);
    body.delete(&mut fx.clock, fx.device);
    index.upsert(gone, vault, &body);
    let snap = index.snapshot();
    assert!(snap.get(gone).is_none());
    assert_eq!(ids(&snap, "", Scope::Hosts), vec![stays]);
    assert!(index.remove(stays));
    assert!(!index.remove(stays));
    assert!(index.snapshot().is_empty());
}

// T-10 (same table as M0-07 T-07)
#[test]
fn t10_resolve_host_arg_table() {
    let mut fx = Fx::new();
    let h1 = fx.host("prod-web-1", "10.0.0.1", &[]);
    let h2 = fx.host("prod-web-2", "10.0.0.2", &[]);
    let h3 = fx.host("db", "10.0.1.5", &[]);
    let snap = fx.index().snapshot();
    let ok = |q: &str| resolve_host_arg_kind(&snap, q);
    assert_eq!(ok("db"), Ok((h3, MatchKind::Label)));
    assert_eq!(ok("10.0.0.1"), Ok((h1, MatchKind::Address)));
    assert_eq!(ok("web-2"), Ok((h2, MatchKind::Fuzzy)));
    assert_eq!(
        ok("web"),
        Err(ResolveError::Ambiguous {
            query: "web".into(),
            candidates: vec!["prod-web-1".into(), "prod-web-2".into()],
            total: 2,
        })
    );
    assert_eq!(
        ok("zzz"),
        Err(ResolveError::NotFound {
            query: "zzz".into()
        })
    );
    assert_eq!(resolve_host_arg(&snap, "db"), Ok(h3));
}

// T-11
#[test]
fn t11_highlights_are_char_indices() {
    let mut fx = Fx::new();
    let id = fx.host("bücher-host", "10.1.1.1", &[]);
    let snap = fx.index().snapshot();
    let hit = |q: &str| {
        snap.query(&Query::parse(q), Scope::Hosts)
            .into_iter()
            .find(|h| h.item_id == id)
            .unwrap()
            .highlights
    };
    assert_eq!(hit("host"), vec![7, 8, 9, 10]);
    assert_eq!(hit("\"cher\""), vec![2, 3, 4, 5]);
    // Normalization: `u` matches `ü`.
    assert_eq!(hit("buch"), vec![0, 1, 2, 3]);
    // A match outside the label has no highlights.
    assert_eq!(hit("\"10.1\""), Vec::<u32>::new());
}

#[test]
fn smart_case_and_kind_filter() {
    let mut fx = Fx::new();
    fx.host("Web", "a", &[]);
    fx.host("web", "b", &[]);
    fx.add(
        ItemKind::Snippet,
        &[("name", t("web deploy")), ("script", t("ls"))],
    );
    let snap = fx.index().snapshot();
    assert_eq!(labels(&snap, "web", Scope::All).len(), 3);
    assert_eq!(labels(&snap, "Web", Scope::All), vec!["Web"]);
    assert_eq!(
        labels(&snap, "kind:snippet web", Scope::Palette),
        vec!["web deploy"]
    );
    assert!(labels(&snap, "kind:bogus", Scope::Palette).is_empty());
}

#[test]
fn snapshot_is_cached_until_a_change() {
    let mut fx = Fx::new();
    fx.host("a", "a", &[]);
    let mut index = fx.index();
    let s1 = index.snapshot();
    let s2 = index.snapshot();
    assert!(std::sync::Arc::ptr_eq(&s1, &s2));
    index.set_item_frecency(ItemId::new(), 1.0);
    assert!(!std::sync::Arc::ptr_eq(&s1, &index.snapshot()));
    assert!(format!("{s1:?}").contains("entries: 1"));
}

/// T-12 (query half, in-tree): 10k entries, a 5-char pattern, < 5 ms per query in
/// release builds (debug builds only check correctness). The full build including
/// decryption is measured in `benches/search.rs`.
#[test]
fn t12_query_10k_under_5ms() {
    let mut fx = Fx::new();
    let tags: Vec<ItemId> = (0..20).map(|i| fx.tag(&format!("tag{i}"))).collect();
    for i in 0..10_000 {
        fx.host(
            &format!("host-{i}-{}", ["web", "db", "cache", "queue"][i % 4]),
            &format!("10.{}.{}.{}", i / 65536, (i / 256) % 256, i % 256),
            &[tags[i % 20]],
        );
    }
    let snap = fx.index().snapshot();
    let q = Query::parse("hwb12");
    let _ = snap.query(&q, Scope::Hosts); // warm-up
    let start = std::time::Instant::now();
    let runs = 5;
    let mut n = 0;
    for _ in 0..runs {
        n = snap.query(&q, Scope::Hosts).len();
    }
    let per = start.elapsed() / runs;
    assert!(n > 0);
    if !cfg!(debug_assertions) {
        assert!(per.as_millis() < 5, "query took {per:?}");
    }
}
