//! form snapshots.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::sync::Arc;

use ratatui::layout::Rect;
use sverb_core::model::{DeviceId, HlcClock, Host, ItemBody, ItemId, ItemKind, VaultId};
use sverb_core::search::{IndexSnapshot, ItemIndex};

use super::catalog::{HostCatalog, HostSummary, TagInfo};
use super::form::{HostFormFeatures, HostFormInit, host_form};
use super::*;
use crate::views::shell::{ShellState, layout};
use crate::widgets::test_util::{draw_with, text};

const NOW: i64 = 1_800_000_000_000;
const MIN: i64 = 60_000;

fn id(n: u8) -> ItemId {
    let mut b = [0u8; 16];
    b[15] = n;
    ItemId::from_bytes(b)
}

fn vault() -> VaultId {
    VaultId::from_bytes([9; 16])
}

struct Fixture {
    index: Arc<IndexSnapshot>,
    catalog: HostCatalog,
}

/// Hosts `(n, host)`, frecency per id, last-connected per id.
fn fixture(hosts: Vec<(u8, Host)>, frecency: &[(u8, f64)], connected: &[(u8, i64)]) -> Fixture {
    let mut clock = HlcClock::default();
    let device = DeviceId::from_bytes([1; 16]);
    let web = id(200);
    let db = id(201);
    let mut bodies = Vec::new();
    for (tid, name, color) in [(web, "web", "green"), (db, "db", "#ff8800")] {
        let mut b = ItemBody::new(ItemKind::Tag, 1);
        b.set("name", name, &mut clock, device);
        b.set("color", color, &mut clock, device);
        bodies.push((tid, b));
    }
    let mut catalog = HostCatalog {
        loaded_at: NOW,
        ..HostCatalog::default()
    };
    catalog.tags.insert(
        web,
        TagInfo {
            name: "web".into(),
            color: Some("green".into()),
        },
    );
    catalog.tags.insert(
        db,
        TagInfo {
            name: "db".into(),
            color: Some("#ff8800".into()),
        },
    );
    for (n, mut host) in hosts {
        if n % 3 == 0 {
            host.tags = vec![web];
        } else if n % 5 == 0 {
            host.tags = vec![web, db];
        }
        let mut b = ItemBody::new(ItemKind::Host, 1);
        host.apply_to(&mut b, &mut clock, device);
        let last = connected.iter().find(|(c, _)| *c == n).map(|(_, t)| *t);
        catalog
            .hosts
            .insert(id(n), HostSummary::from_host(id(n), vault(), &host, last));
        bodies.push((id(n), b));
    }
    let mut ix = ItemIndex::build(bodies.iter().map(|(i, b)| (*i, vault(), b)));
    ix.set_frecency(
        frecency
            .iter()
            .map(|(n, f)| (id(*n), *f))
            .collect::<HashMap<_, _>>(),
    );
    Fixture {
        index: ix.snapshot(),
        catalog,
    }
}

fn host(label: &str, address: &str) -> Host {
    Host {
        label: label.into(),
        address: address.into(),
        ..Host::default()
    }
}

#[test]
fn t03_pinned_then_frecency_then_alpha_and_recent_last_10() {
    let mut hosts = vec![
        (1, host("zulu", "10.0.0.1")),
        (2, host("alpha", "10.0.0.2")),
        (4, host("Mike", "10.0.0.4")),
        (7, host("bravo", "10.0.0.7")),
    ];
    let mut pinned = host("yankee", "10.0.0.8");
    pinned.pinned = true;
    hosts.push((8, pinned));
    // 12 more hosts, each connected at a different time.
    for n in 20..32 {
        hosts.push((n, host(&format!("h{n}"), &format!("10.0.1.{n}"))));
    }
    let connected: Vec<(u8, i64)> = (20..32).map(|n| (n, NOW - i64::from(n) * MIN)).collect();
    let fx = fixture(hosts, &[(7, 3.0), (4, 1.0)], &connected);

    let rows = HostsView::rows(Some(&fx.index), Some(&fx.catalog));
    // Recent: the 10 newest, newest first (h20 connected last).
    assert_eq!(rows[0].key, HostRowKey::RecentGroup);
    let recent: Vec<String> = rows
        .iter()
        .filter(|r| matches!(r.key, HostRowKey::Recent(_)))
        .map(|r| r.label.clone())
        .collect();
    let want: Vec<String> = (20..30).map(|n| format!("h{n}")).collect();
    assert_eq!(recent, want);
    // Then: pinned, frecency (bravo 3 > Mike 1), then alphabetical (case-insensitive).
    let main: Vec<&str> = rows
        .iter()
        .filter(|r| matches!(r.key, HostRowKey::Host(_)))
        .map(|r| r.label.as_str())
        .collect();
    assert_eq!(&main[..5], ["yankee", "bravo", "Mike", "alpha", "h20"]);
    assert_eq!(main.last(), Some(&"zulu"));

    // No connections: no Recent group.
    let fx = fixture(vec![(1, host("a", "a"))], &[], &[]);
    let rows = HostsView::rows(Some(&fx.index), Some(&fx.catalog));
    assert!(rows.iter().all(|r| matches!(r.key, HostRowKey::Host(_))));
}

fn twenty() -> Fixture {
    let mut hosts = Vec::new();
    for n in 1..=20u8 {
        let mut h = host(&format!("prod-web-{n}"), &format!("10.0.0.{n}"));
        if n % 4 == 0 {
            h.username = Some("deploy".into());
        }
        if n % 6 == 0 {
            h.port = Some(2222);
        }
        if n == 3 || n == 11 {
            h.pinned = true;
        }
        if n == 5 {
            h.notes = Some(
                "**Primary** web node.\n- runs `nginx`\n- see [runbook](https://wiki/x)".into(),
            );
            h.keepalive_secs = Some(15);
            h.env = vec![("LANG".into(), "C.UTF-8".into())];
        }
        hosts.push((n, h));
    }
    fixture(
        hosts,
        &[(5, 2.0)],
        &[(5, NOW - 3 * MIN), (9, NOW - 2 * 3_600_000)],
    )
}

fn view(fx: &Fixture) -> HostsView {
    let mut v = HostsView::default();
    v.set_index(Arc::clone(&fx.index));
    v.set_catalog(Arc::new(fx.catalog.clone()));
    v
}

/// The view in the shell's main area (and detail pane when the layout has one).
fn draw_view(v: &HostsView, w: u16, h: u16) -> String {
    let rects = layout(
        Rect::new(0, 0, w, h),
        &ShellState::default(),
        &crate::app::Config::default(),
    );
    text(&draw_with(w, h, true, |frame, cx| {
        v.render(frame, rects.main, cx);
        if let Some(d) = rects.detail {
            v.render_detail(frame, d, cx);
        }
    }))
}

#[test]
fn t11_hosts_view_snapshots() {
    let fx = twenty();
    let mut v = view(&fx);
    // Cursor on the host with notes (under Recent: first row after the group).
    assert!(v.select(id(5)));
    let narrow = draw_view(&v, 80, 24);
    assert!(narrow.contains("Recent"));
    assert!(narrow.contains("★"));
    assert!(narrow.contains("deploy@10.0.0.12:2222"), "{narrow}");
    insta::assert_snapshot!("t11_hosts_80x24", narrow);
    let wide = draw_view(&v, 160, 48);
    assert!(wide.contains("3 minutes ago"), "{wide}");
    assert!(wide.contains("runbook <https://wiki/x>"));
    insta::assert_snapshot!("t11_hosts_160x48", wide);
    // `i` opens the full-screen detail at 80 columns.
    crate::widgets::test_util::keys(&mut v, "i");
    assert!(draw_view(&v, 80, 24).contains("Connected"));
}

#[test]
fn t12_host_form_all_sections() {
    let fx = twenty();
    let mut init = HostFormInit::edit(super::catalog::HostRecord {
        summary: fx.catalog.hosts[&id(5)].clone(),
        password: Some("hunter2".into()),
    });
    init.summary.charset = Some("windows-1252".into());
    let form = host_form(
        &init,
        Some(&fx.catalog),
        Some(Arc::clone(&fx.index)),
        &["dracula".to_owned()],
        30,
        HostFormFeatures::ALL,
    );
    let screen = text(&crate::widgets::test_util::draw(&form, 160, 48, true));
    for heading in [
        "General",
        "Credentials",
        "Connection",
        "Terminal",
        "Forwards",
        "Notes",
    ] {
        assert!(screen.contains(heading), "{heading}: {screen}");
    }
    assert!(!screen.contains("hunter2"));
    insta::assert_snapshot!("t12_host_form_160x48", screen);
    // The registry hides later tasks' fields.
    let form = host_form(
        &init,
        Some(&fx.catalog),
        None,
        &[],
        30,
        super::form::HOST_FORM_FEATURES,
    );
    let screen = text(&crate::widgets::test_util::draw(&form, 160, 48, true));
    // The jump chain is on; snippets are still hidden.
    assert!(screen.contains("Jump hosts"));
    assert!(!screen.contains("Startup snippet"));
    assert!(!screen.contains("Forwards"));
}

#[test]
fn row_targets_and_tags() {
    let fx = twenty();
    let rows = HostsView::rows(Some(&fx.index), Some(&fx.catalog));
    let r = rows
        .iter()
        .find(|r| r.key == HostRowKey::Host(id(12)))
        .unwrap();
    assert_eq!(r.target, "deploy@10.0.0.12:2222");
    assert_eq!(
        r.tags.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(),
        ["web"]
    );
}

mod m2_01 {
    use std::sync::Arc;

    use sverb_core::resolve::{GlobalDefaults, GroupNode, Settings};

    use super::super::catalog::{HostCatalog, HostSummary};
    use super::super::detail::group_lines;
    use super::super::form::{
        GroupFormInit, HOST_FORM_FEATURES, HostFormDialog, HostFormInit, InheritCx, group_form,
        host_form,
    };
    use super::super::{HostRowKey, HostsView};
    use super::{draw_view, fixture, host, id, view};
    use crate::theme::Theme;
    use crate::widgets::test_util::{draw, text};

    const PROD: u8 = 100;
    const SUB: u8 = 101;
    const OTHER: u8 = 102;

    fn node(name: &str, parent: Option<u8>, d: Settings) -> GroupNode {
        GroupNode {
            name: name.into(),
            parent_id: parent.map(id),
            icon: None,
            defaults: d,
        }
    }

    /// `prod` (port 2222, keepalive 60) > `sub`; `other` (nothing set).
    fn with_groups(c: &mut HostCatalog) {
        c.lookup.groups.insert(
            id(PROD),
            node(
                "prod",
                None,
                Settings {
                    port: Some(2222),
                    keepalive_secs: Some(60),
                    ..Settings::default()
                },
            ),
        );
        c.lookup
            .groups
            .insert(id(SUB), node("sub", Some(PROD), Settings::default()));
        c.lookup
            .groups
            .insert(id(OTHER), node("other", None, Settings::default()));
        for g in [PROD, SUB, OTHER] {
            let name = c.lookup.groups[&id(g)].name.clone();
            c.groups.insert(id(g), name);
        }
    }

    fn summary(n: u8, group: Option<u8>, port: Option<u16>) -> HostSummary {
        HostSummary {
            id: id(n),
            label: format!("h{n}"),
            address: format!("10.0.0.{n}"),
            group_id: group.map(id),
            port,
            ..HostSummary::default()
        }
    }

    #[test]
    fn t08_group_detail_counts_inheriting_hosts() {
        let mut c = HostCatalog::default();
        with_groups(&mut c);
        // Two in prod (one with its own port still inherits the keepalive), one in
        // sub (inherits through the chain), one in other, one ungrouped.
        c.hosts.insert(id(1), summary(1, Some(PROD), None));
        c.hosts.insert(id(2), summary(2, Some(PROD), Some(22)));
        c.hosts.insert(id(3), summary(3, Some(SUB), None));
        c.hosts.insert(id(4), summary(4, Some(OTHER), None));
        c.hosts.insert(id(5), summary(5, None, None));
        assert_eq!(c.inheriting_hosts(id(PROD)), 3);
        assert_eq!(c.inheriting_hosts(id(OTHER)), 0);
        // A host that overrides everything the group sets doesn't count.
        let mut own = summary(6, Some(PROD), Some(2200));
        own.keepalive_secs = Some(5);
        c.hosts.insert(id(6), own);
        assert_eq!(c.inheriting_hosts(id(PROD)), 3);

        let theme = Theme::default();
        let lines: Vec<String> = group_lines(id(PROD), &c, &theme)
            .iter()
            .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect())
            .collect();
        let all = lines.join("\n");
        assert!(all.contains("3 hosts inherit these settings"), "{all}");
        assert!(all.contains("3 hosts · 1 subgroup"), "{all}");
        assert!(all.contains("port") && all.contains("2222"), "{all}");
        let sub: Vec<String> = group_lines(id(SUB), &c, &theme)
            .iter()
            .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect())
            .collect();
        assert!(sub.join("\n").contains("prod / sub"));
    }

    #[test]
    fn tree_rows_and_missing_group_chip() {
        let fx = fixture(
            vec![
                (1, host("a", "10.0.0.1")),
                (2, host("b", "10.0.0.2")),
                (3, host("c", "10.0.0.3")),
            ],
            &[],
            &[],
        );
        let mut c = fx.catalog.clone();
        with_groups(&mut c);
        c.hosts.get_mut(&id(1)).expect("h1").group_id = Some(id(SUB));
        c.hosts.get_mut(&id(2)).expect("h2").group_id = Some(id(99)); // deleted
        let rows = HostsView::rows(Some(&fx.index), Some(&c));
        let keys: Vec<HostRowKey> = rows.iter().map(|r| r.key).collect();
        assert_eq!(
            &keys[..3],
            [
                HostRowKey::Group(id(OTHER)),
                HostRowKey::Group(id(PROD)),
                HostRowKey::Group(id(SUB)),
            ]
        );
        let h1 = rows
            .iter()
            .find(|r| r.key == HostRowKey::Host(id(1)))
            .expect("h1");
        assert_eq!(h1.parent, Some(HostRowKey::Group(id(SUB))));
        assert_eq!(h1.target, "10.0.0.1:2222", "the inherited port");
        let h2 = rows
            .iter()
            .find(|r| r.key == HostRowKey::Host(id(2)))
            .expect("h2");
        assert_eq!(h2.parent, None, "a missing group resolves as none");
        assert_eq!(h2.chip, Some("missing group"));

        let mut fx2 = fixture(vec![(1, host("a", "10.0.0.1"))], &[], &[]);
        fx2.catalog = c;
        let mut v = view(&fx2);
        assert!(v.select(id(2)) || v.select(id(1)));
        let screen = draw_view(&v, 120, 30);
        assert!(screen.contains("prod"), "{screen}");
        assert!(screen.contains("sub"), "{screen}");
        // The detail of h1 shows provenance.
        assert!(v.select(id(1)));
        let screen = draw_view(&v, 160, 40);
        assert!(screen.contains("2222 (from group \"prod\")"), "{screen}");
        assert!(screen.contains("prod / sub"), "{screen}");
    }

    #[test]
    fn t11_host_form_shows_inherited_placeholders() {
        let mut c = HostCatalog::default();
        with_groups(&mut c);
        let c = Arc::new(c);
        let mut init = HostFormInit::new_host("db.example", None, None);
        init.summary.group_id = Some(id(PROD));
        let form = host_form(&init, Some(&c), None, &[], 30, HOST_FORM_FEATURES);
        let mut dialog = HostFormDialog {
            item: None,
            form,
            inherit: Some(Box::new(InheritCx {
                catalog: Arc::clone(&c),
                globals: GlobalDefaults::default(),
                vault: None,
            })),
        };
        dialog.sync_inherited();
        let screen = text(&draw(&dialog.form, 120, 40, true));
        assert!(screen.contains("2222 (from group \"prod\")"), "{screen}");
        assert!(screen.contains("60 (from group \"prod\")"), "{screen}");
        insta::assert_snapshot!("t11_m2_inherited_host_form_120x40", screen);

        // Changing the group in the draft updates the placeholders live.
        let field = dialog.form.field_mut("group_id").expect("group field");
        if let crate::widgets::form::FieldWidget::Reference(r) = &mut field.widget {
            r.value = Some(crate::widgets::form::RefValue {
                id: id(OTHER),
                label: "other".into(),
            });
        }
        dialog.sync_inherited();
        let port = dialog.form.field("port").and_then(|f| f.inherited.clone());
        assert_eq!(port.map(|p| p.to_string()).as_deref(), Some("22 (default)"));
    }

    #[test]
    fn group_form_inherits_from_the_parent() {
        let mut c = HostCatalog::default();
        with_groups(&mut c);
        let init = GroupFormInit::edit(&c, id(SUB)).expect("sub");
        let c = Arc::new(c);
        let form = group_form(&init, Some(&c), None, &[], HOST_FORM_FEATURES);
        let mut d = super::super::organize::GroupFormDialog {
            item: init.item,
            vault_defaults: false,
            excluded_parents: [id(SUB)].into(),
            form,
            inherit: Some(InheritCx {
                catalog: c,
                globals: GlobalDefaults::default(),
                vault: None,
            }),
        };
        d.sync_inherited();
        let port = d.form.field("port").and_then(|f| f.inherited.clone());
        assert_eq!(
            port.map(|p| p.to_string()).as_deref(),
            Some("2222 (from group \"prod\")")
        );
    }
}

mod m2_06 {
    use sverb_core::model::{Host, Proxy, ProxyAuth};

    use super::super::catalog::{HostSummary, ProxySummary};
    use super::super::form::{
        HOST_FORM_FEATURES, HostFormInit, PROXY_ADDR, PROXY_COMMAND, PROXY_PASSWORD, PROXY_USER,
        apply_changes, host_form, sync_proxy,
    };
    use crate::widgets::form::{
        FieldChanges, FieldValue, FieldWidget, Form, SecretValue, SelectInput, SelectOption,
    };

    fn form_with(proxy: Option<ProxySummary>) -> Form {
        let init = HostFormInit {
            item: None,
            summary: HostSummary {
                address: "db".into(),
                proxy,
                ..HostSummary::default()
            },
            password: None,
        };
        host_form(&init, None, None, &[], 30, HOST_FORM_FEATURES)
    }

    fn hidden(form: &Form, key: &str) -> bool {
        form.field(key).unwrap().hidden
    }

    fn text(v: &str) -> FieldValue {
        FieldValue::Text(v.into())
    }

    fn kind(v: &str) -> (String, FieldValue) {
        ("proxy.kind".into(), FieldValue::Choice(Some(v.into())))
    }

    /// The proxy section: a kind select with the fields of that kind.
    #[test]
    fn proxy_fields_follow_the_kind() {
        let form = form_with(None);
        assert!(!hidden(&form, "proxy.kind"));
        for key in [PROXY_ADDR, PROXY_USER, PROXY_PASSWORD, PROXY_COMMAND] {
            assert!(hidden(&form, key), "{key}");
        }
        let form = form_with(Some(ProxySummary::Socks5 {
            addr: "proxy:1080".into(),
            user: Some("alice".into()),
        }));
        assert!(!hidden(&form, PROXY_ADDR) && !hidden(&form, PROXY_USER));
        assert!(!hidden(&form, PROXY_PASSWORD) && hidden(&form, PROXY_COMMAND));
        assert_eq!(form.field(PROXY_ADDR).unwrap().value(), text("proxy:1080"));
        let mut form = form_with(Some(ProxySummary::Command("nc %h %p".into())));
        assert!(hidden(&form, PROXY_ADDR) && !hidden(&form, PROXY_COMMAND));
        // Switching the kind shows the other fields (after every key).
        let options = vec![
            SelectOption::new("", "none"),
            SelectOption::new("http", "HTTP CONNECT"),
        ];
        form.field_mut("proxy.kind").unwrap().widget =
            FieldWidget::Select(SelectInput::new(options, Some("http")));
        sync_proxy(&mut form);
        assert!(!hidden(&form, PROXY_ADDR) && hidden(&form, PROXY_COMMAND));
        // The substitution help is on the command field.
        let help = form.field(PROXY_COMMAND).unwrap().help.clone().unwrap();
        assert!(help.contains("%h") && help.contains("%p") && help.contains("%r"));
    }

    #[test]
    fn apply_proxy_changes() {
        let mut host = Host::default();
        apply_changes(
            &mut host,
            &FieldChanges(vec![
                kind("socks5"),
                (PROXY_ADDR.into(), text("proxy:1080")),
                (PROXY_USER.into(), text("alice")),
                (
                    PROXY_PASSWORD.into(),
                    FieldValue::Secret(SecretValue::from("pw")),
                ),
            ]),
        )
        .unwrap();
        let Some(Proxy::Socks5 {
            addr,
            auth: Some(a),
        }) = &host.proxy
        else {
            panic!("{:?}", host.proxy);
        };
        assert_eq!((addr.as_str(), a.user.as_str()), ("proxy:1080", "alice"));
        assert_eq!(a.password.as_ref().unwrap().expose(), "pw");

        // Only the address changes (an edit): the stored password is kept.
        apply_changes(
            &mut host,
            &FieldChanges(vec![(PROXY_ADDR.into(), text("[::1]:1081"))]),
        )
        .unwrap();
        let Some(Proxy::Socks5 { addr, auth }) = &host.proxy else {
            panic!();
        };
        assert_eq!(addr, "[::1]:1081");
        assert_eq!(
            auth.as_ref().unwrap().password.as_ref().unwrap().expose(),
            "pw"
        );
        // Switch to HTTP: the address and credentials carry over.
        apply_changes(&mut host, &FieldChanges(vec![kind("http")])).unwrap();
        assert!(
            matches!(&host.proxy, Some(Proxy::Http { auth: Some(ProxyAuth { user, .. }), .. }) if user == "alice")
        );
        // None.
        apply_changes(&mut host, &FieldChanges(vec![kind("")])).unwrap();
        assert!(host.proxy.is_none());

        // Errors land on the visible field.
        let errs =
            apply_changes(&mut Host::default(), &FieldChanges(vec![kind("http")])).unwrap_err();
        assert_eq!(errs[0].field, PROXY_ADDR);
        let errs = apply_changes(
            &mut Host::default(),
            &FieldChanges(vec![kind("socks5"), (PROXY_ADDR.into(), text("proxy"))]),
        )
        .unwrap_err();
        assert_eq!(errs[0].field, PROXY_ADDR);
        let errs = apply_changes(
            &mut Host::default(),
            &FieldChanges(vec![kind("command"), (PROXY_COMMAND.into(), text("nc %x"))]),
        )
        .unwrap_err();
        assert_eq!(errs[0].field, PROXY_COMMAND);
        assert!(errs[0].message.contains("%x"), "{}", errs[0].message);

        let mut host = Host::default();
        apply_changes(
            &mut host,
            &FieldChanges(vec![
                kind("command"),
                (PROXY_COMMAND.into(), text("socat - TCP:%h:%p")),
            ]),
        )
        .unwrap();
        assert!(matches!(&host.proxy, Some(Proxy::Command(c)) if c == "socat - TCP:%h:%p"));
    }
}
