//! PuTTY sessions importer tests (T-05 snapshot, the mapping, T-06 on Windows).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use super::*;
use crate::importers::preview::{ExistingItem, body_label, classify, materialize};
use crate::importers::{ApplyOptions, Existing, PlanStatus};
use crate::model::{
    DeviceId, HlcClock, Host, ItemBody, ItemId, ManualClock, PortForward, Proxy, VaultId,
};

fn sessions_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/putty/sessions")
}

fn host<'a>(plan: &'a ImportPlan, label: &str) -> &'a HostDraft {
    plan.items
        .iter()
        .find_map(|i| match &i.draft {
            Draft::Host(h) if h.label == label => Some(h.as_ref()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no host {label}"))
}

fn skipped_with(plan: &ImportPlan, needle: &str) -> bool {
    plan.skipped.iter().any(|s| s.reason.contains(needle))
}

/// The sessions fixture directory → the preview (skipped telnet / serial /
/// SOCKS4 / Default Settings sessions, URL-decoded labels, proxies, forwards).
#[test]
fn t05_sessions_snapshot() {
    let plan = parse_dir(&sessions_dir()).unwrap();
    assert_eq!(plan.source, ImportSource::Putty);
    insta::assert_snapshot!("putty_sessions", plan.render_table());

    let prod = host(&plan, "prod web");
    assert_eq!(prod.address, "web.example.com");
    assert_eq!(prod.username.as_deref(), Some("deploy"), "user@ wins");
    assert_eq!(prod.port, Some(2222));
    assert_eq!(prod.identity_files, vec!["/nonexistent/putty/prod.ppk"]);
    assert_eq!(prod.agent_forwarding, Some(true));
    assert_eq!(prod.forwards.len(), 3);
    let kinds: Vec<(ForwardKind, u16, Option<String>, Option<u16>)> = prod
        .forwards
        .iter()
        .map(|r| match &plan.items[*r].draft {
            Draft::Forward(f) => (f.kind, f.bind_port, f.dest_host.clone(), f.dest_port),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(
        kinds,
        vec![
            (ForwardKind::Local, 8080, Some("localhost".into()), Some(80)),
            (
                ForwardKind::Remote,
                2222,
                Some("127.0.0.1".into()),
                Some(22)
            ),
            (ForwardKind::Dynamic, 1080, None, None),
        ]
    );

    let db = host(&plan, "db");
    assert_eq!(db.port, None, "22 is left to inherit");
    assert_eq!(db.username.as_deref(), Some("postgres"));
    assert_eq!(db.agent_forwarding, None);
    assert_eq!(
        db.proxy,
        Some(ProxyDraft {
            kind: ProxyDraftKind::Socks5,
            addr: "bastion.example.com:1080".into(),
            user: Some("jump".into()),
        })
    );
    let http = host(&plan, "corp-http");
    assert_eq!(
        http.proxy.as_ref().map(ToString::to_string).as_deref(),
        Some("http://proxy.corp:3128")
    );
    let v6 = host(&plan, "ipv6 box");
    assert_eq!(v6.address, "2001:db8::1");
    assert_eq!(v6.forwards.len(), 2);

    assert!(skipped_with(
        &plan,
        "non-SSH protocol not supported (telnet)"
    ));
    assert!(skipped_with(
        &plan,
        "non-SSH protocol not supported (serial)"
    ));
    assert!(skipped_with(&plan, "SOCKS4"));
    assert!(skipped_with(&plan, "Default Settings"));
    assert!(skipped_with(&plan, "no HostName"));
    assert!(skipped_with(&plan, "bad listen port"));
    assert!(skipped_with(&plan, "no destination"));
    // The proxy password is never read into the plan.
    assert!(!plan.render_table().contains("hunter2"));
    assert!(plan.notes.iter().any(|n| n.contains("proxy passwords")));
    assert!(plan.warnings.iter().any(|w| w.contains("xterm-256color")));
}

#[test]
fn name_decoding_and_forward_specs() {
    assert_eq!(decode_name("prod%20web"), "prod web");
    assert_eq!(decode_name("a%2Fb%25c"), "a/b%c");
    assert_eq!(decode_name("bad%zzend%2"), "bad%zzend%2");
    assert_eq!(decode_name("caf%C3%A9"), "café");

    let f = parse_forward("4L127.0.0.1:5432=db:5432").unwrap();
    assert_eq!(f.kind, ForwardKind::Local);
    assert_eq!(f.bind_addr.as_deref(), Some("127.0.0.1"));
    assert_eq!(f.dest, Some(("db".into(), 5432)));
    let f = parse_forward("6L[::1]:8443=[2001:db8::2]:443").unwrap();
    assert_eq!(f.bind_addr.as_deref(), Some("::1"));
    assert_eq!(f.dest, Some(("2001:db8::2".into(), 443)));
    let f = parse_forward("D1080=").unwrap();
    assert_eq!(
        (f.kind, f.bind_port, f.dest),
        (ForwardKind::Dynamic, 1080, None)
    );
    assert!(parse_forward("X1=a:1").is_err());
    assert!(parse_forward("L0=a:1").is_err());
    assert!(parse_forward("L80=a").is_err());
    assert!(parse_forward("R9000").is_err());
    assert!(parse_forward("").is_err());

    let map = parse_session_file("A=1\r\nB=x=y\nnoequals\n=v\n");
    assert_eq!(map.get("A").map(String::as_str), Some("1"));
    assert_eq!(map.get("B").map(String::as_str), Some("x=y"));
    assert_eq!(map.len(), 2);
}

#[test]
fn hostile_sessions_never_panic() {
    let mut s = Session {
        name: "x".into(),
        source: "sessions/x".into(),
        ..Session::default()
    };
    for (k, v) in [
        ("HostName", "@"),
        ("PortNumber", "99999"),
        ("ProxyMethod", "2"),
        ("ProxyPort", "-1"),
        ("PortForwardings", ",,,L,R=,D,4,6L[,L[::1]=x"),
    ] {
        s.values.insert(k.into(), v.into());
        let _ = plan(std::slice::from_ref(&s));
    }
    let many = Session {
        values: [
            ("PortForwardings".to_owned(), "D1,".repeat(MAX_FORWARDS * 4)),
            ("HostName".to_owned(), "h".to_owned()),
        ]
        .into_iter()
        .collect(),
        ..s
    };
    let p = plan(&[many]);
    assert_eq!(p.counts().new, 1 + MAX_FORWARDS);
}

#[test]
fn missing_dir_is_a_read_error() {
    let e = parse_dir(Path::new("/nonexistent/sverb-putty")).unwrap_err();
    assert!(matches!(e, ImportError::Read { .. }));
}

/// proxy is written without a password; forwards point at the host).
#[test]
fn materialize_putty_plan() {
    let mut plan = parse_dir(&sessions_dir()).unwrap();
    let vault = VaultId::from_bytes([7; 16]);
    let existing = Existing::new([], vault);
    classify(&mut plan, &existing, None);
    assert!(plan.items.iter().all(|i| i.status == PlanStatus::New));
    let mut clock = HlcClock::new(ManualClock::new(Duration::from_secs(1_800_000_000)));
    let mut n = 0u8;
    let mut ids = move || {
        n += 1;
        ItemId::from_bytes([n; 16])
    };
    let opts = ApplyOptions {
        vault: Some(vault),
        ..ApplyOptions::default()
    };
    let w = materialize(
        &plan,
        &existing,
        &opts,
        &mut clock,
        DeviceId::from_bytes([2; 16]),
        &mut ids,
    )
    .unwrap();
    let body = |label: &str| -> &ItemBody {
        &w.writes
            .iter()
            .find(|x| body_label(&x.body) == label)
            .unwrap_or_else(|| panic!("no {label}"))
            .body
    };
    let db = Host::try_from(body("db")).unwrap_or_default();
    match &db.proxy {
        Some(Proxy::Socks5 { addr, auth }) => {
            assert_eq!(addr, "bastion.example.com:1080");
            let auth = auth.as_ref().unwrap();
            assert_eq!(auth.user, "jump");
            assert!(auth.password.is_none());
        }
        other => panic!("{other:?}"),
    }
    let http = Host::try_from(body("corp-http")).unwrap_or_default();
    assert!(
        matches!(&http.proxy, Some(Proxy::Http { addr, auth: None }) if addr == "proxy.corp:3128")
    );
    let prod = Host::try_from(body("prod web")).unwrap_or_default();
    assert_eq!(prod.port_forwards.len(), 3);
    let fwd = w
        .writes
        .iter()
        .find(|x| x.id == prod.port_forwards[0])
        .unwrap();
    let rule = PortForward::try_from(&fwd.body).unwrap();
    assert_eq!(rule.bind_port, 8080);
    // Re-importing the same sessions: duplicates.
    let existing = Existing::new(
        w.writes.iter().map(|x| ExistingItem {
            id: x.id,
            vault,
            body: x.body.clone(),
        }),
        vault,
    );
    let mut again = parse_dir(&sessions_dir()).unwrap();
    classify(&mut again, &existing, None);
    assert_eq!(again.counts().new, 0, "{}", again.render_table());
}

/// The registry reader, against a temporary key under `HKCU\Software\sverb-test`.
#[cfg(windows)]
#[test]
fn t06_registry_reader() {
    use winreg::{RegKey, enums::HKEY_CURRENT_USER};
    let root = format!(r"Software\sverb-test\putty-{}\Sessions", std::process::id());
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (s, _) = hkcu.create_subkey(format!(r"{root}\prod%20web")).unwrap();
    s.set_value("HostName", &"deploy@web.example.com").unwrap();
    s.set_value("Protocol", &"ssh").unwrap();
    s.set_value("PortNumber", &2222u32).unwrap();
    s.set_value("AgentFwd", &1u32).unwrap();
    s.set_value("PortForwardings", &"L8080=localhost:80,D1080")
        .unwrap();
    let (t, _) = hkcu.create_subkey(format!(r"{root}\router")).unwrap();
    t.set_value("HostName", &"192.168.1.1").unwrap();
    t.set_value("Protocol", &"telnet").unwrap();

    let result = registry::read_sessions(&root);
    let parent = root.trim_end_matches(r"\Sessions").to_owned();
    let _ = hkcu.delete_subkey_all(&parent);
    let sessions = result.unwrap();
    assert_eq!(sessions.len(), 2);
    let p = plan(&sessions);
    let h = host(&p, "prod web");
    assert_eq!(h.port, Some(2222));
    assert_eq!(h.agent_forwarding, Some(true));
    assert_eq!(h.forwards.len(), 2);
    assert!(skipped_with(&p, "telnet"));
}
