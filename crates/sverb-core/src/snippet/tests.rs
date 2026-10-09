#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::*;
use crate::model::{ItemId, VarDef};

fn var(
    name: &str,
    default: Option<&str>,
    filter: Option<Filter>,
) -> (String, Option<String>, Option<Filter>) {
    (name.to_owned(), default.map(str::to_owned), filter)
}

fn only_var(src: &str) -> (String, Option<String>, Option<Filter>) {
    let t = Template::parse(src).unwrap();
    let refs: Vec<&VarRef> = t.refs().collect();
    assert_eq!(refs.len(), 1, "{src}");
    (
        refs[0].name.clone(),
        refs[0].default.clone(),
        refs[0].filter,
    )
}

fn host(label: &str, address: &str, user: &str) -> Builtins {
    Builtins {
        label: label.into(),
        address: address.into(),
        user: user.into(),
        date: "2026-10-08".into(),
    }
}

#[test]
fn t01_parsing_table() {
    for (src, want) in [
        ("{{a}}", var("a", None, None)),
        ("{{ a }}", var("a", None, None)),
        ("{{a:def}}", var("a", Some("def"), None)),
        ("{{a:with:colons}}", var("a", Some("with:colons"), None)),
        ("{{a|q}}", var("a", None, Some(Filter::Quote))),
        (
            "{{ a:def | q }}",
            var("a", Some("def"), Some(Filter::Quote)),
        ),
        ("{{host.label}}", var("host.label", None, None)),
    ] {
        assert_eq!(only_var(src), want, "{src}");
    }
    // `\{{` is a literal `{{`; no variable.
    let t = Template::parse(r"echo \{{literal}}").unwrap();
    assert_eq!(t.parts, vec![Part::Literal("echo {{literal}}".into())]);
    // `{{{{` is not special: `{{` then a name starting with `{{` → invalid.
    assert!(Template::parse("{{{{a}}").is_err());
    // Unclosed → an error with its position.
    let e = Template::parse("echo ok\n  x {{name").unwrap_err();
    assert_eq!(e.kind, TemplateErrorKind::Unclosed);
    assert_eq!((e.offset, e.line, e.column), (12, 2, 5));
    assert_eq!(e.to_string(), "unclosed {{ at line 2, column 5");
    // Invalid names.
    let e = Template::parse("{{1bad}}").unwrap_err();
    assert_eq!(e.kind, TemplateErrorKind::InvalidName("1bad".into()));
    assert!(matches!(
        Template::parse("{{}}").unwrap_err().kind,
        TemplateErrorKind::InvalidName(_)
    ));
    assert_eq!(
        Template::parse("{{a|x}}").unwrap_err().kind,
        TemplateErrorKind::UnknownFilter("x".into())
    );
    // Spans and literals around variables; multibyte text survives.
    let t = Template::parse("é {{a}} ü").unwrap();
    assert_eq!(t.parts.len(), 3);
    assert_eq!(t.refs().next().unwrap().span, 3..8);
}

#[test]
fn user_vars_dedup_and_skip_builtins() {
    let t = Template::parse("{{a}} {{host.user}} {{b:1}} {{a:x}} {{date}}").unwrap();
    let names: Vec<(String, Option<String>)> = t
        .user_vars()
        .into_iter()
        .map(|v| (v.name, v.default))
        .collect();
    assert_eq!(
        names,
        vec![
            ("a".into(), Some("x".into())),
            ("b".into(), Some("1".into()))
        ]
    );
    assert!(t.uses_builtins());
}

#[test]
fn t02_substitution_is_literal_unless_quoted() {
    let values = Values::new().with("x", "a; rm -rf /", false);
    let b = Builtins::default();
    let t = Template::parse("echo {{x}}").unwrap();
    assert_eq!(
        t.render(&values, &b, RenderStyle::Final).unwrap(),
        "echo a; rm -rf /"
    );
    let t = Template::parse("echo {{x|q}}").unwrap();
    assert_eq!(
        t.render(&values, &b, RenderStyle::Final).unwrap(),
        "echo 'a; rm -rf /'"
    );
    let values = Values::new().with("x", "it's", false);
    assert_eq!(
        t.render(&values, &b, RenderStyle::Final).unwrap(),
        r"echo 'it'\''s'"
    );
    // Defaults apply; missing values are errors in Final and placeholders in Preview.
    let t = Template::parse("{{a:1}} {{b}} {{c}} {{b}}").unwrap();
    assert_eq!(
        t.render(&Values::new(), &b, RenderStyle::Final),
        Err(RenderError::Missing(vec!["b".into(), "c".into()]))
    );
    assert_eq!(
        t.render(&Values::new(), &b, RenderStyle::Preview).unwrap(),
        "1 {{b}} {{c}} {{b}}"
    );
    // A NUL byte cannot be quoted.
    let t = Template::parse("{{x|q}}").unwrap();
    assert!(matches!(
        t.render(
            &Values::new().with("x", "a\0b", false),
            &b,
            RenderStyle::Final
        ),
        Err(RenderError::Quote { .. })
    ));
}

#[test]
fn t03_builtins_per_host() {
    let t =
        Template::parse("ssh {{host.user}}@{{host.address}} # {{host.label}} {{date}}").unwrap();
    let v = Values::new();
    let a = t
        .render(&v, &host("web-1", "10.0.0.1", "root"), RenderStyle::Final)
        .unwrap();
    let b = t
        .render(&v, &host("web-2", "10.0.0.2", "deploy"), RenderStyle::Final)
        .unwrap();
    assert_eq!(a, "ssh root@10.0.0.1 # web-1 2026-10-08");
    assert_eq!(b, "ssh deploy@10.0.0.2 # web-2 2026-10-08");
    assert_ne!(a, b);
    // A built-in wins over a user value of the same name.
    let v = Values::new().with("host.label", "spoof", false);
    assert_eq!(
        Template::parse("{{host.label}}")
            .unwrap()
            .render(&v, &host("web-1", "", ""), RenderStyle::Final)
            .unwrap(),
        "web-1"
    );
}

#[derive(Default)]
struct MockHistory(Mutex<Vec<HistoryRecord>>);

impl HistorySink for MockHistory {
    fn record(&self, record: HistoryRecord) {
        self.0.lock().unwrap().push(record);
    }
}

#[derive(Clone, Default)]
struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn t04_secrets_masked_and_never_in_history_or_logs() {
    const CANARY: &str = "CANARY-pw-8f3a1";
    let declared = vec![
        VarDef {
            name: "user".into(),
            default: Some("admin".into()),
            secret: false,
        },
        VarDef {
            name: "password".into(),
            default: None,
            secret: true,
        },
    ];
    let t = Template::parse("login {{user}} {{password}} {{password|q}}").unwrap();
    let vars = effective_vars(&t, &declared);
    let given = Values::new().with("password", CANARY, true);
    let values = with_defaults(&vars, &given);
    let b = Builtins::default();

    let logs = LogBuf::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .finish();
    let sink = MockHistory::default();
    tracing::subscriber::with_default(subscriber, || {
        // Preview: masked.
        let preview = t.render(&values, &b, RenderStyle::Preview).unwrap();
        assert_eq!(preview, format!("login admin {MASK} '{MASK}'"));
        assert!(!preview.contains(CANARY));
        // Final: the real value (it runs).
        let fin = t.render(&values, &b, RenderStyle::Final).unwrap();
        assert!(fin.contains(CANARY));
        // History: placeholders.
        record_run(&sink, &t, &values, &b, None, Some(ItemId::new()));
        // What a careless caller might log.
        tracing::info!(?values, ?vars, "snippet run");
        tracing::debug!(values = ?values.clone(), "values");
        assert!(!format!("{values:?}").contains(CANARY));
    });
    let records = sink.0.lock().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].command, "login admin {{password}} {{password}}");
    assert!(!records[0].command.contains(CANARY));
    let logged = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(logged.contains("snippet run"), "{logged}");
    assert!(!logged.contains(CANARY), "{logged}");
}

#[test]
fn vars_merge_declared_and_undeclared() {
    let t = Template::parse("{{a:inline}} {{b}} {{c:3}}").unwrap();
    let declared = vec![VarDef {
        name: "b".into(),
        default: Some("2".into()),
        secret: true,
    }];
    let vars = effective_vars(&t, &declared);
    let names: Vec<(&str, Option<&str>, bool)> = vars
        .iter()
        .map(|v| (v.name.as_str(), v.default.as_deref(), v.secret))
        .collect();
    assert_eq!(
        names,
        vec![
            ("b", Some("2"), true),
            ("a", Some("inline"), false),
            ("c", Some("3"), false)
        ]
    );
    let und: Vec<String> = undeclared(&t, &declared)
        .into_iter()
        .map(|v| v.name)
        .collect();
    assert_eq!(und, vec!["a", "c"]);
    let no_default = vec![VarDef {
        name: "x".into(),
        default: None,
        secret: false,
    }];
    assert_eq!(missing(&no_default, &Values::new()), vec!["x"]);
    assert!(missing(&no_default, &Values::new().with("x", "", false)).is_empty());
    // Values given on the command line become secret when the variable is.
    let v = with_defaults(&declared, &Values::new().with("b", "s", false));
    assert_eq!(v.get("b"), Some(("s", true)));
}

#[test]
fn t05_paste_text_has_no_trailing_newline() {
    assert_eq!(paste_text("ls -la\n"), "ls -la");
    assert_eq!(paste_text("a\nb\r\n\n"), "a\nb");
}

#[test]
fn t06_paste_and_execute_lines() {
    assert_eq!(paste_execute_bytes("l1\nl2\nl3"), b"l1\rl2\rl3\r");
    assert_eq!(paste_execute_bytes("l1\r\nl2\nl3\n"), b"l1\rl2\rl3\r");
    assert_eq!(paste_execute_bytes("a\n\nb"), b"a\r\rb\r");
    assert!(paste_execute_bytes("").is_empty());
    // Never bracketed: no ESC [ 200 ~ in the output.
    assert!(!paste_execute_bytes("x").contains(&0x1b));
}

fn catalog() -> (TargetCatalog, Vec<ItemId>) {
    let ids: Vec<ItemId> = (0..6).map(|_| ItemId::new()).collect();
    let (web, db) = (ItemId::new(), ItemId::new());
    let (prod, eu, other) = (ItemId::new(), ItemId::new(), ItemId::new());
    let h = |i: usize, label: &str, group: Option<ItemId>, tags: Vec<ItemId>| TargetHost {
        id: ids[i],
        label: label.into(),
        address: format!("10.0.0.{i}"),
        group,
        tags,
    };
    let c = TargetCatalog {
        hosts: vec![
            h(0, "web-2", Some(eu), vec![web]),
            h(1, "web-1", Some(prod), vec![web]),
            h(2, "db-1", Some(eu), vec![db]),
            h(3, "db-2", None, vec![db, web]),
            h(4, "mail", Some(other), vec![]),
            h(5, "lonely", None, vec![]),
        ],
        tags: [
            (web, "web".into()),
            (db, "DB".into()),
            (ItemId::new(), "empty".into()),
        ]
        .into_iter()
        .collect(),
        groups: [
            (prod, ("prod".into(), None)),
            (eu, ("eu".into(), Some(prod))),
            (other, ("other".into(), None)),
            (ItemId::new(), ("vacant".into(), None)),
        ]
        .into_iter()
        .collect(),
    };
    (c, ids)
}

#[test]
fn t13_target_resolution() {
    let (c, ids) = catalog();
    let s = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
    // #tag: by label.
    assert_eq!(
        c.resolve(&s(&["#web"])).unwrap(),
        vec![ids[3], ids[1], ids[0]]
    );
    assert_eq!(c.resolve(&s(&["#db"])).unwrap(), vec![ids[2], ids[3]]);
    // Group: recursive.
    assert_eq!(
        c.resolve(&s(&["prod"])).unwrap(),
        vec![ids[2], ids[1], ids[0]]
    );
    assert_eq!(c.resolve(&s(&["eu"])).unwrap(), vec![ids[2], ids[0]]);
    // Host, then dedup across arguments (first-seen order).
    assert_eq!(
        c.resolve(&s(&["mail", "#web", "web-1", "db-2", "eu"]))
            .unwrap(),
        vec![ids[4], ids[3], ids[1], ids[0], ids[2]]
    );
    assert_eq!(c.resolve(&s(&["10.0.0.5"])).unwrap(), vec![ids[5]]);
    // Errors.
    assert_eq!(
        c.resolve(&s(&["#nope"])),
        Err(TargetError::UnknownTag("nope".into()))
    );
    assert_eq!(
        c.resolve(&s(&["#empty"])),
        Err(TargetError::NoHosts("#empty".into()))
    );
    assert_eq!(
        c.resolve(&s(&["vacant"])),
        Err(TargetError::NoHosts("vacant".into()))
    );
    assert!(matches!(c.resolve(&s(&["zzz"])), Err(TargetError::Host(_))));
    assert!(matches!(c.resolve(&s(&["web"])), Err(TargetError::Host(_))));
}

fn sample_results() -> Vec<HostRunResult> {
    vec![
        HostRunResult {
            host: "web-1".into(),
            exit: Some(0),
            stdout: b" 10:00 up 3 days\n".to_vec(),
            duration: Duration::from_millis(1234),
            ..HostRunResult::default()
        },
        HostRunResult {
            host: "web-2".into(),
            exit: Some(3),
            stderr: b"boom\n".to_vec(),
            duration: Duration::from_millis(250),
            ..HostRunResult::default()
        },
        HostRunResult {
            host: "bin".into(),
            exit: None,
            signal: Some(results::TIMEOUT_SIGNAL.into()),
            stdout: vec![0xff, 0x00, b'a'],
            truncated: true,
            duration: Duration::from_secs(30),
            ..HostRunResult::default()
        },
        HostRunResult::failed("down", "connection refused", Duration::from_millis(5)),
    ]
}

#[test]
fn results_status_summary_and_exports() {
    let r = sample_results();
    let statuses: Vec<String> = r.iter().map(|x| x.status().to_string()).collect();
    assert_eq!(
        statuses,
        vec!["ok", "exit 3", "timeout", "error: connection refused"]
    );
    assert_eq!(results::summarize(&r), Summary::Partial);
    assert_eq!(results::summarize(&r[..1]), Summary::AllOk);
    assert_eq!(results::summarize(&r[1..]), Summary::AllFailed);
    assert_eq!(results::summarize(&[]), Summary::AllOk);

    let json = results::to_json(&r);
    assert_eq!(
        json,
        serde_json::json!({"version": 1, "data": [
            {"host": "web-1", "exit": 0, "signal": null, "stdout": " 10:00 up 3 days\n",
             "stderr": "", "truncated": false, "duration_ms": 1234},
            {"host": "web-2", "exit": 3, "signal": null, "stdout": "", "stderr": "boom\n",
             "truncated": false, "duration_ms": 250},
            {"host": "bin", "exit": null, "signal": "TERM (timeout)", "stdout": "\u{fffd}\u{0}a",
             "stderr": "", "truncated": true, "duration_ms": 30000, "stdout_b64": "/wBh"},
            {"host": "down", "exit": null, "signal": null, "stdout": "", "stderr": "",
             "truncated": false, "duration_ms": 5, "error": "connection refused"},
        ]})
    );

    let text = results::to_text(&r[..2]);
    assert_eq!(
        text,
        "== web-1 (ok, 1.2s) ==\n 10:00 up 3 days\n== web-2 (exit 3, 0.2s) ==\nboom\n"
    );

    let md = results::to_markdown("uptime on #web", &r[..2]);
    assert_eq!(
        md,
        "# uptime on #web\n\n\
         | Host | Status | Exit | Duration | Truncated |\n\
         |---|---|---|---|---|\n\
         | web-1 | ok | 0 | 1.2s | no |\n\
         | web-2 | exit 3 | 3 | 0.2s | no |\n\n\
         ## web-1 (ok)\n\nstdout:\n\n```text\n 10:00 up 3 days\n```\n\n\
         ## web-2 (exit 3)\n\nstderr:\n\n```text\nboom\n```\n\n"
    );
}

#[test]
fn startup_text_or_form() {
    use crate::model::{RunMode, Snippet};
    let mut s = Snippet {
        name: "init".into(),
        script: "cd {{dir:/srv}}\necho {{host.label}}\n".into(),
        description: None,
        tags: Vec::new(),
        variables: Vec::new(),
        run_mode: RunMode::Paste,
        read_only: false,
    };
    let b = host("web-1", "10.0.0.1", "root");
    assert_eq!(
        startup(&s, &b),
        Startup::Ready("cd /srv\recho web-1\r".into())
    );
    s.script = "export TOKEN={{token}}".into();
    assert_eq!(startup(&s, &b), Startup::NeedsValues(vec!["token".into()]));
    s.script = "{{oops".into();
    assert!(matches!(startup(&s, &b), Startup::Invalid(_)));
}
