#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use pretty_assertions::assert_eq;
use proptest::prelude::*;

use super::*;

fn parse(src: &str) -> LoadOutcome {
    Config::from_toml_str(src, &Validators::default())
}

fn errors(src: &str) -> Vec<ConfigError> {
    parse(src).errors
}

fn only_error(src: &str) -> ConfigError {
    let errs = errors(src);
    assert_eq!(
        errs.len(),
        1,
        "expected one error for {src:?}, got {errs:#?}"
    );
    errs.into_iter().next().unwrap()
}

/// Every default in SPEC §15, one row per key (checked against the serialized default).
#[test]
fn t01_defaults_table() {
    let rows: &[(&str, toml::Value)] = &[
        ("general.leader", "ctrl-\\".into()),
        ("general.confirm_quit", true.into()),
        ("general.auto_lock_minutes", 15.into()),
        ("general.lock_disconnects_sessions", false.into()),
        ("general.default_vault", "personal".into()),
        ("ui.theme", "default-dark".into()),
        ("ui.sidebar", "auto".into()),
        ("ui.mouse", true.into()),
        ("ui.truecolor", "auto".into()),
        ("ui.show_which_key", true.into()),
        ("ui.which_key_delay_ms", 400.into()),
        ("ui.date_format", "%Y-%m-%d %H:%M".into()),
        ("ui.ascii", "auto".into()),
        ("ui.reduce_motion", false.into()),
        ("terminal.term", "xterm-256color".into()),
        ("terminal.scrollback", 10000.into()),
        ("terminal.color_scheme", "terminal".into()),
        ("terminal.bell", "visual".into()),
        ("terminal.paste_confirm_multiline", true.into()),
        ("terminal.use_osc_title", false.into()),
        ("terminal.word_separators", " ,│`|:\"'()[]{}<>".into()),
        ("clipboard.osc52", true.into()),
        ("clipboard.allow_remote_write", "ask".into()),
        ("ssh.multiplex", true.into()),
        ("ssh.keepalive_secs", 30.into()),
        ("ssh.host_key_policy", "ask".into()),
        ("ssh.use_system_agent", true.into()),
        ("ssh.read_ssh_config", false.into()),
        ("ssh.hash_known_hosts", false.into()),
        ("ssh.exec_timeout_secs", 60.into()),
        ("ssh.max_auth_attempts", 5.into()),
        ("ssh.connect_timeout_secs", 15.into()),
        ("ssh.auto_reconnect", false.into()),
        ("recording.enabled", false.into()),
        ("recording.include_input", false.into()),
        ("recording.retention_days", 0.into()),
        ("history.enabled", true.into()),
        ("history.sync", false.into()),
        ("history.max_entries_per_host", 5000.into()),
        ("history.ghost_text", false.into()),
        ("sync.push_debounce_ms", 2000.into()),
        ("sync.poll_fallback_secs", 300.into()),
        ("logs.retention_days", 90.into()),
        ("logs.sync", false.into()),
    ];
    let toml::Value::Table(root) = toml::Value::try_from(Config::default()).unwrap() else {
        panic!("not a table");
    };
    let mut seen = 0;
    for (path, expected) in rows {
        let (table, key) = path.split_once('.').unwrap();
        assert_eq!(root[table][key], *expected, "default of {path}");
        assert!(
            apply_scope(path).is_some(),
            "{path} missing from APPLY_SCOPES"
        );
        seen += 1;
    }
    // Every serialized key has a row, and APPLY_SCOPES has nothing extra.
    let serialized: usize = root
        .iter()
        .filter(|(t, _)| *t != "keys")
        .map(|(_, v)| v.as_table().unwrap().len())
        .sum();
    assert_eq!(seen, serialized);
    assert_eq!(APPLY_SCOPES.len(), serialized + 1); // + `keys`

    let keys = &Config::default().keys;
    let term = keys.mode("terminal").unwrap();
    assert_eq!(term[&KeyChordSpec::from("p")], "palette");
    assert_eq!(term[&KeyChordSpec::from("-")], "split_horizontal");
    assert_eq!(term[&KeyChordSpec::from("|")], "split_vertical");
    assert_eq!(term.len(), 3);
    let normal = keys.mode("normal").unwrap();
    assert_eq!(normal[&KeyChordSpec::from("ctrl-k")], "palette");
    assert_eq!(normal.len(), 1);
}

/// The embedded default file parses to `Config::default()` without warnings.
#[test]
fn t02_default_file_round_trips() {
    let out = parse(DEFAULT_CONFIG_TOML);
    assert_eq!(out.errors, vec![]);
    assert_eq!(out.warnings, vec![]);
    assert_eq!(out.config, Config::default());
    // Every key of the model is written out in the file (it documents all of them).
    let file: toml::Table = toml::from_str(DEFAULT_CONFIG_TOML).unwrap();
    for (path, _) in APPLY_SCOPES.iter().filter(|(p, _)| *p != "keys") {
        let (t, k) = path.split_once('.').unwrap();
        assert!(
            file[t].get(k).is_some(),
            "{path} missing from default_config.toml"
        );
    }
}

/// Empty text and a missing file give the defaults, no errors.
#[test]
fn t03_empty_and_missing() {
    let out = parse("");
    assert!(out.errors.is_empty());
    assert_eq!(out.config, Config::default());
    assert_eq!(out.source, ConfigSource::Defaults);

    let out = Config::load_file(
        std::path::Path::new("/nonexistent-sverb/config.toml"),
        &Validators::default(),
        None,
    );
    assert!(out.errors.is_empty() && out.warnings.is_empty());
    assert_eq!(out.config, Config::default());
    assert_eq!(out.source, ConfigSource::Defaults);
}

/// A partial override changes that field only.
#[test]
fn t04_partial_override() {
    let out = parse("[ssh]\nkeepalive_secs = 10");
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    let mut expected = Config::default();
    expected.ssh.keepalive_secs = 10;
    assert_eq!(out.config, expected);
}

/// Unknown key with a suggestion and an exact position.
#[test]
fn t05_unknown_key_suggestion() {
    let e = only_error("[ssh]\nkeepalive_sec = 1");
    assert_eq!(e.path, "ssh.keepalive_sec");
    assert_eq!((e.line, e.col), (2, 1));
    assert!(
        e.hint.as_deref().unwrap().contains("keepalive_secs"),
        "{e:?}"
    );
    assert_eq!(
        e.to_string(),
        "ssh.keepalive_sec:2:1: unknown key `keepalive_sec` in [ssh] (did you mean `keepalive_secs`?)"
    );
}

/// Unknown table; a hint only when a table is within distance 2.
#[test]
fn t06_unknown_table() {
    let e = only_error("[colours]\nx = 1");
    assert_eq!(e.path, "colours");
    assert_eq!(e.hint, None);
    let e = only_error("[sssh]\nx = 1");
    assert_eq!(e.hint.as_deref(), Some("did you mean `ssh`?"));
}

/// Type error at the right path, naming the expected type.
#[test]
fn t07_type_error() {
    let e = only_error("[terminal]\nscrollback = \"lots\"");
    assert_eq!(e.path, "terminal.scrollback");
    assert_eq!((e.line, e.col), (2, 14));
    assert!(e.message.contains("u32"), "{e:?}");
}

/// Enum error lists the variants.
#[test]
fn t08_enum_error() {
    let e = only_error("[ssh]\nhost_key_policy = \"yolo\"");
    assert_eq!(e.path, "ssh.host_key_policy");
    for v in ["strict", "ask", "accept-new"] {
        assert!(e.message.contains(v), "{e:?}");
    }
}

/// Three independent semantic errors → exactly three errors.
#[test]
fn t09_aggregation() {
    let errs = errors(
        "[ui]\nwhich_key_delay_ms = 20000\n[ssh]\nmax_auth_attempts = 0\n[terminal]\nterm = \"bad term\"\n",
    );
    assert_eq!(errs.len(), 3, "{errs:#?}");
    let mut paths: Vec<_> = errs.iter().map(|e| e.path.as_str()).collect();
    paths.sort_unstable();
    assert_eq!(
        paths,
        [
            "ssh.max_auth_attempts",
            "terminal.term",
            "ui.which_key_delay_ms"
        ]
    );
    assert!(errs.iter().all(|e| e.line > 0), "{errs:#?}");
    // Structural errors are aggregated too.
    let errs = errors("[ssh]\nkeepalive_sec = 1\nmultiplex = 3\n[ui]\nmouse = \"yes\"\n");
    assert_eq!(errs.len(), 3, "{errs:#?}");
}

/// Leader validation with the stub validator.
#[test]
fn t10_leader() {
    let leader = |l: &str| parse(&format!("[general]\nleader = {}", toml::Value::from(l)));
    for bad in [
        "g",
        "ctrl-c",
        "ctrl-d",
        "ctrl-z",
        "enter",
        "tab",
        "esc",
        "ctrl-m",
        "ctrl-[",
        "shift-a",
        "ctrl-nope",
    ] {
        let out = leader(bad);
        assert_eq!(out.errors.len(), 1, "{bad}: {:?}", out.errors);
        assert_eq!(out.errors[0].path, "general.leader");
        assert_eq!((out.errors[0].line, out.errors[0].col), (2, 10));
    }
    let out = leader("ctrl-a");
    assert!(out.errors.is_empty());
    assert_eq!(out.warnings.len(), 1);
    assert_eq!(out.warnings[0].severity, Severity::Warning);
    assert!(
        out.warnings[0].message.contains("screen"),
        "{:?}",
        out.warnings
    );
    for good in ["ctrl-\\", "ctrl-g", "ctrl-]", "ctrl-q", "alt-x", "ctrl-4"] {
        let out = leader(good);
        assert!(
            out.errors.is_empty() && out.warnings.is_empty(),
            "{good}: {out:?}"
        );
    }
    assert_eq!(out_leader(&leader("ctrl-g")), "ctrl-g");
}

fn out_leader(o: &LoadOutcome) -> &str {
    o.config.general.leader.as_str()
}

/// Keymap action names, modes and chords.
#[test]
fn t11_keymap_actions() {
    let e = only_error("[keys.normal]\nx = \"nope\"");
    assert_eq!(e.path, "keys.normal.x");
    let out = parse("[keys.normal]\nx = \"palette\"");
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    let normal = out.config.keys.mode("normal").unwrap();
    assert_eq!(normal[&KeyChordSpec::from("x")], "palette");
    assert_eq!(
        normal[&KeyChordSpec::from("ctrl-k")],
        "palette",
        "merged over defaults"
    );

    // `[keys.copy]` exists and takes copy-mode actions only.
    assert_eq!(
        only_error("[keys.visual]\ny = \"quit\"").path,
        "keys.visual"
    );
    assert_eq!(only_error("[keys.copy]\ny = \"quit\"").path, "keys.copy.y");
    let out = parse("[keys.copy]\nx = \"yank\"\ny = \"none\"");
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    let copy = out.config.keys.mode("copy").unwrap();
    assert_eq!(copy[&KeyChordSpec::from("x")], "yank");
    assert_eq!(
        copy[&KeyChordSpec::from("/")],
        "search_forward",
        "merged over defaults"
    );
    assert_eq!(
        only_error("[keys.normal]\n\"hyper-x\" = \"quit\"").path,
        "keys.normal.hyper-x"
    );
    assert_eq!(only_error("[keys.normal]\nx = 1").path, "keys.normal.x");
    // The leader can't be bound after the leader.
    assert_eq!(
        only_error("[keys.terminal]\n\"ctrl-\\\\\" = \"palette\"").path,
        "keys.terminal.ctrl-\\"
    );
    // Same key twice after normalization.
    assert_eq!(
        errors("[keys.normal]\n\"ctrl-x\" = \"quit\"\n\"CTRL-x\" = \"help\"").len(),
        1
    );
}

/// No secrets or server URLs in config.toml.
#[test]
fn t12_secrets_rejected() {
    let e = only_error("[sync]\nserver_url = \"https://x\"");
    assert_eq!(e.path, "sync.server_url");
    assert!(e.hint.as_deref().unwrap().contains("sverb login"), "{e:?}");
    let e = only_error("[sync]\ntoken = \"abc\"");
    assert!(e.hint.as_deref().unwrap().contains("sverb login"), "{e:?}");
}

/// Ranges.
#[test]
fn t13_ranges() {
    assert_eq!(
        only_error("[ui]\nwhich_key_delay_ms = 20000").path,
        "ui.which_key_delay_ms"
    );
    assert_eq!(
        only_error("[ssh]\nmax_auth_attempts = 0").path,
        "ssh.max_auth_attempts"
    );
    assert!(errors("[general]\nauto_lock_minutes = 0").is_empty());
    assert!(errors("[ui]\nwhich_key_delay_ms = 10000").is_empty());
    assert_eq!(
        only_error("[ssh]\nmax_auth_attempts = 21").path,
        "ssh.max_auth_attempts"
    );
    assert_eq!(
        only_error("[sync]\npush_debounce_ms = 99").path,
        "sync.push_debounce_ms"
    );
    assert_eq!(
        only_error("[sync]\npoll_fallback_secs = 29").path,
        "sync.poll_fallback_secs"
    );
    assert_eq!(
        only_error("[ssh]\nexec_timeout_secs = 0").path,
        "ssh.exec_timeout_secs"
    );
    assert_eq!(
        only_error("[ssh]\nconnect_timeout_secs = 0").path,
        "ssh.connect_timeout_secs"
    );
    assert_eq!(
        only_error("[terminal]\nscrollback = 1000001").path,
        "terminal.scrollback"
    );
    assert_eq!(
        only_error("[ssh]\nkeepalive_secs = -1").path,
        "ssh.keepalive_secs"
    );
    assert_eq!(
        only_error("[ui]\ndate_format = \"%Q\"").path,
        "ui.date_format"
    );
    assert_eq!(only_error("[ui]\ntheme = \"nope\"").path, "ui.theme");
    assert_eq!(
        only_error(&format!("[terminal]\nterm = \"{}\"", "x".repeat(65))).path,
        "terminal.term"
    );
    // Unknown color scheme is a warning, not an error.
    let out = parse("[terminal]\ncolor_scheme = \"nope\"");
    assert!(out.errors.is_empty());
    assert_eq!(out.warnings.len(), 1);
}

/// One valid change plus one error → nothing applied.
#[test]
fn t14_all_or_nothing() {
    let out = parse("[ui]\nmouse = false\n[ssh]\nmax_auth_attempts = 0\n");
    assert_eq!(out.errors.len(), 1);
    assert_eq!(out.config, Config::default());

    // On reload the last good config is kept.
    let dir = std::env::temp_dir().join(format!("sverb-config-t14-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("config.toml");
    std::fs::write(&file, "[ui]\nmouse = false\n[ssh]\nmax_auth_attempts = 0\n").unwrap();
    let mut last = Config::default();
    last.ui.theme = "default-light".to_owned();
    let out = Config::reload(&file, &Validators::default(), &last);
    assert_eq!(out.config, last);
    assert_eq!(out.source, ConfigSource::LastGood);
    std::fs::write(&file, "[ui]\nmouse = false\n").unwrap();
    let out = Config::reload(&file, &Validators::default(), &last);
    assert_eq!(out.source, ConfigSource::File(file.clone()));
    assert!(!out.config.ui.mouse);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Syntax errors carry a position.
#[test]
fn syntax_error_position() {
    let e = only_error("[ui]\nmouse = \n");
    assert_eq!(e.line, 2);
    assert!(e.col > 0);
    let e = only_error("[[[");
    assert_eq!(e.line, 1);
}

/// Changing `terminal.term` and `ui.theme` applies the theme and asks for the
/// "new sessions" toast.
#[test]
fn t20_diff_classification() {
    let mut live = LiveConfig::new(Arc::new(Config::default()));
    let mut next = Config::default();
    next.terminal.term = "xterm".to_owned();
    next.ui.theme = "default-light".to_owned();
    let update = live.apply(ConfigEvent::Reloaded {
        config: Arc::new(next),
        warnings: vec![],
    });
    let ConfigUpdate::Applied {
        config,
        diff,
        notice,
        ..
    } = update
    else {
        panic!("not applied");
    };
    assert_eq!(config.ui.theme, "default-light");
    assert_eq!(live.current().ui.theme, "default-light");
    assert_eq!(diff.changed, ["terminal.term", "ui.theme"]);
    assert_eq!(diff.live().collect::<Vec<_>>(), ["ui.theme"]);
    assert_eq!(diff.deferred().collect::<Vec<_>>(), ["terminal.term"]);
    assert_eq!(notice, Some(diff::NEW_SESSIONS_NOTICE));

    // Live-only changes: no toast. Keymap changes are diffed per mode.
    let mut next = (**live.current()).clone();
    next.ui.mouse = false;
    next.keys
        .0
        .get_mut("normal")
        .unwrap()
        .insert("x".into(), "quit".into());
    let ConfigUpdate::Applied { diff, notice, .. } = live.apply(ConfigEvent::Reloaded {
        config: Arc::new(next),
        warnings: vec![],
    }) else {
        panic!("not applied");
    };
    assert_eq!(diff.changed, ["keys.normal", "ui.mouse"]);
    assert_eq!(notice, None);

    // Invalid keeps the last good config; Removed reverts to defaults.
    assert!(matches!(
        live.apply(ConfigEvent::Invalid(vec![])),
        ConfigUpdate::Rejected(_)
    ));
    assert!(!live.current().ui.mouse);
    live.apply(ConfigEvent::Removed);
    assert_eq!(**live.current(), Config::default());
}

#[test]
fn stub_chord_normalization() {
    let v = StubKeymapValidator;
    assert_eq!(v.parse_chord("CTRL-K").unwrap(), "ctrl-k");
    assert_eq!(v.parse_chord("ctrl-4").unwrap(), "ctrl-\\");
    assert_eq!(v.parse_chord("alt-ctrl-x").unwrap(), "ctrl-alt-x");
    assert_eq!(v.parse_chord("-").unwrap(), "-");
    assert_eq!(v.parse_chord("ctrl--").unwrap(), "ctrl--");
    assert_eq!(v.parse_chord("N").unwrap(), "N");
    assert_eq!(v.parse_chord("PageUp").unwrap(), "pageup");
    assert!(v.parse_chord("").is_err());
    assert!(v.parse_chord("ab").is_err());
}

#[test]
fn date_formats() {
    use validate::check_date_format;
    for ok in ["%Y-%m-%d %H:%M", "%-d %b", "%.3f", "%:z", "100%%", ""] {
        assert!(check_date_format(ok).is_ok(), "{ok}");
    }
    for bad in ["%Q", "abc %", "%-"] {
        assert!(check_date_format(bad).is_err(), "{bad}");
    }
}

/// A TOML-ish document built from real tables/keys and random values.
fn toml_like() -> impl Strategy<Value = String> {
    let tables = prop::sample::select(vec![
        "general",
        "ui",
        "terminal",
        "ssh",
        "sync",
        "keys",
        "keys.normal",
        "keys.terminal",
        "x",
    ]);
    let keys = prop::sample::select(vec![
        "leader",
        "theme",
        "scrollback",
        "term",
        "host_key_policy",
        "date_format",
        "p",
        "\"ctrl-\\\\\"",
        "max_auth_attempts",
        "which_key_delay_ms",
        "server_url",
        "a.b",
    ]);
    let values = prop_oneof![
        any::<i64>().prop_map(|i| i.to_string()),
        any::<bool>().prop_map(|b| b.to_string()),
        "\\PC{0,12}".prop_map(|s| toml::Value::from(s).to_string()),
        Just("[1, \"a\"]".to_owned()),
        Just("{ a = 1 }".to_owned()),
        Just("1979-05-27T07:32:00Z".to_owned()),
        Just("1e400".to_owned()),
        Just("\"%\"".to_owned()),
    ];
    prop::collection::vec((tables, prop::collection::vec((keys, values), 0..4)), 0..5).prop_map(
        |sections| {
            let mut s = String::new();
            for (t, kvs) in sections {
                s.push_str(&format!("[{t}]\n"));
                for (k, v) in kvs {
                    s.push_str(&format!("{k} = {v}\n"));
                }
            }
            s
        },
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// T-23 (structured half): realistic documents never panic.
    #[test]
    fn t23_no_panics_structured(doc in toml_like()) {
        let out = parse(&doc);
        if !out.errors.is_empty() {
            prop_assert_eq!(out.config, Config::default());
        }
    }

    /// T-23 (random half): arbitrary text never panics.
    #[test]
    fn t23_no_panics_random(doc in "[\\[\\]a-z_.=\"'{}, \\n0-9\\-\\\\#]{0,80}|\\PC{0,80}") {
        let _ = parse(&doc);
    }
}

// Accepted keys that this version doesn't act on yet warn instead of failing.
#[test]
fn not_yet_effective_keys_warn() {
    let out = parse("[ssh]\nread_ssh_config = true\n[terminal]\nbell = \"none\"\n");
    assert_eq!(out.errors, vec![]);
    let paths: Vec<&str> = out.warnings.iter().map(|w| w.path.as_str()).collect();
    assert_eq!(paths, ["ssh.read_ssh_config", "terminal.bell"]);
    assert!(out.config.ssh.read_ssh_config);
    assert!(parse("[terminal]\nbell = \"visual\"\n").warnings.is_empty());
}
