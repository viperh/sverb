#![allow(clippy::unwrap_used, clippy::expect_used)]

//! password prompt), T-05 (ranking), T-07 (per-host cap).

use super::*;
use crate::model::UnixMillis;

fn id(b: u8) -> ItemId {
    ItemId::from_bytes([b; 16])
}

fn entry(cmd: &str, host: Option<ItemId>, at: i64) -> HistoryEntry {
    HistoryEntry {
        command: cmd.into(),
        host_id: host,
        executed_at: UnixMillis(at),
        exit_code: Some(0),
        ..HistoryEntry::default()
    }
}

fn ctx(line: &str) -> CaptureContext<'_> {
    CaptureContext {
        cursor_line: line,
        previous_line: None,
        alt_screen: false,
        secret_prompt_open: false,
    }
}

// ------------------------------------------------------------------- T-03

#[test]
fn t03_prompt_is_learned_and_stripped() {
    let mut p = PromptLearner::new();
    assert_eq!(
        heuristic_capture(&ctx("user@h:~$ ls -la"), &p),
        None,
        "nothing learned yet"
    );
    for _ in 0..3 {
        p.observe("user@h:~$ ");
    }
    assert_eq!(
        p.pattern(),
        Some(&PromptPattern::Exact("user@h:~$ ".into()))
    );
    assert_eq!(
        heuristic_capture(&ctx("user@h:~$ ls -la"), &p).as_deref(),
        Some("ls -la")
    );
    // A line that does not start with the prompt (program output) is not captured.
    assert_eq!(heuristic_capture(&ctx("Continue? y"), &p), None);
    // An empty command is not captured.
    assert_eq!(heuristic_capture(&ctx("user@h:~$ "), &p), None);
}

#[test]
fn t03_prompt_with_changing_cwd_is_anchored() {
    let mut p = PromptLearner::new();
    p.observe("user@h:~$ ");
    p.observe("user@h:/tmp$ ");
    p.observe("user@h:/var/log$ ");
    assert_eq!(
        p.pattern(),
        Some(&PromptPattern::Anchored {
            anchor: "user@h:".into(),
            sigil: '$'
        })
    );
    assert_eq!(p.strip("user@h:/etc$ cat hosts"), Some("cat hosts"));
    assert_eq!(p.strip("root@x:/etc# id"), None);
}

#[test]
fn t03_only_prompt_like_text_is_observed_and_the_window_is_five() {
    let mut p = PromptLearner::new();
    p.observe("Password: ");
    p.observe("loading...");
    p.observe("$");
    assert!(!p.is_learned());
    p.observe("❯ ");
    assert_eq!(p.strip("❯ git status"), Some("git status"));
    // Five newer observations push the old prompt out.
    for _ in 0..5 {
        p.observe("[root@db ~]# ");
    }
    assert_eq!(
        p.pattern(),
        Some(&PromptPattern::Exact("[root@db ~]# ".into()))
    );
    assert_eq!(p.strip("❯ git status"), None);
}

// ------------------------------------------------------------------- T-04

#[test]
fn t04_no_capture_on_the_alt_screen_or_after_a_password_prompt() {
    let mut p = PromptLearner::new();
    p.observe("user@h:~$ ");
    let line = "user@h:~$ ls";
    assert_eq!(heuristic_capture(&ctx(line), &p).as_deref(), Some("ls"));

    let alt = CaptureContext {
        alt_screen: true,
        ..ctx(line)
    };
    assert_eq!(heuristic_capture(&alt, &p), None);

    let after_password = CaptureContext {
        previous_line: Some("Password:"),
        ..ctx(line)
    };
    assert_eq!(heuristic_capture(&after_password, &p), None);
    for prev in [
        "[sudo] password for user: ",
        "Enter passphrase for key '/k':",
        "API Token:",
    ] {
        let c = CaptureContext {
            previous_line: Some(prev),
            ..ctx(line)
        };
        assert_eq!(heuristic_capture(&c, &p), None, "{prev}");
    }
    // A password prompt on the cursor line itself.
    assert_eq!(heuristic_capture(&ctx("Password: hunter2"), &p), None);
    // Not a prompt: no colon at the end.
    let c = CaptureContext {
        previous_line: Some("password changed successfully"),
        ..ctx(line)
    };
    assert_eq!(heuristic_capture(&c, &p).as_deref(), Some("ls"));

    let secret = CaptureContext {
        secret_prompt_open: true,
        ..ctx(line)
    };
    assert_eq!(heuristic_capture(&secret, &p), None);
}

// ------------------------------------------------------------------- T-05

#[test]
fn t05_host_history_before_global_with_frequency_boost_and_prefix() {
    let h1 = Some(id(1));
    let h2 = Some(id(2));
    let hour = 3_600_000;
    let history = vec![
        // Host 1: `git status` used often (older), `git stash` once (newer).
        entry("git status", h1, 10 * hour),
        entry("git status", h1, 11 * hour),
        entry("git status", h1, 12 * hour),
        entry("git stash", h1, 13 * hour),
        entry("ls", h1, 13 * hour + hour / 2),
        // Host 2: newest of all, still after host 1's entries.
        entry("git log", h2, 100 * hour),
        // Also used on host 2, but host 1 has it: shown once, as H.
        entry("ls", h2, 101 * hour),
    ];
    let snippets = vec![SnippetSource {
        id: id(9),
        name: "deploy".into(),
        first_line: "git pull && make".into(),
    }];
    let commons = ["git status", "git push", "ls -la"];

    let req = SuggestRequest {
        host: h1,
        prefix: "",
        query: "",
        limit: 50,
    };
    let rows = suggest(&req, &history, &snippets, &commons);
    let got: Vec<(char, &str)> = rows
        .iter()
        .map(|s| (s.source.icon(), s.text.as_str()))
        .collect();
    assert_eq!(
        got,
        [
            // 3 uses at 10–12 h beat 1 use at 13–14 h (frequency boost).
            ('H', "git status"),
            ('H', "ls"),
            ('H', "git stash"),
            ('G', "git log"),
            ('S', "git pull && make"),
            ('C', "git push"),
            ('C', "ls -la"),
        ]
    );
    assert_eq!(rows[0].count, 3);

    // Prefix filter (tier 1): only candidates extending `git s`.
    let req = SuggestRequest {
        prefix: "git s",
        ..req
    };
    let rows = suggest(&req, &history, &snippets, &commons);
    let got: Vec<&str> = rows.iter().map(|s| s.text.as_str()).collect();
    assert_eq!(got, ["git status", "git stash"]);
    assert_eq!(remainder(&rows[0].text, "git s"), "tatus");

    // Fuzzy query, snippets by name.
    let req = SuggestRequest {
        prefix: "",
        query: "deploy",
        ..req
    };
    let rows = suggest(&req, &history, &snippets, &commons);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].snippet, Some(id(9)));
}

#[test]
fn t05_unverified_and_exit_code_come_from_the_entries() {
    let mut bad = entry("make", None, 2);
    bad.exit_code = Some(2);
    bad.verified = false;
    let mut old = entry("make", None, 1);
    old.verified = false;
    let req = SuggestRequest {
        host: None,
        prefix: "",
        query: "",
        limit: 10,
    };
    let rows = suggest(&req, &[old, bad], &[], &[]);
    assert_eq!(rows.len(), 1);
    assert!(rows[0].unverified);
    assert_eq!(rows[0].exit_code, Some(2), "the latest use's exit code");
    let entries = rows_to_entries(&rows);
    assert_eq!(ghost_suggestion(None, "ma", &entries), Some("make"));
    assert_eq!(
        ghost_suggestion(None, "make", &entries),
        None,
        "nothing to add"
    );
    assert_eq!(ghost_suggestion(None, "", &rows_to_entries(&rows)), None);
}

fn rows_to_entries(rows: &[Suggestion]) -> Vec<HistoryEntry> {
    rows.iter()
        .map(|s| entry(&s.text, None, s.last_used.0))
        .collect()
}

#[test]
fn t05_static_set_is_large_and_unique() {
    let all = static_commands();
    assert!(all.len() >= 300, "{}", all.len());
    let unique: std::collections::HashSet<_> = all.iter().collect();
    assert_eq!(unique.len(), all.len());
    for want in [
        "git status",
        "docker ps",
        "kubectl get pods",
        "systemctl restart",
        "ls -la",
    ] {
        assert!(all.contains(&want), "{want}");
    }
}

// ------------------------------------------------------------------- T-07

#[test]
fn t07_cap_per_host_trims_the_oldest() {
    let h1 = Some(id(1));
    let h2 = Some(id(2));
    let mut entries = Vec::new();
    for i in 0..10u8 {
        entries.push(StoredEntry {
            id: id(10 + i),
            entry: entry(&format!("c{i}"), h1, i64::from(i)),
        });
    }
    for i in 0..3u8 {
        entries.push(StoredEntry {
            id: id(50 + i),
            entry: entry("x", h2, 0),
        });
    }
    let mut trimmed = trim_to_cap(&entries, h1, 7);
    trimmed.sort();
    assert_eq!(
        trimmed,
        [id(10), id(11), id(12)],
        "the three oldest of host 1"
    );
    assert!(
        trim_to_cap(&entries, h2, 7).is_empty(),
        "host 2 is under the cap"
    );
    assert_eq!(trim_to_cap(&entries, h2, 0).len(), 3);
    assert_eq!(entries_of(&entries, h2).len(), 3);
}

#[test]
fn clean_command_drops_controls_and_blanks() {
    assert_eq!(clean_command("  ls\x07 -l \t"), Some("ls -l".into()));
    assert_eq!(clean_command(" \t "), None);
    assert!(is_secret_prompt("Password:"));
    assert!(!is_secret_prompt("passwd"));
}
