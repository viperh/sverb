//! M7-05 T-06: the emulator-level protections against malicious remote output
//! (SPEC §17 "Malicious remote output", §7.3), together in one module. Each test feeds
//! hostile bytes to a real emulator (or the paste encoder) and checks that nothing is
//! executed, opened, copied or echoed back.
//!
//! The UI half of the same rules lives next to the reducer:
//! - OSC 52 writes need the user's consent under the default `ask` policy:
//!   `sverb-tui` `app::input::remote_io::tests::t14_remote_clipboard_ask` and
//!   `remote_clipboard_never_and_always`;
//! - an OSC 8 link opens only after a keypress and a confirm dialog that shows the URL:
//!   `sverb-tui` `app::copy_tests::t09_open_link_needs_confirmation`.
//!
//! `docs/threat-model.md` maps all of them to the §17 table.
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use sverb_term::{
    AlacrittyEmulator, ClipboardTarget, Emulator, EmulatorConfig, GridPoint, TermEvent, TermModes,
    input::{PASTE_END, PASTE_START, encode_paste, strip_paste_markers},
    policy::{ClipboardDecision, ClipboardWritePolicy, MAX_CLIPBOARD_WRITE_BYTES, MAX_TITLE_CHARS},
};

fn emu() -> AlacrittyEmulator {
    AlacrittyEmulator::new(EmulatorConfig {
        cols: 80,
        rows: 24,
        scrollback: 100,
    })
}

fn replies(e: &mut AlacrittyEmulator) -> Vec<u8> {
    e.take_responses().iter().flat_map(|b| b.to_vec()).collect()
}

/// OSC 52 **reads** are always denied: no reply carries the clipboard back to the
/// remote, whatever the target, terminator or prior writes.
#[test]
fn osc52_reads_are_always_denied() {
    let mut e = emu();
    e.feed(b"\x1b]52;c;c2VjcmV0\x07");
    let _ = e.take_events();
    for query in [
        &b"\x1b]52;c;?\x07"[..],
        b"\x1b]52;p;?\x1b\\",
        b"\x1b]52;s;?\x07",
        b"\x1b]52;;?\x07",
        b"\x1b]52;cpqs01234567;?\x07",
    ] {
        e.feed(query);
        assert!(replies(&mut e).is_empty(), "{query:?} got a reply");
        assert!(e.take_events().is_empty(), "{query:?} reported an event");
    }
}

/// OSC 52 **writes** are only reported (the UI gates them; `ask` by default), never
/// answered, and oversized ones are dropped.
#[test]
fn osc52_writes_are_reported_for_the_ui_to_gate() {
    let mut e = emu();
    e.feed(b"\x1b]52;c;aGVsbG8=\x07");
    assert_eq!(
        e.take_events(),
        vec![TermEvent::ClipboardWriteRequest {
            target: ClipboardTarget::Clipboard,
            text: "hello".into(),
        }]
    );
    assert!(replies(&mut e).is_empty());

    // The default policy asks; `never` drops; only an explicit `always` relays.
    assert_eq!(ClipboardWritePolicy::default(), ClipboardWritePolicy::Ask);
    assert_eq!(
        ClipboardWritePolicy::Ask.decide(),
        ClipboardDecision::Prompt
    );
    assert_eq!(
        ClipboardWritePolicy::Never.decide(),
        ClipboardDecision::Drop
    );
    assert_eq!(
        ClipboardWritePolicy::Always.decide(),
        ClipboardDecision::Relay
    );

    // Larger than the cap: not reported at all.
    let big = "A".repeat((MAX_CLIPBOARD_WRITE_BYTES / 3 + 1) * 4 + 8);
    e.feed(format!("\x1b]52;c;{big}\x07").as_bytes());
    let events = e.take_events();
    assert!(
        !events
            .iter()
            .any(|ev| matches!(ev, TermEvent::ClipboardWriteRequest { .. })),
        "an oversized write was reported"
    );
}

/// OSC 7 only stores the working directory (an event with sanitized text); nothing is
/// opened or replied.
#[test]
fn osc7_only_reports_the_directory() {
    let mut e = emu();
    e.feed(b"\x1b]7;file://host.example/tmp/a%20b\x1b\\");
    let events = e.take_events();
    assert!(
        events.iter().all(|ev| matches!(ev, TermEvent::Cwd { .. })),
        "{events:?}"
    );
    assert!(
        events
            .iter()
            .any(|ev| matches!(ev, TermEvent::Cwd { path, .. } if path == "/tmp/a b")),
        "{events:?}"
    );
    // Control characters in the path never reach the UI.
    e.feed(b"\x1b]7;file://h/tmp/%1b%5b31mevil%07\x07");
    for ev in e.take_events() {
        if let TermEvent::Cwd { path, .. } = ev {
            assert!(!path.chars().any(char::is_control), "{path:?}");
        }
    }
    assert!(replies(&mut e).is_empty());
}

/// OSC 8 hyperlinks are only attached to cells: printing one emits no event and no
/// reply. Opening it is a separate, confirmed user action in the UI.
#[test]
fn osc8_links_open_nothing_by_themselves() {
    let mut e = emu();
    e.feed(b"\x1b]8;;file:///etc/passwd\x1b\\click\x1b]8;;\x1b\\");
    e.feed(b"\x1b]8;id=x;javascript:alert(1)\x07js\x1b]8;;\x07");
    assert!(e.take_events().is_empty());
    assert!(replies(&mut e).is_empty());
    let link = e.hyperlink_at(GridPoint::new(0, 0)).unwrap();
    assert_eq!(link.uri, "file:///etc/passwd");
}

/// Titles are capped at 256 chars and stripped of control characters.
#[test]
fn titles_are_capped_and_sanitized() {
    let mut e = emu();
    let mut seq = b"\x1b]0;".to_vec();
    // Control characters that do not end the string (an ESC would abort it).
    seq.extend_from_slice("\u{1}\u{8}\u{7f}\u{9b}2Jx".as_bytes());
    seq.extend(std::iter::repeat_n(b'y', 5_000));
    seq.push(0x07);
    e.feed(&seq);
    let events = e.take_events();
    let [TermEvent::Title(Some(title))] = events.as_slice() else {
        panic!("{events:?}")
    };
    assert_eq!(MAX_TITLE_CHARS, 256);
    assert!(title.chars().count() <= MAX_TITLE_CHARS, "{}", title.len());
    assert!(!title.chars().any(char::is_control), "{title:?}");
    // XTWINOPS title report (CSI 21 t) is never answered: the title can't be echoed
    // back as input.
    e.feed(b"\x1b[21t\x1b[20t");
    assert!(replies(&mut e).is_empty());
}

/// Query replies are generated by the emulator from its own state, never echoed from
/// remote input.
#[test]
fn query_replies_are_generated_not_echoed() {
    let mut e = emu();
    e.feed(b"\x1b[c");
    assert_eq!(replies(&mut e), b"\x1b[?6c");
    e.feed(b"\x1b[5;7H\x1b[6n");
    assert_eq!(replies(&mut e), b"\x1b[5;7R");
    // Query-shaped text inside an OSC string is not a query, and is never echoed.
    e.feed(b"\x1b]2;[6n \x9b6n\x07");
    assert!(replies(&mut e).is_empty());
    // An ESC aborts a string (as in xterm): what follows is a real query, and its
    // reply is built from the emulator's state, not from the remote's bytes.
    e.feed(b"\x1b]2;\x1b[6n\x07");
    e.feed(b"\x1bPq\x1b[c\x1b\\");
    assert_eq!(replies(&mut e), b"\x1b[5;7R\x1b[?6c");
    // DECRQSS / XTGETTCAP style requests do not reflect their payload.
    e.feed(b"\x1bP$qrm -rf ~\x1b\\\x1bP+q726d202d7266\x1b\\");
    let r = String::from_utf8_lossy(&replies(&mut e)).into_owned();
    assert!(!r.contains("rm -rf"), "{r:?}");
}

/// OSCs and DCS strings that execute or open things in other terminals (iTerm2 file
/// transfer, notifications, kitty remote control, tmux passthrough, vim `drop`) do
/// nothing here: no reply, no event.
#[test]
fn dangerous_terminal_extensions_are_inert() {
    let mut e = emu();
    for seq in [
        &b"\x1b]1337;File=name=eA==;inline=1:aGVsbG8=\x07"[..],
        b"\x1b]1337;SetUserVar=x=eQ==\x07",
        b"\x1b]9;notify me\x07",
        b"\x1b]777;notify;title;body\x07",
        b"\x1b]5113;ac=send;id=1\x1b\\",
        b"\x1bP@kitty-cmd{\"cmd\":\"launch\"}\x1b\\",
        b"\x1b]51;[\"drop\",\"/etc/passwd\"]\x07",
        b"\x1b]50;?\x07",
        b"\x1b]6;1;bg;red;brightness;255\x07",
    ] {
        e.feed(seq);
        assert!(replies(&mut e).is_empty(), "{seq:?} got a reply");
        let events = e.take_events();
        assert!(
            events.iter().all(|ev| matches!(ev, TermEvent::Bell)),
            "{seq:?} produced {events:?}"
        );
    }
}

/// tmux passthrough is not unwrapped: the doubled ESC ends the DCS, and the OSC 52 that
/// follows is an ordinary write request, which the UI gates like any other.
#[test]
fn tmux_passthrough_is_not_a_bypass() {
    let mut e = emu();
    e.feed(b"\x1bPtmux;\x1b\x1b]52;c;aGk=\x07\x1b\\");
    assert!(replies(&mut e).is_empty());
    for ev in e.take_events() {
        assert!(
            matches!(
                ev,
                TermEvent::ClipboardWriteRequest { .. } | TermEvent::Bell
            ),
            "{ev:?}"
        );
    }
    e.feed(b"\x1bPtmux;\x1b\x1b]52;c;?\x07\x1b\\");
    assert!(
        replies(&mut e).is_empty(),
        "a read through tmux passthrough got a reply"
    );
}

/// A paste can't end bracketed paste early: every `ESC[201~` (and `ESC[200~`) inside
/// the text is removed, also when one is split around another.
#[test]
fn paste_cannot_inject_an_end_marker() {
    let modes = TermModes {
        bracketed_paste: true,
        ..TermModes::default()
    };
    for text in [
        "ls\x1b[201~rm -rf ~\n",
        "\x1b[20\x1b[201~1~rm -rf ~\n",
        "\x1b[2\x1b[200~01~\x1b[201~echo pwned\r",
        "a\x1b[200~b",
    ] {
        let out = String::from_utf8(encode_paste(text, &modes).to_vec()).unwrap();
        assert!(
            out.starts_with(PASTE_START) && out.ends_with(PASTE_END),
            "{out:?}"
        );
        let body = &out[PASTE_START.len()..out.len() - PASTE_END.len()];
        assert!(
            !body.contains(PASTE_END) && !body.contains(PASTE_START),
            "{out:?}"
        );
        assert_eq!(strip_paste_markers(body), body);
    }
}
