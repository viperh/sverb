//! OSC 133 shell integration (T-01 parser split at every byte boundary, T-02 a
//! recorded bash session with the integration installed).
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use sverb_term::{
    AlacrittyEmulator, Emulator, EmulatorConfig, PromptMarkKind, TermEvent,
    osc133::{PromptState, ShellCommand},
};

const BASH_STREAM: &[u8] = include_bytes!("streams/bash_osc133.bin");

fn emu(cols: u16, rows: u16) -> AlacrittyEmulator {
    AlacrittyEmulator::new(EmulatorConfig {
        cols,
        rows,
        scrollback: 1000,
    })
}

fn marks(events: &[TermEvent]) -> Vec<PromptMarkKind> {
    events
        .iter()
        .filter_map(|e| match e {
            TermEvent::PromptMark { kind, .. } => Some(*kind),
            _ => None,
        })
        .collect()
}

fn commands(events: &[TermEvent]) -> Vec<ShellCommand> {
    events
        .iter()
        .filter_map(|e| match e {
            TermEvent::Command(c) => Some(c.clone()),
            _ => None,
        })
        .collect()
}

fn cmd(command: &str, exit_code: Option<i32>) -> ShellCommand {
    ShellCommand {
        command: command.into(),
        exit_code,
    }
}

/// A/B/C/D (with and without exit codes, BEL and ST terminated) are recognized
/// whatever the read boundaries, and the captured command is the same.
#[test]
fn t01_marks_split_at_every_byte_boundary() {
    let stream: &[u8] =
        b"\x1b]133;A\x07$ \x1b]133;B\x1b\\echo hi\r\n\x1b]133;C\x07hi\r\n\x1b]133;D;42\x07\
\x1b]133;A\x07$ \x1b]133;B\x07true\r\n\x1b]133;C\x07\x1b]133;D\x1b\\";
    let want_marks = vec![
        PromptMarkKind::PromptStart,
        PromptMarkKind::CommandStart,
        PromptMarkKind::OutputStart,
        PromptMarkKind::CommandFinished {
            exit_code: Some(42),
        },
        PromptMarkKind::PromptStart,
        PromptMarkKind::CommandStart,
        PromptMarkKind::OutputStart,
        PromptMarkKind::CommandFinished { exit_code: None },
    ];
    let want_cmds = vec![cmd("echo hi", Some(42)), cmd("true", None)];

    // Whole, then every single split point, then byte by byte.
    let mut cases: Vec<Vec<&[u8]>> = vec![vec![stream]];
    for i in 1..stream.len() {
        cases.push(vec![&stream[..i], &stream[i..]]);
    }
    cases.push(stream.chunks(1).collect());
    for (n, chunks) in cases.iter().enumerate() {
        let mut e = emu(80, 24);
        let mut events = Vec::new();
        for c in chunks {
            e.feed(c);
            events.extend(e.take_events());
        }
        assert_eq!(marks(&events), want_marks, "case {n}");
        assert_eq!(commands(&events), want_cmds, "case {n}");
    }
}

/// A recorded bash session with the integration (colored prompt, a stray `D` from
/// the rc file, a failing command, a command wrapped over three rows at 40 columns, an
/// empty `Enter`) gives exactly three commands with their exit codes.
#[test]
fn t02_recorded_bash_session() {
    let long = format!("echo {}", "x".repeat(70));
    let want = vec![
        cmd("ls", Some(0)),
        cmd("false", Some(1)),
        cmd(&long, Some(0)),
    ];
    for chunk in [BASH_STREAM.len(), 7, 1] {
        let mut e = emu(40, 10);
        let mut events = Vec::new();
        for c in BASH_STREAM.chunks(chunk) {
            e.feed(c);
            events.extend(e.take_events());
        }
        assert_eq!(commands(&events), want, "chunk {chunk}");
        // The shell waits at a fresh prompt with an empty command line.
        assert_eq!(
            e.prompt_state(),
            PromptState {
                integrated: true,
                input: Some(String::new())
            }
        );
    }
}

#[test]
fn prompt_state_reports_the_typed_prefix() {
    let mut e = emu(80, 24);
    assert_eq!(e.prompt_state(), PromptState::default());
    e.feed(b"\x1b]133;A\x07user@h:~$ \x1b]133;B\x07git ");
    assert_eq!(e.prompt_state().input.as_deref(), Some("git "));
    e.feed(b"st");
    assert_eq!(e.prompt_state().input.as_deref(), Some("git st"));
    // Running: no command line.
    e.feed(b"atus\r\n\x1b]133;C\x07");
    assert_eq!(
        e.prompt_state(),
        PromptState {
            integrated: true,
            input: None
        }
    );
    e.feed(b"On branch main\r\n\x1b]133;D;0\x07");
    assert_eq!(commands(&e.take_events()), [cmd("git status", Some(0))]);
}

#[test]
fn output_that_scrolls_and_clears_does_not_change_the_command() {
    let mut e = emu(20, 4);
    e.feed(b"\x1b]133;A\x07$ \x1b]133;B\x07clear\r\n\x1b]133;C\x07");
    // `clear` output: home, erase screen and scrollback, then lots of lines.
    e.feed(b"\x1b[H\x1b[2J\x1b[3J");
    for i in 0..50 {
        e.feed(format!("line {i}\r\n").as_bytes());
    }
    e.feed(b"\x1b]133;D;0\x07");
    assert_eq!(commands(&e.take_events()), [cmd("clear", Some(0))]);
}

#[test]
fn a_new_prompt_without_d_reports_the_command_without_exit_code() {
    let mut e = emu(80, 24);
    e.feed(b"\x1b]133;A\x07$ \x1b]133;B\x07sleep 1\r\n\x1b]133;C\x07^C\r\n");
    e.feed(b"\x1b]133;A\x07$ \x1b]133;B\x07");
    assert_eq!(commands(&e.take_events()), [cmd("sleep 1", None)]);
    // Stray marks: D without a command, C without B.
    e.feed(b"\x1b]133;D;0\x07\x1b]133;C\x07\x1b]133;D;3\x07");
    assert!(commands(&e.take_events()).is_empty());
}
