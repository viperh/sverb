#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use sverb_crypto::Key32;

use super::{
    asciicast::{Event, EventKind, Header, MAX_EVENT_DATA, Utf8Stream, split_data},
    player::{CHECKPOINT_EVERY, IDLE_CAP, Player, playback_times},
    reader::{Recording, RecordingError, read_recording},
    writer::{ChunkWriter, FILE_HEADER_LEN, Recorder, RecorderMeta},
};

fn key() -> Key32 {
    Key32::from_bytes([7; 32])
}

const CONN: [u8; 16] = [1; 16];

fn secs(s: f64) -> Duration {
    Duration::from_secs_f64(s)
}

/// Record `events` (output only), sealing a chunk after every `per_chunk` events.
fn record(conn: [u8; 16], outputs: &[(f64, &str)], per_chunk: usize) -> Vec<u8> {
    let chunks = ChunkWriter::new(Vec::new(), key(), conn).unwrap();
    let mut rec = Recorder::new(chunks, RecorderMeta::default(), (80, 24));
    rec.resize(Duration::ZERO, 80, 24).unwrap();
    for (i, (t, text)) in outputs.iter().enumerate() {
        rec.output(secs(*t), text.as_bytes()).unwrap();
        if (i + 1) % per_chunk == 0 {
            rec.flush_chunk().unwrap();
        }
    }
    rec.finish().unwrap()
}

/// Byte ranges of each chunk frame (length prefix included).
fn frames(file: &[u8]) -> Vec<std::ops::Range<usize>> {
    let mut out = Vec::new();
    let mut pos = FILE_HEADER_LEN;
    while pos + 4 <= file.len() {
        let len = u32::from_be_bytes(file[pos..pos + 4].try_into().unwrap()) as usize;
        out.push(pos..pos + 4 + len);
        pos += 4 + len;
    }
    out
}

fn read(file: &[u8]) -> Result<Recording, RecordingError> {
    read_recording(file, key())
}

#[test]
fn t01_asciicast_lines_are_valid_json() {
    let mut header = Header::new(120, 40);
    header.timestamp = Some(1_700_000_000);
    header.title = Some("prod \"web\" ✓".into());
    header.env = Some(super::asciicast::HeaderEnv {
        term: Some("xterm-256color".into()),
    });
    let line = header.to_line();
    let v: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(v["version"], 2);
    assert_eq!(v["width"], 120);
    assert_eq!(v["height"], 40);
    assert_eq!(v["timestamp"], 1_700_000_000);
    assert_eq!(v["env"]["TERM"], "xterm-256color");
    assert_eq!(v["title"], "prod \"web\" ✓");
    assert_eq!(Header::parse(&line).unwrap(), header);

    let data = "\x1b[31mred\x1b[0m\r\n\x00\x07\x7f tab\t é 🦀 \"q\" \\ \u{2028}";
    let ev = Event::new(secs(1.5), EventKind::Output, data);
    let line = ev.to_line();
    assert!(line.starts_with("[1.500000, \"o\", \""), "{line}");
    assert!(line.contains("\\u001b[31m"), "{line}");
    assert!(
        !line.chars().any(|c| (c as u32) < 0x20),
        "raw control char in {line:?}"
    );
    let v: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(v[0].as_f64(), Some(1.5));
    assert_eq!(v[1], "o");
    assert_eq!(v[2], data);
    assert_eq!(Event::parse(&line).unwrap(), ev);

    let r = Event::new(secs(2.0), EventKind::Resize, "100x30");
    assert_eq!(
        Event::parse(&r.to_line()).unwrap().resize_size(),
        Some((100, 30))
    );

    // A fixture as written by asciinema 2.x.
    let fixture = concat!(
        "{\"version\": 2, \"width\": 80, \"height\": 24, \"timestamp\": 1504467315, ",
        "\"title\": \"Demo\", \"env\": {\"TERM\": \"xterm-256color\", \"SHELL\": \"/bin/zsh\"}}\n",
        "[0.248848, \"o\", \"\\u001b]0;user@host:~\\u0007\"]\n",
        "[1.001376, \"o\", \"\\u001b[1m$ \\u001b[0m\"]\n",
        "[2.143733, \"o\", \"é\\r\\n\"]\n",
    );
    let mut lines = fixture.lines();
    let h = Header::parse(lines.next().unwrap()).unwrap();
    assert_eq!((h.width, h.height), (80, 24));
    let evs: Vec<Event> = lines.map(|l| Event::parse(l).unwrap()).collect();
    assert_eq!(evs.len(), 3);
    assert_eq!(evs[2].data, "é\r\n");
    // Our own lines parse the same way a generic JSON reader does.
    for ev in &evs {
        let v: serde_json::Value = serde_json::from_str(&ev.to_line()).unwrap();
        assert_eq!(v[2], ev.data.as_str());
    }
}

#[test]
fn split_data_respects_char_boundaries_and_limit() {
    let s = "é".repeat(MAX_EVENT_DATA); // 2 bytes each
    let pieces: Vec<&str> = split_data(&s).collect();
    assert!(pieces.iter().all(|p| p.len() <= MAX_EVENT_DATA));
    assert_eq!(pieces.concat(), s);
    // Worst-case escaping still fits a chunk.
    let ctrl = "\x01".repeat(MAX_EVENT_DATA);
    let line = Event::new(secs(1.0), EventKind::Output, ctrl).to_line();
    assert!(line.len() < super::writer::CHUNK_PLAINTEXT_MAX);
}

#[test]
fn utf8_stream_carries_split_sequences() {
    let mut s = Utf8Stream::default();
    let bytes = "a🦀b".as_bytes();
    let mut out = s.decode(&bytes[..2]);
    out += &s.decode(&bytes[2..]);
    assert_eq!(out, "a🦀b");
    assert_eq!(s.decode(b"x\xffy"), "x\u{FFFD}y");
    let _ = s.decode(&[0xF0, 0x9F]);
    assert_eq!(s.finish(), "\u{FFFD}");
}

#[test]
fn round_trip_small() {
    let file = record(CONN, &[(0.5, "hello\r\n"), (1.0, "world")], 100);
    let rec = read(&file).unwrap();
    assert!(!rec.incomplete);
    assert_eq!((rec.header.width, rec.header.height), (80, 24));
    let data: Vec<&str> = rec.events.iter().map(|e| e.data.as_str()).collect();
    assert_eq!(data, ["hello\r\n", "world"]);
    assert_eq!(rec.events[1].time, secs(1.0));
}

#[test]
fn t03_truncation_is_reported_and_prefix_survives() {
    let outs: Vec<(f64, String)> = (0..9)
        .map(|i| (f64::from(i), format!("line {i}\r\n")))
        .collect();
    let outs: Vec<(f64, &str)> = outs.iter().map(|(t, s)| (*t, s.as_str())).collect();
    let file = record(CONN, &outs, 3);
    let fr = frames(&file);
    assert_eq!(fr.len(), 4, "3 full chunks + an empty final one");

    // Drop the final chunk.
    let cut = &file[..fr[3].start];
    let rec = read(cut).unwrap();
    assert!(rec.incomplete);
    assert_eq!(rec.events.len(), 9);

    // Drop the last two chunks.
    let cut = &file[..fr[2].start];
    let rec = read(cut).unwrap();
    assert!(rec.incomplete);
    assert_eq!(rec.events.len(), 6);
    assert_eq!(rec.events[5].data, "line 5\r\n");

    // A torn chunk at the end (crash mid-write).
    let cut = &file[..fr[2].start + 10];
    let rec = read(cut).unwrap();
    assert!(rec.incomplete);
    assert_eq!(rec.events.len(), 6);

    // Intact: complete.
    assert!(!read(&file).unwrap().incomplete);
}

#[test]
fn t04_reordered_or_foreign_chunks_fail_auth() {
    let outs = [(0.0, "a"), (1.0, "b"), (2.0, "c"), (3.0, "d")];
    let file = record(CONN, &outs, 2);
    let fr = frames(&file);
    assert!(fr.len() >= 3);

    // Swap chunks 0 and 1.
    let mut swapped = file[..FILE_HEADER_LEN].to_vec();
    swapped.extend_from_slice(&file[fr[1].clone()]);
    swapped.extend_from_slice(&file[fr[0].clone()]);
    swapped.extend_from_slice(&file[fr[2].start..]);
    assert!(matches!(
        read(&swapped),
        Err(RecordingError::Auth { chunk: 0 })
    ));

    // Chunk 1 from another recording (different conn_id), same index.
    let other = record([2; 16], &outs, 2);
    let ofr = frames(&other);
    let mut spliced = file[..fr[1].start].to_vec();
    spliced.extend_from_slice(&other[ofr[1].clone()]);
    spliced.extend_from_slice(&file[fr[2].start..]);
    assert!(matches!(
        read(&spliced),
        Err(RecordingError::Auth { chunk: 1 })
    ));

    // Re-labelling the header's conn_id breaks every chunk.
    let mut relabeled = file.clone();
    relabeled[7] ^= 1;
    assert!(matches!(
        read(&relabeled),
        Err(RecordingError::Auth { chunk: 0 })
    ));

    // The final chunk moved before a non-final one.
    let mut early_last = file[..FILE_HEADER_LEN].to_vec();
    early_last.extend_from_slice(&file[fr[0].clone()]);
    early_last.extend_from_slice(&file[fr[fr.len() - 1].clone()]);
    assert!(matches!(
        read(&early_last),
        Err(RecordingError::Auth { chunk: 1 })
    ));

    // Wrong key.
    assert!(matches!(
        read_recording(&file[..], Key32::from_bytes([8; 32])),
        Err(RecordingError::Auth { chunk: 0 })
    ));

    // Not a recording.
    assert!(matches!(
        read(b"{\"version\":2}"),
        Err(RecordingError::NotARecording)
    ));
}

#[test]
fn t05_input_only_with_opt_in() {
    for include_input in [false, true] {
        let chunks = ChunkWriter::new(Vec::new(), key(), CONN).unwrap();
        let meta = RecorderMeta {
            include_input,
            ..RecorderMeta::default()
        };
        let mut rec = Recorder::new(chunks, meta, (80, 24));
        rec.output(secs(0.1), b"Password: ").unwrap();
        rec.input(secs(0.5), b"hunter2\r").unwrap();
        rec.output(secs(0.6), b"\r\n$ ").unwrap();
        let file = rec.finish().unwrap();
        let rec = read(&file).unwrap();
        let inputs: Vec<&Event> = rec
            .events
            .iter()
            .filter(|e| e.kind == EventKind::Input)
            .collect();
        if include_input {
            assert_eq!(inputs.len(), 1);
            assert_eq!(inputs[0].data, "hunter2\r");
        } else {
            assert!(inputs.is_empty());
            assert!(!rec.events.iter().any(|e| e.data.contains("hunter2")));
        }
    }
}

fn recording(events: Vec<Event>) -> Recording {
    Recording {
        header: Header::new(40, 10),
        events,
        incomplete: false,
    }
}

#[test]
fn t08_idle_gaps_are_capped_at_two_seconds() {
    let events = vec![
        Event::new(secs(0.0), EventKind::Output, "a"),
        Event::new(secs(0.5), EventKind::Output, "b"),
        Event::new(secs(30.5), EventKind::Output, "c"),
        Event::new(secs(31.0), EventKind::Output, "d"),
    ];
    let times = playback_times(&events, IDLE_CAP);
    assert_eq!(times, [secs(0.0), secs(0.5), secs(2.5), secs(3.0)]);

    let mut p = Player::new(recording(events));
    assert_eq!(p.total(), secs(3.0));
    p.toggle_pause();
    assert!(p.is_playing());
    p.advance(secs(2.4));
    assert!(!p.emulator().screen_dump(false).contains("abc"));
    p.advance(secs(0.1)); // 2.5 s: "c" has played, 28 s of idle took 2 s.
    assert!(p.emulator().screen_dump(false).contains("abc"));
    p.advance(secs(10.0));
    assert!(p.at_end());
    assert!(!p.is_playing());
    assert!(p.emulator().screen_dump(false).contains("abcd"));
}

#[test]
fn speed_scales_wall_time() {
    let events = vec![
        Event::new(secs(0.0), EventKind::Output, "a"),
        Event::new(secs(1.0), EventKind::Output, "b"),
    ];
    let mut p = Player::new(recording(events));
    p.faster();
    p.faster();
    p.faster();
    assert_eq!(p.speed(), super::Speed::X4);
    p.toggle_pause();
    p.advance(secs(0.25));
    assert_eq!(p.elapsed(), secs(1.0));
    assert!(p.emulator().screen_dump(false).contains("ab"));
    p.slower();
    assert_eq!(p.speed(), super::Speed::X2);
}

fn long_recording() -> Recording {
    let mut events = vec![Event::new(secs(0.0), EventKind::Output, "\x1b[2J\x1b[H")];
    for i in 1..=100_u32 {
        let t = secs(f64::from(i));
        let text = match i % 7 {
            0 => format!("\x1b[2J\x1b[H\x1b[1;3{}mclear {i}\x1b[0m\r\n", i % 8),
            3 => format!("\x1b[5;10H\x1b[4mat {i}\x1b[24m"),
            _ => format!("line {i} \x1b[3{}m■\x1b[0m\r\n", i % 8),
        };
        events.push(Event::new(t, EventKind::Output, text));
        if i == 50 {
            events.push(Event::new(t, EventKind::Resize, "50x12"));
        }
    }
    recording(events)
}

#[test]
fn t09_seek_back_via_checkpoint_matches_linear_replay() {
    for target in [secs(75.5), secs(31.0), secs(55.2), secs(3.0)] {
        // Linear replay to `target`.
        let mut linear = Player::new(long_recording());
        linear.toggle_pause();
        linear.advance(target);
        assert_eq!(linear.elapsed(), target);

        // Play to the end (taking checkpoints), then seek back.
        let mut seeker = Player::new(long_recording());
        seeker.seek_to(secs(100.0));
        assert!(seeker.checkpoint_count() >= 3, "{seeker:?}");
        seeker.seek_to(target);
        assert_eq!(seeker.elapsed(), target);
        assert_eq!(
            seeker.emulator().screen_dump(true),
            linear.emulator().screen_dump(true),
            "target {target:?}"
        );
    }
    assert_eq!(CHECKPOINT_EVERY, secs(30.0));
}

#[test]
fn seek_steps_are_five_seconds_and_clamped() {
    let mut p = Player::new(long_recording());
    p.seek_by(true);
    assert_eq!(p.elapsed(), secs(5.0));
    p.seek_by(false);
    p.seek_by(false);
    assert_eq!(p.elapsed(), Duration::ZERO);
    p.seek_to(secs(1000.0));
    assert_eq!(p.elapsed(), p.total());
    // Play at the end restarts.
    p.toggle_pause();
    assert!(p.is_playing());
    assert_eq!(p.elapsed(), Duration::ZERO);
}
