//! M3-05 integration tests: the recorder task end to end (T-02, T-06, T-07, T-12).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    io::{self, Write},
    sync::{Arc, Condvar, Mutex},
    time::Duration,
};

use sverb_crypto::Key32;
use sverb_term::recording::{
    EventKind, RecorderMeta, RecorderOptions, SyncWrite, create_recording_file, read_recording,
    spawn_recorder,
    writer::{CHUNK_PLAINTEXT_MAX, FILE_HEADER_LEN},
};

fn key() -> Key32 {
    Key32::from_bytes([42; 32])
}

const CONN: [u8; 16] = [9; 16];

/// An in-memory file shared with the test.
#[derive(Clone, Default)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl SharedBuf {
    fn bytes(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone()
    }
}

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl SyncWrite for SharedBuf {}

/// Chunk plaintext sizes are not visible in the file, but ciphertext = plaintext + tag.
fn chunk_lens(file: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    let mut pos = FILE_HEADER_LEN;
    while pos + 4 <= file.len() {
        let len = u32::from_be_bytes(file[pos..pos + 4].try_into().unwrap()) as usize;
        out.push(len);
        pos += 4 + len;
    }
    out
}

// T-02
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t02_300kb_round_trip_in_multiple_chunks() {
    let buf = SharedBuf::default();
    let mut opts = RecorderOptions::new(CONN, key());
    // Backpressure is T-07; here every event must get through.
    opts.capacity = 4096;
    let (tap, handle) = spawn_recorder(buf.clone(), opts).unwrap();
    tap.resize(100, 30);
    let mut sent = String::new();
    let mut i = 0_u32;
    while sent.len() < 300 * 1024 {
        // Mixed content: escapes, unicode, and a few large reads.
        let piece = if i.is_multiple_of(50) {
            "x".repeat(20_000)
        } else {
            format!("\x1b[3{}mline {i} é🦀\x1b[0m\r\n", i % 8)
        };
        tap.output(piece.as_bytes());
        sent.push_str(&piece);
        i += 1;
        if i.is_multiple_of(64) {
            // Let the writer drain so nothing is dropped.
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
    tap.resize(120, 40);
    drop(tap);
    let summary = handle.join.await.unwrap().unwrap();
    assert_eq!(summary.dropped_bytes, 0);

    let file = buf.bytes();
    let lens = chunk_lens(&file);
    assert!(lens.len() >= 5, "300 KB must span several chunks: {lens:?}");
    assert_eq!(lens.len() as u64, summary.chunks);
    for len in &lens {
        assert!(
            *len - 24 - 16 <= CHUNK_PLAINTEXT_MAX,
            "chunk plaintext > 64 KiB"
        );
    }

    let rec = read_recording(&file[..], key()).unwrap();
    assert!(!rec.incomplete, "the final chunk carries is_last");
    assert_eq!((rec.header.width, rec.header.height), (100, 30));
    let out: String = rec
        .events
        .iter()
        .filter(|e| e.kind == EventKind::Output)
        .map(|e| e.data.as_str())
        .collect();
    assert_eq!(out, sent);
    let last = rec.events.last().unwrap();
    assert_eq!(last.kind, EventKind::Resize);
    assert_eq!(last.resize_size(), Some((120, 40)));
    assert!(rec.events.windows(2).all(|w| w[0].time <= w[1].time));
}

// T-06
#[tokio::test(start_paused = true)]
async fn t06_crash_leaves_a_readable_prefix() {
    let buf = SharedBuf::default();
    let (tap, handle) = spawn_recorder(buf.clone(), RecorderOptions::new(CONN, key())).unwrap();
    tap.resize(80, 24);
    for s in 0..6 {
        tap.output(format!("second {s}\r\n").as_bytes());
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    // 6 s of activity: the 5 s flush sealed a chunk. Now "crash" (no close).
    handle.join.abort();
    let _ = handle.join.await;
    drop(tap);

    let file = buf.bytes();
    assert!(
        !chunk_lens(&file).is_empty(),
        "a chunk was flushed within 5 s"
    );
    let rec = read_recording(&file[..], key()).unwrap();
    assert!(rec.incomplete, "no final chunk: reported as truncated");
    let text: String = rec.events.iter().map(|e| e.data.as_str()).collect();
    assert!(text.contains("second 0"), "{text:?}");
    assert!(text.contains("second 4"), "{text:?}");
}

/// A writer whose writes block until the gate opens.
#[derive(Clone)]
struct GatedBuf {
    buf: SharedBuf,
    gate: Arc<(Mutex<bool>, Condvar)>,
    writes: Arc<Mutex<usize>>,
}

impl GatedBuf {
    fn open(&self) {
        let (lock, cv) = &*self.gate;
        *lock.lock().unwrap() = true;
        cv.notify_all();
    }
}

impl Write for GatedBuf {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        *self.writes.lock().unwrap() += 1;
        let (lock, cv) = &*self.gate;
        let mut open = lock.lock().unwrap();
        while !*open {
            open = cv.wait(open).unwrap();
        }
        drop(open);
        self.buf.write(data)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl SyncWrite for GatedBuf {}

// T-07
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t07_backpressure_drops_and_marks_without_blocking() {
    let gated = GatedBuf {
        buf: SharedBuf::default(),
        gate: Arc::new((Mutex::new(true), Condvar::new())),
        writes: Arc::default(),
    };
    let mut opts = RecorderOptions::new(CONN, key());
    opts.capacity = 8;
    let (tap, handle) = spawn_recorder(gated.clone(), opts).unwrap();
    // Close the gate: the next chunk write blocks the writer.
    *gated.gate.0.lock().unwrap() = false;

    let started = std::time::Instant::now();
    let big = "y".repeat(16 * 1024);
    for _ in 0..200 {
        tap.output(big.as_bytes()); // must never block
    }
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the tap blocked the session"
    );
    // Wait until the writer is stuck in a write.
    for _ in 0..200 {
        if *gated.writes.lock().unwrap() > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(*gated.writes.lock().unwrap() > 0, "the writer never wrote");

    gated.open();
    // Let the writer drain the queue, then the next event carries the dropped count.
    tokio::time::sleep(Duration::from_millis(300)).await;
    tap.output(b"after unblock");
    drop(tap);
    let summary = handle.join.await.unwrap().unwrap();
    assert!(summary.dropped_bytes > 0);

    let rec = read_recording(&gated.buf.bytes()[..], key()).unwrap();
    assert!(!rec.incomplete);
    let markers: Vec<_> = rec
        .events
        .iter()
        .filter(|e| e.kind == EventKind::Marker)
        .collect();
    assert!(!markers.is_empty(), "a dropped-bytes marker was written");
    let total: u64 = markers
        .iter()
        .map(|m| {
            m.data
                .strip_prefix("dropped ")
                .and_then(|s| s.strip_suffix(" bytes"))
                .unwrap()
                .parse::<u64>()
                .unwrap()
        })
        .sum();
    assert_eq!(total, summary.dropped_bytes);
    let kept: usize = rec
        .events
        .iter()
        .filter(|e| e.kind == EventKind::Output && e.data != "after unblock")
        .map(|e| e.data.len())
        .sum();
    assert_eq!(kept as u64 + total, 200 * 16 * 1024);
    assert!(rec.events.iter().any(|e| e.data == "after unblock"));
}

// T-12
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t12_file_mode_and_no_plaintext() {
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "sverb-rec-t12-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let recordings = dir.join("recordings");
    let (path, file) = create_recording_file(&recordings, &CONN).unwrap();
    assert!(
        path.to_string_lossy()
            .ends_with("09090909090909090909090909090909.cast.sv")
    );
    let mut opts = RecorderOptions::new(CONN, key());
    opts.meta = RecorderMeta {
        title: Some("canary-host".into()),
        include_input: true,
        ..RecorderMeta::default()
    };
    let (tap, handle) = spawn_recorder(file, opts).unwrap();
    let canary = "CANARY-7f3a9e-secret-output";
    tap.output(format!("echo {canary}\r\n{canary}\r\n").as_bytes());
    tap.input(b"typed-CANARY-input");
    drop(tap);
    handle.join.await.unwrap().unwrap();

    let bytes = std::fs::read(&path).unwrap();
    let hay = String::from_utf8_lossy(&bytes);
    assert!(!hay.contains("CANARY"), "plaintext leaked into the file");
    assert!(!hay.contains("canary-host"));
    assert!(bytes.starts_with(b"SVREC1\0"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let dmode = std::fs::metadata(&recordings).unwrap().permissions().mode() & 0o777;
        assert_eq!(dmode, 0o700);
    }

    let rec = read_recording(std::fs::File::open(&path).unwrap(), key()).unwrap();
    assert_eq!(rec.header.title.as_deref(), Some("canary-host"));
    assert!(rec.events.iter().any(|e| e.data.contains(canary)));
    // Existing files are never overwritten.
    assert!(create_recording_file(&recordings, &CONN).is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}
