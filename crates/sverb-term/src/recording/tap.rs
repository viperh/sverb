//! The session's output tap and the recording writer task (SPEC §7.5).
//!
//! The session actor holds a [`RecordingTap`] and calls [`RecordingTap::output`] (and
//! `input`/`resize`) as data flows. Every call is a `try_send` on a bounded channel: it
//! **never blocks or awaits**. When the channel is full the event is dropped and its size
//! added to a shared counter; the next event that gets through carries the count, and the
//! writer writes `[t, "m", "dropped N bytes"]` before it (or at close).
//!
//! The writer task ([`spawn_recorder`]) seals a chunk when 64 KiB are buffered or when the
//! oldest buffered data is [`FLUSH_INTERVAL`] old (so a crash loses at most ~5 s), and on
//! close writes the final chunk and `fsync`s. It ends when every tap clone is dropped.
//!
//! **Vault lock:** the writer receives the recording key once at start and keeps it until
//! close (zeroized on drop). Recording therefore continues while the vault is locked, as
//! sessions stay connected (SPEC §5.3).

use std::{
    io,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use sverb_crypto::{Key32, canon::Id16};
use tokio::{
    sync::mpsc::{self, error::TrySendError},
    task::JoinHandle,
    time::Instant,
};

use super::writer::{ChunkWriter, Recorder, RecorderMeta};

/// Seal buffered data at least this often.
pub const FLUSH_INTERVAL: Duration = Duration::from_secs(5);

/// Default capacity of the tap channel (events, each ≤ one read of ≤ 64 KiB).
pub const TAP_CAPACITY: usize = 256;

/// What the session reports.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TapMsg {
    Output(Bytes),
    Input(Bytes),
    Resize(u16, u16),
}

#[derive(Debug)]
struct Envelope {
    at: Instant,
    msg: TapMsg,
    /// Bytes dropped (channel full) before this event.
    dropped_before: u64,
}

/// The session side of a recording. Cheap to clone; recording stops when every clone is
/// dropped.
#[derive(Debug, Clone)]
pub struct RecordingTap {
    tx: mpsc::Sender<Envelope>,
    dropped: Arc<AtomicU64>,
    include_input: bool,
}

impl RecordingTap {
    fn send(&self, msg: TapMsg, size: usize) {
        let dropped_before = self.dropped.swap(0, Ordering::AcqRel);
        let env = Envelope {
            at: Instant::now(),
            msg,
            dropped_before,
        };
        match self.tx.try_send(env) {
            Ok(()) => {}
            Err(TrySendError::Full(env) | TrySendError::Closed(env)) => {
                self.dropped
                    .fetch_add(env.dropped_before + size as u64, Ordering::AcqRel);
            }
        }
    }

    /// Remote output (as fed to the emulator). Never blocks.
    pub fn output(&self, data: &[u8]) {
        if !data.is_empty() {
            self.send(TapMsg::Output(Bytes::copy_from_slice(data)), data.len());
        }
    }

    /// Input sent to the remote. A no-op unless input recording was enabled.
    pub fn input(&self, data: &[u8]) {
        if self.include_input && !data.is_empty() {
            self.send(TapMsg::Input(Bytes::copy_from_slice(data)), data.len());
        }
    }

    /// The emulator was resized (the first call sizes the asciicast header).
    pub fn resize(&self, cols: u16, rows: u16) {
        self.send(TapMsg::Resize(cols, rows), 0);
    }

    /// Whether input is recorded.
    pub fn include_input(&self) -> bool {
        self.include_input
    }

    /// Whether the writer is gone (it failed, or finished).
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
}

/// Recording parameters.
#[derive(Debug, Clone)]
pub struct RecorderOptions {
    /// The connection id (file name and AAD).
    pub conn_id: Id16,
    /// `HKDF(LMK, "sverb/recording/v1")`.
    pub key: Key32,
    /// Header metadata and `include_input`.
    pub meta: RecorderMeta,
    /// Header size when output arrives before the session reports its size.
    pub fallback_size: (u16, u16),
    /// Seal at least this often ([`FLUSH_INTERVAL`]).
    pub flush_interval: Duration,
    /// Tap channel capacity ([`TAP_CAPACITY`]).
    pub capacity: usize,
}

impl RecorderOptions {
    /// Defaults for `conn_id` and `key`.
    pub fn new(conn_id: Id16, key: Key32) -> Self {
        Self {
            conn_id,
            key,
            meta: RecorderMeta::default(),
            fallback_size: (80, 24),
            flush_interval: FLUSH_INTERVAL,
            capacity: TAP_CAPACITY,
        }
    }
}

/// How a recording ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RecordingSummary {
    /// Chunks written, including the final one.
    pub chunks: u64,
    /// Bytes dropped because the writer could not keep up.
    pub dropped_bytes: u64,
}

/// Something the writer can `fsync` at close (a no-op for in-memory writers).
pub trait SyncWrite: io::Write + Send + 'static {
    /// Flush to stable storage.
    ///
    /// # Errors
    /// The sync failed.
    fn sync(&mut self) -> io::Result<()> {
        self.flush()
    }
}

impl SyncWrite for std::fs::File {
    fn sync(&mut self) -> io::Result<()> {
        self.sync_all()
    }
}

impl SyncWrite for Vec<u8> {}

/// File name of a recording: `<conn_id as 32 hex digits>.cast.sv`.
#[must_use]
pub fn recording_file_name(conn_id: &Id16) -> String {
    use std::fmt::Write as _;
    let mut name = String::with_capacity(40);
    for b in conn_id {
        let _ = write!(name, "{b:02x}");
    }
    name.push_str(".cast.sv");
    name
}

/// Create `dir` (0700 on unix) and a new recording file in it (0600 on unix).
///
/// # Errors
/// The directory or file could not be created (an existing file is an error).
pub fn create_recording_file(dir: &Path, conn_id: &Id16) -> io::Result<(PathBuf, std::fs::File)> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)?;
    let path = dir.join(recording_file_name(conn_id));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = opts.open(&path)?;
    Ok((path, file))
}

/// A running recording.
#[derive(Debug)]
pub struct RecorderHandle {
    /// Resolves when the recording is closed (every tap dropped) and fully written.
    pub join: JoinHandle<io::Result<RecordingSummary>>,
}

/// Write the file header into `out` and start the writer task. Must be called inside a
/// tokio runtime.
///
/// # Errors
/// Writing the file header failed.
pub fn spawn_recorder<W: SyncWrite>(
    out: W,
    opts: RecorderOptions,
) -> io::Result<(RecordingTap, RecorderHandle)> {
    let chunks = ChunkWriter::new(out, opts.key.clone(), opts.conn_id)?;
    let include_input = opts.meta.include_input;
    let recorder = Recorder::new(chunks, opts.meta.clone(), opts.fallback_size);
    let (tx, rx) = mpsc::channel(opts.capacity.max(1));
    let dropped = Arc::new(AtomicU64::new(0));
    let tap = RecordingTap {
        tx,
        dropped: Arc::clone(&dropped),
        include_input,
    };
    let join = tokio::spawn(run_writer(recorder, rx, dropped, opts.flush_interval));
    Ok((tap, RecorderHandle { join }))
}

async fn run_writer<W: SyncWrite>(
    mut recorder: Recorder<W>,
    mut rx: mpsc::Receiver<Envelope>,
    dropped: Arc<AtomicU64>,
    flush_interval: Duration,
) -> io::Result<RecordingSummary> {
    let start = Instant::now();
    let mut summary = RecordingSummary::default();
    // When the oldest unsealed data must be sealed.
    let mut deadline: Option<Instant> = None;
    loop {
        let env = tokio::select! {
            env = rx.recv() => env,
            () = sleep_until(deadline) => {
                recorder.flush_chunk()?;
                deadline = None;
                continue;
            }
        };
        let Some(env) = env else { break };
        let t = env.at.saturating_duration_since(start);
        if env.dropped_before > 0 {
            summary.dropped_bytes += env.dropped_before;
            recorder.marker(t, &format!("dropped {} bytes", env.dropped_before))?;
        }
        let chunks_before = recorder.chunks_written();
        match env.msg {
            TapMsg::Output(b) => recorder.output(t, &b)?,
            TapMsg::Input(b) => recorder.input(t, &b)?,
            TapMsg::Resize(c, r) => recorder.resize(t, c, r)?,
        }
        if recorder.buffered() == 0 {
            deadline = None;
        } else if deadline.is_none() || recorder.chunks_written() != chunks_before {
            deadline = Some(Instant::now() + flush_interval);
        }
    }
    let late = dropped.swap(0, Ordering::AcqRel);
    if late > 0 {
        summary.dropped_bytes += late;
        let t = Instant::now().saturating_duration_since(start);
        recorder.marker(t, &format!("dropped {late} bytes"))?;
    }
    // The final chunk and fsync are blocking file I/O.
    let finish = move || -> io::Result<u64> {
        let chunks = recorder.chunks_written() + 1;
        let mut out = recorder.finish()?;
        out.sync()?;
        Ok(chunks)
    };
    summary.chunks = match tokio::runtime::Handle::current().runtime_flavor() {
        tokio::runtime::RuntimeFlavor::CurrentThread => finish()?,
        _ => tokio::task::spawn_blocking(finish)
            .await
            .map_err(|e| io::Error::other(e.to_string()))??,
    };
    Ok(summary)
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending().await,
    }
}
