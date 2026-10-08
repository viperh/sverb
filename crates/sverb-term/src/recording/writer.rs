//! The `.cast.sv` container writer (SPEC §7.5).
//!
//! ```text
//! "SVREC1\0" | conn_id (16) | chunk_size (u32 BE)
//! repeated:  len (u32 BE) | nonce (24) | ciphertext+tag     (sverb_crypto::recording)
//! ```
//!
//! Each chunk's plaintext is whole asciicast lines, at most [`CHUNK_PLAINTEXT_MAX`] bytes,
//! sealed with `aad = conn_id || chunk_index || is_last`. Only the last chunk (written by
//! [`ChunkWriter::finish`], possibly empty) has `is_last = 1`, so a reader detects a
//! truncated file and still opens every complete earlier chunk.
//!
//! [`Recorder`] turns session events into asciicast lines (UTF-8 decoding across reads,
//! long output split into several events, input dropped unless opted in).

use std::{io, time::Duration};

use sverb_crypto::{Key32, canon::Id16, random::os_rng, recording::seal_chunk};
use zeroize::Zeroizing;

use super::asciicast::{EventKind, Header, Utf8Stream, event_line, split_data};

/// File magic.
pub const MAGIC: &[u8; 7] = b"SVREC1\0";

/// Maximum plaintext per chunk (64 KiB).
pub const CHUNK_PLAINTEXT_MAX: usize = 64 * 1024;

/// Length of the file header: magic + conn_id + chunk size.
pub const FILE_HEADER_LEN: usize = MAGIC.len() + 16 + 4;

/// Writes sealed chunks of asciicast lines to `W`.
pub struct ChunkWriter<W: io::Write> {
    out: W,
    key: Key32,
    conn_id: Id16,
    index: u64,
    buf: Zeroizing<Vec<u8>>,
}

impl<W: io::Write> std::fmt::Debug for ChunkWriter<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChunkWriter")
            .field("index", &self.index)
            .field("buffered", &self.buf.len())
            .finish_non_exhaustive()
    }
}

impl<W: io::Write> ChunkWriter<W> {
    /// Write the file header and start at chunk 0.
    ///
    /// # Errors
    /// Writing the header failed.
    pub fn new(mut out: W, key: Key32, conn_id: Id16) -> io::Result<Self> {
        let mut header = Vec::with_capacity(FILE_HEADER_LEN);
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(&conn_id);
        #[allow(clippy::cast_possible_truncation)] // 64 KiB
        header.extend_from_slice(&(CHUNK_PLAINTEXT_MAX as u32).to_be_bytes());
        out.write_all(&header)?;
        out.flush()?;
        Ok(Self {
            out,
            key,
            conn_id,
            index: 0,
            buf: Zeroizing::new(Vec::with_capacity(CHUNK_PLAINTEXT_MAX)),
        })
    }

    /// Append one line (a `\n` is added). Seals the buffered chunk first when the line
    /// would not fit.
    ///
    /// # Errors
    /// Writing a chunk failed.
    pub fn push_line(&mut self, line: &str) -> io::Result<()> {
        if !self.buf.is_empty() && self.buf.len() + line.len() + 1 > CHUNK_PLAINTEXT_MAX {
            self.seal(false)?;
        }
        self.buf.extend_from_slice(line.as_bytes());
        self.buf.push(b'\n');
        if self.buf.len() >= CHUNK_PLAINTEXT_MAX {
            self.seal(false)?;
        }
        Ok(())
    }

    /// Seal the buffered lines now (no-op when nothing is buffered).
    ///
    /// # Errors
    /// Writing the chunk failed.
    pub fn flush_chunk(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        self.seal(false)
    }

    /// Bytes of plaintext waiting to be sealed.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Chunks written so far.
    pub fn chunks_written(&self) -> u64 {
        self.index
    }

    /// Seal the rest as the final chunk (`is_last = 1`) and return the writer.
    ///
    /// # Errors
    /// Writing the chunk failed.
    pub fn finish(mut self) -> io::Result<W> {
        self.seal(true)?;
        Ok(self.out)
    }

    fn seal(&mut self, is_last: bool) -> io::Result<()> {
        let sealed = seal_chunk(
            &self.key,
            &self.conn_id,
            self.index,
            is_last,
            &self.buf,
            &mut os_rng(),
        )
        .map_err(|e| io::Error::other(e.to_string()))?;
        let len = u32::try_from(sealed.len()).map_err(|_| io::Error::other("chunk too large"))?;
        let mut frame = Vec::with_capacity(4 + sealed.len());
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(&sealed);
        // One write per chunk: a crash leaves at most one partial chunk at the end.
        self.out.write_all(&frame)?;
        self.out.flush()?;
        self.index += 1;
        self.buf.clear();
        Ok(())
    }
}

/// What the recorder needs to know up front.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecorderMeta {
    /// Unix time (seconds) when recording started.
    pub timestamp: Option<i64>,
    /// `TERM` sent to the remote.
    pub term: Option<String>,
    /// The host label.
    pub title: Option<String>,
    /// Record input events (`recording.include_input`).
    pub include_input: bool,
}

/// Turns session events into asciicast lines in a [`ChunkWriter`].
///
/// The header is written lazily, sized by the first resize (the session reports its size
/// when the recorder attaches) or `fallback` when output comes first.
pub struct Recorder<W: io::Write> {
    chunks: ChunkWriter<W>,
    meta: RecorderMeta,
    fallback: (u16, u16),
    header_written: bool,
    out_utf8: Utf8Stream,
    in_utf8: Utf8Stream,
    last_time: Duration,
}

impl<W: io::Write> std::fmt::Debug for Recorder<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recorder")
            .field("chunks", &self.chunks)
            .field("header_written", &self.header_written)
            .finish_non_exhaustive()
    }
}

impl<W: io::Write> Recorder<W> {
    /// A recorder writing into `chunks`.
    pub fn new(chunks: ChunkWriter<W>, meta: RecorderMeta, fallback: (u16, u16)) -> Self {
        Self {
            chunks,
            meta,
            fallback,
            header_written: false,
            out_utf8: Utf8Stream::default(),
            in_utf8: Utf8Stream::default(),
            last_time: Duration::ZERO,
        }
    }

    fn header(&mut self, cols: u16, rows: u16) -> io::Result<()> {
        if self.header_written {
            return Ok(());
        }
        self.header_written = true;
        let mut header = Header::new(cols, rows);
        header.timestamp = self.meta.timestamp;
        header.title.clone_from(&self.meta.title);
        header.env = self
            .meta
            .term
            .clone()
            .map(|term| super::asciicast::HeaderEnv { term: Some(term) });
        self.chunks.push_line(&header.to_line())
    }

    fn ensure_header(&mut self) -> io::Result<()> {
        let (c, r) = self.fallback;
        self.header(c, r)
    }

    /// Event times never go backwards (asciinema requires it).
    fn clamp(&mut self, t: Duration) -> Duration {
        let t = t.max(self.last_time);
        self.last_time = t;
        t
    }

    fn text_event(&mut self, t: Duration, kind: EventKind, text: &str) -> io::Result<()> {
        for piece in split_data(text) {
            self.chunks.push_line(&event_line(t, kind, piece))?;
        }
        Ok(())
    }

    /// Remote output.
    ///
    /// # Errors
    /// Writing a chunk failed.
    pub fn output(&mut self, t: Duration, bytes: &[u8]) -> io::Result<()> {
        self.ensure_header()?;
        let t = self.clamp(t);
        let text = self.out_utf8.decode(bytes);
        self.text_event(t, EventKind::Output, &text)
    }

    /// Input sent to the remote. Dropped unless `include_input`.
    ///
    /// # Errors
    /// Writing a chunk failed.
    pub fn input(&mut self, t: Duration, bytes: &[u8]) -> io::Result<()> {
        if !self.meta.include_input {
            return Ok(());
        }
        self.ensure_header()?;
        let t = self.clamp(t);
        let text = self.in_utf8.decode(bytes);
        self.text_event(t, EventKind::Input, &text)
    }

    /// The pane was resized. The first resize before any event sizes the header instead.
    ///
    /// # Errors
    /// Writing a chunk failed.
    pub fn resize(&mut self, t: Duration, cols: u16, rows: u16) -> io::Result<()> {
        if !self.header_written {
            return self.header(cols, rows);
        }
        let t = self.clamp(t);
        self.chunks
            .push_line(&event_line(t, EventKind::Resize, &format!("{cols}x{rows}")))
    }

    /// A marker event (`[t, "m", label]`).
    ///
    /// # Errors
    /// Writing a chunk failed.
    pub fn marker(&mut self, t: Duration, label: &str) -> io::Result<()> {
        self.ensure_header()?;
        let t = self.clamp(t);
        self.chunks
            .push_line(&event_line(t, EventKind::Marker, label))
    }

    /// Seal what is buffered (the 5 s flush).
    ///
    /// # Errors
    /// Writing the chunk failed.
    pub fn flush_chunk(&mut self) -> io::Result<()> {
        self.chunks.flush_chunk()
    }

    /// Plaintext bytes not yet sealed.
    pub fn buffered(&self) -> usize {
        self.chunks.buffered()
    }

    /// Chunks written so far.
    pub fn chunks_written(&self) -> u64 {
        self.chunks.chunks_written()
    }

    /// Write the final chunk and return the output.
    ///
    /// # Errors
    /// Writing the chunk failed.
    pub fn finish(mut self) -> io::Result<W> {
        self.ensure_header()?;
        let t = self.last_time;
        let tail = self.out_utf8.finish();
        if !tail.is_empty() {
            self.text_event(t, EventKind::Output, &tail)?;
        }
        self.chunks.finish()
    }
}
