//! Streaming reader for `.cast.sv` files (SPEC §7.5).
//!
//! [`ChunkReader`] decrypts one chunk at a time. Each chunk is opened with the expected
//! index and `is_last = 0`, then `is_last = 1`; a chunk that opens with neither fails with
//! [`RecordingError::Auth`] (reordered, swapped, from another recording, or tampered).
//! Reaching the end of the file without a final chunk (or with a partial chunk) is not an
//! error: the reader reports the recording as **incomplete** and keeps every complete
//! chunk before it (a crash leaves a readable prefix).

use std::{fmt, io};

use sverb_crypto::{Key32, aead::TAG_LEN, canon::Id16, keys::NONCE_LEN, recording::open_chunk};
use zeroize::Zeroizing;

use super::{
    asciicast::{CastError, Event, Header},
    writer::{CHUNK_PLAINTEXT_MAX, MAGIC},
};

/// Why a recording cannot be read.
#[derive(Debug)]
#[non_exhaustive]
pub enum RecordingError {
    /// The file could not be read.
    Io(io::Error),
    /// Not a sverb recording (bad magic).
    NotARecording,
    /// A chunk failed authentication (wrong key, reordered or foreign chunk, tampering).
    Auth {
        /// The chunk index that failed.
        chunk: u64,
    },
    /// A structural problem (absurd chunk length, data after the final chunk, bad lines).
    Corrupt(String),
}

impl fmt::Display for RecordingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "cannot read the recording: {e}"),
            Self::NotARecording => f.write_str("not a sverb recording"),
            Self::Auth { chunk } => write!(
                f,
                "recording chunk {chunk} failed authentication (wrong key, or the file was modified)"
            ),
            Self::Corrupt(msg) => write!(f, "corrupt recording: {msg}"),
        }
    }
}

impl std::error::Error for RecordingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for RecordingError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<CastError> for RecordingError {
    fn from(e: CastError) -> Self {
        Self::Corrupt(e.0)
    }
}

/// Read until `buf` is full or EOF; returns the bytes read.
fn read_full(r: &mut impl io::Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// Decrypts chunks one by one.
pub struct ChunkReader<R: io::Read> {
    r: R,
    key: Key32,
    conn_id: Id16,
    index: u64,
    max_chunk: usize,
    finished: bool,
    incomplete: bool,
}

impl<R: io::Read> fmt::Debug for ChunkReader<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChunkReader")
            .field("index", &self.index)
            .field("finished", &self.finished)
            .field("incomplete", &self.incomplete)
            .finish_non_exhaustive()
    }
}

impl<R: io::Read> ChunkReader<R> {
    /// Read the file header.
    ///
    /// # Errors
    /// I/O errors, a bad magic, or a header cut short.
    pub fn open(mut r: R, key: Key32) -> Result<Self, RecordingError> {
        let mut head = [0_u8; MAGIC.len() + 16 + 4];
        let n = read_full(&mut r, &mut head)?;
        if n < MAGIC.len() || &head[..MAGIC.len()] != MAGIC {
            return Err(RecordingError::NotARecording);
        }
        if n < head.len() {
            return Err(RecordingError::Corrupt("file header cut short".into()));
        }
        let mut conn_id = [0_u8; 16];
        conn_id.copy_from_slice(&head[MAGIC.len()..MAGIC.len() + 16]);
        let mut size = [0_u8; 4];
        size.copy_from_slice(&head[MAGIC.len() + 16..]);
        let chunk_size = u32::from_be_bytes(size) as usize;
        if chunk_size == 0 || chunk_size > 16 * CHUNK_PLAINTEXT_MAX {
            return Err(RecordingError::Corrupt(format!(
                "bad chunk size {chunk_size}"
            )));
        }
        Ok(Self {
            r,
            key,
            conn_id,
            index: 0,
            max_chunk: chunk_size + NONCE_LEN + TAG_LEN,
            finished: false,
            incomplete: false,
        })
    }

    /// The recording's connection id (from the file header).
    pub fn conn_id(&self) -> Id16 {
        self.conn_id
    }

    /// The next chunk's plaintext, or `None` at the end (check [`Self::incomplete`]).
    ///
    /// # Errors
    /// I/O, authentication or structural errors.
    pub fn next_chunk(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, RecordingError> {
        if self.finished {
            return Ok(None);
        }
        let mut len = [0_u8; 4];
        let n = read_full(&mut self.r, &mut len)?;
        if n < 4 {
            // EOF (or a torn length) before the final chunk: truncated.
            self.finished = true;
            self.incomplete = true;
            return Ok(None);
        }
        let len = u32::from_be_bytes(len) as usize;
        if len < NONCE_LEN + TAG_LEN || len > self.max_chunk {
            return Err(RecordingError::Corrupt(format!(
                "chunk {} has length {len}",
                self.index
            )));
        }
        let mut chunk = vec![0_u8; len];
        if read_full(&mut self.r, &mut chunk)? < len {
            self.finished = true;
            self.incomplete = true;
            return Ok(None);
        }
        let index = self.index;
        let (plain, is_last) = match open_chunk(&self.key, &self.conn_id, index, false, &chunk) {
            Ok(p) => (p, false),
            Err(_) => match open_chunk(&self.key, &self.conn_id, index, true, &chunk) {
                Ok(p) => (p, true),
                Err(_) => return Err(RecordingError::Auth { chunk: index }),
            },
        };
        self.index += 1;
        if is_last {
            self.finished = true;
            let mut probe = [0_u8; 1];
            if read_full(&mut self.r, &mut probe)? > 0 {
                return Err(RecordingError::Corrupt("data after the final chunk".into()));
            }
        }
        Ok(Some(plain))
    }

    /// Whether the end was reached without a final chunk.
    pub fn incomplete(&self) -> bool {
        self.incomplete
    }
}

/// A decrypted recording.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recording {
    /// The asciicast header.
    pub header: Header,
    /// Every event, in order.
    pub events: Vec<Event>,
    /// The file ended before its final chunk ("recording incomplete (truncated)").
    pub incomplete: bool,
}

/// Streams the asciicast lines of a recording, chunk by chunk.
#[derive(Debug)]
pub struct LineReader<R: io::Read> {
    chunks: ChunkReader<R>,
    pending: Vec<String>,
}

impl<R: io::Read> LineReader<R> {
    /// Wrap a chunk reader.
    pub fn new(chunks: ChunkReader<R>) -> Self {
        Self {
            chunks,
            pending: Vec::new(),
        }
    }

    /// The next line (without `\n`), or `None` at the end.
    ///
    /// # Errors
    /// As [`ChunkReader::next_chunk`]; a chunk that is not UTF-8 is `Corrupt`.
    pub fn next_line(&mut self) -> Result<Option<String>, RecordingError> {
        while self.pending.is_empty() {
            let Some(plain) = self.chunks.next_chunk()? else {
                return Ok(None);
            };
            let text = std::str::from_utf8(&plain)
                .map_err(|_| RecordingError::Corrupt("chunk is not UTF-8".into()))?;
            // Lines are whole within a chunk; pop from the back.
            self.pending = text
                .split('\n')
                .filter(|l| !l.is_empty())
                .rev()
                .map(str::to_owned)
                .collect();
        }
        Ok(self.pending.pop())
    }

    /// Whether the recording was truncated (valid once `next_line` returned `None`).
    pub fn incomplete(&self) -> bool {
        self.chunks.incomplete()
    }
}

/// Decrypt a whole recording (streaming, chunk by chunk).
///
/// # Errors
/// I/O, authentication or structural errors; a recording without even a header line.
pub fn read_recording(r: impl io::Read, key: Key32) -> Result<Recording, RecordingError> {
    let mut lines = LineReader::new(ChunkReader::open(r, key)?);
    let Some(first) = lines.next_line()? else {
        return Err(if lines.incomplete() {
            RecordingError::Corrupt("recording incomplete before its header".into())
        } else {
            RecordingError::Corrupt("empty recording".into())
        });
    };
    let header = Header::parse(&first)?;
    let mut events = Vec::new();
    while let Some(line) = lines.next_line()? {
        events.push(Event::parse(&line)?);
    }
    Ok(Recording {
        header,
        events,
        incomplete: lines.incomplete(),
    })
}

/// Decrypt a recording and write it as plain asciicast v2 (`sverb export recording`).
/// Returns whether it was incomplete.
///
/// # Errors
/// Reading or writing failed.
pub fn export_plain(
    r: impl io::Read,
    key: Key32,
    mut out: impl io::Write,
) -> Result<bool, RecordingError> {
    let mut lines = LineReader::new(ChunkReader::open(r, key)?);
    let mut first = true;
    while let Some(line) = lines.next_line()? {
        if first {
            Header::parse(&line)?;
            first = false;
        }
        out.write_all(line.as_bytes())?;
        out.write_all(b"\n")?;
    }
    if first {
        return Err(RecordingError::Corrupt("empty recording".into()));
    }
    out.flush()?;
    Ok(lines.incomplete())
}
