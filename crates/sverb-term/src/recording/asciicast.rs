//! asciicast v2 lines (SPEC §7.5): one JSON header object, then one JSON array per event.
//!
//! ```text
//! {"version":2,"width":80,"height":24,"timestamp":1700000000,"env":{"TERM":"xterm-256color"},"title":"web"}
//! [0.248848, "o", "hello\r\n"]
//! [1.000000, "r", "100x30"]
//! [2.500000, "m", "dropped 4096 bytes"]
//! ```
//!
//! Strings are escaped by `serde_json` (control characters as `\u00XX`, non-ASCII kept as
//! UTF-8), which is what `asciinema play` reads. A single event's data is capped at
//! [`MAX_EVENT_DATA`] bytes so that even a fully escaped line (6 bytes per control
//! character) fits in one 64 KiB chunk; [`split_data`] cuts longer output at character
//! boundaries into several events with the same timestamp.

use std::{fmt, time::Duration};

use serde::{Deserialize, Serialize};

/// Largest `data` of one event, in bytes (×6 for `\u00XX` escapes + framing < 64 KiB).
pub const MAX_EVENT_DATA: usize = 8 * 1024;

/// The asciicast header line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// Always 2.
    pub version: u32,
    /// Terminal width in cells.
    pub width: u16,
    /// Terminal height in cells.
    pub height: u16,
    /// Unix time (seconds) when recording started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<i64>,
    /// `{"TERM": …}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<HeaderEnv>,
    /// The host label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

/// The `env` object of the header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderEnv {
    /// The `TERM` the remote saw.
    #[serde(rename = "TERM", default, skip_serializing_if = "Option::is_none")]
    pub term: Option<String>,
}

impl Header {
    /// A v2 header.
    #[must_use]
    pub fn new(width: u16, height: u16) -> Self {
        Self {
            version: 2,
            width,
            height,
            timestamp: None,
            env: None,
            title: None,
        }
    }

    /// The header as one JSON line (no trailing newline).
    #[must_use]
    pub fn to_line(&self) -> String {
        // A struct of strings and integers always serializes.
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Parse a header line.
    ///
    /// # Errors
    /// Not JSON, not an object of the expected shape, or `version != 2`.
    pub fn parse(line: &str) -> Result<Self, CastError> {
        let header: Self =
            serde_json::from_str(line).map_err(|e| CastError(format!("bad header: {e}")))?;
        if header.version != 2 {
            return Err(CastError(format!(
                "unsupported asciicast version {}",
                header.version
            )));
        }
        Ok(header)
    }
}

/// An event's type code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventKind {
    /// `"o"`: output.
    Output,
    /// `"i"`: input (only with `recording.include_input`).
    Input,
    /// `"r"`: resize, data `"COLSxROWS"`.
    Resize,
    /// `"m"`: marker (sverb writes `dropped N bytes` here).
    Marker,
}

impl EventKind {
    /// The one-letter code.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Output => "o",
            Self::Input => "i",
            Self::Resize => "r",
            Self::Marker => "m",
        }
    }

    fn from_code(code: &str) -> Option<Self> {
        Some(match code {
            "o" => Self::Output,
            "i" => Self::Input,
            "r" => Self::Resize,
            "m" => Self::Marker,
            _ => return None,
        })
    }
}

/// One event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// Time since the start of the recording.
    pub time: Duration,
    /// What happened.
    pub kind: EventKind,
    /// Output/input text, `"COLSxROWS"` or a marker label.
    pub data: String,
}

impl Event {
    /// An event.
    #[must_use]
    pub fn new(time: Duration, kind: EventKind, data: impl Into<String>) -> Self {
        Self {
            time,
            kind,
            data: data.into(),
        }
    }

    /// The event as one JSON line (no trailing newline).
    #[must_use]
    pub fn to_line(&self) -> String {
        event_line(self.time, self.kind, &self.data)
    }

    /// Parse an event line. Unknown event codes are an error (callers may skip them).
    ///
    /// # Errors
    /// Not a `[number, string, string]` array, or an unknown code.
    pub fn parse(line: &str) -> Result<Self, CastError> {
        let (t, code, data): (f64, String, String) =
            serde_json::from_str(line).map_err(|e| CastError(format!("bad event: {e}")))?;
        let kind = EventKind::from_code(&code)
            .ok_or_else(|| CastError(format!("unknown event type {code:?}")))?;
        if !t.is_finite() || t < 0.0 {
            return Err(CastError(format!("bad event time {t}")));
        }
        Ok(Self {
            time: Duration::from_secs_f64(t),
            kind,
            data,
        })
    }

    /// For a resize event, the `(cols, rows)` it carries.
    #[must_use]
    pub fn resize_size(&self) -> Option<(u16, u16)> {
        if self.kind != EventKind::Resize {
            return None;
        }
        let (c, r) = self.data.split_once('x')?;
        Some((c.trim().parse().ok()?, r.trim().parse().ok()?))
    }
}

/// `[t, "k", "data"]` with `t` in seconds, 6 decimals (as asciinema writes it).
#[must_use]
pub fn event_line(time: Duration, kind: EventKind, data: &str) -> String {
    let data = serde_json::to_string(data).unwrap_or_else(|_| "\"\"".to_owned());
    format!("[{:.6}, \"{}\", {data}]", time.as_secs_f64(), kind.code())
}

/// Split `data` into pieces of at most [`MAX_EVENT_DATA`] bytes at character boundaries.
pub fn split_data(data: &str) -> impl Iterator<Item = &str> {
    let mut rest = data;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        let mut end = rest.len().min(MAX_EVENT_DATA);
        while !rest.is_char_boundary(end) {
            end -= 1;
        }
        let (head, tail) = rest.split_at(end);
        rest = tail;
        Some(head)
    })
}

/// A malformed asciicast line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CastError(pub String);

impl fmt::Display for CastError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CastError {}

/// Decodes a byte stream into UTF-8 text, carrying incomplete sequences across calls.
/// Invalid bytes become U+FFFD (the emulator does the same).
#[derive(Debug, Default)]
pub struct Utf8Stream {
    carry: Vec<u8>,
}

impl Utf8Stream {
    /// Decode `bytes`, keeping a trailing incomplete sequence for the next call.
    pub fn decode(&mut self, bytes: &[u8]) -> String {
        let mut input = std::mem::take(&mut self.carry);
        input.extend_from_slice(bytes);
        let mut out = String::with_capacity(input.len());
        let mut rest: &[u8] = &input;
        loop {
            match std::str::from_utf8(rest) {
                Ok(s) => {
                    out.push_str(s);
                    break;
                }
                Err(e) => {
                    let (valid, after) = rest.split_at(e.valid_up_to());
                    // `valid` is valid UTF-8 by construction.
                    out.push_str(&String::from_utf8_lossy(valid));
                    match e.error_len() {
                        Some(n) => {
                            out.push('\u{FFFD}');
                            rest = &after[n..];
                        }
                        None => {
                            self.carry = after.to_vec();
                            break;
                        }
                    }
                }
            }
        }
        out
    }

    /// Flush a dangling incomplete sequence (end of stream).
    pub fn finish(&mut self) -> String {
        if self.carry.is_empty() {
            String::new()
        } else {
            self.carry.clear();
            "\u{FFFD}".to_owned()
        }
    }
}
