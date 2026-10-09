//! Results of a multi-host snippet run (SPEC §9.7, §16) and their exports.
//!
//! - [`to_json`]: `{"version":1,"data":[{host, exit, signal, stdout, stderr, truncated,
//!   duration_ms}]}`. `stdout`/`stderr` are UTF-8-lossy strings; when a stream is not
//!   valid UTF-8, `stdout_b64`/`stderr_b64` carry the exact bytes. A host that could not
//!   be reached has `"error"` (and `exit`/`signal` null).
//! - [`to_markdown`]: a summary table, then each host's output in fenced blocks.
//! - [`to_text`]: the CLI's per-host blocks (`== host (exit 0, 1.2s) ==`, stdout, stderr).
//! - [`summarize`]: all ok / partial / all failed (CLI exit 0 / 7 / 1).

use std::fmt::Write as _;
use std::time::Duration;

use base64::Engine as _;
use serde::Serialize;

/// The `signal` of a run that hit its timeout (as `sverb_conn::ssh::exec`).
pub const TIMEOUT_SIGNAL: &str = "TERM (timeout)";

/// What one host did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostRunResult {
    /// The host label.
    pub host: String,
    /// Exit status.
    pub exit: Option<u32>,
    /// Exit signal (`TERM (timeout)` on timeout).
    pub signal: Option<String>,
    /// Standard output (capped).
    pub stdout: Vec<u8>,
    /// Standard error (capped).
    pub stderr: Vec<u8>,
    /// Output was cut at the cap.
    pub truncated: bool,
    /// Wall time.
    pub duration: Duration,
    /// The host could not be reached or the command not started.
    pub error: Option<String>,
}

/// A host's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunStatus {
    /// Exit 0.
    Ok,
    /// Non-zero exit.
    Exit(u32),
    /// Killed by a signal.
    Signal(String),
    /// Hit the timeout.
    Timeout,
    /// Not run (connection, auth, channel).
    Error(String),
}

impl RunStatus {
    /// Exit 0.
    pub fn ok(&self) -> bool {
        *self == Self::Ok
    }
}

impl std::fmt::Display for RunStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ok => f.write_str("ok"),
            Self::Exit(n) => write!(f, "exit {n}"),
            Self::Signal(s) => write!(f, "signal {s}"),
            Self::Timeout => f.write_str("timeout"),
            Self::Error(e) => write!(f, "error: {e}"),
        }
    }
}

impl HostRunResult {
    /// A host that was not run.
    pub fn failed(host: impl Into<String>, error: impl Into<String>, duration: Duration) -> Self {
        Self {
            host: host.into(),
            error: Some(error.into()),
            duration,
            ..Self::default()
        }
    }

    /// The outcome.
    pub fn status(&self) -> RunStatus {
        if let Some(e) = &self.error {
            return RunStatus::Error(e.clone());
        }
        if self.signal.as_deref() == Some(TIMEOUT_SIGNAL) {
            return RunStatus::Timeout;
        }
        match (self.exit, &self.signal) {
            (Some(0), _) => RunStatus::Ok,
            (Some(n), _) => RunStatus::Exit(n),
            (None, Some(s)) => RunStatus::Signal(s.clone()),
            (None, None) => RunStatus::Error("no exit status".to_owned()),
        }
    }

    /// Duration in whole milliseconds.
    pub fn duration_ms(&self) -> u64 {
        u64::try_from(self.duration.as_millis()).unwrap_or(u64::MAX)
    }
}

/// `1.2s`
pub fn secs(d: Duration) -> String {
    format!("{:.1}s", d.as_secs_f64())
}

/// How a run went overall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Summary {
    /// Every host exited 0 (or there were none).
    AllOk,
    /// Some failed.
    Partial,
    /// All failed.
    AllFailed,
}

/// The overall outcome.
pub fn summarize(results: &[HostRunResult]) -> Summary {
    let failed = results.iter().filter(|r| !r.status().ok()).count();
    if failed == 0 {
        Summary::AllOk
    } else if failed == results.len() {
        Summary::AllFailed
    } else {
        Summary::Partial
    }
}

#[derive(Serialize)]
struct JsonRow<'a> {
    host: &'a str,
    exit: Option<u32>,
    signal: Option<&'a str>,
    stdout: String,
    stderr: String,
    truncated: bool,
    duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    stdout_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stderr_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
}

#[derive(Serialize)]
struct Envelope<'a> {
    version: u32,
    data: Vec<JsonRow<'a>>,
}

fn b64_unless_utf8(bytes: &[u8]) -> Option<String> {
    std::str::from_utf8(bytes)
        .is_err()
        .then(|| base64::engine::general_purpose::STANDARD.encode(bytes))
}

/// The JSON export as a value (keys sorted).
pub fn to_json(results: &[HostRunResult]) -> serde_json::Value {
    serde_json::to_value(envelope(results)).unwrap_or(serde_json::Value::Null)
}

/// The JSON export as one line, fields in documented order (`--json`, file export).
pub fn to_json_string(results: &[HostRunResult]) -> String {
    serde_json::to_string(&envelope(results)).unwrap_or_default()
}

fn envelope(results: &[HostRunResult]) -> Envelope<'_> {
    let data = results
        .iter()
        .map(|r| JsonRow {
            host: &r.host,
            exit: r.exit,
            signal: r.signal.as_deref(),
            stdout: String::from_utf8_lossy(&r.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&r.stderr).into_owned(),
            truncated: r.truncated,
            duration_ms: r.duration_ms(),
            stdout_b64: b64_unless_utf8(&r.stdout),
            stderr_b64: b64_unless_utf8(&r.stderr),
            error: r.error.as_deref(),
        })
        .collect();
    Envelope { version: 1, data }
}

fn fence(text: &str) -> String {
    let mut longest = 0;
    let mut run = 0;
    for c in text.chars() {
        if c == '`' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    "`".repeat((longest + 1).max(3))
}

fn cell(text: &str) -> String {
    text.replace('|', "\\|").replace('\n', " ")
}

fn push_block(out: &mut String, label: &str, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let text = String::from_utf8_lossy(bytes);
    let f = fence(&text);
    let _ = writeln!(out, "{label}:\n\n{f}text\n{}", text.trim_end_matches('\n'));
    let _ = writeln!(out, "{f}\n");
}

/// The Markdown export.
pub fn to_markdown(title: &str, results: &[HostRunResult]) -> String {
    let mut out = format!("# {}\n\n", cell(title));
    out.push_str("| Host | Status | Exit | Duration | Truncated |\n");
    out.push_str("|---|---|---|---|---|\n");
    for r in results {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} |",
            cell(&r.host),
            cell(&r.status().to_string()),
            r.exit.map_or_else(|| "–".to_owned(), |e| e.to_string()),
            secs(r.duration),
            if r.truncated { "yes" } else { "no" }
        );
    }
    out.push('\n');
    for r in results {
        let _ = writeln!(out, "## {} ({})\n", r.host, r.status());
        push_block(&mut out, "stdout", &r.stdout);
        push_block(&mut out, "stderr", &r.stderr);
    }
    out
}

/// The CLI's per-host blocks.
pub fn to_text(results: &[HostRunResult]) -> String {
    let mut out = String::new();
    for r in results {
        let mut head = format!("{}, {}", r.status(), secs(r.duration));
        if r.truncated {
            head.push_str(", truncated");
        }
        let _ = writeln!(out, "== {} ({head}) ==", r.host);
        for stream in [&r.stdout, &r.stderr] {
            if stream.is_empty() {
                continue;
            }
            let text = String::from_utf8_lossy(stream);
            out.push_str(&text);
            if !text.ends_with('\n') {
                out.push('\n');
            }
        }
    }
    out
}
