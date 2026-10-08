//! In-memory ring buffers of recent log lines (M0-04 §2.1).
//!
//! Two independent [`LogRing`] instances exist (we chose two rings over one ring with
//! a reader-side level filter, so the crash ring can never be flooded out by debug
//! chatter and never holds a debug line, not even transiently):
//! - the **crash ring** (200 lines, `info`+, always on) feeds crash reports (M0-05),
//! - the **debug ring** (5,000 lines, same filter as the log file, only with `--debug`
//!   in the TUI) feeds the log pane (M0-11).

use std::{
    collections::VecDeque,
    fmt::{self, Write as _},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use parking_lot::Mutex;
use tracing::{
    Event, Level, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::{Layer, layer::Context};

/// One formatted log event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    /// When the event was recorded.
    pub at: SystemTime,
    /// Event level.
    pub level: Level,
    /// Event target (usually the module path).
    pub target: String,
    /// The message followed by the event's other fields as ` key=value`.
    pub message: String,
}

impl fmt::Display for LogLine {
    /// `2026-10-07T20:00:00.123Z  INFO target: message`, like the log file.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_rfc3339(f, self.at)?;
        write!(f, " {:>5} {}: {}", self.level, self.target, self.message)
    }
}

#[derive(Debug)]
struct RingInner {
    lines: VecDeque<LogLine>,
    capacity: usize,
    pushed: u64,
}

/// A cloneable handle to a bounded buffer of the most recent [`LogLine`]s.
///
/// Writers (the [`RingLayer`]) and readers (log pane, crash report) share it. The lock
/// is held only to push or copy lines, never while formatting an event.
#[derive(Debug, Clone)]
pub struct LogRing {
    inner: Arc<Mutex<RingInner>>,
}

impl LogRing {
    /// Creates an empty ring keeping at most `capacity` lines (at least one).
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            inner: Arc::new(Mutex::new(RingInner {
                lines: VecDeque::with_capacity(capacity),
                capacity,
                pushed: 0,
            })),
        }
    }

    /// The maximum number of lines kept.
    pub fn capacity(&self) -> usize {
        self.inner.lock().capacity
    }

    /// The number of lines currently held.
    pub fn len(&self) -> usize {
        self.inner.lock().lines.len()
    }

    /// Whether the ring holds no lines.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total number of lines ever pushed. Readers compare it with a previous value
    /// to know whether anything changed without copying the buffer.
    pub fn total_pushed(&self) -> u64 {
        self.inner.lock().pushed
    }

    /// Appends a line, evicting the oldest one when full.
    pub fn push(&self, line: LogLine) {
        let mut inner = self.inner.lock();
        if inner.lines.len() == inner.capacity {
            inner.lines.pop_front();
        }
        inner.lines.push_back(line);
        inner.pushed += 1;
    }

    /// A copy of every held line, oldest first.
    pub fn snapshot(&self) -> Vec<LogLine> {
        self.inner.lock().lines.iter().cloned().collect()
    }

    /// A copy of the newest `n` lines, oldest first.
    pub fn tail(&self, n: usize) -> Vec<LogLine> {
        let inner = self.inner.lock();
        let skip = inner.lines.len().saturating_sub(n);
        inner.lines.iter().skip(skip).cloned().collect()
    }

    /// Like [`LogRing::tail`], but gives up after `timeout` instead of blocking
    /// forever. For the panic hook (M0-05), which may run while a thread that
    /// panicked mid-push still holds the lock.
    pub fn try_tail(&self, n: usize, timeout: Duration) -> Option<Vec<LogLine>> {
        let inner = self.inner.try_lock_for(timeout)?;
        let skip = inner.lines.len().saturating_sub(n);
        Some(inner.lines.iter().skip(skip).cloned().collect())
    }
}

/// A `tracing` layer that formats each event into a [`LogLine`] and pushes it into a
/// [`LogRing`]. Filter it with `.with_filter(..)`.
#[derive(Debug, Clone)]
pub struct RingLayer {
    ring: LogRing,
}

impl RingLayer {
    /// A layer writing into `ring`.
    pub fn new(ring: LogRing) -> Self {
        Self { ring }
    }
}

impl<S: Subscriber> Layer<S> for RingLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = LineVisitor::default();
        event.record(&mut visitor);
        let meta = event.metadata();
        self.ring.push(LogLine {
            at: SystemTime::now(),
            level: *meta.level(),
            target: meta.target().to_owned(),
            message: visitor.finish(),
        });
    }
}

/// Collects `message` first and the other fields as ` key=value` (values use
/// `Debug`, so secret types print `[REDACTED]`).
#[derive(Default)]
struct LineVisitor {
    message: String,
    fields: String,
}

impl LineVisitor {
    fn finish(mut self) -> String {
        if self.message.is_empty() {
            self.fields.trim_start().to_owned()
        } else {
            self.message.push_str(&self.fields);
            self.message
        }
    }
}

impl Visit for LineVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            let _ = write!(self.fields, " {}={value:?}", field.name());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            let _ = write!(self.fields, " {}={value:?}", field.name());
        }
    }
}

/// Writes `at` as RFC 3339 in UTC with millisecond precision.
fn write_rfc3339(f: &mut impl fmt::Write, at: SystemTime) -> fmt::Result {
    let since = at.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = since.as_secs();
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let (y, m, d) = civil_from_days(days);
    write!(
        f,
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem / 60 % 60,
        rem % 60,
        since.subsec_millis()
    )
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian
/// (Howard Hinnant's `civil_from_days`, for non-negative day counts).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(i: usize) -> LogLine {
        LogLine {
            at: UNIX_EPOCH,
            level: Level::INFO,
            target: "t".into(),
            message: i.to_string(),
        }
    }

    #[test]
    fn keeps_the_newest_lines_in_order() {
        let ring = LogRing::new(3);
        for i in 0..5 {
            ring.push(line(i));
        }
        let msgs: Vec<_> = ring.snapshot().into_iter().map(|l| l.message).collect();
        assert_eq!(msgs, ["2", "3", "4"]);
        assert_eq!(ring.total_pushed(), 5);
        let tail: Vec<_> = ring.tail(2).into_iter().map(|l| l.message).collect();
        assert_eq!(tail, ["3", "4"]);
        assert_eq!(ring.tail(10).len(), 3);
        assert_eq!(
            ring.try_tail(1, Duration::from_millis(10)).map(|v| v.len()),
            Some(1)
        );
    }

    #[test]
    fn display_matches_the_file_format() {
        let l = LogLine {
            at: UNIX_EPOCH + Duration::from_millis(1_791_403_200_123),
            level: Level::WARN,
            target: "sverb_conn".into(),
            message: "hello k=1".into(),
        };
        assert_eq!(
            l.to_string(),
            "2026-10-07T20:00:00.123Z  WARN sverb_conn: hello k=1"
        );
    }

    #[test]
    fn civil_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(civil_from_days(20_733), (2026, 10, 7));
    }
}
