//! ProxyCommand (SPEC §6.1.5).
//!
//! - [`expand_command`]: `%h` → target host, `%p` → port, `%r` → remote user, `%%` →
//!   `%`; any other `%x` (or a trailing `%`) is an error ([`validate_command`] checks
//!   this in the host form). Substituted values that contain anything but
//!   `[A-Za-z0-9._@:+=,/-]` (or IPv6 brackets) are single-quoted, so a synced user name
//!   can't inject shell syntax into an approved command.
//! - [`ProxyCommandStream`]: `sh -c 'exec <command>'` on Unix (like OpenSSH; `cmd /C`
//!   on Windows), its stdin/stdout as the stream, the environment inherited. stderr
//!   goes line by line to the debug log and a short tail; when the command closes its
//!   stdout while it said something on stderr, the read fails with that tail, so the
//!   connection error (and the `ConnLog` detail) shows it. The child is killed (and
//!   reaped) when the stream is dropped: on session close and on connect failure.

use std::{
    collections::VecDeque,
    fmt,
    future::Future as _,
    io,
    pin::Pin,
    process::Stdio,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};

use parking_lot::Mutex;
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, BufReader, ReadBuf},
    process::{Child, ChildStdin, ChildStdout, Command},
    time::Sleep,
};
use tracing::debug;

/// How many stderr lines are kept for the error detail.
pub const STDERR_TAIL_LINES: usize = 20;
/// The longest stderr line kept (characters).
const STDERR_LINE_MAX: usize = 300;
/// How long a stdout EOF waits for the last stderr lines.
const EOF_GRACE: Duration = Duration::from_millis(300);

/// A ProxyCommand that can't be expanded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommandError {
    /// The command is empty.
    #[error("the ProxyCommand is empty")]
    Empty,
    /// `%x` with an unknown `x`.
    #[error("unknown substitution %{0} in the ProxyCommand (use %h, %p, %r or %%)")]
    UnknownToken(char),
    /// A `%` at the end.
    #[error("a lone % at the end of the ProxyCommand (use %% for a literal %)")]
    TrailingPercent,
}

/// Whether `value` can go into a shell command unquoted.
fn shell_safe(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '.' | '_' | '@' | ':' | '+' | '=' | ',' | '/' | '-' | '[' | ']'
                )
        })
}

/// `value` as one shell word.
fn quote(value: &str) -> String {
    if shell_safe(value) {
        value.to_owned()
    } else if cfg!(windows) {
        format!("\"{}\"", value.replace('"', ""))
    } else {
        format!("'{}'", value.replace('\'', r"'\''"))
    }
}

fn expand(
    command: &str,
    mut sub: impl FnMut(char) -> Option<String>,
) -> Result<String, CommandError> {
    if command.trim().is_empty() {
        return Err(CommandError::Empty);
    }
    let mut out = String::with_capacity(command.len());
    let mut chars = command.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            None => return Err(CommandError::TrailingPercent),
            Some('%') => out.push('%'),
            Some(t) => out.push_str(&sub(t).ok_or(CommandError::UnknownToken(t))?),
        }
    }
    Ok(out)
}

/// Substitute `%h %p %r %%` in `command`.
///
/// # Errors
/// [`CommandError`].
pub fn expand_command(
    command: &str,
    host: &str,
    port: u16,
    user: &str,
) -> Result<String, CommandError> {
    expand(command, |t| match t {
        'h' => Some(quote(super::unbracket(host))),
        'p' => Some(port.to_string()),
        'r' => Some(quote(user)),
        _ => None,
    })
}

/// Check a ProxyCommand for the host form (non-empty, known substitutions only).
///
/// # Errors
/// [`CommandError`].
pub fn validate_command(command: &str) -> Result<(), CommandError> {
    expand(command, |t| matches!(t, 'h' | 'p' | 'r').then(String::new)).map(|_| ())
}

#[derive(Debug, Default)]
struct StderrState {
    lines: VecDeque<String>,
    done: bool,
    waker: Option<Waker>,
}

/// The stderr tail shared with the reader task.
#[derive(Debug, Default, Clone)]
struct StderrTail(Arc<Mutex<StderrState>>);

impl StderrTail {
    fn push(&self, line: String) {
        let mut s = self.0.lock();
        if s.lines.len() == STDERR_TAIL_LINES {
            s.lines.pop_front();
        }
        s.lines.push_back(line);
    }

    fn finish(&self) {
        let waker = {
            let mut s = self.0.lock();
            s.done = true;
            s.waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }
}

/// Printable characters only (no terminal escapes in logs or the UI), bounded.
fn clean_line(line: &str) -> String {
    line.chars()
        .filter(|c| !c.is_control() || *c == '\t')
        .take(STDERR_LINE_MAX)
        .collect::<String>()
        .trim_end()
        .to_owned()
}

/// A running ProxyCommand used as a byte stream (see the module docs).
pub struct ProxyCommandStream {
    child: Option<Child>,
    /// `None` after shutdown (closing the pipe is the child's EOF).
    stdin: Option<ChildStdin>,
    stdout: ChildStdout,
    stderr: StderrTail,
    grace: Option<Pin<Box<Sleep>>>,
}

impl fmt::Debug for ProxyCommandStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyCommandStream")
            .field("pid", &self.pid())
            .finish_non_exhaustive()
    }
}

impl ProxyCommandStream {
    /// Spawn the expanded command line (needs a Tokio runtime).
    ///
    /// # Errors
    /// The shell could not be started.
    pub fn spawn(line: &str) -> io::Result<Self> {
        let mut cmd = if cfg!(windows) {
            let mut c = Command::new("cmd");
            c.arg("/C").arg(line);
            c
        } else {
            let mut c = Command::new("sh");
            c.arg("-c").arg(format!("exec {line}"));
            c
        };
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        // Its own process group: terminal signals meant for sverb don't reach it.
        #[cfg(unix)]
        cmd.process_group(0);
        let mut child = cmd.spawn()?;
        let missing = || io::Error::other("ProxyCommand pipes missing");
        let stdin = child.stdin.take().ok_or_else(missing)?;
        let stdout = child.stdout.take().ok_or_else(missing)?;
        let stderr = child.stderr.take().ok_or_else(missing)?;
        let tail = StderrTail::default();
        let reader = tail.clone();
        let pid = child.id();
        debug!(?pid, "ProxyCommand started");
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let line = clean_line(&line);
                if line.is_empty() {
                    continue;
                }
                debug!(?pid, stderr = %line, "ProxyCommand stderr");
                reader.push(line);
            }
            reader.finish();
        });
        Ok(Self {
            child: Some(child),
            stdin: Some(stdin),
            stdout,
            stderr: tail,
            grace: None,
        })
    }

    /// The child's process id (while it runs).
    pub fn pid(&self) -> Option<u32> {
        self.child.as_ref().and_then(Child::id)
    }

    /// The last stderr lines (oldest first).
    pub fn stderr_tail(&self) -> Vec<String> {
        self.stderr.0.lock().lines.iter().cloned().collect()
    }

    /// On stdout EOF: wait (briefly) for stderr to end, then report its tail.
    fn poll_eof(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        {
            let mut s = self.stderr.0.lock();
            if !s.done {
                s.waker = Some(cx.waker().clone());
            }
        }
        let done = self.stderr.0.lock().done;
        if !done {
            let grace = self
                .grace
                .get_or_insert_with(|| Box::pin(tokio::time::sleep(EOF_GRACE)));
            if grace.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
        }
        let tail = self.stderr_tail();
        if tail.is_empty() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("ProxyCommand closed the connection: {}", tail.join(" | ")),
            )))
        }
    }
}

impl Drop for ProxyCommandStream {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = child.start_kill();
        // Reap it, so no zombie is left behind (kill_on_drop covers a missing runtime).
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                let status = child.wait().await;
                debug!(?status, "ProxyCommand ended");
            });
        }
    }
}

impl AsyncRead for ProxyCommandStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.grace.is_none() {
            let before = buf.filled().len();
            match Pin::new(&mut this.stdout).poll_read(cx, buf) {
                Poll::Ready(Ok(())) if buf.filled().len() == before && buf.remaining() > 0 => {}
                other => return other,
            }
        }
        this.poll_eof(cx)
    }
}

impl AsyncWrite for ProxyCommandStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().stdin {
            Some(stdin) => Pin::new(stdin).poll_write(cx, buf),
            None => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().stdin {
            Some(stdin) => Pin::new(stdin).poll_flush(cx),
            None => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(stdin) = &mut this.stdin {
            std::task::ready!(Pin::new(stdin).poll_flush(cx))?;
        }
        // Dropping the pipe closes it: the child sees EOF on stdin.
        this.stdin = None;
        Poll::Ready(Ok(()))
    }
}
