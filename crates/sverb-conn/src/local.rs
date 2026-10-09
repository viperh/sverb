//! The local terminal transport (SPEC §6.2) over `portable-pty`.
//!
//! [`LocalConnector`] turns a [`SessionSpec::Local`] into a [`LocalTransport`]: a shell
//! running in a pseudo-terminal on this machine. Register it with
//! [`SessionManager::register_connector`](crate::SessionManager::register_connector)
//! for [`TransportKind::Local`].
//!
//! # Shell
//! [`LocalSpec::shell`] if set, otherwise `$SHELL` (falling back to `/bin/sh`) on Unix,
//! and `pwsh.exe` when it is on `PATH` (falling back to `%ComSpec%`, then `cmd.exe`) on
//! Windows. The shell is **not** started as a login shell (tmux's default for new
//! panes); `terminal.local_shell_args` may make that configurable later.
//!
//! # Working directory
//! [`LocalSpec::cwd`] if set and a directory, otherwise the user's home directory (never
//! sverb's own working directory). A `cwd` that is not a directory falls back to the
//! home directory with a warning, like tmux does.
//!
//! # Environment
//! The child inherits sverb's environment, except:
//! - every `SVERB_*` variable is removed (sverb-internal: test homes, the config path, …),
//! - `TERM` is set to `terminal.term` ([`LocalOptions::term`], default `xterm-256color`),
//! - `COLORTERM=truecolor` is set when [`LocalOptions::colorterm`] is on (the default:
//!   the emulator renders 24-bit color),
//! - `PWD` is set to the working directory,
//! - [`LocalSpec::env`] is applied on top,
//! - **`SVERB_PANE=<session id>`** is set last, so scripts can tell which sverb pane they
//!   run in (the numeric session id, e.g. `SVERB_PANE=3`).
//!
//! # Blocking I/O
//! portable-pty's reader and writer are blocking, so they never run on the tokio
//! runtime: a reader thread forwards output chunks (≤ [`READ_CHUNK`] bytes) over a bounded
//! channel ([`READ_QUEUE`] chunks), adapted to `AsyncRead` for [`Transport::reader`]; a
//! writer thread drains a bounded input channel ([`WRITE_QUEUE`] writes). Spawning
//! happens in `spawn_blocking`.
//!
//! # Exit and close
//! When the shell exits, the reader hits EOF and [`Transport::exit_status`] reports the
//! exit code (a process killed by a signal reports `1`, portable-pty's convention). The
//! session becomes `Disconnected { Exited(code) }`.
//!
//! [`Transport::close`] hangs up the child (SIGHUP on Unix), escalates to SIGKILL after
//! [`KILL_GRACE`] (`TerminateProcess` on Windows), reaps it and joins the I/O threads.
//! Dropping an open transport does the same in the background.
//!
//! On Windows, ConPTY keeps the output pipe open after the child exits until the
//! pseudo-console is closed, so a small waiter thread drops the master once the child
//! has exited; the reader then sees EOF as on Unix.

use std::{
    ffi::OsString,
    fmt, io,
    io::{Read, Write},
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    thread::JoinHandle,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex;
use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};
use sverb_core::{
    error_report::ErrorReport,
    paths::{EnvSource, SystemEnv},
};
use tokio::{
    io::{AsyncRead, ReadBuf},
    sync::mpsc,
};
use tracing::{debug, trace, warn};

use crate::{
    session::{DisconnectReason, LocalSpec, SessionSpec},
    transport::{ConnectCtx, ConnectError, Connector, Transport, TransportKind},
};

/// `TERM` when `terminal.term` is not set.
pub const DEFAULT_TERM: &str = "xterm-256color";

/// The variable that tells child processes which sverb pane they run in.
pub const PANE_ENV: &str = "SVERB_PANE";

/// Largest chunk the reader thread forwards.
pub const READ_CHUNK: usize = 64 * 1024;

/// Output chunks buffered between the reader thread and the session.
pub const READ_QUEUE: usize = 32;

/// Writes buffered between the session and the writer thread.
pub const WRITE_QUEUE: usize = 64;

/// How long `close` waits after the hang-up before killing the child.
pub const KILL_GRACE: Duration = Duration::from_secs(1);

/// How long `exit_status` waits for the child to be reaped after EOF.
const EXIT_WAIT: Duration = Duration::from_secs(1);

/// How long `close` waits for the I/O threads.
const JOIN_WAIT: Duration = Duration::from_secs(1);

/// Poll interval while waiting for the child.
const POLL: Duration = Duration::from_millis(10);

type SharedChild = Arc<Mutex<Box<dyn Child + Send + Sync>>>;
type SharedMaster = Arc<Mutex<Option<Box<dyn MasterPty + Send>>>>;

/// Settings shared by every local session (from `[terminal]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalOptions {
    /// `TERM` for the child (`terminal.term`).
    pub term: String,
    /// Set `COLORTERM=truecolor`.
    pub colorterm: bool,
}

impl Default for LocalOptions {
    fn default() -> Self {
        Self {
            term: DEFAULT_TERM.to_owned(),
            colorterm: true,
        }
    }
}

/// The [`Connector`] for [`TransportKind::Local`]. Re-register it to apply new
/// [`LocalOptions`] to sessions opened afterwards (`terminal.term` applies to new
/// sessions).
#[derive(Debug, Clone, Default)]
pub struct LocalConnector {
    opts: LocalOptions,
}

impl LocalConnector {
    /// A connector with these options.
    pub fn new(opts: LocalOptions) -> Self {
        Self { opts }
    }

    /// The options.
    pub fn options(&self) -> &LocalOptions {
        &self.opts
    }
}

#[async_trait]
impl Connector for LocalConnector {
    async fn connect(
        &self,
        spec: &SessionSpec,
        ctx: &mut ConnectCtx<'_>,
    ) -> Result<Box<dyn Transport>, ConnectError> {
        let SessionSpec::Local(local) = spec else {
            return Err(ConnectError::new(DisconnectReason::Connect));
        };
        let (cols, rows) = ctx.size();
        let local = local.clone();
        let opts = self.opts.clone();
        let pane = ctx.id().0;
        // openpty + fork/exec (and PATH lookups) block: keep them off the runtime. If
        // this future is dropped, the finished transport is dropped too, which kills
        // the child.
        let spawned = tokio::task::spawn_blocking(move || {
            LocalTransport::spawn(&local, &opts, pane, cols, rows)
        })
        .await;
        match spawned {
            Ok(Ok(transport)) => Ok(Box::new(transport)),
            Ok(Err(err)) => {
                warn!(session = pane, %err, "cannot start the local shell");
                Err(ConnectError::with_report(
                    DisconnectReason::Connect,
                    ErrorReport::msg(format!("Cannot start the local shell: {err}")),
                ))
            }
            Err(err) => Err(ConnectError::with_report(
                DisconnectReason::Internal,
                ErrorReport::msg(format!("local shell spawn task failed: {err}")),
            )),
        }
    }
}

/// A shell in a local pseudo-terminal.
pub struct LocalTransport {
    master: SharedMaster,
    child: SharedChild,
    pid: Option<u32>,
    shell: String,
    reader: PtyReader,
    writer: Option<mpsc::Sender<Bytes>>,
    threads: Vec<JoinHandle<()>>,
    exit: Option<i32>,
    closed: bool,
}

impl fmt::Debug for LocalTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalTransport")
            .field("pid", &self.pid)
            .field("shell", &self.shell)
            .field("exit", &self.exit)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl LocalTransport {
    /// Spawn the shell for `spec` in a new `cols`×`rows` pty. `pane` is the session id
    /// (`SVERB_PANE`). Blocking: call it from `spawn_blocking`.
    pub fn spawn(
        spec: &LocalSpec,
        opts: &LocalOptions,
        pane: u64,
        cols: u16,
        rows: u16,
    ) -> io::Result<Self> {
        let pair = native_pty_system()
            .openpty(pty_size(cols, rows))
            .map_err(other)?;
        let reader = pair.master.try_clone_reader().map_err(other)?;
        let writer = pair.master.take_writer().map_err(other)?;

        let shell = spec.shell.clone().unwrap_or_else(default_shell);
        let cmd = build_command(&shell, spec, opts, pane, &SystemEnv);
        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|err| io::Error::new(io::ErrorKind::NotFound, format!("{shell}: {err:#}")))?;
        // Only the child may hold the slave side, or the reader never sees EOF.
        drop(pair.slave);
        let pid = child.process_id();
        debug!(pane, ?pid, %shell, "local shell started");

        let child: SharedChild = Arc::new(Mutex::new(child));
        let master: SharedMaster = Arc::new(Mutex::new(Some(pair.master)));
        let (out_tx, out_rx) = mpsc::channel(READ_QUEUE);
        let (in_tx, in_rx) = mpsc::channel(WRITE_QUEUE);
        let mut transport = Self {
            master,
            child,
            pid,
            shell,
            reader: PtyReader {
                rx: out_rx,
                pending: Bytes::new(),
            },
            writer: Some(in_tx),
            threads: Vec::new(),
            exit: None,
            closed: false,
        };
        // On failure from here on, dropping `transport` kills the child.
        transport.threads.push(spawn_reader(reader, out_tx)?);
        transport.threads.push(spawn_writer(writer, in_rx)?);
        #[cfg(windows)]
        transport.threads.push(spawn_waiter(
            Arc::clone(&transport.child),
            Arc::clone(&transport.master),
        )?);
        Ok(transport)
    }

    /// The child's process id.
    pub fn pid(&self) -> Option<u32> {
        self.pid
    }

    /// The program that was started.
    pub fn shell(&self) -> &str {
        &self.shell
    }

    /// The exit code, if the child has been reaped.
    fn poll_exit(&mut self) -> Option<i32> {
        if self.exit.is_none()
            && let Ok(Some(status)) = self.child.lock().try_wait()
        {
            self.exit = Some(exit_code(&status));
        }
        self.exit
    }

    /// Stop the I/O channels: the writer thread ends, and the reader thread stops at its
    /// next chunk.
    fn stop_io(&mut self) {
        self.writer = None;
        self.reader.rx.close();
    }
}

#[async_trait]
impl Transport for LocalTransport {
    async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        let Some(writer) = &self.writer else {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"));
        };
        if writer.send(Bytes::copy_from_slice(data)).await.is_err() {
            // The writer thread ended: the shell is gone. Its exit arrives through the
            // reader (EOF, then `exit_status`), so input typed meanwhile is dropped
            // rather than turned into a connection error.
            trace!(pid = ?self.pid, "input after the local shell went away dropped");
            self.writer = None;
        }
        Ok(())
    }

    async fn resize(&mut self, cols: u16, rows: u16) -> io::Result<()> {
        match self.master.lock().as_ref() {
            Some(master) => master.resize(pty_size(cols, rows)).map_err(other),
            None => Ok(()),
        }
    }

    fn reader(&mut self) -> &mut (dyn AsyncRead + Unpin + Send) {
        &mut self.reader
    }

    async fn close(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.stop_io();
        if self.poll_exit().is_none() {
            hang_up(&self.child);
            let deadline = Instant::now() + KILL_GRACE;
            while self.poll_exit().is_none() && Instant::now() < deadline {
                tokio::time::sleep(POLL).await;
            }
            if self.poll_exit().is_none() {
                debug!(pid = ?self.pid, "local shell ignored the hang-up; killing it");
                force_kill(&self.child);
                let deadline = Instant::now() + KILL_GRACE;
                while self.poll_exit().is_none() && Instant::now() < deadline {
                    tokio::time::sleep(POLL).await;
                }
            }
        }
        // Closing the master hangs up whatever else still holds the pty.
        self.master.lock().take();
        let threads = std::mem::take(&mut self.threads);
        let joined = tokio::task::spawn_blocking(move || {
            for thread in threads {
                let _ = thread.join();
            }
        });
        if tokio::time::timeout(JOIN_WAIT, joined).await.is_err() {
            // A grandchild still holds the pty open; the reader thread ends when it does.
            debug!(pid = ?self.pid, "pty reader still blocked; detached");
        }
        match self.exit {
            Some(_) => Ok(()),
            None => Err(io::Error::other("the local shell did not exit")),
        }
    }

    fn kind(&self) -> TransportKind {
        TransportKind::Local
    }

    async fn exit_status(&mut self) -> Option<i32> {
        let deadline = Instant::now() + EXIT_WAIT;
        loop {
            if let Some(code) = self.poll_exit() {
                return Some(code);
            }
            if Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(POLL).await;
        }
    }
}

impl Drop for LocalTransport {
    fn drop(&mut self) {
        self.stop_io();
        if self.closed || self.poll_exit().is_some() {
            return;
        }
        // Dropped while the shell still runs (connect cancelled, session task gone):
        // hang up now, and kill and reap it in the background.
        hang_up(&self.child);
        let child = Arc::clone(&self.child);
        let master = Arc::clone(&self.master);
        let reaper = std::thread::Builder::new()
            .name("sverb-pty-reap".to_owned())
            .spawn(move || {
                let deadline = Instant::now() + KILL_GRACE;
                while Instant::now() < deadline {
                    if !matches!(child.lock().try_wait(), Ok(None)) {
                        master.lock().take();
                        return;
                    }
                    std::thread::sleep(POLL);
                }
                force_kill(&child);
                let _ = child.lock().wait();
                master.lock().take();
            });
        if let Err(err) = reaper {
            warn!(%err, "cannot reap the local shell");
            force_kill(&self.child);
        }
    }
}

/// The output stream: chunks from the reader thread. Cancel-safe (the unread rest of a
/// chunk is kept in `pending`).
#[derive(Debug)]
struct PtyReader {
    rx: mpsc::Receiver<Bytes>,
    pending: Bytes,
}

impl AsyncRead for PtyReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.pending.is_empty() {
            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => self.pending = chunk,
                // EOF: nothing written to `buf`.
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
        // Fill `buf` with what is already queued: pty reads are often small, and one
        // larger read means fewer emulator locks and wake-ups in the session.
        loop {
            let n = buf.remaining().min(self.pending.len());
            let chunk = self.pending.split_to(n);
            buf.put_slice(&chunk);
            if buf.remaining() == 0 || !self.pending.is_empty() {
                break;
            }
            match self.rx.try_recv() {
                Ok(chunk) => self.pending = chunk,
                Err(_) => break,
            }
        }
        Poll::Ready(Ok(()))
    }
}

fn spawn_reader(
    mut reader: Box<dyn Read + Send>,
    tx: mpsc::Sender<Bytes>,
) -> io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("sverb-pty-read".to_owned())
        .spawn(move || {
            let mut buf = vec![0_u8; READ_CHUNK];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if tx.blocking_send(Bytes::copy_from_slice(&buf[..n])).is_err() {
                            break;
                        }
                    }
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                    // Linux reports EIO once the last slave descriptor is closed.
                    Err(err) => {
                        trace!(%err, "pty read ended");
                        break;
                    }
                }
            }
        })
}

fn spawn_writer(
    mut writer: Box<dyn Write + Send>,
    mut rx: mpsc::Receiver<Bytes>,
) -> io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("sverb-pty-write".to_owned())
        .spawn(move || {
            while let Some(data) = rx.blocking_recv() {
                if let Err(err) = writer.write_all(&data).and_then(|()| writer.flush()) {
                    debug!(%err, "pty write failed");
                    break;
                }
            }
        })
}

/// Windows: drop the master once the child exited, so ConPTY closes the output pipe.
#[cfg(windows)]
fn spawn_waiter(child: SharedChild, master: SharedMaster) -> io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("sverb-pty-wait".to_owned())
        .spawn(move || {
            loop {
                if master.lock().is_none() {
                    return;
                }
                if !matches!(child.lock().try_wait(), Ok(None)) {
                    master.lock().take();
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        })
}

/// Unix: SIGHUP. Windows: `TerminateProcess` (there is no gentler equivalent).
fn hang_up(child: &SharedChild) {
    // portable-pty's cloned killer sends only SIGHUP on Unix.
    let mut killer = child.lock().clone_killer();
    if let Err(err) = killer.kill() {
        trace!(%err, "hang-up failed");
    }
}

/// Unix: SIGKILL. Windows: `TerminateProcess`.
fn force_kill(child: &SharedChild) {
    let mut guard = child.lock();
    let child: &mut dyn Child = &mut **guard;
    let result = match child.downcast_mut::<std::process::Child>() {
        // `std::process::Child::kill` is SIGKILL on Unix.
        Some(std_child) => std::process::Child::kill(std_child),
        None => child.kill(),
    };
    if let Err(err) = result {
        trace!(%err, "kill failed");
    }
}

fn exit_code(status: &portable_pty::ExitStatus) -> i32 {
    i32::try_from(status.exit_code()).unwrap_or(i32::MAX)
}

fn pty_size(cols: u16, rows: u16) -> PtySize {
    PtySize {
        rows: rows.max(1),
        cols: cols.max(1),
        pixel_width: 0,
        pixel_height: 0,
    }
}

fn other(err: impl fmt::Display) -> io::Error {
    io::Error::other(format!("{err:#}"))
}

/// Whether `key` is a sverb-internal variable.
fn is_internal_var(key: &std::ffi::OsStr) -> bool {
    let key = key.to_string_lossy();
    // Windows variable names are case-insensitive.
    #[cfg(windows)]
    let key = key.to_ascii_uppercase();
    key.starts_with("SVERB_")
}

/// The command for `shell` with the environment and working directory of
/// [the module docs](self).
fn build_command(
    shell: &str,
    spec: &LocalSpec,
    opts: &LocalOptions,
    pane: u64,
    env: &dyn EnvSource,
) -> CommandBuilder {
    let mut cmd = CommandBuilder::new(shell);
    let internal: Vec<OsString> = std::env::vars_os()
        .map(|(k, _)| k)
        .filter(|k| is_internal_var(k))
        .collect();
    for key in internal {
        cmd.env_remove(key);
    }
    cmd.env("TERM", &opts.term);
    if opts.colorterm {
        cmd.env("COLORTERM", "truecolor");
    }
    for (key, value) in &spec.env {
        cmd.env(key, value);
    }
    cmd.env(PANE_ENV, pane.to_string());
    if let Some(dir) = working_dir(spec.cwd.as_deref(), env) {
        // An inherited `PWD` (sverb's own directory) would mislead shells' `pwd`.
        cmd.env("PWD", &dir);
        cmd.cwd(dir);
    }
    cmd
}

/// `cwd` if it is a directory, else the home directory.
fn working_dir(cwd: Option<&Path>, env: &dyn EnvSource) -> Option<PathBuf> {
    if let Some(dir) = cwd {
        if dir.is_dir() {
            return Some(dir.to_path_buf());
        }
        warn!(cwd = %dir.display(), "local shell: not a directory; using the home directory");
    }
    env.home_dir()
}

/// `$SHELL`, else `/bin/sh`.
#[cfg(not(windows))]
fn default_shell() -> String {
    std::env::var("SHELL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "/bin/sh".to_owned())
}

/// `pwsh.exe` if on `PATH`, else `%ComSpec%`, else `cmd.exe`.
#[cfg(windows)]
fn default_shell() -> String {
    if let Some(pwsh) = find_in_path("pwsh.exe") {
        return pwsh.to_string_lossy().into_owned();
    }
    std::env::var("ComSpec")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "cmd.exe".to_owned())
}

#[cfg(windows)]
fn find_in_path(exe: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(exe))
        .find(|candidate| candidate.is_file())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::ffi::OsStr;

    use super::*;

    struct FakeEnv(Option<PathBuf>);

    impl EnvSource for FakeEnv {
        fn var(&self, _key: &str) -> Option<OsString> {
            None
        }
        fn home_dir(&self) -> Option<PathBuf> {
            self.0.clone()
        }
        fn uid(&self) -> Option<u32> {
            None
        }
    }

    #[test]
    fn internal_vars() {
        assert!(is_internal_var(OsStr::new("SVERB_HOME")));
        assert!(is_internal_var(OsStr::new("SVERB_PANE")));
        assert!(!is_internal_var(OsStr::new("SVERBX")));
        assert!(!is_internal_var(OsStr::new("HOME")));
    }

    #[test]
    fn command_environment() {
        let spec = LocalSpec {
            cwd: None,
            shell: None,
            env: vec![("FOO".to_owned(), "bar".to_owned())],
        };
        let opts = LocalOptions {
            term: "xterm".to_owned(),
            colorterm: true,
        };
        let home = std::env::temp_dir();
        let cmd = build_command("/bin/sh", &spec, &opts, 9, &FakeEnv(Some(home.clone())));
        assert_eq!(cmd.get_env("TERM"), Some(OsStr::new("xterm")));
        assert_eq!(cmd.get_env("COLORTERM"), Some(OsStr::new("truecolor")));
        assert_eq!(cmd.get_env("FOO"), Some(OsStr::new("bar")));
        assert_eq!(cmd.get_env(PANE_ENV), Some(OsStr::new("9")));
        assert_eq!(cmd.get_cwd(), Some(&home.into_os_string()));
        // Not a login shell: argv[0] is the program itself.
        assert_eq!(cmd.get_argv(), &vec![OsString::from("/bin/sh")]);
    }

    #[test]
    fn no_colorterm_when_disabled() {
        let opts = LocalOptions {
            colorterm: false,
            ..LocalOptions::default()
        };
        let cmd = build_command("sh", &LocalSpec::default(), &opts, 1, &FakeEnv(None));
        assert_eq!(cmd.get_env("TERM"), Some(OsStr::new(DEFAULT_TERM)));
        // Whatever sverb inherited, the child does not get it from us.
        if std::env::var_os("COLORTERM").is_none() {
            assert_eq!(cmd.get_env("COLORTERM"), None);
        }
    }

    #[test]
    fn cwd_falls_back_to_home() {
        let home = std::env::temp_dir();
        let env = FakeEnv(Some(home.clone()));
        let missing = home.join("sverb-m1-12-definitely-missing");
        assert_eq!(working_dir(Some(&missing), &env), Some(home.clone()));
        assert_eq!(working_dir(None, &env), Some(home.clone()));
        assert_eq!(working_dir(Some(&home), &FakeEnv(None)), Some(home));
    }

    #[cfg(unix)]
    #[test]
    fn default_shell_is_not_empty() {
        assert!(!default_shell().is_empty());
    }
}
