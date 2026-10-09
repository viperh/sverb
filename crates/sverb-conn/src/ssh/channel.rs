//! The session channel (SPEC §6.1.1 steps 5, 6 and 8): env, PTY, shell, and the data
//! path adapted to the [`Transport`] trait.
//!
//! - [`pty_modes`]: `VERASE` from the host's `backspace`, `IUTF8 = 1` only when the
//!   remote charset is UTF-8 (otherwise the remote line discipline would treat
//!   multi-byte input as UTF-8 and break erase for single-byte charsets).
//! - `open_shell`: `set_env` for each pair (rejections are logged at `debug` and
//!   ignored), the agent-forwarding hook, `request_pty`, `request_shell`. All
//!   requests want a reply; replies arrive in order, so each one is matched to its
//!   request.
//! - [`SshTransport`]: a pump task owns the channel's read half: `Data` and stderr
//!   (`ExtendedData{ext:1}`) go to the reader; `ExitStatus`/`ExitSignal` are
//!   remembered; `Close` (or the connection dropping) ends the stream — `Ok(0)` after a
//!   clean exit or close, an error carrying `Timeout` after a keepalive timeout. The
//!   startup input (§6.1.1 step 6) is typed once the first output arrives or after
//!   [`STARTUP_DELAY`], whichever comes first.

use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex;
use russh::{
    ChannelMsg, ChannelReadHalf, ChannelWriteHalf, Disconnect, Pty,
    client::{Handle, Msg},
};
use sverb_core::{error_report::ErrorReport, model::Backspace};
use tokio::{
    io::{AsyncRead, ReadBuf},
    sync::mpsc,
    task::AbortHandle,
};
use tracing::{debug, trace};

use super::{
    errors::SshError,
    handler::{ClientHandler, EndCause, Shared},
    resolved::SshTarget,
};
use crate::{
    session::DisconnectReason,
    transport::{Transport, TransportFailure, TransportKind},
};

/// When to type the startup input if no output arrived yet.
pub const STARTUP_DELAY: Duration = Duration::from_millis(500);

/// Reads queued between the pump and the actor.
const READ_QUEUE: usize = 64;

/// SSH extended data type for stderr.
const EXT_STDERR: u32 = 1;

/// The PTY modes for a host (RFC 4254 §8).
pub fn pty_modes(backspace: Backspace, utf8: bool) -> Vec<(Pty, u32)> {
    let erase = match backspace {
        Backspace::Del => 0x7f,
        Backspace::CtrlH => 0x08,
    };
    let mut modes = vec![(Pty::VERASE, erase)];
    if utf8 {
        modes.push((Pty::IUTF8, 1));
    }
    modes
}

/// Output queued before the shell request was answered.
pub(crate) type Early = Vec<Bytes>;

/// Send env, PTY and shell requests on a fresh session channel and check the replies.
///
/// # Errors
/// The shell (or the channel) was refused, or the connection failed.
pub(crate) async fn open_shell(
    read: &mut ChannelReadHalf,
    write: &ChannelWriteHalf<Msg>,
    host: &SshTarget,
    (cols, rows): (u16, u16),
) -> Result<Early, SshError> {
    let channel_err = |e: russh::Error| SshError::Channel(e.to_string());
    #[derive(Debug)]
    enum Req<'a> {
        Env(&'a str),
        Pty,
        Shell,
        Agent,
    }
    let mut sent = Vec::new();
    for (name, value) in &host.env {
        write
            .set_env(true, name.as_str(), value.as_str())
            .await
            .map_err(channel_err)?;
        sent.push(Req::Env(name));
    }
    // `auth-agent-req@openssh.com` before the pty and shell (§6.1.6).
    if host.agent_forwarding {
        write.agent_forward(true).await.map_err(channel_err)?;
        sent.push(Req::Agent);
    }
    write
        .request_pty(
            true,
            &host.term,
            u32::from(cols),
            u32::from(rows),
            0,
            0,
            &pty_modes(host.backspace, host.is_utf8()),
        )
        .await
        .map_err(channel_err)?;
    sent.push(Req::Pty);
    write.request_shell(true).await.map_err(channel_err)?;
    sent.push(Req::Shell);

    let mut early = Vec::new();
    for req in sent {
        let ok = loop {
            match read.wait().await {
                Some(ChannelMsg::Success) => break true,
                Some(ChannelMsg::Failure) => break false,
                Some(ChannelMsg::Data { data }) => early.push(data),
                Some(ChannelMsg::ExtendedData {
                    data,
                    ext: EXT_STDERR,
                }) => early.push(data),
                Some(ChannelMsg::Close | ChannelMsg::Eof) | None => {
                    return Err(SshError::Channel(
                        "the server closed the channel".to_owned(),
                    ));
                }
                Some(other) => trace!(msg = msg_name(&other), "ignored during channel setup"),
            }
        };
        match (req, ok) {
            (_, true) => {}
            (Req::Env(name), false) => debug!(var = name, "env request rejected (AcceptEnv)"),
            (Req::Pty, false) => debug!("pty request rejected; continuing without a pty"),
            (Req::Agent, false) => debug!("agent forwarding refused by the server"),
            (Req::Shell, false) => {
                return Err(SshError::Channel(
                    "the server refused to start a shell".to_owned(),
                ));
            }
        }
    }
    Ok(early)
}

fn msg_name(msg: &ChannelMsg) -> &'static str {
    match msg {
        ChannelMsg::WindowAdjusted { .. } => "WindowAdjusted",
        ChannelMsg::ExitStatus { .. } => "ExitStatus",
        ChannelMsg::ExitSignal { .. } => "ExitSignal",
        ChannelMsg::XonXoff { .. } => "XonXoff",
        _ => "other",
    }
}

/// What the pump learned about the remote process.
#[derive(Debug, Default)]
pub(crate) struct ExitInfo {
    pub(crate) status: Option<u32>,
    pub(crate) signal: Option<String>,
}

/// The reader end: bytes from the pump, with a partially consumed chunk.
struct ChannelReader {
    rx: mpsc::Receiver<io::Result<Bytes>>,
    pending: Bytes,
}

impl AsyncRead for ChannelReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.pending.is_empty() {
                let n = self.pending.len().min(buf.remaining());
                let chunk = self.pending.split_to(n);
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }
            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(Ok(bytes))) => self.pending = bytes,
                Poll::Ready(Some(Err(err))) => return Poll::Ready(Err(err)),
                // End of stream: `Ok(0)`.
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// A connected SSH shell as a [`Transport`].
pub struct SshTransport {
    write: ChannelWriteHalf<Msg>,
    reader: ChannelReader,
    handle: Arc<Handle<ClientHandler>>,
    exit: Arc<Mutex<ExitInfo>>,
    tasks: Vec<AbortHandle>,
    closed: bool,
    // The connection is shared; `close` closes only this channel.
    shared_connection: bool,
}

impl std::fmt::Debug for SshTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshTransport")
            .field("exit", &*self.exit.lock())
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

/// Everything the pump needs.
pub(crate) struct PumpParts {
    pub(crate) read: ChannelReadHalf,
    pub(crate) early: Early,
    pub(crate) startup: Option<Bytes>,
    pub(crate) shared: Arc<Shared>,
    pub(crate) keepalive_secs: u32,
    /// The jump hops under this connection: a hop that went down names the failure.
    pub(crate) chain: Option<Arc<super::connect::jump::Chain>>,
}

impl SshTransport {
    /// Start the pump and wrap the channel.
    pub(crate) fn start(
        write: ChannelWriteHalf<Msg>,
        handle: Arc<Handle<ClientHandler>>,
        parts: PumpParts,
    ) -> Self {
        let (tx, rx) = mpsc::channel(READ_QUEUE);
        let exit = Arc::new(Mutex::new(ExitInfo::default()));
        let mut parts = parts;
        let startup_writer = parts
            .startup
            .take()
            .map(|bytes| (bytes, write.make_writer()));
        let pump = tokio::spawn(pump(parts, startup_writer, tx, Arc::clone(&exit)));
        Self {
            write,
            reader: ChannelReader {
                rx,
                pending: Bytes::new(),
            },
            handle,
            exit,
            tasks: vec![pump.abort_handle()],
            closed: false,
            shared_connection: false,
        }
    }

    /// The connection is shared with other sessions (`ssh.multiplex`): `close` closes
    /// this channel only; the connection is released when the transport drops.
    pub(crate) fn set_shared_connection(&mut self, shared: bool) {
        self.shared_connection = shared;
    }

    /// Stop `task` when the transport is dropped.
    pub(crate) fn own_task(&mut self, task: AbortHandle) {
        self.tasks.push(task);
    }
}

impl Drop for SshTransport {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

fn to_io(err: russh::Error) -> io::Error {
    match err {
        russh::Error::IO(io) => io,
        other => io::Error::new(io::ErrorKind::BrokenPipe, other.to_string()),
    }
}

#[async_trait]
impl Transport for SshTransport {
    async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.write
            .data_bytes(Bytes::copy_from_slice(data))
            .await
            .map_err(to_io)
    }

    async fn resize(&mut self, cols: u16, rows: u16) -> io::Result<()> {
        self.write
            .window_change(u32::from(cols), u32::from(rows), 0, 0)
            .await
            .map_err(to_io)
    }

    fn reader(&mut self) -> &mut (dyn AsyncRead + Unpin + Send) {
        &mut self.reader
    }

    async fn close(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let _ = self.write.close().await;
        // Other sessions still use the connection.
        if self.shared_connection {
            return Ok(());
        }
        self.handle
            .disconnect(Disconnect::ByApplication, "", "en")
            .await
            .map_err(to_io)
    }

    fn kind(&self) -> TransportKind {
        TransportKind::Ssh
    }

    async fn exit_status(&mut self) -> Option<i32> {
        let exit = self.exit.lock();
        if let Some(signal) = &exit.signal {
            debug!(%signal, "remote process killed by a signal");
        }
        exit.status.map(|s| i32::try_from(s).unwrap_or(i32::MAX))
    }
}

/// How the channel ended, for the reader.
fn end_of_stream(shared: &Shared, exit: &ExitInfo, keepalive_secs: u32) -> Option<io::Error> {
    if exit.status.is_some() {
        return None;
    }
    connection_end(shared, keepalive_secs)
}

/// Why the connection ended, as the reader's error (`None`: a clean end). Every user
/// of a shared connection (shells and tunnels) maps it the same way, so they all
/// disconnect with the same reason.
pub(crate) fn connection_end(shared: &Shared, keepalive_secs: u32) -> Option<io::Error> {
    match shared.end.lock().clone() {
        Some(EndCause::KeepaliveTimeout) => {
            let err = SshError::KeepaliveTimeout {
                interval_secs: keepalive_secs,
            };
            Some(TransportFailure::new(DisconnectReason::Timeout, err.report()).into_io())
        }
        Some(EndCause::Error(msg)) => Some(
            TransportFailure::new(
                DisconnectReason::Connect,
                ErrorReport::from_messages(["SSH connection failed".to_owned(), msg]),
            )
            .into_io(),
        ),
        Some(EndCause::Remote(_)) | None => None,
    }
}

async fn pump(
    parts: PumpParts,
    mut startup: Option<(Bytes, impl tokio::io::AsyncWrite + Unpin)>,
    tx: mpsc::Sender<io::Result<Bytes>>,
    exit: Arc<Mutex<ExitInfo>>,
) {
    let PumpParts {
        mut read,
        early,
        shared,
        keepalive_secs,
        chain,
        ..
    } = parts;
    let mut seen_output = !early.is_empty();
    for chunk in early {
        if tx.send(Ok(chunk)).await.is_err() {
            return;
        }
    }
    let delay = tokio::time::sleep(STARTUP_DELAY);
    tokio::pin!(delay);
    loop {
        if seen_output && let Some((bytes, mut writer)) = startup.take() {
            type_startup(&bytes, &mut writer).await;
        }
        let msg = tokio::select! {
            msg = read.wait() => msg,
            () = &mut delay, if startup.is_some() => {
                seen_output = true;
                continue;
            }
        };
        match msg {
            Some(ChannelMsg::Data { data })
            | Some(ChannelMsg::ExtendedData {
                data,
                ext: EXT_STDERR,
            }) => {
                seen_output = true;
                if tx.send(Ok(data)).await.is_err() {
                    return;
                }
            }
            Some(ChannelMsg::ExitStatus { exit_status }) => exit.lock().status = Some(exit_status),
            Some(ChannelMsg::ExitSignal { signal_name, .. }) => {
                exit.lock().signal = Some(format!("{signal_name:?}"));
            }
            Some(ChannelMsg::Eof) => trace!("remote eof"),
            Some(ChannelMsg::Close) | None => break,
            Some(other) => trace!(msg = msg_name(&other), "channel message ignored"),
        }
    }
    // The connection may be going down at the same time: let the handler record why.
    tokio::task::yield_now().await;
    // The channel ended without an exit status: if a jump hop went down, the
    // failure names that hop (the target only saw its stream end).
    if let Some(chain) = &chain
        && exit.lock().status.is_none()
        && let Some(failure) = chain.hop_failure().await
    {
        let _ = tx.send(Err(failure.into_io())).await;
        return;
    }
    let failure = {
        let exit = exit.lock();
        end_of_stream(&shared, &exit, keepalive_secs)
    };
    if let Some(err) = failure {
        let _ = tx.send(Err(err)).await;
    }
}

async fn type_startup(bytes: &[u8], writer: &mut (impl tokio::io::AsyncWrite + Unpin)) {
    use tokio::io::AsyncWriteExt;
    if let Err(err) = writer.write_all(bytes).await {
        debug!(%err, "startup input not sent");
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// VERASE from `backspace`, IUTF8 only for UTF-8.
    #[test]
    fn t04_pty_modes() {
        assert_eq!(
            pty_modes(Backspace::CtrlH, true),
            [(Pty::VERASE, 8), (Pty::IUTF8, 1)]
        );
        assert_eq!(
            pty_modes(Backspace::Del, true),
            [(Pty::VERASE, 0x7f), (Pty::IUTF8, 1)]
        );
        assert_eq!(pty_modes(Backspace::Del, false), [(Pty::VERASE, 0x7f)]);
    }

    #[test]
    fn keepalive_end_maps_to_timeout() {
        let shared = Shared::default();
        *shared.end.lock() = Some(EndCause::KeepaliveTimeout);
        let err = end_of_stream(&shared, &ExitInfo::default(), 1).unwrap();
        let failure = TransportFailure::from_io(&err).unwrap();
        assert_eq!(failure.reason, DisconnectReason::Timeout);
        assert_eq!(
            failure.report.short,
            "Connection lost (no response for 3 s)"
        );
        // An exit status wins: a clean end.
        let exit = ExitInfo {
            status: Some(0),
            signal: None,
        };
        assert!(end_of_stream(&shared, &exit, 1).is_none());
        // A remote disconnect is a plain close.
        *shared.end.lock() = Some(EndCause::Remote("bye".into()));
        assert!(end_of_stream(&shared, &ExitInfo::default(), 1).is_none());
    }
}
