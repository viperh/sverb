//! [`MockTransport`]: an in-memory duplex transport for tests (`test-util` feature).
//!
//! [`MockTransport::pair`] returns the transport (give it to a session through
//! [`MockSpec`](crate::MockSpec)) and a [`MockRemote`], which plays the remote side:
//! it writes the session's output and observes what the session wrote, resized and
//! closed.

use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex;
use tokio::{
    io::{AsyncRead, AsyncWriteExt, DuplexStream, ReadBuf},
    sync::mpsc,
};

use crate::transport::{Transport, TransportKind};

/// Capacity of the in-memory output pipe.
pub const MOCK_PIPE_CAPACITY: usize = 4 * 1024 * 1024;

/// Something the session did to the transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MockOp {
    /// `write`.
    Write(Bytes),
    /// `resize`.
    Resize {
        /// Columns.
        cols: u16,
        /// Rows.
        rows: u16,
    },
    /// `close`.
    Close,
}

/// The session side.
#[derive(Debug)]
pub struct MockTransport {
    reader: MockReader,
    ops: mpsc::UnboundedSender<MockOp>,
    exit: Arc<Mutex<Option<i32>>>,
    hang_on_close: bool,
}

/// The remote side.
#[derive(Debug)]
pub struct MockRemote {
    output: Option<DuplexStream>,
    ops: mpsc::UnboundedReceiver<MockOp>,
    exit: Arc<Mutex<Option<i32>>>,
}

#[derive(Debug)]
struct MockReader {
    inner: DuplexStream,
    panic_on_read: bool,
}

impl AsyncRead for MockReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.panic_on_read {
            panic!("MockTransport: panic on read (test)");
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl MockTransport {
    /// A connected transport / remote pair.
    pub fn pair() -> (Self, MockRemote) {
        let (session_end, remote_end) = tokio::io::duplex(MOCK_PIPE_CAPACITY);
        let (ops_tx, ops_rx) = mpsc::unbounded_channel();
        let exit = Arc::new(Mutex::new(None));
        (
            Self {
                reader: MockReader {
                    inner: session_end,
                    panic_on_read: false,
                },
                ops: ops_tx,
                exit: Arc::clone(&exit),
                hang_on_close: false,
            },
            MockRemote {
                output: Some(remote_end),
                ops: ops_rx,
                exit,
            },
        )
    }

    /// Panic on the first read (panic containment tests).
    #[must_use]
    pub fn panic_on_read(mut self) -> Self {
        self.reader.panic_on_read = true;
        self
    }

    /// Never finish `close` (shutdown timeout tests).
    #[must_use]
    pub fn hang_on_close(mut self) -> Self {
        self.hang_on_close = true;
        self
    }

    /// Box it for a [`MockSpec`](crate::MockSpec).
    pub fn boxed(self) -> Box<dyn Transport> {
        Box::new(self)
    }
}

#[async_trait]
impl Transport for MockTransport {
    async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        let _ = self.ops.send(MockOp::Write(Bytes::copy_from_slice(data)));
        Ok(())
    }

    async fn resize(&mut self, cols: u16, rows: u16) -> io::Result<()> {
        let _ = self.ops.send(MockOp::Resize { cols, rows });
        Ok(())
    }

    fn reader(&mut self) -> &mut (dyn AsyncRead + Unpin + Send) {
        &mut self.reader
    }

    async fn close(&mut self) -> io::Result<()> {
        let _ = self.ops.send(MockOp::Close);
        if self.hang_on_close {
            std::future::pending::<()>().await;
        }
        Ok(())
    }

    fn kind(&self) -> TransportKind {
        TransportKind::Mock
    }

    async fn exit_status(&mut self) -> Option<i32> {
        *self.exit.lock()
    }
}

impl MockRemote {
    /// Send output to the session.
    pub async fn send(&mut self, data: &[u8]) -> io::Result<()> {
        match &mut self.output {
            Some(out) => out.write_all(data).await,
            None => Err(io::Error::new(io::ErrorKind::BrokenPipe, "finished")),
        }
    }

    /// End the output (the session sees EOF), with an exit status or without one.
    pub fn finish(&mut self, exit: Option<i32>) {
        *self.exit.lock() = exit;
        self.output = None;
    }

    /// The next thing the session did, waiting for it.
    pub async fn next_op(&mut self) -> Option<MockOp> {
        self.ops.recv().await
    }

    /// Everything the session did so far, without waiting.
    pub fn drain_ops(&mut self) -> Vec<MockOp> {
        let mut ops = Vec::new();
        while let Ok(op) = self.ops.try_recv() {
            ops.push(op);
        }
        ops
    }

    /// Wait until the session has written at least `n` bytes; returns them all
    /// (non-write ops are skipped).
    pub async fn read_written(&mut self, n: usize) -> Vec<u8> {
        let mut out = Vec::new();
        while out.len() < n {
            match self.ops.recv().await {
                Some(MockOp::Write(b)) => out.extend_from_slice(&b),
                Some(_) => {}
                None => break,
            }
        }
        out
    }
}
