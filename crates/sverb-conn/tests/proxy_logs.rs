//! A ProxyCommand's stderr reaches the debug log (the session log). A test
//! binary of its own so the global capture subscriber sees every callsite.
#![allow(clippy::unwrap_used, clippy::expect_used, unreachable_pub)]
#![cfg(unix)]

use std::{
    io,
    sync::{Arc, Mutex},
    time::Duration,
};

use sverb_conn::proxy::ProxyCommandStream;
use tokio::io::AsyncReadExt;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Self;

    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

#[tokio::test]
async fn t08_proxy_command_stderr_is_logged() {
    let logs = Capture::default();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(logs.clone())
            .finish(),
    )
    .unwrap();
    let mut stream = ProxyCommandStream::spawn(
        "sh -c 'echo \"nc: connect to db port 22: refused\" >&2; printf \"\\033[31mred\\n\" >&2'",
    )
    .unwrap();
    let mut buf = Vec::new();
    let err = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut buf))
        .await
        .unwrap()
        .unwrap_err();
    assert!(err.to_string().contains("refused"), "{err}");
    let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    let line = text
        .lines()
        .find(|l| l.contains("ProxyCommand stderr") && l.contains("connect to db port 22: refused"))
        .unwrap_or_else(|| panic!("stderr not logged:\n{text}"));
    assert!(line.contains("DEBUG"), "{line}");
    // Control characters (terminal escapes) never reach the log.
    assert!(!text.contains('\u{1b}'), "{text}");
    assert!(text.contains("[31mred"), "{text}");
}
