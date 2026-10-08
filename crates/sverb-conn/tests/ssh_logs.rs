//! M1-13 T-17: a full loopback SSH connection logs no hostnames or addresses at `info`
//! and above (SPEC §17); the session id is logged instead. A test binary of its own so
//! the capture subscriber sees every callsite.
#![allow(clippy::unwrap_used, clippy::expect_used, unreachable_pub)]

use std::{
    io,
    sync::{Arc, Mutex},
    time::Duration,
};

use sverb_conn::{
    Bytes, OpenOptions, SessionCmd, SessionEvent, SessionId, SessionManager, SessionSpec,
    SessionState, SshSpec, TransportKind,
    ssh::{
        InsecureAcceptAnyHostKey, SshConnector,
        testing::{TestResolver, start_server},
    },
};
use tokio::sync::mpsc;

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

async fn wait_state(
    rx: &mut mpsc::UnboundedReceiver<(SessionId, SessionEvent)>,
    pred: impl Fn(&SessionState) -> bool,
) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let (_, SessionEvent::State(s)) = rx.recv().await.unwrap()
                && pred(&s)
            {
                return;
            }
        }
    })
    .await
    .unwrap();
}

#[test]
fn t17_no_hostnames_in_info_logs() {
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(capture.clone())
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let port = rt.block_on(async {
        let (addr, _) = start_server().await;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mgr = SessionManager::new(tx);
        let connector = SshConnector::new(Arc::new(TestResolver {
            addr,
            password: "secret",
            edit: |_| {},
        }))
        .with_verifier(Arc::new(InsecureAcceptAnyHostKey::insecure_for_testing()));
        mgr.register_connector(TransportKind::Ssh, Arc::new(connector));
        let handle = mgr
            .open_with(
                SessionSpec::Ssh(SshSpec {
                    host: addr.ip().to_string(),
                    port: addr.port(),
                    ..SshSpec::default()
                }),
                OpenOptions::default(),
            )
            .unwrap();
        wait_state(&mut rx, |s| matches!(s, SessionState::Connected { .. })).await;
        handle
            .cmd_tx
            .send(SessionCmd::Input(Bytes::from_static(b"exit 7\r")))
            .await
            .unwrap();
        wait_state(&mut rx, |s| matches!(s, SessionState::Disconnected { .. })).await;
        mgr.shutdown(Duration::from_secs(2)).await;
        addr.port()
    });
    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("connecting session=#1"),
        "info logs are captured:\n{logs}"
    );
    assert!(logs.contains("ssh session open session=#1"), "{logs}");
    assert!(!logs.contains("127.0.0.1"), "address in info logs:\n{logs}");
    assert!(
        !logs.contains(&format!(":{port}")),
        "port in info logs:\n{logs}"
    );
}
