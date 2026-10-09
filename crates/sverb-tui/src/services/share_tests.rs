//! The share service's runtime pieces: the viewer pane's transport (ordered
//! resizes, no EOF, discarded writes), the mapping of viewer events into the pane,
//! and a viewer pane opened through the session service.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use sverb_conn::SessionEvent;
use sverb_term::{AlacrittyEmulator, Emulator, EmulatorConfig, GridPoint};
use tokio::io::AsyncReadExt;

use super::*;
use crate::runtime::sessions::{self, SessionNotice};

fn emulator(cols: u16, rows: u16) -> SharedEmulator {
    let e: Box<dyn Emulator> = Box::new(AlacrittyEmulator::new(EmulatorConfig {
        cols,
        rows,
        scrollback: 100,
    }));
    Arc::new(e.into())
}

fn screen(term: &SharedEmulator) -> String {
    let t = term.lock();
    let (cols, rows) = t.size();
    t.grid_text(
        GridPoint::new(0, 0),
        GridPoint::new(i32::from(rows) - 1, usize::from(cols) - 1),
    )
}

#[tokio::test]
async fn viewer_reader_keeps_resizes_in_order() {
    let term = emulator(80, 24);
    let slot = Arc::new(ViewerSlot::default());
    *slot.term.lock().unwrap() = Some(Arc::clone(&term));
    let (tx, rx) = mpsc::unbounded_channel();
    let mut transport = ViewerTransport {
        reader: ViewerReader {
            rx,
            buf: Vec::new(),
            pos: 0,
            slot: Arc::clone(&slot),
        },
        slot,
    };
    tx.send(Chunk::Bytes(b"abc".to_vec())).unwrap();
    tx.send(Chunk::Resize(100, 30)).unwrap();
    tx.send(Chunk::Bytes(b"def".to_vec())).unwrap();
    let mut buf = [0_u8; 2];
    // Reads are bounded by the caller's buffer; the rest stays queued.
    assert_eq!(transport.reader().read(&mut buf).await.unwrap(), 2);
    assert_eq!(&buf, b"ab");
    assert_eq!(transport.reader().read(&mut buf).await.unwrap(), 1);
    assert_eq!(&buf[..1], b"c");
    // Not resized before the bytes queued ahead of the resize were read.
    assert_eq!(term.lock().size(), (80, 24));
    assert_eq!(transport.reader().read(&mut buf).await.unwrap(), 2);
    assert_eq!(&buf, b"de");
    assert_eq!(term.lock().size(), (100, 30));
    // Writes (the emulator's replies) go nowhere; no EOF once the task is gone.
    transport.write(b"\x1b[?62c").await.unwrap();
    drop(tx);
    assert_eq!(transport.reader().read(&mut buf).await.unwrap(), 1);
    let pending =
        tokio::time::timeout(Duration::from_millis(50), transport.reader().read(&mut buf)).await;
    assert!(pending.is_err(), "an ended share must not look like EOF");
    transport.close().await.unwrap();
}

#[test]
fn viewer_events_in_the_pane() {
    let (chunks, status) = viewer_event(ViewerEvent::WaitingForApproval);
    assert_eq!(status, Some(ViewerStatus::Waiting));
    assert!(
        matches!(&chunks[..], [Chunk::Bytes(b)] if String::from_utf8_lossy(b).contains("Waiting for host approval…"))
    );

    let (chunks, status) = viewer_event(ViewerEvent::Snapshot {
        cols: 120,
        rows: 40,
        vt: b"SCREEN".to_vec(),
    });
    assert_eq!(
        status,
        Some(ViewerStatus::Live {
            cols: 120,
            rows: 40
        })
    );
    assert!(matches!(
        &chunks[..],
        [Chunk::Resize(120, 40), Chunk::Bytes(reset), Chunk::Bytes(vt)]
            if reset.starts_with(b"\x1b[!p") && vt == b"SCREEN"
    ));

    let text = |ev| match viewer_event(ev).0.as_slice() {
        [Chunk::Bytes(b)] => String::from_utf8_lossy(b).into_owned(),
        other => panic!("{other:?}"),
    };
    let ended = text(ViewerEvent::Ended {
        reason: "denied by the host".into(),
    });
    assert!(
        ended.contains("Share ended (denied by the host)"),
        "{ended}"
    );
    let integrity = text(ViewerEvent::Ended {
        reason: INTEGRITY_ERROR.into(),
    });
    assert!(integrity.contains("Share connection integrity error"));
    assert!(!integrity.contains("Share ended"));
    assert_eq!(
        viewer_event(ViewerEvent::ControlGranted(true)).1,
        Some(ViewerStatus::Control(true))
    );
}

/// A viewer pane opened through the session service: it renders the status lines and
/// ends when the share's server can't be reached (a loopback port nothing listens on).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn join_opens_a_viewer_pane_that_shows_the_end() {
    let (notices, mut notice_rx) = sessions::channel();
    let mut svc = SessionService::new(notices);
    let (tx, mut events) = mpsc::channel(64);
    let share = ShareService::default();
    let id = SessionId(42);
    let link = ShareLink::new(
        "127.0.0.1:1",
        [3; 16],
        sverb_crypto::share::ShareKey::from_bytes([4; 32]),
    )
    .unwrap()
    .to_sverb_link();
    share.execute(ShareEffect::Join { id, link }, None, Some(&mut svc), &tx);

    let ended = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Some(UiEvent::Share(ShareEvent::Viewer {
                id: got,
                status: ViewerStatus::Ended { reason },
            })) = events.recv().await
            {
                assert_eq!(got, id);
                return reason;
            }
        }
    })
    .await
    .expect("the viewer pane never ended");
    assert!(!ended.is_empty());
    let mut opened = false;
    while let Ok(n) = notice_rx.try_recv() {
        if let SessionNotice::Opened { id: o, .. } = n {
            opened |= o == id;
        }
        if let SessionNotice::Event(_, SessionEvent::Error(e)) = n {
            panic!("viewer pane failed: {}", e.short);
        }
    }
    assert!(opened);
    let term = svc
        .manager()
        .get(sverb_conn::SessionId(id.0))
        .expect("the pane stays open")
        .term;
    let start = std::time::Instant::now();
    loop {
        let s = screen(&term);
        if s.contains("Joining the shared terminal…") && s.contains("Share ended (") {
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(5), "{s}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Typing in it goes nowhere without control (and never panics).
    share.execute(
        ShareEffect::Input {
            id,
            input: SessionInput::Raw(b"ls\r".to_vec()),
        },
        None,
        Some(&mut svc),
        &tx,
    );
    svc.close(id);
}
