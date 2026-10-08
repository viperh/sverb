//! The input task (M0-09): terminal events → [`InputEvent`] on a bounded channel.
//!
//! The task owns crossterm's `EventStream` (or, in tests, any stream of the same
//! item type) and pushes converted events into a bounded `mpsc` of capacity
//! [`INPUT_CAPACITY`]. When the loop falls behind, the task waits for room
//! (`send().await`); input is never dropped.
//!
//! Key kinds: `Press` and `Repeat` are forwarded (held keys repeat with the kitty
//! protocol), `Release` is ignored.

use std::io;

use crossterm::event::{Event as CtEvent, KeyEventKind};
use futures::{Stream, StreamExt};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::error;

use crate::app::InputEvent;

/// Capacity of the bounded input channel.
pub const INPUT_CAPACITY: usize = 1024;

/// Sender half of the input channel.
pub type InputSender = mpsc::Sender<InputEvent>;

/// Receiver half of the input channel (read by the event loop).
pub type InputReceiver = mpsc::Receiver<InputEvent>;

/// A new bounded input channel.
pub fn channel() -> (InputSender, InputReceiver) {
    mpsc::channel(INPUT_CAPACITY)
}

/// Convert one crossterm event. `None` for events the UI ignores (key releases).
pub fn convert(ev: CtEvent) -> Option<InputEvent> {
    Some(match ev {
        CtEvent::Key(key) => match key.kind {
            KeyEventKind::Press | KeyEventKind::Repeat => InputEvent::Key(key),
            KeyEventKind::Release => return None,
        },
        CtEvent::Mouse(m) => InputEvent::Mouse(m),
        CtEvent::Paste(s) => InputEvent::Paste(s),
        CtEvent::FocusGained => InputEvent::FocusGained,
        CtEvent::FocusLost => InputEvent::FocusLost,
        CtEvent::Resize(cols, rows) => InputEvent::Resize { cols, rows },
    })
}

/// Forward `stream` into `tx` until the stream ends or the receiver is gone.
pub async fn pump<S>(mut stream: S, tx: InputSender)
where
    S: Stream<Item = io::Result<CtEvent>> + Unpin,
{
    while let Some(ev) = stream.next().await {
        let input = match ev {
            Ok(ev) => match convert(ev) {
                Some(input) => input,
                None => continue,
            },
            Err(err) => {
                error!(%err, "terminal input error");
                continue;
            }
        };
        if tx.send(input).await.is_err() {
            break;
        }
    }
}

/// Spawn the input task on crossterm's `EventStream`.
pub fn spawn_terminal_input(tx: InputSender) -> JoinHandle<()> {
    tokio::spawn(pump(crossterm::event::EventStream::new(), tx))
}

/// Stop the input task and wait until it is gone, so nothing reads the terminal
/// while (or after) it is restored.
pub async fn stop(task: JoinHandle<()>) {
    task.abort();
    // `Err(Cancelled)` is the expected outcome; a panic was already reported by the hook.
    let _ = task.await;
}

#[cfg(test)]
mod tests {
    use crossterm::event::{KeyCode, KeyEvent, KeyEventState, KeyModifiers};

    use super::*;

    fn key(kind: KeyEventKind) -> io::Result<CtEvent> {
        Ok(CtEvent::Key(KeyEvent {
            code: KeyCode::Char('j'),
            modifiers: KeyModifiers::NONE,
            kind,
            state: KeyEventState::NONE,
        }))
    }

    // T-07
    #[tokio::test]
    async fn repeat_keys_accepted_release_ignored() {
        let (tx, mut rx) = channel();
        let events = vec![
            key(KeyEventKind::Press),
            key(KeyEventKind::Repeat),
            key(KeyEventKind::Release),
            Err(io::Error::other("transient")),
        ];
        pump(futures::stream::iter(events), tx).await;
        let mut got = Vec::new();
        while let Some(ev) = rx.recv().await {
            got.push(ev);
        }
        assert_eq!(got.len(), 2, "{got:?}");
        let kinds: Vec<_> = got
            .iter()
            .map(|ev| match ev {
                InputEvent::Key(k) => k.kind,
                other => panic!("unexpected {other:?}"),
            })
            .collect();
        assert_eq!(kinds, [KeyEventKind::Press, KeyEventKind::Repeat]);
    }

    #[test]
    fn resize_and_paste_convert() {
        assert_eq!(
            convert(CtEvent::Resize(100, 30)),
            Some(InputEvent::Resize {
                cols: 100,
                rows: 30
            })
        );
        assert_eq!(
            convert(CtEvent::Paste("x".into())),
            Some(InputEvent::Paste("x".into()))
        );
    }
}
