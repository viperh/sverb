//! OS signals → [`LoopSignal`] (SPEC §18).
//!
//! - Unix: `SIGTERM`, `SIGHUP` and `SIGINT` → [`LoopSignal::Shutdown`] (`SIGINT` only
//!   arrives outside raw mode, e.g. while suspended). `SIGCONT` →
//!   [`LoopSignal::Continued`] (clear and redraw everything). `SIGWINCH` is already
//!   delivered by crossterm as a `Resize` event.
//! - Windows: console close and system shutdown → [`LoopSignal::Shutdown`].
//!
//! The loop turns `Shutdown` into `UiEvent::ShutdownRequested`; the reducer answers
//! with `Quit { code: 0 }` without confirmation.

use tokio::{sync::mpsc, task::JoinHandle};
use tracing::warn;

/// A signal the event loop reacts to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LoopSignal {
    /// Leave cleanly (exit 0, terminal restored).
    Shutdown,
    /// The process was continued after a stop: repaint the whole screen.
    Continued,
}

/// Sender half of the signal channel.
pub type SignalSender = mpsc::Sender<LoopSignal>;

/// Receiver half of the signal channel.
pub type SignalReceiver = mpsc::Receiver<LoopSignal>;

/// A new signal channel. Signals are rare; a small buffer is plenty.
pub fn channel() -> (SignalSender, SignalReceiver) {
    mpsc::channel(16)
}

/// Install the handlers and forward signals to `tx`. Abort the returned tasks on exit.
///
/// A handler that cannot be installed is logged and skipped.
pub fn spawn(tx: &SignalSender) -> Vec<JoinHandle<()>> {
    imp::spawn(tx)
}

#[cfg(unix)]
mod imp {
    use tokio::signal::unix::{SignalKind, signal};

    use super::*;

    pub(super) fn spawn(tx: &SignalSender) -> Vec<JoinHandle<()>> {
        [
            (SignalKind::terminate(), LoopSignal::Shutdown, "SIGTERM"),
            (SignalKind::hangup(), LoopSignal::Shutdown, "SIGHUP"),
            (SignalKind::interrupt(), LoopSignal::Shutdown, "SIGINT"),
            (
                SignalKind::from_raw(signal_hook::consts::signal::SIGCONT),
                LoopSignal::Continued,
                "SIGCONT",
            ),
        ]
        .into_iter()
        .filter_map(|(kind, what, name)| match signal(kind) {
            Ok(mut stream) => {
                let tx = tx.clone();
                Some(tokio::spawn(async move {
                    while stream.recv().await.is_some() {
                        if tx.send(what).await.is_err() {
                            break;
                        }
                    }
                }))
            }
            Err(err) => {
                warn!(%err, signal = name, "cannot install signal handler");
                None
            }
        })
        .collect()
    }
}

#[cfg(windows)]
mod imp {
    use tokio::signal::windows::{ctrl_close, ctrl_shutdown};

    use super::*;

    pub(super) fn spawn(tx: &SignalSender) -> Vec<JoinHandle<()>> {
        let mut tasks = Vec::new();
        match ctrl_close() {
            Ok(mut close) => {
                let tx = tx.clone();
                tasks.push(tokio::spawn(async move {
                    while close.recv().await.is_some() {
                        if tx.send(LoopSignal::Shutdown).await.is_err() {
                            break;
                        }
                    }
                }));
            }
            Err(err) => warn!(%err, "cannot install the console close handler"),
        }
        match ctrl_shutdown() {
            Ok(mut shutdown) => {
                let tx = tx.clone();
                tasks.push(tokio::spawn(async move {
                    while shutdown.recv().await.is_some() {
                        if tx.send(LoopSignal::Shutdown).await.is_err() {
                            break;
                        }
                    }
                }));
            }
            Err(err) => warn!(%err, "cannot install the shutdown handler"),
        }
        tasks
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    use super::*;

    pub(super) fn spawn(_tx: &SignalSender) -> Vec<JoinHandle<()>> {
        warn!("signal handling is not supported on this platform");
        Vec::new()
    }
}
