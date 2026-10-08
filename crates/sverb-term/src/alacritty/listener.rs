//! Synchronous `EventListener`: alacritty pushes events into a shared queue that
//! [`super::AlacrittyEmulator`] drains after every `feed`.

use std::sync::Arc;

use alacritty_terminal::event::{Event, EventListener};
use parking_lot::Mutex;

/// Collects alacritty events. Cloned once: one copy lives inside `Term`, one in the emulator.
#[derive(Clone, Default)]
pub(crate) struct Listener {
    queue: Arc<Mutex<Vec<Event>>>,
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listener")
            .field("queued", &self.queue.lock().len())
            .finish()
    }
}

impl Listener {
    /// Take every queued event.
    pub(crate) fn drain(&self) -> Vec<Event> {
        std::mem::take(&mut *self.queue.lock())
    }
}

impl EventListener for Listener {
    fn send_event(&self, event: Event) {
        match event {
            // Rendering hints we don't need: dirty tracking is done by the session layer.
            Event::MouseCursorDirty | Event::CursorBlinkingChange | Event::Wakeup => {}
            // SECURITY (SPEC §17): OSC 52 reads are always denied. Drop the request (and its
            // formatter) right here so it can never be queued, answered or reach the UI.
            Event::ClipboardLoad(..) => {}
            other => self.queue.lock().push(other),
        }
    }
}
