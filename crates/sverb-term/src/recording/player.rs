//! The replay engine (SPEC §9.12): a fresh emulator fed from a decrypted recording.
//!
//! - **Timeline.** Gaps between events are capped at [`IDLE_CAP`] (2 s), so playback time
//!   is not recording time. `elapsed`/`total` are playback time.
//! - **Speed** 1×/2×/4× scales wall time ([`Player::advance`]).
//! - **Seeking** forward applies events; seeking backwards restores the latest in-memory
//!   checkpoint at or before the target (an emulator snapshot taken every
//!   [`CHECKPOINT_EVERY`] of *recording* time) and replays from there, or replays from the
//!   start when there is none.
//! - Output and resize events drive the emulator; input and marker events are skipped.
//!
//! The UI (the Logs view's player, `sverb-tui`) owns the wall clock and calls `advance`.

use std::time::Duration;

use bytes::Bytes;

use super::{
    asciicast::{Event, EventKind},
    reader::Recording,
};
use crate::{AlacrittyEmulator, Emulator, EmulatorConfig};

/// Longest idle gap played back.
pub const IDLE_CAP: Duration = Duration::from_secs(2);

/// Recording time between emulator checkpoints.
pub const CHECKPOINT_EVERY: Duration = Duration::from_secs(30);

/// Seek step for `←`/`→`.
pub const SEEK_STEP: Duration = Duration::from_secs(5);

/// Playback speed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Speed {
    /// 1×.
    #[default]
    X1,
    /// 2×.
    X2,
    /// 4×.
    X4,
}

impl Speed {
    /// The multiplier.
    #[must_use]
    pub fn factor(self) -> u32 {
        match self {
            Self::X1 => 1,
            Self::X2 => 2,
            Self::X4 => 4,
        }
    }

    /// One step faster (saturating at 4×).
    #[must_use]
    pub fn faster(self) -> Self {
        match self {
            Self::X1 => Self::X2,
            Self::X2 | Self::X4 => Self::X4,
        }
    }

    /// One step slower (saturating at 1×).
    #[must_use]
    pub fn slower(self) -> Self {
        match self {
            Self::X4 => Self::X2,
            Self::X2 | Self::X1 => Self::X1,
        }
    }
}

/// Emulator state before `events[next]`.
#[derive(Debug, Clone)]
struct Checkpoint {
    next: usize,
    cols: u16,
    rows: u16,
    vt: Bytes,
}

/// Map recording times to playback times with every gap capped at `cap`.
#[must_use]
pub fn playback_times(events: &[Event], cap: Duration) -> Vec<Duration> {
    let mut out = Vec::with_capacity(events.len());
    let mut prev_raw = Duration::ZERO;
    let mut t = Duration::ZERO;
    for ev in events {
        let gap = ev.time.saturating_sub(prev_raw);
        t += gap.min(cap);
        prev_raw = prev_raw.max(ev.time);
        out.push(t);
    }
    out
}

/// A replay in progress.
pub struct Player {
    events: Vec<Event>,
    times: Vec<Duration>,
    total: Duration,
    initial: (u16, u16),
    emu: AlacrittyEmulator,
    next: usize,
    clock: Duration,
    playing: bool,
    speed: Speed,
    checkpoints: Vec<Checkpoint>,
    last_checkpoint_raw: Duration,
    incomplete: bool,
    title: Option<String>,
}

impl std::fmt::Debug for Player {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Player")
            .field("events", &self.events.len())
            .field("next", &self.next)
            .field("clock", &self.clock)
            .field("total", &self.total)
            .field("playing", &self.playing)
            .field("speed", &self.speed)
            .field("checkpoints", &self.checkpoints.len())
            .finish_non_exhaustive()
    }
}

impl Player {
    /// A paused player at the start of `rec`.
    #[must_use]
    pub fn new(rec: Recording) -> Self {
        let events: Vec<Event> = rec
            .events
            .into_iter()
            .filter(|e| matches!(e.kind, EventKind::Output | EventKind::Resize))
            .collect();
        let times = playback_times(&events, IDLE_CAP);
        let total = times.last().copied().unwrap_or_default();
        let initial = (rec.header.width.max(1), rec.header.height.max(1));
        Self {
            events,
            times,
            total,
            initial,
            emu: fresh(initial.0, initial.1),
            next: 0,
            clock: Duration::ZERO,
            playing: false,
            speed: Speed::X1,
            checkpoints: Vec::new(),
            last_checkpoint_raw: Duration::ZERO,
            incomplete: rec.incomplete,
            title: rec.header.title,
        }
    }

    /// The emulator showing the current frame.
    pub fn emulator(&self) -> &AlacrittyEmulator {
        &self.emu
    }

    /// Playback position.
    pub fn elapsed(&self) -> Duration {
        self.clock
    }

    /// Playback length (idle gaps capped).
    pub fn total(&self) -> Duration {
        self.total
    }

    /// Whether the clock is running.
    pub fn is_playing(&self) -> bool {
        self.playing
    }

    /// Current speed.
    pub fn speed(&self) -> Speed {
        self.speed
    }

    /// The recording was truncated ("recording incomplete (truncated)").
    pub fn incomplete(&self) -> bool {
        self.incomplete
    }

    /// The recording's title (host label).
    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    /// Whether playback reached the end.
    pub fn at_end(&self) -> bool {
        self.next >= self.events.len() && self.clock >= self.total
    }

    /// Number of in-memory checkpoints (tests).
    pub fn checkpoint_count(&self) -> usize {
        self.checkpoints.len()
    }

    /// Play/pause (`Space`). Playing at the end restarts from the beginning.
    pub fn toggle_pause(&mut self) {
        if !self.playing && self.at_end() {
            self.seek_to(Duration::ZERO);
        }
        self.playing = !self.playing;
    }

    /// Set playing on or off.
    pub fn set_playing(&mut self, playing: bool) {
        self.playing = playing;
    }

    /// `+`.
    pub fn faster(&mut self) {
        self.speed = self.speed.faster();
    }

    /// `-`.
    pub fn slower(&mut self) {
        self.speed = self.speed.slower();
    }

    /// Advance by `wall` real time (scaled by the speed). Returns whether the screen
    /// changed. Stops at the end.
    pub fn advance(&mut self, wall: Duration) -> bool {
        if !self.playing {
            return false;
        }
        let target = (self.clock + wall * self.speed.factor()).min(self.total);
        let changed = self.apply_until(target);
        self.clock = target;
        if self.next >= self.events.len() && self.clock >= self.total {
            self.playing = false;
        }
        changed
    }

    /// The wall time until the next event at the current speed (for scheduling redraws).
    pub fn until_next_event(&self) -> Option<Duration> {
        let t = *self.times.get(self.next)?;
        Some(t.saturating_sub(self.clock) / self.speed.factor())
    }

    /// `→` (positive) / `←` (negative): seek by [`SEEK_STEP`] multiples.
    pub fn seek_by(&mut self, forward: bool) {
        let target = if forward {
            (self.clock + SEEK_STEP).min(self.total)
        } else {
            self.clock.saturating_sub(SEEK_STEP)
        };
        self.seek_to(target);
    }

    /// Seek to a playback time.
    pub fn seek_to(&mut self, target: Duration) {
        let target = target.min(self.total);
        if target < self.clock || self.applied_after(target) {
            self.restore_for(target);
        }
        self.apply_until(target);
        self.clock = target;
    }

    /// Whether an event after `target` has already been applied.
    fn applied_after(&self, target: Duration) -> bool {
        self.next > 0 && self.times[self.next - 1] > target
    }

    /// Reset the emulator to the latest checkpoint whose state is at or before `target`.
    fn restore_for(&mut self, target: Duration) {
        let cp = self
            .checkpoints
            .iter()
            .rev()
            .find(|cp| cp.next == 0 || self.times[cp.next - 1] <= target)
            .cloned();
        match cp {
            Some(cp) => {
                self.emu = fresh(cp.cols, cp.rows);
                self.emu.feed(&cp.vt);
                drain(&mut self.emu);
                self.next = cp.next;
                // As when the checkpoint was taken (just before `events[next]`).
                self.last_checkpoint_raw =
                    self.events.get(cp.next).map_or(Duration::ZERO, |e| e.time);
            }
            None => {
                self.emu = fresh(self.initial.0, self.initial.1);
                self.next = 0;
                self.last_checkpoint_raw = Duration::ZERO;
            }
        }
    }

    /// Apply events with playback time ≤ `target`. Takes checkpoints on the way.
    fn apply_until(&mut self, target: Duration) -> bool {
        let mut changed = false;
        while self.next < self.events.len() && self.times[self.next] <= target {
            let raw = self.events[self.next].time;
            if raw >= self.last_checkpoint_raw + CHECKPOINT_EVERY {
                self.take_checkpoint();
                self.last_checkpoint_raw = raw;
            }
            let ev = &self.events[self.next];
            match ev.kind {
                EventKind::Output => self.emu.feed(ev.data.as_bytes()),
                EventKind::Resize => {
                    if let Some((c, r)) = ev.resize_size() {
                        self.emu.resize(c, r);
                    }
                }
                EventKind::Input | EventKind::Marker => {}
            }
            self.next += 1;
            changed = true;
        }
        if changed {
            drain(&mut self.emu);
        }
        changed
    }

    fn take_checkpoint(&mut self) {
        if self
            .checkpoints
            .last()
            .is_some_and(|cp| cp.next >= self.next)
        {
            return;
        }
        drain(&mut self.emu);
        self.emu.flush_sync();
        let (cols, rows) = self.emu.size();
        self.checkpoints.push(Checkpoint {
            next: self.next,
            cols,
            rows,
            vt: self.emu.snapshot_vt(),
        });
    }
}

fn fresh(cols: u16, rows: u16) -> AlacrittyEmulator {
    AlacrittyEmulator::new(EmulatorConfig {
        cols,
        rows,
        ..EmulatorConfig::default()
    })
}

/// Replies and events go nowhere in a replay.
fn drain(emu: &mut AlacrittyEmulator) {
    let _ = emu.take_responses();
    let _ = emu.take_events();
}
