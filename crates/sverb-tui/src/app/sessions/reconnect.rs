//! M1-16: the disconnect banner, reconnect and the optional auto-reconnect
//! (SPEC §6.1.2, §6.1.9; `tasks/03-KEYBINDINGS.md` §3.1 A4, §4.4).
//!
//! - **Banner.** A session that drops (`State(Disconnected { reason })`, any reason but
//!   `Exited`) shows `Disconnected (<reason>) — [Enter] reconnect · leader x close ·
//!   leader i details` over the bottom of its pane; the content stays visible. The pane
//!   is *dead*: Normal mode, only `Enter` and the leader do anything, every other key
//!   is swallowed (never sent, never interpreted) with a hint toast "Session
//!   disconnected — Enter to reconnect". `leader x` closes the pane, `leader i` shows
//!   the error chain (and selects the session's ConnLog entry in the Logs view).
//! - **Exited.** A remote exit is not a banner but a calmer footer, `Session ended (exit
//!   N) — [Enter] reconnect · leader x close` (a local shell: `Process exited (code N) —
//!   [Enter] restart`, M1-12).
//! - **Reconnect.** `Enter` sends `Effect::ReconnectSession` → `SessionCmd::Reconnect`;
//!   the actor reuses the emulator (scrollback kept), resets the modes and writes the
//!   `── reconnected at HH:MM:SS ──` separator. Until the session is connected again the
//!   pane takes no input (host-key and auth prompts are dialogs and still work).
//! - **Auto-reconnect** (host `auto_reconnect` → group chain → `ssh.auto_reconnect`,
//!   resolved fresh at each drop): SSH sessions that were connected retry with the
//!   `sverb_conn::session::actor::backoff` schedule (1 s → 30 s, ±20% jitter, at most 10
//!   tries), never after `HostKey`, `Auth` or `Exited`. The banner shows the countdown
//!   `Reconnecting in 4 s (attempt 3/10) — [Enter] now · [Esc] cancel · leader x close`;
//!   after the last failure it shows "gave up after 10 attempts". A prompt during an
//!   attempt pauses the loop: the next countdown only starts after the next drop.
//!
//! The countdown ticks once per second with `TimerKind::DialogTick` and a [`DialogId`]
//! allocated for it (the reducer's timer ids live in `app/event.rs` and `app/mod.rs`,
//! which M1-17 held while this was written; see the M1-16 merge notes). The jitter is
//! seeded from the drop's `Disconnected::at` instant, so the reducer stays pure.

use std::hash::{Hash, Hasher};

use crossterm::event::KeyCode;
use sverb_conn::session::actor::backoff::{self, MAX_ATTEMPTS, SplitMix64};
use sverb_conn::{DisconnectReason, SessionState};
use sverb_core::error_report::ErrorReport;
use sverb_core::model::ItemId;
use sverb_core::resolve::GlobalDefaults;

use crate::app::{App, Effect, SessionId, TimerKind, ToastLevel};
use crate::keymap::chord::{KeyChord, Mods};
use crate::views::DialogId;
use crate::widgets::terminal_pane::{Countdown, PaneOverlay};

/// The hint flashed when a key hits a disconnected pane.
pub(crate) const DISCONNECTED_HINT: &str = "Session disconnected — Enter to reconnect";

/// Countdown tick.
const TICK_MS: u64 = 1000;

impl App {
    /// Remember the last error a session reported (for `leader i`).
    pub(crate) fn reconnect_on_error(&mut self, id: SessionId, report: &ErrorReport) {
        if self.panes.contains_key(&id) || self.tabs.sessions.contains(&id) {
            let report = report.clone();
            self.update_reconnect(id, |p| p.reconnect.last_error = Some(report));
        }
    }

    /// Follow a session's state: banner, footer, countdown, back to live.
    pub(crate) fn reconnect_on_state(
        &mut self,
        id: SessionId,
        state: &SessionState,
        effects: &mut Vec<Effect>,
    ) {
        if !self.tabs.sessions.contains(&id) {
            return;
        }
        match state {
            SessionState::Connected { .. } => {
                self.cancel_countdown(id, effects);
                self.update_reconnect(id, |p| {
                    p.reconnect = Default::default();
                    if matches!(
                        p.overlay,
                        PaneOverlay::Disconnected { .. }
                            | PaneOverlay::Reconnecting { .. }
                            | PaneOverlay::Exited { .. }
                            | PaneOverlay::Connecting { .. }
                    ) {
                        p.overlay = PaneOverlay::None;
                    }
                });
            }
            SessionState::Disconnected {
                reason: DisconnectReason::Exited(code),
                ..
            } => {
                self.cancel_countdown(id, effects);
                let remote = self.is_ssh_pane(id);
                let code = *code;
                self.update_reconnect(id, |p| {
                    p.reconnect.attempt = 0;
                    p.reconnect.in_progress = false;
                    p.reconnect.reason = Some(DisconnectReason::Exited(code).message());
                    p.overlay = PaneOverlay::Exited {
                        code: Some(code),
                        remote,
                    };
                });
            }
            SessionState::Disconnected { reason, at } => {
                self.on_drop(id, *reason, *at, effects);
            }
            // M2-05: per-hop progress of a jump chain ("connecting via bastion (1/2)").
            SessionState::Connecting { hop, of } if *of > 1 => {
                let detail = self.hop_progress(id, *hop, *of);
                self.update_reconnect(id, |p| {
                    let frame = match p.overlay {
                        PaneOverlay::Connecting { frame, .. } => frame,
                        _ => 0,
                    };
                    p.overlay = PaneOverlay::Connecting { frame, detail };
                });
            }
            _ => {}
        }
        self.mode = self.derive_mode();
    }

    // M2-05
    /// `connecting via bastion (1/2)` (an intermediate hop) or `connecting to inner
    /// (2/2)` (the target), with the hop names from the pane's host's effective chain.
    fn hop_progress(&self, id: SessionId, hop: usize, of: usize) -> String {
        let globals = GlobalDefaults::from_config(&self.config);
        let host = self
            .panes
            .get(&id)
            .and_then(|p| p.host.as_deref())
            .and_then(|h| h.parse::<ItemId>().ok());
        let summary = host.and_then(|h| self.views.hosts.catalog()?.hosts.get(&h).cloned());
        let name = summary.as_ref().and_then(|s| {
            if hop >= of {
                return Some(s.display_label().to_owned());
            }
            let catalog = self.views.hosts.catalog()?;
            let hops = catalog.effective_chain(s, &globals).ok()?;
            hops.get(hop - 1).map(|h| {
                if h.label.is_empty() {
                    h.address.clone()
                } else {
                    h.label.clone()
                }
            })
        });
        match (name, hop >= of) {
            (Some(name), false) => format!("connecting via {name} ({hop}/{of})"),
            (Some(name), true) => format!("connecting to {name} ({hop}/{of})"),
            (None, _) => format!("connecting (hop {hop}/{of})"),
        }
    }

    fn on_drop(
        &mut self,
        id: SessionId,
        reason: DisconnectReason,
        at: std::time::Instant,
        effects: &mut Vec<Effect>,
    ) {
        self.cancel_countdown(id, effects);
        let info = self.pane(id).reconnect;
        let auto = !info.cancelled
            && reason != DisconnectReason::Internal
            && backoff::retries(reason)
            && self.is_ssh_pane(id)
            && self.auto_reconnect_enabled(id);
        let text = reason.message();
        let next = info.attempt + 1;
        if !auto {
            // Auth/HostKey during an auto run end it: the banner, not a countdown.
            self.update_reconnect(id, |p| {
                p.reconnect.attempt = 0;
                p.reconnect.in_progress = false;
                p.reconnect.reason = Some(text.clone());
                p.overlay = PaneOverlay::Disconnected {
                    reason: text,
                    gave_up: None,
                };
            });
            return;
        }
        let mut rng = SplitMix64::new(jitter_seed(id, at, next));
        let Some(delay) = backoff::delay(next, &mut rng) else {
            self.update_reconnect(id, |p| {
                p.reconnect.attempt = 0;
                p.reconnect.in_progress = false;
                p.reconnect.reason = Some(text.clone());
                p.overlay = PaneOverlay::Disconnected {
                    reason: text,
                    gave_up: Some(MAX_ATTEMPTS),
                };
            });
            return;
        };
        let remaining_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX).max(1);
        let countdown = Countdown {
            tick: self.ids.dialog(),
            attempt: next,
            remaining_ms,
            step_ms: remaining_ms.min(TICK_MS),
        };
        self.update_reconnect(id, |p| {
            p.reconnect.in_progress = false;
            p.reconnect.reason = Some(text);
            p.reconnect.countdown = Some(countdown);
            p.overlay = countdown_overlay(&countdown);
        });
        effects.push(Effect::ScheduleTimer {
            kind: TimerKind::DialogTick(countdown.tick),
            after: std::time::Duration::from_millis(countdown.step_ms),
        });
    }

    /// A countdown tick (`TimerKind::DialogTick` with a countdown's id). `false` when
    /// `tick` is not a countdown (then it is a dialog's).
    pub(crate) fn on_reconnect_tick(&mut self, tick: DialogId, effects: &mut Vec<Effect>) -> bool {
        let Some((id, countdown)) = self.panes.iter().find_map(|(id, p)| {
            p.reconnect
                .countdown
                .filter(|c| c.tick == tick)
                .map(|c| (*id, c))
        }) else {
            return false;
        };
        let remaining_ms = countdown.remaining_ms.saturating_sub(countdown.step_ms);
        if remaining_ms == 0 {
            self.start_reconnect(id, Some(countdown.attempt), effects);
            return true;
        }
        let next = Countdown {
            remaining_ms,
            step_ms: remaining_ms.min(TICK_MS),
            ..countdown
        };
        self.update_reconnect(id, |p| {
            p.reconnect.countdown = Some(next);
            p.overlay = countdown_overlay(&next);
        });
        effects.push(Effect::ScheduleTimer {
            kind: TimerKind::DialogTick(tick),
            after: std::time::Duration::from_millis(next.step_ms),
        });
        true
    }

    /// Reconnect now: `attempt` is the auto-reconnect attempt (`None`: by hand, which
    /// starts a new series).
    fn start_reconnect(&mut self, id: SessionId, attempt: Option<u32>, effects: &mut Vec<Effect>) {
        self.cancel_countdown(id, effects);
        let detail = match attempt {
            Some(n) => format!("reconnecting (attempt {n}/{MAX_ATTEMPTS})"),
            None => "reconnecting".to_owned(),
        };
        self.update_reconnect(id, |p| {
            p.reconnect.attempt = attempt.unwrap_or(0);
            p.reconnect.cancelled = false;
            p.reconnect.in_progress = true;
            p.overlay = PaneOverlay::Connecting { frame: 0, detail };
        });
        effects.push(Effect::ReconnectSession(id));
        self.mode = self.derive_mode();
    }

    /// Stop a running countdown (no-op without one).
    fn cancel_countdown(&mut self, id: SessionId, effects: &mut Vec<Effect>) {
        let Some(countdown) = self.panes.get(&id).and_then(|p| p.reconnect.countdown) else {
            return;
        };
        effects.push(Effect::CancelTimer(TimerKind::DialogTick(countdown.tick)));
        self.update_reconnect(id, |p| p.reconnect.countdown = None);
    }

    /// Whether `id`'s pane shows the banner, the countdown or a reconnect in progress
    /// (or the exited footer): it takes no terminal input.
    pub(crate) fn is_dead_pane(&self, id: SessionId) -> bool {
        if self.is_exited(id) {
            return true;
        }
        self.panes.get(&id).is_some_and(|p| {
            p.reconnect.in_progress
                || matches!(
                    p.overlay,
                    PaneOverlay::Disconnected { .. }
                        | PaneOverlay::Reconnecting { .. }
                        // M3-03: a workspace's "Host missing" placeholder.
                        | PaneOverlay::Missing { .. }
                )
        })
    }

    /// A key on a dead pane (the leader never gets here). `true` when handled here;
    /// `false` leaves it to the exited-pane handling (M1-12).
    pub(crate) fn on_reconnect_key(
        &mut self,
        id: SessionId,
        chord: KeyChord,
        effects: &mut Vec<Effect>,
    ) -> bool {
        let pane = self.pane(id);
        let plain = chord.mods == Mods::NONE;
        match pane.overlay {
            PaneOverlay::Reconnecting { .. } => {
                match chord.code {
                    KeyCode::Enter if plain => {
                        let attempt = pane.reconnect.countdown.map(|c| c.attempt);
                        self.start_reconnect(id, attempt, effects);
                    }
                    KeyCode::Esc if plain => {
                        self.cancel_countdown(id, effects);
                        let reason = pane.reconnect.reason.unwrap_or_default();
                        self.update_reconnect(id, |p| {
                            p.reconnect.cancelled = true;
                            p.reconnect.attempt = 0;
                            p.overlay = PaneOverlay::Disconnected {
                                reason,
                                gave_up: None,
                            };
                        });
                        self.push_toast(
                            ToastLevel::Info,
                            "Auto-reconnect cancelled".to_owned(),
                            effects,
                        );
                    }
                    // Swallowed (§4.4).
                    _ => {}
                }
                true
            }
            PaneOverlay::Disconnected { .. } => {
                if chord.code == KeyCode::Enter && plain {
                    self.start_reconnect(id, None, effects);
                } else {
                    self.push_toast(ToastLevel::Info, DISCONNECTED_HINT.to_owned(), effects);
                }
                true
            }
            // M3-03: a placeholder takes no keys (`leader x` closes it).
            PaneOverlay::Missing { .. } => true,
            // Reconnecting: nothing reaches the session until it is connected again.
            _ if pane.reconnect.in_progress => true,
            PaneOverlay::Exited { remote: true, .. } if chord.code == KeyCode::Enter && plain => {
                self.tabs.exited.remove(&id);
                self.start_reconnect(id, None, effects);
                true
            }
            _ => false,
        }
    }

    /// `leader x` on a dead pane: stop the countdown, then close (M1-12's
    /// `close_exited_pane` does the closing).
    pub(crate) fn before_close_dead_pane(&mut self, id: SessionId, effects: &mut Vec<Effect>) {
        self.cancel_countdown(id, effects);
    }

    /// `leader i` on a disconnected pane: select the session's ConnLog entry (M3-06) and
    /// show the error chain. `false` when the focused pane is not disconnected.
    pub(crate) fn show_disconnect_details(&mut self, effects: &mut Vec<Effect>) -> bool {
        use crate::views::dialogs::ModalDialog;
        use crate::widgets::dialog::Modal;
        let Some(id) = self.focused_session() else {
            return false;
        };
        if !self.is_dead_pane(id) {
            return false;
        }
        let pane = self.pane(id);
        let mut body = format!(
            "{}: {}",
            pane.label,
            pane.reconnect
                .reason
                .clone()
                .unwrap_or_else(|| "disconnected".to_owned())
        );
        if let Some(report) = &pane.reconnect.last_error {
            body.push_str("\n\n");
            body.push_str(&report.to_string());
        }
        let logged = self.show_conn_log(id);
        if logged {
            body.push_str("\n\nThe connection log entry is selected in Logs.");
        }
        self.push_dialog(crate::views::DialogKind::Modal(ModalDialog::new(
            Modal::info("Disconnected", &body),
        )));
        let _ = effects;
        true
    }

    /// An SSH pane (it connected over SSH at least once).
    fn is_ssh_pane(&self, id: SessionId) -> bool {
        self.tabs.ssh.contains_key(&id)
    }

    /// `auto_reconnect` for the pane's host, resolved now (host → group chain → vault
    /// defaults → `ssh.auto_reconnect`); unsaved targets use `ssh.auto_reconnect`.
    fn auto_reconnect_enabled(&self, id: SessionId) -> bool {
        let globals = GlobalDefaults::from_config(&self.config);
        let host = self
            .panes
            .get(&id)
            .and_then(|p| p.host.as_deref())
            .and_then(|h| h.parse::<ItemId>().ok());
        let catalog = self.views.hosts.catalog();
        match (host, catalog) {
            (Some(host), Some(catalog)) => match catalog.hosts.get(&host) {
                Some(summary) => catalog.resolve(summary, &globals).auto_reconnect,
                None => globals.auto_reconnect,
            },
            _ => globals.auto_reconnect,
        }
    }

    fn update_reconnect(
        &mut self,
        id: SessionId,
        f: impl FnOnce(&mut crate::widgets::terminal_pane::PaneInfo),
    ) {
        let mut info = self.pane(id);
        f(&mut info);
        if self.panes.get(&id) != Some(&info) {
            self.panes.insert(id, info);
            self.needs_redraw = true;
        }
    }
}

/// The countdown banner for `c`.
fn countdown_overlay(c: &Countdown) -> PaneOverlay {
    PaneOverlay::Reconnecting {
        in_secs: c.remaining_ms.div_ceil(1000),
        attempt: c.attempt,
        of: MAX_ATTEMPTS,
    }
}

/// The jitter seed of attempt `attempt` after the drop at `at`.
fn jitter_seed(id: SessionId, at: std::time::Instant, attempt: u32) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    id.0.hash(&mut h);
    at.hash(&mut h);
    attempt.hash(&mut h);
    h.finish()
}

#[cfg(test)]
#[path = "reconnect_tests.rs"]
mod tests;
