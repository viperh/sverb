//! The recording replay player (SPEC §9.12), embedded by the Logs view.
//!
//! ```text
//! ┌ Replay · web-1 ───────────────────────────────┐
//! │ (the recorded terminal, sized per the header)  │
//! │                                                │
//! │ ▶ 00:12 / 01:30 ━━━━━━━━──────────────── 2×    │
//! │ Space play/pause · +/- speed · ←/→ 5s · q close│
//! └────────────────────────────────────────────────┘
//! ```
//!
//! The engine is `sverb_term::recording::Player` (2 s idle cap, 1×/2×/4×, checkpointed
//! seeking). This view adds the keys and the drawing. It has no clock: the host calls
//! [`ReplayView::tick`] with the `Instant` of a timer event and schedules the next tick
//! after [`ReplayView::next_tick_in`]. Opening a recording needs the unlocked vault
//! (`services::recording::open_recording` with the recording key).

use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph},
};
use sverb_term::{
    Emulator, ViewState,
    recording::{Player, Recording, Speed},
};

use crate::theme::Theme;

/// Shown for a recording without its final chunk.
pub const INCOMPLETE: &str = "recording incomplete (truncated)";

/// Longest wait between ticks while playing (keeps the progress bar moving).
pub const MAX_TICK: Duration = Duration::from_millis(100);

/// What a key did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayOutcome {
    /// Handled; redraw.
    Consumed,
    /// `q`/`Esc`: close the player.
    Close,
    /// Not a player key.
    Ignored,
}

/// The player view.
#[derive(Debug)]
pub struct ReplayView {
    player: Player,
    label: String,
    last_tick: Option<Instant>,
}

impl ReplayView {
    /// A player for `recording`, labelled `label` (the host). Starts playing.
    pub fn new(recording: Recording, label: impl Into<String>) -> Self {
        let mut player = Player::new(recording);
        player.set_playing(true);
        Self {
            player,
            label: label.into(),
            last_tick: None,
        }
    }

    /// The engine.
    pub fn player(&self) -> &Player {
        &self.player
    }

    /// Player keys: `Space`, `+`/`-`, `←`/`→`, `q`/`Esc`.
    pub fn handle_key(&mut self, key: KeyEvent) -> ReplayOutcome {
        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return ReplayOutcome::Ignored;
        }
        match key.code {
            KeyCode::Char(' ') => {
                self.player.toggle_pause();
                // Paused time does not count.
                self.last_tick = None;
            }
            KeyCode::Char('+' | '=') => self.player.faster(),
            KeyCode::Char('-' | '_') => self.player.slower(),
            KeyCode::Right => self.player.seek_by(true),
            KeyCode::Left => self.player.seek_by(false),
            KeyCode::Char('q') | KeyCode::Esc => return ReplayOutcome::Close,
            _ => return ReplayOutcome::Ignored,
        }
        ReplayOutcome::Consumed
    }

    /// Advance to `now`. Returns whether anything visible changed.
    pub fn tick(&mut self, now: Instant) -> bool {
        let Some(last) = self.last_tick.replace(now) else {
            // Start of playback (or resume): apply what is due now.
            return self.player.advance(Duration::ZERO) || self.player.is_playing();
        };
        if !self.player.is_playing() {
            return false;
        }
        self.player.advance(now.saturating_duration_since(last));
        true
    }

    /// When to call [`ReplayView::tick`] next; `None` while paused or at the end.
    pub fn next_tick_in(&self) -> Option<Duration> {
        if !self.player.is_playing() {
            return None;
        }
        let next = self.player.until_next_event().unwrap_or(MAX_TICK);
        Some(next.clamp(Duration::from_millis(1), MAX_TICK))
    }

    /// Draw the player.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect, theme: &Theme, focused: bool) {
        let title = match self.player.title() {
            Some(t) if !t.is_empty() && t != self.label => {
                format!(" Replay · {} · {t} ", self.label)
            }
            _ => format!(" Replay · {} ", self.label),
        };
        let block = Block::bordered()
            .border_style(theme.border_for(focused))
            .title(Span::styled(title, theme.title_for(focused)));
        let inner = block.inner(area);
        frame.render_widget(block, area);
        if inner.is_empty() {
            return;
        }
        let footer = if self.player.incomplete() { 3 } else { 2 };
        let [screen, bottom] =
            Layout::vertical([Constraint::Min(0), Constraint::Length(footer)]).areas(inner);
        frame.render_widget(Clear, screen);
        if !screen.is_empty() {
            self.player
                .emulator()
                .render(screen, frame.buffer_mut(), &ViewState::default());
        }
        let mut lines = Vec::with_capacity(3);
        if self.player.incomplete() {
            lines.push(Line::from(Span::styled(INCOMPLETE, theme.warn)));
        }
        lines.push(self.progress_line(bottom.width, theme));
        lines.push(Line::from(Span::styled(
            "Space play/pause · +/- speed · ←/→ 5s · q close",
            theme.dim,
        )));
        frame.render_widget(Paragraph::new(lines).style(theme.base), bottom);
    }

    fn progress_line(&self, width: u16, theme: &Theme) -> Line<'static> {
        let icon = if self.player.is_playing() {
            "▶"
        } else {
            "⏸"
        };
        let speed = match self.player.speed() {
            Speed::X1 => "1×",
            Speed::X2 => "2×",
            Speed::X4 => "4×",
        };
        let times = format!(
            "{icon} {} / {} ",
            clock(self.player.elapsed()),
            clock(self.player.total())
        );
        let fixed = times.chars().count() + speed.len() + 1;
        let bar_len = usize::from(width).saturating_sub(fixed);
        let total = self.player.total().as_secs_f64();
        let ratio = if total > 0.0 {
            (self.player.elapsed().as_secs_f64() / total).clamp(0.0, 1.0)
        } else {
            1.0
        };
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let done = ((bar_len as f64) * ratio).round() as usize;
        Line::from(vec![
            Span::styled(times, theme.base),
            Span::styled("━".repeat(done), theme.accent),
            Span::styled("─".repeat(bar_len.saturating_sub(done)), theme.dim),
            Span::styled(format!(" {speed}"), theme.base),
        ])
    }
}

/// `mm:ss` (or `h:mm:ss`).
fn clock(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 3600 {
        format!("{}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
    } else {
        format!("{:02}:{:02}", s / 60, s % 60)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use pretty_assertions::assert_eq;
    use ratatui::{Terminal, backend::TestBackend};
    use sverb_term::recording::{Event, EventKind, Header};

    use super::*;

    fn rec(incomplete: bool) -> Recording {
        Recording {
            header: Header::new(30, 5),
            events: vec![
                Event::new(Duration::ZERO, EventKind::Output, "hello"),
                Event::new(Duration::from_secs(40), EventKind::Output, " world"),
            ],
            incomplete,
        }
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn draw(view: &ReplayView, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        let theme = Theme::default();
        terminal
            .draw(|f| view.render(f, f.area(), &theme, true))
            .unwrap();
        crate::testing::buffer_to_string(terminal.backend().buffer())
    }

    #[test]
    fn keys_drive_the_player() {
        let mut v = ReplayView::new(rec(false), "web-1");
        assert!(v.player().is_playing());
        assert_eq!(
            v.handle_key(key(KeyCode::Char(' '))),
            ReplayOutcome::Consumed
        );
        assert!(!v.player().is_playing());
        assert_eq!(
            v.handle_key(key(KeyCode::Char('+'))),
            ReplayOutcome::Consumed
        );
        assert_eq!(v.player().speed(), Speed::X2);
        v.handle_key(key(KeyCode::Char('+')));
        v.handle_key(key(KeyCode::Char('+')));
        assert_eq!(v.player().speed(), Speed::X4);
        v.handle_key(key(KeyCode::Char('-')));
        assert_eq!(v.player().speed(), Speed::X2);
        v.handle_key(key(KeyCode::Right));
        // The 40 s gap plays as 2 s: total 2 s, so +5 s clamps to the end.
        assert_eq!(v.player().elapsed(), Duration::from_secs(2));
        v.handle_key(key(KeyCode::Left));
        assert_eq!(v.player().elapsed(), Duration::ZERO);
        assert_eq!(
            v.handle_key(key(KeyCode::Char('x'))),
            ReplayOutcome::Ignored
        );
        assert_eq!(v.handle_key(key(KeyCode::Esc)), ReplayOutcome::Close);
        assert_eq!(v.handle_key(key(KeyCode::Char('q'))), ReplayOutcome::Close);
    }

    #[test]
    fn ticks_advance_only_while_playing() {
        let mut v = ReplayView::new(rec(false), "web-1");
        // A fixed origin from the harness (views never read the clock).
        let t0 = crate::testing::AppHarness::new(crate::app::Config::default()).now();
        v.tick(t0);
        assert!(draw(&v, 40, 10).contains("hello"));
        assert!(!draw(&v, 40, 10).contains("world"));
        v.tick(t0 + Duration::from_millis(2100));
        assert!(draw(&v, 40, 10).contains("hello world"));
        assert!(v.player().at_end());
        assert_eq!(v.next_tick_in(), None);
    }

    #[test]
    fn renders_progress_and_incomplete_notice_at_any_size() {
        let v = ReplayView::new(rec(true), "web-1");
        let screen = draw(&v, 50, 12);
        assert!(screen.contains("Replay · web-1"), "{screen}");
        assert!(screen.contains("00:00 / 00:02"), "{screen}");
        assert!(screen.contains(INCOMPLETE), "{screen}");
        assert!(screen.contains("1×"), "{screen}");
        for (w, h) in [(0, 0), (1, 1), (3, 2), (10, 3)] {
            let _ = draw(&v, w, h);
        }
        assert_eq!(clock(Duration::from_secs(3725)), "1:02:05");
    }
}
