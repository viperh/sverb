//! The account wizard (Settings → Sync → "Log in to a server" / "Create an
//!
//! The flows themselves (OPAQUE, key generation, the random recovery-word check,
//! the import preview) run in the sync service, which owns their secrets and state;
//! after every input it sends the next [`WizardScreen`]. This dialog only shows the
//! screen and collects one field at a time:
//!
//! * typing edits the field (masked for passwords), `Enter` submits it;
//! * without a field, the screen's choice keys answer (`Enter` = the first choice);
//! * `Esc` cancels the flow (nothing is kept); on the last screen it closes.

use std::fmt;

use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    style::Modifier,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph, Wrap},
};
use zeroize::Zeroizing;

use crate::{
    app::{
        VaultPassword,
        sync_ui::{WizardCmd, WizardFlow, WizardScreen},
    },
    views::{Outcome, RenderCx, ViewCx, ViewEvent},
};

/// What the dialog asks the reducer to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WizardAnswer {
    /// Send this to the service.
    Cmd(WizardCmd),
    /// The dialog closed.
    Closed {
        /// The flow finished (start syncing).
        done: bool,
        /// The vault must be unlocked again.
        relock: bool,
    },
}

/// The dialog.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountWizardDialog {
    /// Which flow.
    pub flow: WizardFlow,
    /// The current screen.
    pub screen: WizardScreen,
    input: Zeroizing<String>,
    answer: Option<WizardAnswer>,
}

impl fmt::Debug for AccountWizardDialog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountWizardDialog")
            .field("flow", &self.flow)
            .field("screen", &self.screen)
            .finish_non_exhaustive()
    }
}

impl AccountWizardDialog {
    /// A dialog waiting for the service's first screen.
    pub fn new(flow: WizardFlow) -> Self {
        let title = match flow {
            WizardFlow::Login => "Log in to a server",
            WizardFlow::Register => "Create an account",
        };
        Self {
            flow,
            screen: WizardScreen {
                title: title.to_owned(),
                busy: true,
                ..WizardScreen::default()
            },
            input: Zeroizing::default(),
            answer: None,
        }
    }

    /// A new screen from the service.
    pub fn set_screen(&mut self, screen: WizardScreen) {
        if screen.prompt != self.screen.prompt {
            self.input = Zeroizing::default();
        }
        self.screen = screen;
    }

    /// The text typed so far (tests).
    pub fn input(&self) -> &str {
        &self.input
    }

    /// Takes the pending answer.
    pub fn take_answer(&mut self) -> Option<WizardAnswer> {
        self.answer.take()
    }

    /// Handle input.
    pub fn handle(&mut self, ev: &ViewEvent, cx: &mut ViewCx<'_>) -> Outcome {
        match ev {
            ViewEvent::Paste(text) if self.screen.prompt.is_some() => {
                self.input.push_str(text.trim_end_matches(['\r', '\n']));
            }
            ViewEvent::Key(key) => {
                if key.modifiers.contains(KeyModifiers::CONTROL) {
                    return Outcome::Consumed;
                }
                // The reducer pops the dialog on `Closed` (`App::take_wizard_answer`).
                self.key(key.code);
            }
            _ => return Outcome::Consumed,
        }
        cx.request_redraw();
        Outcome::Consumed
    }

    fn key(&mut self, code: KeyCode) {
        let s = &self.screen;
        if s.done {
            if matches!(code, KeyCode::Enter | KeyCode::Esc) {
                self.answer = Some(WizardAnswer::Closed {
                    done: true,
                    relock: s.relock,
                });
            }
            return;
        }
        if code == KeyCode::Esc {
            self.answer = Some(WizardAnswer::Closed {
                done: false,
                relock: false,
            });
            return;
        }
        if s.busy {
            return;
        }
        if s.prompt.is_some() {
            match code {
                KeyCode::Enter => {
                    let text = std::mem::take(&mut self.input);
                    self.answer = Some(WizardAnswer::Cmd(WizardCmd::Submit(VaultPassword::new(
                        text,
                    ))));
                }
                KeyCode::Backspace => {
                    self.input.pop();
                }
                KeyCode::Char(c) => self.input.push(c),
                _ => {}
            }
            return;
        }
        let pick = match code {
            KeyCode::Enter => s.choices.first().map(|(c, _)| *c),
            KeyCode::Char(c) => s.choices.iter().find(|(k, _)| *k == c).map(|(k, _)| *k),
            _ => None,
        };
        if let Some(c) = pick {
            self.answer = Some(WizardAnswer::Cmd(WizardCmd::Choice(c)));
        }
    }

    /// Draw centered in `area`.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let theme = cx.theme;
        let s = &self.screen;
        let mut lines: Vec<Line<'static>> = s.body.iter().map(|l| Line::raw(l.clone())).collect();
        if let Some(e) = &s.error {
            if !lines.is_empty() {
                lines.push(Line::raw(""));
            }
            lines.push(Line::styled(e.clone(), theme.error));
        }
        if let Some(p) = &s.prompt {
            if !lines.is_empty() {
                lines.push(Line::raw(""));
            }
            let shown = if p.secret {
                "•".repeat(self.input.chars().count())
            } else {
                self.input.to_string()
            };
            lines.push(Line::from(vec![
                Span::styled(format!("{}: ", p.label), theme.dim),
                Span::styled(shown, theme.base),
                Span::styled("▏", theme.accent),
            ]));
        }
        if s.busy {
            lines.push(Line::raw(""));
            lines.push(Line::styled("Working…", theme.dim));
        }
        lines.push(Line::raw(""));
        let mut keys = Vec::new();
        if s.done {
            keys.push(Span::styled("[Enter]", theme.accent));
            keys.push(Span::raw(" Close"));
        } else {
            if s.prompt.is_some() {
                keys.push(Span::styled("[Enter]", theme.accent));
                keys.push(Span::raw(" Next   "));
            }
            for (c, label) in &s.choices {
                keys.push(Span::styled(format!("[{c}]"), theme.accent));
                keys.push(Span::raw(format!(" {label}   ")));
            }
            keys.push(Span::styled("[Esc]", theme.accent));
            keys.push(Span::raw(" Cancel"));
        }
        lines.push(Line::from(keys));

        let w = area.width.min(76);
        let inner_w = usize::from(w.saturating_sub(2)).max(1);
        let needed: usize = lines
            .iter()
            .map(|l| l.width().max(1).div_ceil(inner_w))
            .sum();
        let h = u16::try_from(needed + 2)
            .unwrap_or(u16::MAX)
            .min(area.height);
        let rect = Rect {
            x: area.x + (area.width - w) / 2,
            y: area.y + (area.height - h) / 2,
            width: w,
            height: h,
        };
        let block = Block::bordered()
            .title(Span::styled(
                format!(" {} ", s.title),
                theme.title_for(true).add_modifier(Modifier::BOLD),
            ))
            .border_style(theme.border_for(true));
        frame.render_widget(Clear, rect);
        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .block(block),
            rect,
        );
    }
}
