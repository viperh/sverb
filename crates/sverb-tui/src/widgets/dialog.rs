//! M1-06: generic modal dialogs (SPEC §8.6): `Confirm`, `Prompt`, `Choice`,
//! `Progress` and `Info`. Specialized dialogs (host key M1-15, auth prompts, snippet
//! variables, agent confirm) build on [`Modal`].
//!
//! A [`Modal`] is pure state. [`Modal::handle_key`] returns `Some(answer)` once the
//! dialog is answered; [`Modal::tick`] advances virtual time (timeouts, the progress
//! spinner) and returns the timeout's answer when it runs out. The app keeps open
//! dialogs on its stack (`views::dialogs::DialogKind::Modal`, top dialog first,
//! modal: nothing behind it sees input); forms embed one for "Discard changes?".
//!
//! Layout: centered, at most 80% of the width, wrapped body text. Buttons are reached
//! by their mnemonic letter (shown bracketed and underlined: `[a]ccept`), by
//! `Tab`/`←/→` then `Enter`. `Esc` cancels. A `danger` dialog always starts on its
//! safe button, so `Enter` never confirms a destructive action by accident.
//! Focus is drawn with the selection style (reverse + bold without color).

use std::time::Duration;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    style::Modifier,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph},
};

use crate::{
    views::RenderCx,
    widgets::{
        form::{SecretInput, SecretValue, TextInput, select::popup_nav},
        truncate, width, wrap,
    },
};

/// Spinner frames for `Progress`.
const SPINNER: [&str; 4] = ["|", "/", "-", "\\"];

/// How a button behaves in a `danger` dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonRole {
    /// Neither safe nor destructive.
    Normal,
    /// Backs out (cancel, keep, reject): the default of a danger dialog.
    Safe,
    /// The destructive choice.
    Danger,
}

/// A dialog button.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Button {
    /// Answer id ([`ModalAnswer::Button`]).
    pub id: String,
    /// Shown text.
    pub label: String,
    /// The key that presses it (matched case-insensitively).
    pub mnemonic: Option<char>,
    /// Safe / danger.
    pub role: ButtonRole,
}

impl Button {
    /// A button answering `id`, shown as `label`, pressed by `mnemonic`.
    pub fn new(id: &str, label: &str, mnemonic: char) -> Self {
        Self {
            id: id.to_owned(),
            label: label.to_owned(),
            mnemonic: Some(mnemonic.to_ascii_lowercase()),
            role: ButtonRole::Normal,
        }
    }

    /// Mark as the safe choice.
    #[must_use]
    pub fn safe(mut self) -> Self {
        self.role = ButtonRole::Safe;
        self
    }

    /// Mark as the destructive choice.
    #[must_use]
    pub fn danger(mut self) -> Self {
        self.role = ButtonRole::Danger;
        self
    }

    /// The label with the mnemonic bracketed, as spans (letter underlined + bold).
    fn spans(&self, style: ratatui::style::Style) -> Vec<Span<'static>> {
        let mn = self.mnemonic;
        let pos = mn.and_then(|m| {
            self.label
                .char_indices()
                .find(|(_, c)| c.to_ascii_lowercase() == m)
                .map(|(i, c)| (i, c.len_utf8()))
        });
        let key_style = style.add_modifier(Modifier::UNDERLINED | Modifier::BOLD);
        match (pos, mn) {
            (Some((i, len)), _) => vec![
                Span::styled(self.label[..i].to_owned(), style),
                Span::styled("[", style),
                Span::styled(self.label[i..i + len].to_owned(), key_style),
                Span::styled("]", style),
                Span::styled(self.label[i + len..].to_owned(), style),
            ],
            (None, Some(m)) => vec![
                Span::styled(format!("{} ", self.label), style),
                Span::styled("[", style),
                Span::styled(m.to_string(), key_style),
                Span::styled("]", style),
            ],
            (None, None) => vec![Span::styled(self.label.clone(), style)],
        }
    }
}

/// How a modal was answered.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ModalAnswer {
    /// A button (by id).
    Button(String),
    /// A text prompt was submitted.
    Text(String),
    /// A secret prompt was submitted.
    Secret(SecretValue),
    /// A choice was made (index into the options).
    Choice(usize),
    /// `Esc` (or the cancel of a progress dialog).
    Cancelled,
    /// The timeout ran out ([`Modal::with_timeout`] may answer something else).
    TimedOut,
}

impl ModalAnswer {
    /// Whether this is button `id`.
    pub fn is_button(&self, id: &str) -> bool {
        matches!(self, Self::Button(b) if b == id)
    }

    /// A stable key for routing answers to effects (`button:<id>`, `choice:<n>`,
    /// `text`, `secret`, `cancelled`, `timed-out`).
    pub fn route_key(&self) -> String {
        match self {
            Self::Button(id) => format!("button:{id}"),
            Self::Text(_) => "text".to_owned(),
            Self::Secret(_) => "secret".to_owned(),
            Self::Choice(i) => format!("choice:{i}"),
            Self::Cancelled => "cancelled".to_owned(),
            Self::TimedOut => "timed-out".to_owned(),
        }
    }
}

/// The input of a prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptInput {
    /// Plain text.
    Text(TextInput),
    /// Masked (`ctrl-r` reveals).
    Secret(SecretInput),
}

/// What kind of modal.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ModalKind {
    /// Buttons.
    Confirm {
        /// The buttons, left to right.
        buttons: Vec<Button>,
        /// The focused button.
        focused: usize,
    },
    /// A text or secret input; `Enter` submits, `Esc` cancels.
    Prompt {
        /// Label before the input.
        label: String,
        /// The input.
        input: PromptInput,
    },
    /// A list; `↑/↓`, digits `1`–`9`, `Enter` choose, `Esc` cancels.
    Choice {
        /// The options.
        options: Vec<String>,
        /// Highlighted option.
        selected: usize,
    },
    /// A spinner; `Esc` (or `c`) cancels when cancellable.
    Progress {
        /// Spinner frame.
        frame: usize,
        /// Whether it can be cancelled.
        cancellable: bool,
    },
    /// A message; `Enter`/`Esc`/`o` dismiss (answers `Button("ok")`).
    Info,
}

/// A running timeout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timeout {
    /// Time left.
    pub remaining: Duration,
    /// What the dialog answers when it runs out.
    pub answer: ModalAnswer,
}

/// A modal dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Modal {
    /// Title.
    pub title: String,
    /// Body text (wrapped; `\n` separates paragraphs).
    pub body: String,
    /// What it is.
    pub kind: ModalKind,
    /// Destructive: the default button is the safe one.
    pub danger: bool,
    /// The countdown, if any.
    pub timeout: Option<Timeout>,
}

impl Modal {
    /// A confirmation. `default` is the initially focused button; in a `danger`
    /// dialog it is replaced by the first [`ButtonRole::Safe`] button (else the last
    /// non-danger one) if it points at a destructive button.
    pub fn confirm(
        title: &str,
        body: &str,
        buttons: Vec<Button>,
        default: usize,
        danger: bool,
    ) -> Self {
        let mut focused = default.min(buttons.len().saturating_sub(1));
        if danger
            && buttons
                .get(focused)
                .is_some_and(|b| b.role != ButtonRole::Safe)
        {
            focused = buttons
                .iter()
                .position(|b| b.role == ButtonRole::Safe)
                .or_else(|| buttons.iter().rposition(|b| b.role != ButtonRole::Danger))
                .unwrap_or(focused);
        }
        Self {
            title: title.to_owned(),
            body: body.to_owned(),
            kind: ModalKind::Confirm { buttons, focused },
            danger,
            timeout: None,
        }
    }

    /// A text prompt (or a masked one with `secret`).
    pub fn prompt(title: &str, body: &str, label: &str, secret: bool) -> Self {
        let input = if secret {
            PromptInput::Secret(SecretInput::default())
        } else {
            PromptInput::Text(TextInput::default())
        };
        Self {
            title: title.to_owned(),
            body: body.to_owned(),
            kind: ModalKind::Prompt {
                label: label.to_owned(),
                input,
            },
            danger: false,
            timeout: None,
        }
    }

    /// A list of choices.
    pub fn choice(title: &str, body: &str, options: Vec<String>) -> Self {
        Self {
            title: title.to_owned(),
            body: body.to_owned(),
            kind: ModalKind::Choice {
                options,
                selected: 0,
            },
            danger: false,
            timeout: None,
        }
    }

    /// A spinner with a message.
    pub fn progress(title: &str, body: &str, cancellable: bool) -> Self {
        Self {
            title: title.to_owned(),
            body: body.to_owned(),
            kind: ModalKind::Progress {
                frame: 0,
                cancellable,
            },
            danger: false,
            timeout: None,
        }
    }

    /// A message.
    pub fn info(title: &str, body: &str) -> Self {
        Self {
            title: title.to_owned(),
            body: body.to_owned(),
            kind: ModalKind::Info,
            danger: false,
            timeout: None,
        }
    }

    /// Answer `answer` after `after` (driven by [`Modal::tick`]); a countdown shows.
    #[must_use]
    pub fn with_timeout(mut self, after: Duration, answer: ModalAnswer) -> Self {
        self.timeout = Some(Timeout {
            remaining: after,
            answer,
        });
        self
    }

    /// Whether the dialog needs ticks (a timeout or a spinner).
    pub fn ticks(&self) -> bool {
        self.timeout.is_some() || matches!(self.kind, ModalKind::Progress { .. })
    }

    /// The dialog edits text (Insert mode, M0-10).
    pub fn wants_text(&self) -> bool {
        matches!(self.kind, ModalKind::Prompt { .. })
    }

    /// Time left before the timeout answer.
    pub fn remaining(&self) -> Option<Duration> {
        self.timeout.as_ref().map(|t| t.remaining)
    }

    /// The focused button's id (confirm dialogs).
    pub fn focused_button(&self) -> Option<&str> {
        match &self.kind {
            ModalKind::Confirm { buttons, focused } => buttons.get(*focused).map(|b| b.id.as_str()),
            _ => None,
        }
    }

    /// Advance virtual time by `elapsed`. Returns the timeout answer when it runs out.
    pub fn tick(&mut self, elapsed: Duration) -> Option<ModalAnswer> {
        if let ModalKind::Progress { frame, .. } = &mut self.kind {
            *frame = (*frame + 1) % SPINNER.len();
        }
        let t = self.timeout.as_mut()?;
        t.remaining = t.remaining.saturating_sub(elapsed);
        (t.remaining.is_zero()).then(|| t.answer.clone())
    }

    /// Insert a paste into a prompt.
    pub fn paste(&mut self, text: &str) {
        if let ModalKind::Prompt { input, .. } = &mut self.kind {
            match input {
                PromptInput::Text(t) => {
                    t.insert_str(text);
                }
                PromptInput::Secret(s) => {
                    s.insert_str(text);
                }
            }
        }
    }

    /// Apply one key. `Some(answer)`: the dialog is answered and should close.
    pub fn handle_key(&mut self, key: &KeyEvent) -> Option<ModalAnswer> {
        let plain = !key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT);
        match &mut self.kind {
            ModalKind::Confirm { buttons, focused } => {
                let n = buttons.len().max(1);
                match key.code {
                    KeyCode::Esc => return Some(ModalAnswer::Cancelled),
                    KeyCode::Enter => {
                        return buttons
                            .get(*focused)
                            .map(|b| ModalAnswer::Button(b.id.clone()));
                    }
                    KeyCode::Tab | KeyCode::Right => *focused = (*focused + 1) % n,
                    KeyCode::BackTab | KeyCode::Left => *focused = (*focused + n - 1) % n,
                    KeyCode::Char(c) if plain => {
                        let c = c.to_ascii_lowercase();
                        if let Some(b) = buttons.iter().find(|b| b.mnemonic == Some(c)) {
                            return Some(ModalAnswer::Button(b.id.clone()));
                        }
                    }
                    _ => {}
                }
                None
            }
            ModalKind::Prompt { input, .. } => match key.code {
                KeyCode::Esc => Some(ModalAnswer::Cancelled),
                KeyCode::Enter => Some(match input {
                    PromptInput::Text(t) => ModalAnswer::Text(t.text().to_owned()),
                    PromptInput::Secret(s) => ModalAnswer::Secret(s.value().clone()),
                }),
                _ => {
                    match input {
                        PromptInput::Text(t) => {
                            t.handle_key(key);
                        }
                        PromptInput::Secret(s) => {
                            s.handle_key(key);
                        }
                    }
                    None
                }
            },
            ModalKind::Choice { options, selected } => {
                if let Some(to) = popup_nav(key, *selected, options.len()) {
                    *selected = to;
                    return None;
                }
                match key.code {
                    KeyCode::Char('j') if plain => {
                        *selected = (*selected + 1).min(options.len().saturating_sub(1));
                    }
                    KeyCode::Char('k') if plain => *selected = selected.saturating_sub(1),
                    KeyCode::Enter if !options.is_empty() => {
                        return Some(ModalAnswer::Choice(*selected));
                    }
                    KeyCode::Char(c @ '1'..='9') if plain => {
                        let i = usize::from(c as u8 - b'1');
                        if i < options.len() {
                            return Some(ModalAnswer::Choice(i));
                        }
                    }
                    KeyCode::Esc => return Some(ModalAnswer::Cancelled),
                    _ => {}
                }
                None
            }
            ModalKind::Progress { cancellable, .. } => match key.code {
                KeyCode::Esc if *cancellable => Some(ModalAnswer::Cancelled),
                KeyCode::Char('c') if *cancellable && plain => Some(ModalAnswer::Cancelled),
                _ => None,
            },
            ModalKind::Info => match key.code {
                KeyCode::Enter | KeyCode::Esc | KeyCode::Char('o' | 'q') => {
                    Some(ModalAnswer::Button("ok".to_owned()))
                }
                _ => None,
            },
        }
    }

    fn countdown(&self) -> Option<String> {
        let t = self.timeout.as_ref()?;
        let secs = t.remaining.as_secs() + u64::from(t.remaining.subsec_nanos() > 0);
        Some(format!("{secs} s left"))
    }

    /// Draw the dialog centered in `area`.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect, cx: &RenderCx<'_>) {
        let theme = cx.theme;
        let max_w = (usize::from(area.width) * 4 / 5).max(10);
        // Content width before wrapping: the longest paragraph, the buttons, the title.
        let buttons_w = match &self.kind {
            ModalKind::Confirm { buttons, .. } => {
                buttons.iter().map(|b| width(&b.label) + 5).sum::<usize>()
            }
            ModalKind::Choice { options, .. } => {
                options.iter().map(|o| width(o) + 6).max().unwrap_or(0)
            }
            ModalKind::Prompt { label, .. } => (width(label) + 24).max(38),
            _ => 0,
        };
        let body_w = self.body.lines().map(width).max().unwrap_or(0);
        let inner_w = body_w
            .max(buttons_w)
            .max(width(&self.title) + 2)
            .max(24)
            .min(max_w.saturating_sub(4));
        let mut lines: Vec<Line<'static>> = Vec::new();
        for para in self.body.split('\n').filter(|_| !self.body.is_empty()) {
            if para.trim().is_empty() {
                lines.push(Line::raw(""));
                continue;
            }
            for l in wrap(para, inner_w, 20) {
                lines.push(Line::styled(l, theme.base));
            }
        }
        match &self.kind {
            ModalKind::Confirm { buttons, focused } => {
                lines.push(Line::raw(""));
                let mut spans = Vec::new();
                for (i, b) in buttons.iter().enumerate() {
                    if i > 0 {
                        spans.push(Span::raw("  "));
                    }
                    let style = if i == *focused {
                        theme.selection
                    } else if b.role == ButtonRole::Danger {
                        theme.error
                    } else {
                        theme.base
                    };
                    spans.push(Span::styled(" ", style));
                    spans.extend(b.spans(style));
                    spans.push(Span::styled(" ", style));
                }
                lines.push(Line::from(spans).centered());
            }
            ModalKind::Prompt { label, input } => {
                if !lines.is_empty() {
                    lines.push(Line::raw(""));
                }
                let label = format!("{label} ");
                let w = inner_w.saturating_sub(width(&label)).max(1);
                let mut spans = vec![Span::styled(label, theme.accent)];
                let field = match input {
                    PromptInput::Text(t) => t.line(w, theme.base, cx.focused),
                    PromptInput::Secret(s) => s.line(w, theme.base, cx.focused),
                };
                spans.extend(field.spans);
                lines.push(Line::from(spans));
                lines.push(Line::raw(""));
                let hint = match input {
                    PromptInput::Secret(_) => "enter ok · esc cancel · ctrl-r reveal",
                    PromptInput::Text(_) => "enter ok · esc cancel",
                };
                lines.push(Line::styled(hint, theme.dim));
            }
            ModalKind::Choice { options, selected } => {
                lines.push(Line::raw(""));
                for (i, o) in options.iter().enumerate() {
                    let sel = i == *selected;
                    let style = if sel { theme.selection } else { theme.base };
                    let n = if i < 9 {
                        format!("{}", i + 1)
                    } else {
                        " ".to_owned()
                    };
                    let text = format!("{} {n}. {}", if sel { "›" } else { " " }, o);
                    let text = truncate(&text, inner_w);
                    let pad = inner_w.saturating_sub(width(&text));
                    lines.push(Line::styled(
                        format!(
                            "{text}{}",
                            if sel { " ".repeat(pad) } else { String::new() }
                        ),
                        style,
                    ));
                }
            }
            ModalKind::Progress { frame, cancellable } => {
                lines.push(Line::raw(""));
                let mut spans = vec![Span::styled(
                    format!("{} working…", SPINNER[*frame % SPINNER.len()]),
                    theme.accent,
                )];
                if *cancellable {
                    spans.push(Span::styled("   esc cancel", theme.dim));
                }
                lines.push(Line::from(spans));
            }
            ModalKind::Info => {
                lines.push(Line::raw(""));
                lines.push(
                    Line::from(vec![
                        Span::styled(" ", theme.selection),
                        Span::styled("[", theme.selection),
                        Span::styled(
                            "O",
                            theme
                                .selection
                                .add_modifier(Modifier::UNDERLINED | Modifier::BOLD),
                        ),
                        Span::styled("]K ", theme.selection),
                    ])
                    .centered(),
                );
            }
        }
        if let Some(cd) = self.countdown() {
            lines.push(Line::raw(""));
            lines.push(Line::styled(cd, theme.warn).right_aligned());
        }
        let max_h = usize::from(area.height);
        let h = (lines.len() + 2).min(max_h);
        let rect = crate::views::dialogs::centered(area, inner_w + 4, h);
        if rect.width < 3 || rect.height < 3 {
            return;
        }
        frame.render_widget(Clear, rect);
        let title = if self.danger {
            format!(" ! {} ", self.title)
        } else {
            format!(" {} ", self.title)
        };
        let title_style = if self.danger {
            theme.error
        } else {
            theme.title_for(true)
        };
        let block = Block::bordered()
            .title(Span::styled(title, title_style))
            .border_style(if self.danger {
                theme.error
            } else {
                theme.border_focused
            });
        let inner = block.inner(rect);
        frame.render_widget(block.style(theme.base), rect);
        let inner = Rect {
            x: inner.x + 1,
            width: inner.width.saturating_sub(2),
            ..inner
        };
        frame.render_widget(Paragraph::new(lines), inner);
    }
}
