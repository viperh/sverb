//! Helpers for driving and drawing a single view in tests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{Terminal, backend::TestBackend, buffer::Buffer};

use crate::{
    app::{Config, Effect, Mode, state::IdGen},
    keymap::chord::KeyChord,
    testing::buffer_to_string,
    theme::{Theme, ThemeEnv},
    views::{Outcome, RenderCx, View, ViewCx, ViewEvent},
};

/// Feed `ev` to `view` with a throwaway context; returns the outcome and effects.
pub(crate) fn send(view: &mut dyn View, ev: &ViewEvent) -> (Outcome, Vec<Effect>) {
    let config = Config::default();
    let mut effects = Vec::new();
    let mut pending = BTreeMap::new();
    let mut ids = IdGen::default();
    let mut cx = ViewCx::new(&config, &mut effects, &mut pending, &mut ids);
    let outcome = view.handle(ev, &mut cx);
    (outcome, effects)
}

/// Press each whitespace-separated chord (`"j j ctrl-d"`).
pub(crate) fn keys(view: &mut dyn View, chords: &str) {
    for chord in KeyChord::parse_sequence(chords).unwrap() {
        send(view, &ViewEvent::Key(chord.to_key_event()));
    }
}

/// Press one raw key.
pub(crate) fn key(view: &mut dyn View, code: KeyCode, mods: KeyModifiers) -> Outcome {
    send(view, &ViewEvent::Key(KeyEvent::new(code, mods))).0
}

/// Type text, one char per key.
pub(crate) fn type_text(view: &mut dyn View, text: &str) {
    for c in text.chars() {
        key(view, KeyCode::Char(c), KeyModifiers::NONE);
    }
}

/// A theme: default dark, or monochrome (`NO_COLOR`).
pub(crate) fn theme(no_color: bool) -> Theme {
    Theme::resolve(
        "default-dark",
        sverb_core::config::TruecolorMode::On,
        ThemeEnv {
            no_color,
            colorterm_truecolor: true,
        },
    )
}

/// Draw `view` (focused) into a `w`×`h` buffer.
pub(crate) fn draw(view: &dyn View, w: u16, h: u16, no_color: bool) -> Buffer {
    draw_with(w, h, no_color, |frame, cx| {
        view.render(frame, frame.area(), cx);
    })
}

/// Draw with a custom closure.
pub(crate) fn draw_with(
    w: u16,
    h: u16,
    no_color: bool,
    f: impl FnOnce(&mut ratatui::Frame<'_>, &RenderCx<'_>),
) -> Buffer {
    let config = Config::default();
    let theme = theme(no_color);
    let cx = RenderCx {
        config: &config,
        mode: Mode::Normal,
        focused: true,
        theme: &theme,
        debug: false,
    };
    let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
    terminal.draw(|frame| f(frame, &cx)).unwrap();
    terminal.backend().buffer().clone()
}

/// The buffer as text.
pub(crate) fn text(buf: &Buffer) -> String {
    buffer_to_string(buf)
}

/// Every cell is free of color (`NO_COLOR`).
pub(crate) fn assert_no_color(buf: &Buffer) {
    use ratatui::style::Color;
    for cell in buf.content() {
        assert!(
            matches!(cell.fg, Color::Reset) && matches!(cell.bg, Color::Reset),
            "colored cell {:?}",
            cell
        );
    }
}
