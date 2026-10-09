//! Test harness for driving [`App`] without a terminal or runtime
//! (compiled for this crate's tests and with feature `test-util`).
//!
//! ```ignore
//! let mut h = AppHarness::new(Config::default());
//! h.keys("j j q");
//! assert_eq!(h.effects(), &[Effect::Quit { code: 0 }]);
//! insta::assert_snapshot!(h.render(80, 24));
//! ```

use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::{Duration, Instant},
};

use ratatui::{Terminal, backend::TestBackend, buffer::Buffer};

use sverb_core::logging::LogRing;

use crate::{
    app::{App, Config, Effect, InputEvent, SessionId, TimerFired, TimerKind, ToastLevel, UiEvent},
    keymap::chord::KeyChord,
    theme::ThemeEnv,
};

/// Drives an [`App`] with scripted events on a virtual clock.
#[derive(Debug)]
pub struct AppHarness {
    app: App,
    origin: Instant,
    now: Duration,
    effects: Vec<Effect>,
    timers: BTreeMap<TimerKind, Duration>,
}

impl AppHarness {
    /// A fresh app with a fixed `Instant` origin for the virtual clock.
    pub fn new(config: Config) -> Self {
        Self {
            app: App::new(Arc::new(config)),
            origin: Instant::now(),
            now: Duration::ZERO,
            effects: Vec::new(),
            timers: BTreeMap::new(),
        }
    }

    /// The app under test.
    pub fn app(&self) -> &App {
        &self.app
    }

    /// Mark sessions as open (stand-in until M1-08 delivers session events).
    pub fn with_sessions(mut self, n: u64) -> Self {
        self.app.tabs.sessions.extend((0..n).map(SessionId));
        self
    }

    // M0-10
    /// Focus a live session pane (Terminal mode). Stand-in until M1-08/M1-17.
    pub fn with_live_session(mut self) -> Self {
        self.app.focus_session(SessionId(1));
        self
    }

    /// Mutable access for test setup (dialogs, focus).
    pub fn app_mut(&mut self) -> &mut App {
        &mut self.app
    }

    /// The virtual "now".
    pub fn now(&self) -> Instant {
        self.origin + self.now
    }

    /// Deliver one event and record the effects it returns.
    pub fn send(&mut self, ev: UiEvent) -> &mut Self {
        let effects = self.app.handle(ev);
        self.record(effects);
        self
    }

    // M0-11
    /// Show a toast the way the reducer does, recording its timers.
    pub fn toast(&mut self, level: ToastLevel, message: &str) -> &mut Self {
        let mut effects = Vec::new();
        self.app.push_toast(level, message.to_owned(), &mut effects);
        self.record(effects);
        self
    }

    // M1-06
    /// Open a generic modal the way the reducer does, recording its tick timer.
    pub fn modal(&mut self, dialog: crate::views::dialogs::ModalDialog) -> crate::views::DialogId {
        let mut effects = Vec::new();
        let id = self.app.push_modal(dialog, &mut effects);
        self.record(effects);
        id
    }

    // M0-11
    /// Use this terminal environment for the theme (`NO_COLOR`, `COLORTERM`).
    #[must_use]
    pub fn with_theme_env(mut self, env: ThemeEnv) -> Self {
        self.app = self.app.with_theme_env(env);
        self
    }

    // M0-11
    /// Turn on `--debug` with this log ring.
    #[must_use]
    pub fn with_debug_ring(mut self, ring: LogRing) -> Self {
        self.app = self.app.with_debug_ring(Some(ring));
        self
    }

    // M0-11
    /// Deliver a terminal resize (the shell's responsive rules use the last size).
    pub fn resize(&mut self, cols: u16, rows: u16) -> &mut Self {
        self.send(UiEvent::Input(InputEvent::Resize { cols, rows }))
    }

    // M0-11
    /// Draw into a `TestBackend` and return the buffer (symbols and styles).
    pub fn render_buffer(&self, w: u16, h: u16) -> Buffer {
        let Ok(mut terminal) = Terminal::new(TestBackend::new(w, h));
        let Ok(_) = terminal.draw(|f| self.app.render(f));
        terminal.backend().buffer().clone()
    }

    fn record(&mut self, effects: Vec<Effect>) {
        for effect in &effects {
            match effect {
                Effect::ScheduleTimer { kind, after } => {
                    self.timers.insert(*kind, self.now + *after);
                }
                Effect::CancelTimer(kind) => {
                    self.timers.remove(kind);
                }
                _ => {}
            }
        }
        self.effects.extend(effects);
    }

    /// Press each whitespace-separated chord, e.g. `"ctrl-g q"`.
    ///
    /// # Panics
    /// On an unparsable chord (this is a test helper).
    pub fn keys(&mut self, chords: &str) -> &mut Self {
        let seq = match KeyChord::parse_sequence(chords) {
            Ok(seq) => seq,
            Err(err) => panic!("AppHarness::keys: {err}"),
        };
        for chord in seq {
            self.send(UiEvent::Input(InputEvent::Key(chord.to_key_event())));
        }
        self
    }

    /// All effects returned so far.
    pub fn effects(&self) -> &[Effect] {
        &self.effects
    }

    /// Return and clear the accumulated effects.
    pub fn take_effects(&mut self) -> Vec<Effect> {
        std::mem::take(&mut self.effects)
    }

    /// Advance the virtual clock, delivering due timers in order.
    pub fn advance(&mut self, ms: u64) -> &mut Self {
        let target = self.now + Duration::from_millis(ms);
        loop {
            let next = self
                .timers
                .iter()
                .filter(|(_, due)| **due <= target)
                .min_by_key(|(kind, due)| (**due, **kind))
                .map(|(kind, due)| (*kind, *due));
            let Some((kind, due)) = next else { break };
            self.timers.remove(&kind);
            self.now = due;
            let at = self.origin + due;
            self.send(UiEvent::Timer(TimerFired { kind, at }));
        }
        self.now = target;
        self
    }

    /// Draw into a `TestBackend` of `w`×`h` cells and return the screen as text.
    pub fn render(&self, w: u16, h: u16) -> String {
        render_app(&self.app, w, h)
    }
}

/// Draw `app` into a `w`×`h` `TestBackend` and return the buffer as text.
pub fn render_app(app: &App, w: u16, h: u16) -> String {
    let Ok(mut terminal) = Terminal::new(TestBackend::new(w, h));
    let Ok(_) = terminal.draw(|f| app.render(f));
    buffer_to_string(terminal.backend().buffer())
}

/// One line per buffer row, trailing spaces kept so the size is visible in snapshots.
pub fn buffer_to_string(buf: &Buffer) -> String {
    let area = buf.area;
    let mut out = String::new();
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            out.push_str(buf[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

/// Canned terminal grids for rendering session panes without real sessions (from M1-10).
#[derive(Debug, Default, Clone)]
pub struct FakeSessionRegistry {
    grids: HashMap<SessionId, Vec<String>>,
}

impl FakeSessionRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register the grid (one string per row) shown for `id`.
    pub fn insert(&mut self, id: SessionId, rows: impl IntoIterator<Item = impl Into<String>>) {
        self.grids
            .insert(id, rows.into_iter().map(Into::into).collect());
    }

    /// The grid for `id`, if any.
    pub fn grid(&self, id: SessionId) -> Option<&[String]> {
        self.grids.get(&id).map(Vec::as_slice)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use pretty_assertions::assert_eq;
    use proptest::prelude::*;
    use sverb_core::error_report::ErrorReport;

    use super::*;
    use crate::{
        app::{EffectId, EffectOutput, PendingKind, ToastLevel, VaultEffect, hosts::ItemEffect},
        views::{DialogKind, hosts::form::HostFormDialog},
        widgets::form::FieldValue,
    };

    fn confirm(on: bool) -> Config {
        let mut c = Config::default();
        c.general.confirm_quit = on;
        c
    }

    fn key(code: KeyCode) -> UiEvent {
        UiEvent::Input(InputEvent::Key(KeyEvent::new(code, KeyModifiers::NONE)))
    }

    // ---- T-01 Determinism -------------------------------------------------------------

    fn alphabet(i: u8, origin: Instant) -> UiEvent {
        match i {
            0 => key(KeyCode::Char('q')),
            1 => key(KeyCode::Char('y')),
            2 => key(KeyCode::Char('n')),
            3 => key(KeyCode::Esc),
            4 => key(KeyCode::Char('j')),
            5 => key(KeyCode::Char('k')),
            6 => key(KeyCode::Char('?')),
            7 => key(KeyCode::Enter),
            8 => key(KeyCode::Char('x')),
            9 => key(KeyCode::Backspace),
            10 => UiEvent::Input(InputEvent::Key(KeyEvent::new(
                KeyCode::Char('z'),
                KeyModifiers::CONTROL,
            ))),
            11 => UiEvent::Input(InputEvent::Paste("pasted".into())),
            12 => UiEvent::Input(InputEvent::Resize { cols: 80, rows: 24 }),
            13 => UiEvent::Input(InputEvent::FocusLost),
            14 => UiEvent::Input(InputEvent::FocusGained),
            15..=17 => UiEvent::Timer(TimerFired {
                kind: TimerKind::ToastExpiry(crate::app::ToastId(u64::from(i - 15))),
                at: origin + Duration::from_millis(u64::from(i)),
            }),
            18..=21 => UiEvent::EffectDone {
                id: EffectId(u64::from(i - 18)),
                result: Ok(EffectOutput::Done),
            },
            _ => UiEvent::EffectDone {
                id: EffectId(u64::from(i % 4)),
                result: Err(ErrorReport::msg("disk full")),
            },
        }
    }

    fn scripted_app() -> App {
        let mut app = App::new(Arc::new(confirm(true)));
        app.tabs.sessions.push(SessionId(1));
        app.push_dialog(DialogKind::HostForm(HostFormDialog::blank()));
        app
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn t01_reducer_is_deterministic(script in proptest::collection::vec(0u8..24, 200)) {
            let origin = Instant::now();
            let mut a = scripted_app();
            let mut b = a.clone();
            for &i in &script {
                let ea = a.handle(alphabet(i, origin));
                let eb = b.handle(alphabet(i, origin));
                prop_assert_eq!(&ea, &eb);
                // T-11: one input never fans out unboundedly.
                prop_assert!(ea.len() < 64, "{} effects for one event", ea.len());
            }
            prop_assert_eq!(&a, &b);
            prop_assert_eq!(format!("{a:?}"), format!("{b:?}"));
        }
    }

    // ---- T-02 No I/O in the reducer ---------------------------------------------------

    #[test]
    fn t02_reducer_modules_import_no_io() {
        // Built from pieces so this file doesn't trip the scan if it is ever included.
        let forbidden = [
            ["tok", "io"].concat(),
            ["std::", "fs"].concat(),
            ["std::", "net"].concat(),
            ["System", "Time"].concat(),
            ["Instant::", "now"].concat(),
            ["ra", "nd"].concat() + "::",
        ];
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut checked = 0;
        for dir in ["app", "views", "keymap"] {
            let mut stack = vec![root.join(dir)];
            while let Some(path) = stack.pop() {
                let Ok(entries) = std::fs::read_dir(&path) else {
                    panic!("cannot read {}", path.display());
                };
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_dir() {
                        stack.push(p);
                        continue;
                    }
                    let Ok(src) = std::fs::read_to_string(&p) else {
                        panic!("cannot read {}", p.display());
                    };
                    checked += 1;
                    for (n, line) in src.lines().enumerate() {
                        let code = line.trim_start();
                        if code.starts_with("//") {
                            continue;
                        }
                        for f in &forbidden {
                            assert!(
                                !code.contains(f.as_str()),
                                "{}:{}: reducer code must not use `{f}`: {line}",
                                p.display(),
                                n + 1
                            );
                        }
                    }
                }
            }
        }
        assert!(checked >= 5, "scanned only {checked} files");
    }

    // ---- T-03 / T-04 / T-05 Quit ------------------------------------------------------

    #[test]
    fn t03_quit_without_sessions() {
        let mut h = AppHarness::new(confirm(true));
        h.keys("q");
        assert_eq!(h.effects(), &[Effect::Quit { code: 0 }]);
    }

    #[test]
    fn t04_quit_with_sessions_asks_first() {
        let mut h = AppHarness::new(confirm(true)).with_sessions(1);
        h.keys("q");
        assert_eq!(h.effects(), &[]);
        assert_eq!(h.app().dialogs().len(), 1);
        assert_eq!(h.app().dialogs()[0].kind, DialogKind::ConfirmQuit);

        h.keys("y");
        assert_eq!(h.take_effects(), vec![Effect::Quit { code: 0 }]);
        assert!(h.app().dialogs().is_empty());

        for cancel in ["n", "esc"] {
            h.keys("q");
            assert_eq!(h.app().dialogs().len(), 1);
            h.keys(cancel);
            assert!(h.app().dialogs().is_empty(), "{cancel} pops the dialog");
            assert_eq!(h.take_effects(), vec![], "{cancel} yields no effects");
        }
    }

    #[test]
    fn t05_quit_without_confirmation() {
        let mut h = AppHarness::new(confirm(false)).with_sessions(3);
        h.keys("q");
        assert_eq!(h.effects(), &[Effect::Quit { code: 0 }]);
        assert!(h.app().dialogs().is_empty());
    }

    // ---- T-06 Effect correlation ------------------------------------------------------

    fn open_form_and_save(h: &mut AppHarness) -> EffectId {
        let dialog = h
            .app
            .push_dialog(DialogKind::HostForm(HostFormDialog::blank()));
        h.keys("tab w e b ctrl-s");
        let effects = h.take_effects();
        let [
            Effect::Vault(VaultEffect::Items(ItemEffect::Save {
                id, item, changes, ..
            })),
        ] = effects.as_slice()
        else {
            panic!("expected one Save, got {effects:?}");
        };
        assert_eq!(*item, None);
        assert_eq!(
            changes.get("address"),
            Some(&FieldValue::Text("web".into()))
        );
        assert_eq!(
            h.app.pending.get(id),
            Some(&PendingKind::SaveItem { dialog })
        );
        *id
    }

    #[test]
    fn t06_effect_results_are_correlated() {
        let mut h = AppHarness::new(Config::default());
        let id = open_form_and_save(&mut h);

        // An unknown id changes nothing.
        let before = h.app().clone();
        h.send(UiEvent::EffectDone {
            id: EffectId(id.0 + 100),
            result: Err(ErrorReport::msg("nope")),
        });
        assert_eq!(h.app(), &before);
        assert_eq!(h.take_effects(), vec![]);

        // Err: an error toast with ErrorReport.short; the form stays open.
        let report = ErrorReport {
            short: "database is locked".into(),
            chain: vec!["sqlite busy".into()],
        };
        h.send(UiEvent::EffectDone {
            id,
            result: Err(report),
        });
        let toast = &h.app().toasts()[0];
        assert_eq!(toast.level, ToastLevel::Error);
        assert!(toast.message.contains("database is locked"));
        assert_eq!(h.app().dialogs().len(), 1);
        assert_eq!(h.app().pending_effects(), 0);

        // A late duplicate for the same id is ignored.
        let before = h.app().clone();
        h.send(UiEvent::EffectDone {
            id,
            result: Ok(EffectOutput::Done),
        });
        assert_eq!(h.app(), &before);

        // Retry, then Ok closes the originating form.
        h.take_effects();
        h.keys("ctrl-s");
        let [Effect::Vault(VaultEffect::Items(ItemEffect::Save { id: retry, .. }))] =
            h.take_effects()[..]
        else {
            panic!("expected a retry Save");
        };
        assert_ne!(retry, id, "ids are monotonic");
        h.send(UiEvent::EffectDone {
            id: retry,
            result: Ok(EffectOutput::Done),
        });
        assert!(h.app().dialogs().is_empty());
    }

    #[test]
    fn toasts_expire_through_scheduled_timers() {
        let mut h = AppHarness::new(Config::default());
        let id = open_form_and_save(&mut h);
        h.send(UiEvent::EffectDone {
            id,
            result: Err(ErrorReport::msg("boom")),
        });
        assert_eq!(h.app().toasts().len(), 1);
        // M0-11: errors are sticky (SPEC §8.7); `Esc` dismisses them (the first one
        // closes the still-open form).
        h.advance(60_000);
        assert_eq!(h.app().toasts().len(), 1);
        h.keys("esc d esc");
        assert!(h.app().toasts().is_empty());
        // Other levels fade after 4 s.
        h.toast(ToastLevel::Info, "hello");
        h.advance(3_999);
        assert_eq!(h.app().toasts().len(), 1);
        h.advance(1);
        assert!(h.app().toasts().is_empty());
    }

    // ---- T-07 Dispatch order ----------------------------------------------------------

    #[test]
    fn t07_dialog_then_view_then_keymap() {
        let mut h = AppHarness::new(confirm(true)).with_sessions(1);
        h.app_mut().seed_three_hosts();
        // No dialog: the view consumes `j`.
        h.keys("j");
        assert_eq!(h.app().views().hosts.list.cursor(), 1);

        // With a dialog open, `j` is consumed by the dialog and never reaches the view.
        h.keys("q");
        assert_eq!(h.app().dialogs().len(), 1);
        h.keys("j k j");
        assert_eq!(h.app().views().hosts.list.cursor(), 1);
        assert_eq!(h.take_effects(), vec![]);
        h.keys("esc");

        // A key the view ignores (`ctrl-z`) reaches the global keymap.
        h.keys("ctrl-z");
        assert_eq!(h.take_effects(), vec![Effect::Suspend]);
        assert_eq!(h.app().views().hosts.list.cursor(), 1);
    }

    #[test]
    fn release_events_are_ignored() {
        let mut h = AppHarness::new(Config::default());
        let mut ev = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE);
        ev.kind = crossterm::event::KeyEventKind::Release;
        h.send(UiEvent::Input(InputEvent::Key(ev)));
        assert_eq!(h.effects(), &[]);
    }

    // ---- T-08 Render is infallible ----------------------------------------------------

    #[test]
    fn t08_every_view_renders_at_every_size() {
        let mut states = Vec::new();
        let base = AppHarness::new(Config::default());
        states.push(base.app().clone());
        let mut help = AppHarness::new(Config::default());
        help.keys("?");
        states.push(help.app().clone());
        let mut confirm_dialog = AppHarness::new(confirm(true)).with_sessions(1);
        confirm_dialog.keys("q");
        states.push(confirm_dialog.app().clone());
        let mut form = AppHarness::new(Config::default());
        let id = open_form_and_save(&mut form);
        form.send(UiEvent::EffectDone {
            id,
            result: Err(ErrorReport::msg("a rather long error message for a toast")),
        });
        states.push(form.app().clone());

        for app in &states {
            for (w, h) in [(1, 1), (10, 3), (80, 24), (300, 100), (0, 0), (2, 1)] {
                let text = render_app(app, w, h);
                assert_eq!(text.lines().count(), usize::from(h));
            }
        }
    }

    // ---- T-09 Snapshots ---------------------------------------------------------------

    #[test]
    fn t09_initial_state_snapshots() {
        let h = AppHarness::new(Config::default());
        insta::assert_snapshot!("initial_80x24", h.render(80, 24));
        insta::assert_snapshot!("initial_160x48", h.render(160, 48));
    }

    #[test]
    fn t09_dialog_snapshot() {
        let mut h = AppHarness::new(Config::default()).with_sessions(1);
        h.keys("q");
        insta::assert_snapshot!("confirm_quit_80x24", h.render(80, 24));
    }

    // ---- T-11 No ping-pong ------------------------------------------------------------

    #[test]
    fn t11_single_inputs_have_bounded_effects() {
        let origin = Instant::now();
        // From several starting states, every event of the alphabet yields < 64 effects.
        for start in [
            App::new(Arc::new(Config::default())),
            scripted_app(),
            AppHarness::new(confirm(true))
                .with_sessions(1)
                .app()
                .clone(),
        ] {
            for i in 0u8..24 {
                let mut app = start.clone();
                let effects = app.handle(alphabet(i, origin));
                assert!(effects.len() < 64, "event {i}: {} effects", effects.len());
            }
        }
    }

    #[test]
    fn help_opens_and_closes() {
        let mut h = AppHarness::new(Config::default());
        h.keys("?");
        assert!(matches!(h.app().dialogs()[0].kind, DialogKind::Help(_)));
        h.keys("q");
        assert!(h.app().dialogs().is_empty());
        assert_eq!(h.effects(), &[], "q closes help, it does not quit");
    }

    #[test]
    fn fake_session_registry_returns_grids() {
        let mut reg = FakeSessionRegistry::new();
        reg.insert(SessionId(7), ["$ ls", "a b c"]);
        assert_eq!(reg.grid(SessionId(7)).map(<[String]>::len), Some(2));
        assert!(reg.grid(SessionId(8)).is_none());
    }
}
