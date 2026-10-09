//! `config.toml`: the typed model, defaults, parsing, validation, schema and hot reload (SPEC §15).
//!
//! No ratatui and no crossterm here. Key chords and theme names are kept as strings
//! and checked through the [`KeymapValidator`] and [`ThemeCatalog`] traits, which the
//! TUI and `sverb-term` implement. Until then the
//! [`StubKeymapValidator`] and [`StubThemeCatalog`] stand in.
//!
//! Loading is all-or-nothing: a file with any error never partially applies. At
//! startup the fallback is [`Config::default`]; on reload it is the last good config.

pub mod diff;
pub mod model;
pub mod schema;
pub mod validate;
pub mod watch;

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub use diff::{ConfigDiff, ConfigUpdate, LiveConfig};
pub use model::*;
pub use watch::{ConfigEvent, ConfigWatcher, WatchError};

use crate::paths::Paths;

/// The defaults as a commented TOML file, printed by `sverb config --print-default`.
pub const DEFAULT_CONFIG_TOML: &str = include_str!("default_config.toml");

/// How serious a [`ConfigError`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// The file is rejected.
    Error,
    /// Accepted, but the user should know (e.g. a leader that shadows a shell key).
    Warning,
}

/// One problem found in a config file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    /// Dotted key path, e.g. `ssh.keepalive_sec`. Empty for syntax errors.
    pub path: String,
    /// 1-based line, 0 when unknown.
    pub line: usize,
    /// 1-based column (in characters), 0 when unknown.
    pub col: usize,
    /// What is wrong.
    pub message: String,
    /// How to fix it, e.g. the nearest known key.
    pub hint: Option<String>,
    /// Error or warning.
    pub severity: Severity,
}

impl ConfigError {
    pub(crate) fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            line: 0,
            col: 0,
            message: message.into(),
            hint: None,
            severity: Severity::Error,
        }
    }

    pub(crate) fn at(mut self, (line, col): (usize, usize)) -> Self {
        self.line = line;
        self.col = col;
        self
    }

    pub(crate) fn hint(mut self, hint: Option<String>) -> Self {
        self.hint = hint;
        self
    }

    pub(crate) fn warning(mut self) -> Self {
        self.severity = Severity::Warning;
        self
    }
}

/// `path:line:col: message (hint)`; parts that are unknown are left out.
impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let path = if self.path.is_empty() {
            "config.toml"
        } else {
            &self.path
        };
        if self.line > 0 {
            write!(f, "{path}:{}:{}: {}", self.line, self.col, self.message)?;
        } else {
            write!(f, "{path}: {}", self.message)?;
        }
        if let Some(hint) = &self.hint {
            write!(f, " ({hint})")?;
        }
        Ok(())
    }
}

impl std::error::Error for ConfigError {}

/// Where the effective config came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSource {
    /// No file (or the file was rejected and the defaults are in effect at startup).
    Defaults,
    /// This file, parsed without errors.
    File(PathBuf),
    /// The file was rejected on reload; the last good config stays in effect.
    LastGood,
}

/// Result of [`Config::load`].
#[derive(Debug, Clone)]
pub struct LoadOutcome {
    /// The config to use. Never a partially applied file.
    pub config: Config,
    /// Problems that rejected the file (empty when it was accepted).
    pub errors: Vec<ConfigError>,
    /// Problems that did not reject the file.
    pub warnings: Vec<ConfigError>,
    /// Where `config` came from.
    pub source: ConfigSource,
}

impl LoadOutcome {
    /// `true` when the file had no errors (warnings are allowed).
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Result of a leader check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaderCheck {
    /// Fine.
    Ok,
    /// Accepted, with a warning naming the programs it conflicts with.
    Warn(String),
    /// Rejected.
    Reject(String),
}

/// Checks key chords and action names. Implemented by `sverb-tui`.
pub trait KeymapValidator: fmt::Debug + Send + Sync {
    /// Parse a chord; returns its normalized form (used to find duplicates) or why it is invalid.
    fn parse_chord(&self, chord: &str) -> Result<String, String>;
    /// Check a chord for use as the leader.
    fn check_leader(&self, chord: &str) -> LeaderCheck;
    /// Mode names allowed as `[keys.<mode>]`.
    fn modes(&self) -> Vec<String>;
    /// Whether `action` can be bound in `mode`.
    fn action_exists(&self, mode: &str, action: &str) -> bool;
}

/// Knows which UI themes and terminal color schemes exist.
pub trait ThemeCatalog: fmt::Debug + Send + Sync {
    /// Whether a UI theme of this name exists.
    fn has_ui_theme(&self, name: &str) -> bool;
    /// Whether a terminal color scheme of this name exists.
    fn has_color_scheme(&self, name: &str) -> bool;
}

/// The injected validators used by [`Config::load`] and the watcher.
#[derive(Debug, Clone)]
pub struct Validators {
    /// Key chords and actions.
    pub keymap: Arc<dyn KeymapValidator>,
    /// Theme and color scheme names.
    pub themes: Arc<dyn ThemeCatalog>,
}

impl Default for Validators {
    /// The stubs: [`StubKeymapValidator`] and [`StubThemeCatalog`].
    fn default() -> Self {
        Self {
            keymap: Arc::new(StubKeymapValidator),
            themes: Arc::new(StubThemeCatalog),
        }
    }
}

impl Config {
    /// Load `Paths::config_file()`. A missing file gives the defaults (logged at debug only).
    pub fn load(paths: &Paths, validators: &Validators) -> LoadOutcome {
        Self::load_file(&paths.config_file(), validators, None)
    }

    /// Reload `path`, keeping `last_good` if the file is rejected. A missing file gives the defaults.
    pub fn reload(path: &Path, validators: &Validators, last_good: &Config) -> LoadOutcome {
        Self::load_file(path, validators, Some(last_good))
    }

    /// Load a specific file (`sverb config --check --file`). `fallback` is used on errors
    /// (`None` → defaults).
    pub fn load_file(
        path: &Path,
        validators: &Validators,
        fallback: Option<&Config>,
    ) -> LoadOutcome {
        match std::fs::read_to_string(path) {
            Ok(src) => {
                let mut outcome = Self::from_toml_str(&src, validators);
                if outcome.is_ok() {
                    outcome.source = ConfigSource::File(path.to_owned());
                } else if let Some(last) = fallback {
                    outcome.config = last.clone();
                    outcome.source = ConfigSource::LastGood;
                }
                outcome
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                tracing::debug!(path = %path.display(), "no config file; using defaults");
                LoadOutcome {
                    config: Config::default(),
                    errors: Vec::new(),
                    warnings: Vec::new(),
                    source: ConfigSource::Defaults,
                }
            }
            Err(e) => LoadOutcome {
                config: fallback.cloned().unwrap_or_default(),
                errors: vec![ConfigError::new(
                    "",
                    format!("cannot read {}: {e}", path.display()),
                )],
                warnings: Vec::new(),
                source: if fallback.is_some() {
                    ConfigSource::LastGood
                } else {
                    ConfigSource::Defaults
                },
            },
        }
    }

    /// Parse and validate TOML text. On any error `config` is [`Config::default`].
    pub fn from_toml_str(src: &str, validators: &Validators) -> LoadOutcome {
        let parsed = validate::parse(src, validators);
        match parsed.config {
            Some(config) if parsed.errors.is_empty() => LoadOutcome {
                config,
                errors: Vec::new(),
                warnings: parsed.warnings,
                source: ConfigSource::Defaults,
            },
            _ => LoadOutcome {
                config: Config::default(),
                errors: parsed.errors,
                warnings: parsed.warnings,
                source: ConfigSource::Defaults,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

///
/// Chord syntax: `[ctrl-][alt-][shift-]<key>`, where `<key>` is one character or a
/// named key (`esc`, `enter`, `tab`, `space`, `f1`…`f12`, arrows, …).
#[derive(Debug, Clone, Copy, Default)]
pub struct StubKeymapValidator;

/// Action names known to the stub.
const STUB_ACTIONS: &[&str] = &[
    "send_leader",
    "new_tab_pick_host",
    "new_local_tab",
    "quick_connect",
    "go_to_tab_1",
    "go_to_tab_2",
    "go_to_tab_3",
    "go_to_tab_4",
    "go_to_tab_5",
    "go_to_tab_6",
    "go_to_tab_7",
    "go_to_tab_8",
    "go_to_tab_9",
    "next_tab",
    "prev_tab",
    "rename_tab",
    "move_tab_left",
    "move_tab_right",
    "close_pane",
    "close_tab",
    "split_horizontal",
    "split_vertical",
    "focus_left",
    "focus_down",
    "focus_up",
    "focus_right",
    "resize_left",
    "resize_down",
    "resize_up",
    "resize_right",
    "resize_mode",
    "zoom_pane",
    "toggle_broadcast",
    "mark_broadcast_pane",
    "session_info",
    "share_pane",
    "palette",
    "snippet_picker",
    "copy_mode",
    "autocomplete",
    "accept_ghost_text",
    "toggle_recording",
    "toggle_views",
    "toggle_sidebar",
    "notification_history",
    "help",
    "toggle_log_pane",
    "lock_vault",
    "suspend",
    "quit",
];

/// Copy-mode action names (`[keys.copy]`). sverb-tui's copy-mode
/// table (`views::sessions::copy_mode::CopyAction`) has exactly these.
pub const COPY_ACTIONS: &[&str] = &[
    "move_left",
    "move_down",
    "move_up",
    "move_right",
    "word_forward",
    "word_backward",
    "word_end",
    "big_word_forward",
    "big_word_backward",
    "big_word_end",
    "line_start",
    "line_first_non_blank",
    "line_end",
    "top",
    "bottom",
    "screen_top",
    "screen_middle",
    "screen_bottom",
    "half_page_up",
    "half_page_down",
    "page_up",
    "page_down",
    "paragraph_backward",
    "paragraph_forward",
    "select_char",
    "select_line",
    "select_block",
    "swap_anchor",
    "yank",
    "yank_line",
    "search_forward",
    "search_backward",
    "search_next",
    "search_prev",
    "open_link",
    "exit",
];

const STUB_NAMED_KEYS: &[&str] = &[
    "esc",
    "enter",
    "tab",
    "backtab",
    "backspace",
    "delete",
    "insert",
    "home",
    "end",
    "pageup",
    "pagedown",
    "up",
    "down",
    "left",
    "right",
    "space",
    "f1",
    "f2",
    "f3",
    "f4",
    "f5",
    "f6",
    "f7",
    "f8",
    "f9",
    "f10",
    "f11",
    "f12",
];

impl StubKeymapValidator {
    /// `(ctrl, alt, shift, key)` with `key` normalized.
    fn split(chord: &str) -> Result<(bool, bool, bool, String), String> {
        if chord.is_empty() {
            return Err("empty key chord".to_owned());
        }
        let (mut ctrl, mut alt, mut shift) = (false, false, false);
        let mut rest = chord;
        loop {
            // Only strip a modifier if something is left after it (`ctrl--` is ctrl + `-`).
            let lower = rest.to_ascii_lowercase();
            let stripped = ["ctrl-", "alt-", "shift-"]
                .iter()
                .find_map(|m| (lower.starts_with(m) && rest.len() > m.len()).then_some(*m));
            match stripped {
                Some("ctrl-") => ctrl = true,
                Some("alt-") => alt = true,
                Some(_) => shift = true,
                None => break,
            }
            rest = &rest[stripped.map_or(0, str::len)..];
        }
        let mut chars = rest.chars();
        let key = match (chars.next(), chars.next()) {
            (Some(c), None) if !c.is_whitespace() && !c.is_control() => {
                let c = if ctrl {
                    match c {
                        '4' => '\\',
                        '5' => ']',
                        '6' => '^',
                        '7' | '/' => '_',
                        c => c.to_ascii_lowercase(),
                    }
                } else {
                    c
                };
                c.to_string()
            }
            _ => {
                let named = rest.to_ascii_lowercase();
                let named = match named.as_str() {
                    "escape" => "esc".to_owned(),
                    "return" => "enter".to_owned(),
                    "del" => "delete".to_owned(),
                    other => other.to_owned(),
                };
                if STUB_NAMED_KEYS.contains(&named.as_str()) {
                    named
                } else {
                    return Err(format!("unknown key `{rest}` in chord `{chord}`"));
                }
            }
        };
        Ok((ctrl, alt, shift, key))
    }

    fn normalize(ctrl: bool, alt: bool, shift: bool, key: &str) -> String {
        let mut out = String::new();
        for (on, name) in [(ctrl, "ctrl-"), (alt, "alt-"), (shift, "shift-")] {
            if on {
                out.push_str(name);
            }
        }
        out.push_str(key);
        out
    }
}

impl KeymapValidator for StubKeymapValidator {
    fn parse_chord(&self, chord: &str) -> Result<String, String> {
        let (ctrl, alt, shift, key) = Self::split(chord)?;
        Ok(Self::normalize(ctrl, alt, shift, &key))
    }

    fn check_leader(&self, chord: &str) -> LeaderCheck {
        let (ctrl, alt, shift, key) = match Self::split(chord) {
            Ok(parts) => parts,
            Err(e) => return LeaderCheck::Reject(e),
        };
        if !ctrl && !alt {
            return LeaderCheck::Reject(format!(
                "the leader must include ctrl or alt, otherwise `{chord}` could never be typed into a session"
            ));
        }
        let plain_ctrl = ctrl && !alt && !shift;
        let rejected = match key.as_str() {
            "c" | "d" | "z" | "m" | "i" | "[" => plain_ctrl,
            "enter" | "tab" | "esc" => true,
            _ => false,
        };
        if rejected {
            return LeaderCheck::Reject(format!(
                "`{}` is needed for basic shell use (interrupt, EOF, job control, enter, tab or escape)",
                Self::normalize(ctrl, alt, shift, &key)
            ));
        }
        if plain_ctrl {
            let conflicts = match key.as_str() {
                "a" => Some("readline/emacs start of line and GNU screen's prefix"),
                "b" => Some("tmux's prefix and readline back-char"),
                "e" => Some("readline/emacs end of line"),
                "k" => Some("readline/emacs kill line"),
                "r" => Some("shell reverse history search"),
                "u" => Some("readline kill to start of line"),
                "w" => Some("readline delete word and vim window commands"),
                "l" => Some("clear screen in shells and redraw in many programs"),
                _ => None,
            };
            if let Some(what) = conflicts {
                return LeaderCheck::Warn(format!(
                    "leader `ctrl-{key}` hides {what} from your sessions (press it twice to send it)"
                ));
            }
        }
        LeaderCheck::Ok
    }

    fn modes(&self) -> Vec<String> {
        // `[keys.copy]`.
        vec![
            "terminal".to_owned(),
            "normal".to_owned(),
            "copy".to_owned(),
        ]
    }

    fn action_exists(&self, mode: &str, action: &str) -> bool {
        // Copy mode has its own actions.
        if mode == "copy" {
            return action == "none" || COPY_ACTIONS.contains(&action);
        }
        STUB_ACTIONS.contains(&action)
    }
}

/// Stand-in theme catalog: the built-in UI theme names and the `terminal` scheme. The TUI
#[derive(Debug, Clone, Copy, Default)]
pub struct StubThemeCatalog;

impl ThemeCatalog for StubThemeCatalog {
    fn has_ui_theme(&self, name: &str) -> bool {
        // `high-contrast` added.
        matches!(name, "default-dark" | "default-light" | "high-contrast")
    }

    fn has_color_scheme(&self, name: &str) -> bool {
        name == "terminal"
    }
}

#[cfg(test)]
mod tests;
