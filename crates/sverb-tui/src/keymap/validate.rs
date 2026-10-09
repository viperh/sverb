//! The real [`KeymapValidator`] for `config.toml` (replaces `StubKeymapValidator`).
//!
//! Leader rules: the leader must include `ctrl` or
//! `alt`; `ctrl-c`, `ctrl-d`, `ctrl-z`, `ctrl-m`/`enter`, `ctrl-i`/`tab` and
//! `ctrl-[`/`esc` are rejected; `ctrl-a b e k r u w l` are accepted with a warning that
//! names the programs they hide from sessions.

use std::{str::FromStr, sync::Arc};

use crossterm::event::KeyCode;
use sverb_core::config::{KeymapValidator, LeaderCheck, Validators};

use crate::views::sessions::copy_mode::CopyAction;

/// The `[keys.copy]` table name.
const COPY_TABLE: &str = "copy";

use super::{
    action::ActionName,
    chord::{KeyChord, Mods},
    keymap::{Table, UNBIND},
};

/// Validates `general.leader` and `[keys.*]` with sverb-tui's chord grammar and registry.
#[derive(Debug, Clone, Copy, Default)]
pub struct TuiKeymapValidator;

/// Validators for `Config::load` and the config watcher: the real keymap validator and
pub fn validators() -> Validators {
    Validators {
        keymap: Arc::new(TuiKeymapValidator),
        themes: Arc::new(crate::theme::UiThemeCatalog),
    }
}

/// Programs a plain `ctrl-<letter>` leader hides from sessions (warning text).
fn conflicts(c: char) -> Option<&'static str> {
    Some(match c {
        'a' => "readline/emacs start of line and GNU screen's prefix",
        'b' => "tmux's prefix and readline back-char",
        'e' => "readline/emacs end of line",
        'k' => "readline/emacs kill line and nano cut",
        'r' => "shell reverse history search",
        'u' => "readline kill to start of line",
        'w' => "readline delete word and vim window commands",
        'l' => "clear screen in shells and redraw in many programs",
        _ => return None,
    })
}

/// Check a chord for use as the leader.
pub fn check_leader(chord: &KeyChord) -> LeaderCheck {
    if !chord.mods.intersects(Mods::CTRL | Mods::ALT) {
        return LeaderCheck::Reject(format!(
            "the leader must include ctrl or alt, otherwise `{chord}` could never be typed into a session"
        ));
    }
    let plain_ctrl = chord.mods == Mods::CTRL;
    let needed = match chord.code {
        KeyCode::Enter | KeyCode::Tab | KeyCode::Esc => true,
        KeyCode::Char('c' | 'd' | 'z' | 'm' | 'i' | '[') => plain_ctrl,
        _ => false,
    };
    if needed {
        return LeaderCheck::Reject(format!(
            "`{chord}` is needed for basic shell use (interrupt, EOF, job control, enter, tab or escape)"
        ));
    }
    if let KeyCode::Char(c) = chord.code
        && plain_ctrl
        && let Some(what) = conflicts(c)
    {
        return LeaderCheck::Warn(format!(
            "leader `{chord}` hides {what} from your sessions (press it twice to send it)"
        ));
    }
    LeaderCheck::Ok
}

impl KeymapValidator for TuiKeymapValidator {
    /// Accepts one chord or a whitespace-separated sequence (`"g g"`); returns the
    /// canonical text, so `"shift-l"` and `"L"` are recognized as the same key.
    fn parse_chord(&self, chord: &str) -> Result<String, String> {
        KeyChord::parse_sequence(chord)
            .map(|seq| KeyChord::display_sequence(&seq))
            .map_err(|e| e.to_string())
    }

    fn check_leader(&self, chord: &str) -> LeaderCheck {
        match KeyChord::parse_sequence(chord) {
            Ok(seq) if seq.len() == 1 => check_leader(&seq[0]),
            Ok(_) => LeaderCheck::Reject("the leader must be a single chord".to_owned()),
            Err(e) => LeaderCheck::Reject(e.to_string()),
        }
    }

    fn modes(&self) -> Vec<String> {
        let mut modes: Vec<String> = [Table::Leader, Table::Normal]
            .iter()
            .map(|t| t.config_name().to_owned())
            .collect();
        // `[keys.copy]` (copy-mode actions).
        modes.push(COPY_TABLE.to_owned());
        modes
    }

    fn action_exists(&self, mode: &str, action: &str) -> bool {
        if mode == COPY_TABLE {
            return action == UNBIND || CopyAction::from_str(action).is_ok();
        }
        action == UNBIND || ActionName::from_str(action).is_ok()
    }
}
