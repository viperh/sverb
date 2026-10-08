//! The leader / key-sequence state machine (SPEC §8.2, `tasks/03-KEYBINDINGS.md` §1.1).
//!
//! ```text
//! Idle ──leader──▶ Pending { Leader } ──key──▶ resolve ──▶ Idle
//! Idle ──prefix of a Normal sequence──▶ Pending { Normal } ──key──▶ resolve ──▶ Idle
//! ```
//!
//! - After the leader the next key is looked up in the after-leader table (config
//!   `[keys.terminal]`; it applies in **every** mode despite the name).
//! - Leader + leader → the literal leader goes to the focused session.
//! - Leader + unbound key → toast, and the key is **discarded** (never forwarded).
//! - `Esc` cancels. No key within [`LEADER_TIMEOUT`] → back to Idle silently.
//! - The which-key popup appears after `ui.which_key_delay_ms`; while it is visible
//!   the timeout is suspended so the user can read it.
//! - Normal-mode multi-key sequences (`g g`) use the same machine with
//!   [`SEQUENCE_TIMEOUT`]; on timeout the binding of the typed prefix (if any) runs.
//!
//! Timers go through `Effect::ScheduleTimer` (`TimerKind::WhichKey` and
//! `TimerKind::LeaderTimeout`, which is the timeout of any pending sequence), so the
//! machine is fully testable through the reducer. [`step`] is the pure transition.

use std::time::Duration;

use crossterm::event::KeyCode;

use super::{
    action::ActionName,
    chord::KeyChord,
    keymap::{Keymap, Lookup, Table},
};

/// No key within this long after the leader → back to Idle.
pub const LEADER_TIMEOUT: Duration = Duration::from_millis(1500);

/// No key within this long inside a Normal-mode multi-key sequence → resolve it.
pub const SEQUENCE_TIMEOUT: Duration = Duration::from_millis(1000);

/// Key-sequence state of the reducer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum KeyState {
    /// No sequence in progress.
    #[default]
    Idle,
    /// A sequence is in progress.
    Pending(Pending),
}

/// A sequence in progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    /// Which table the keys are looked up in.
    pub table: Table,
    /// Keys typed so far (after the leader, for [`Table::Leader`]).
    pub keys: Vec<KeyChord>,
    /// The which-key popup is visible (the timeout is suspended meanwhile).
    pub which_key: bool,
}

impl Pending {
    /// Right after the leader.
    pub fn leader() -> Self {
        Self {
            table: Table::Leader,
            keys: Vec::new(),
            which_key: false,
        }
    }
}

/// What the reducer should do with a key while a sequence is pending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// The sequence is still a prefix of a binding: keep waiting.
    Wait(Pending),
    /// Run this action.
    Run(ActionName),
    /// Leader + leader: send the literal leader to the focused session.
    SendLeader,
    /// `Esc`: cancel silently.
    Cancel,
    /// Leader + an unbound sequence: toast `No binding for <keys>`, discard the key.
    Unbound(Vec<KeyChord>),
    /// A Normal-mode sequence broke: run `exact` (the binding of the typed prefix, if
    /// any), then handle the new key as if nothing were pending.
    Reprocess {
        /// What the typed prefix was bound to.
        exact: Option<ActionName>,
    },
}

/// Transition for `chord` while `pending`.
pub fn step(keymap: &Keymap, pending: &Pending, chord: KeyChord) -> Step {
    if pending.table == Table::Leader && pending.keys.is_empty() {
        if chord == keymap.leader() {
            return Step::SendLeader;
        }
        if chord.code == KeyCode::Esc && chord.mods.is_empty() {
            return Step::Cancel;
        }
    }
    let mut seq = pending.keys.clone();
    seq.push(chord);
    match keymap.lookup_seq(pending.table, &seq) {
        Lookup::Action(action) => Step::Run(action),
        Lookup::Prefix { .. } => Step::Wait(Pending {
            keys: seq,
            ..pending.clone()
        }),
        Lookup::Unbound => match pending.table {
            Table::Leader => Step::Unbound(seq),
            Table::Normal => Step::Reprocess {
                exact: match keymap.lookup_seq(Table::Normal, &pending.keys) {
                    Lookup::Action(a) | Lookup::Prefix { exact: Some(a) } => Some(a),
                    _ => None,
                },
            },
        },
    }
}

/// What a timeout resolves to: the binding of exactly the typed keys, if any.
pub fn on_timeout(keymap: &Keymap, pending: &Pending) -> Option<ActionName> {
    if pending.keys.is_empty() {
        return None;
    }
    match keymap.lookup_seq(pending.table, &pending.keys) {
        Lookup::Action(a) | Lookup::Prefix { exact: Some(a) } => Some(a),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> KeyChord {
        s.parse().unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn leader_steps() {
        let km = Keymap::default();
        let p = Pending::leader();
        assert_eq!(step(&km, &p, c("ctrl-\\")), Step::SendLeader);
        assert_eq!(step(&km, &p, c("esc")), Step::Cancel);
        assert_eq!(
            step(&km, &p, c("-")),
            Step::Run(ActionName::SplitHorizontal)
        );
        assert_eq!(step(&km, &p, c("y")), Step::Unbound(vec![c("y")]));
    }

    #[test]
    fn normal_sequences() {
        let mut km = Keymap::default();
        km.bind_seq(Table::Normal, vec![c("g"), c("g")], ActionName::Help);
        let p = Pending {
            table: Table::Normal,
            keys: vec![c("g")],
            which_key: false,
        };
        assert_eq!(step(&km, &p, c("g")), Step::Run(ActionName::Help));
        assert_eq!(step(&km, &p, c("x")), Step::Reprocess { exact: None });
        assert_eq!(on_timeout(&km, &p), None);
        km.bind(c("g"), ActionName::Palette);
        assert_eq!(on_timeout(&km, &p), Some(ActionName::Palette));
    }
}
