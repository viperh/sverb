//! The effective keymap: built-in tables (`tasks/03-KEYBINDINGS.md` §4) merged with
//! `[keys.terminal]` / `[keys.normal]` from `config.toml`.
//!
//! - The **after-leader** table (config name `terminal`, kept from SPEC §15) applies in
//!   **every** mode: it is looked up for the keys typed after the leader.
//! - The **Normal** table applies only while sverb's own views have focus.
//! - There is deliberately **no** table for Terminal mode: there every key except the
//!   leader goes to the session (the pass-through guarantee, §1.2).
//!
//! Both tables map key *sequences* (usually one chord) to actions, so multi-key
//! bindings like `g g` work through the same prefix lookup ([`Keymap::lookup_seq`]).

use std::collections::HashMap;

use serde::Serialize;
use sverb_core::config::Config;

use super::{
    action::{ActionName, Group},
    chord::KeyChord,
};

/// The default leader (`tasks/03-KEYBINDINGS.md` §3.2).
pub const DEFAULT_LEADER: &str = "ctrl-\\";

/// The value that unbinds a key in `[keys.*]`.
pub const UNBIND: &str = "none";

/// Built-in after-leader bindings (§4.1). Leader + leader (`send_leader`) is implicit.
pub const AFTER_LEADER_DEFAULTS: &[(&str, ActionName)] = &[
    // Sessions and tabs
    ("c", ActionName::NewTabPickHost),
    ("t", ActionName::NewLocalTab),
    ("o", ActionName::QuickConnect),
    ("1", ActionName::GoToTab1),
    ("2", ActionName::GoToTab2),
    ("3", ActionName::GoToTab3),
    ("4", ActionName::GoToTab4),
    ("5", ActionName::GoToTab5),
    ("6", ActionName::GoToTab6),
    ("7", ActionName::GoToTab7),
    ("8", ActionName::GoToTab8),
    ("9", ActionName::GoToTab9),
    ("n", ActionName::NextTab),
    ("N", ActionName::PrevTab),
    (",", ActionName::RenameTab),
    ("<", ActionName::MoveTabLeft),
    (">", ActionName::MoveTabRight),
    ("x", ActionName::ClosePane),
    ("X", ActionName::CloseTab),
    // Panes
    ("-", ActionName::SplitHorizontal),
    ("|", ActionName::SplitVertical),
    ("h", ActionName::FocusLeft),
    ("j", ActionName::FocusDown),
    ("k", ActionName::FocusUp),
    ("l", ActionName::FocusRight),
    ("left", ActionName::FocusLeft),
    ("down", ActionName::FocusDown),
    ("up", ActionName::FocusUp),
    ("right", ActionName::FocusRight),
    ("H", ActionName::ResizeLeft),
    ("J", ActionName::ResizeDown),
    ("K", ActionName::ResizeUp),
    ("L", ActionName::ResizeRight),
    ("r", ActionName::ResizeMode),
    ("z", ActionName::ZoomPane),
    ("b", ActionName::ToggleBroadcast),
    ("B", ActionName::MarkBroadcastPane),
    ("i", ActionName::SessionInfo),
    ("S", ActionName::SharePane),
    // Tools
    ("p", ActionName::Palette),
    ("e", ActionName::SnippetPicker),
    ("[", ActionName::CopyMode),
    ("space", ActionName::Autocomplete),
    ("tab", ActionName::AcceptGhostText),
    ("R", ActionName::ToggleRecording),
    // UI
    ("v", ActionName::ToggleViews),
    ("s", ActionName::ToggleSidebar),
    ("!", ActionName::NotificationHistory),
    ("?", ActionName::Help),
    ("D", ActionName::ToggleLogPane),
    // App
    ("ctrl-l", ActionName::LockVault),
    ("ctrl-z", ActionName::Suspend),
    ("q", ActionName::Quit),
];

/// Built-in Normal-mode bindings (§4.2) that map to registry actions. List keys
/// (`j k g G …`) belong to each view and are handled there after this table.
pub const NORMAL_DEFAULTS: &[(&str, ActionName)] = &[
    ("ctrl-k", ActionName::Palette),
    ("?", ActionName::Help),
    ("q", ActionName::Quit),
    ("ctrl-z", ActionName::Suspend),
];

/// Which table a binding lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Table {
    /// After the leader, in every mode (`[keys.terminal]`).
    Leader,
    /// Normal mode (`[keys.normal]`).
    Normal,
}

impl Table {
    /// The `[keys.<name>]` table name in `config.toml`.
    pub fn config_name(self) -> &'static str {
        match self {
            Self::Leader => "terminal",
            Self::Normal => "normal",
        }
    }

    /// The name shown in `sverb keys --dump` and the docs.
    pub fn label(self) -> &'static str {
        match self {
            Self::Leader => "leader",
            Self::Normal => "normal",
        }
    }
}

/// Result of looking up a (partial) key sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup {
    /// Bound, and no longer binding starts with this sequence.
    Action(ActionName),
    /// A longer binding starts with this sequence; `exact` is what runs on timeout.
    Prefix {
        /// The action bound to exactly this sequence, if any.
        exact: Option<ActionName>,
    },
    /// Nothing starts with this sequence.
    Unbound,
}

/// Chord sequences → actions, for one table.
type Bindings = HashMap<Vec<KeyChord>, ActionName>;

/// The effective keymap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keymap {
    leader: KeyChord,
    after_leader: Bindings,
    normal: Bindings,
}

impl Default for Keymap {
    /// The built-in tables with the default leader `ctrl-\`.
    fn default() -> Self {
        Self {
            leader: default_leader(),
            after_leader: builtin(AFTER_LEADER_DEFAULTS),
            normal: builtin(NORMAL_DEFAULTS),
        }
    }
}

fn default_leader() -> KeyChord {
    KeyChord::ctrl('\\')
}

fn builtin(table: &[(&str, ActionName)]) -> Bindings {
    table
        .iter()
        .filter_map(|(keys, action)| Some((KeyChord::parse_sequence(keys).ok()?, *action)))
        .collect()
}

impl Keymap {
    /// The built-ins merged with `config`'s leader and `[keys.*]` tables.
    ///
    /// The config was validated at load time ([`super::TuiKeymapValidator`]); entries
    /// that still don't parse are skipped. `"none"` unbinds a key.
    pub fn from_config(config: &Config) -> Self {
        let mut map = Self::default();
        if let Ok(leader) = config.general.leader.as_str().parse() {
            map.leader = leader;
        }
        for table in [Table::Leader, Table::Normal] {
            let Some(bindings) = config.keys.mode(table.config_name()) else {
                continue;
            };
            for (keys, action) in bindings {
                let Ok(seq) = KeyChord::parse_sequence(keys.as_str()) else {
                    continue;
                };
                if action == UNBIND {
                    map.table_mut(table).remove(&seq);
                } else if let Ok(action) = action.parse() {
                    map.table_mut(table).insert(seq, action);
                }
            }
        }
        // The leader after the leader always sends it (validation rejects binding it).
        let leader = map.leader;
        map.after_leader.remove(&vec![leader]);
        map
    }

    /// The leader chord.
    pub fn leader(&self) -> KeyChord {
        self.leader
    }

    fn table(&self, table: Table) -> &Bindings {
        match table {
            Table::Leader => &self.after_leader,
            Table::Normal => &self.normal,
        }
    }

    fn table_mut(&mut self, table: Table) -> &mut Bindings {
        match table {
            Table::Leader => &mut self.after_leader,
            Table::Normal => &mut self.normal,
        }
    }

    /// The action bound to the single chord `chord` in Normal mode, if any.
    pub fn lookup(&self, chord: &KeyChord) -> Option<ActionName> {
        self.normal.get(std::slice::from_ref(chord)).copied()
    }

    /// The action bound to `chord` right after the leader, if any.
    pub fn lookup_after_leader(&self, chord: &KeyChord) -> Option<ActionName> {
        self.after_leader.get(std::slice::from_ref(chord)).copied()
    }

    /// Look up a (possibly partial) sequence in `table`.
    pub fn lookup_seq(&self, table: Table, seq: &[KeyChord]) -> Lookup {
        let bindings = self.table(table);
        let exact = bindings.get(seq).copied();
        let longer = bindings
            .keys()
            .any(|k| k.len() > seq.len() && k.starts_with(seq));
        match (exact, longer) {
            (_, true) => Lookup::Prefix { exact },
            (Some(action), false) => Lookup::Action(action),
            (None, false) => Lookup::Unbound,
        }
    }

    /// Bind (or rebind) a single chord in Normal mode.
    pub fn bind(&mut self, chord: KeyChord, action: ActionName) {
        self.normal.insert(vec![chord], action);
    }

    /// Bind (or rebind) a sequence in `table`.
    pub fn bind_seq(&mut self, table: Table, seq: Vec<KeyChord>, action: ActionName) {
        self.table_mut(table).insert(seq, action);
    }

    /// All bindings of `table`, sorted by registry order, then by key text.
    pub fn bindings(&self, table: Table) -> Vec<(Vec<KeyChord>, ActionName)> {
        let mut rows: Vec<_> = self
            .table(table)
            .iter()
            .map(|(k, a)| (k.clone(), *a))
            .collect();
        rows.sort_by_cached_key(|(k, a)| {
            // Single characters before named keys (`h` before `left`).
            let text = KeyChord::display_sequence(k);
            (a.order(), text.chars().count() > 1, text)
        });
        rows
    }

    /// Every key sequence bound to `action` after the leader (display order).
    pub fn after_leader_keys(&self, action: ActionName) -> Vec<Vec<KeyChord>> {
        if action == ActionName::SendLeader {
            let mut keys = vec![vec![self.leader]];
            keys.extend(
                self.bindings(Table::Leader)
                    .into_iter()
                    .filter(|(_, a)| *a == action)
                    .map(|(k, _)| k),
            );
            return keys;
        }
        self.bindings(Table::Leader)
            .into_iter()
            .filter(|(_, a)| *a == action)
            .map(|(k, _)| k)
            .collect()
    }

    /// The effective keymap as rows for `sverb keys --dump`, the help screen and the
    /// palette: the leader row first, then the after-leader and Normal tables.
    pub fn effective(config: &Config) -> Vec<BindingRow> {
        let map = Self::from_config(config);
        let defaults = Self::default();
        let leader = map.leader;
        let leader_text = leader.to_string();
        let mut rows = vec![BindingRow {
            table: Table::Leader,
            keys: format!("{leader_text} {leader_text}"),
            action: ActionName::SendLeader,
            description: ActionName::SendLeader.description(),
            group: ActionName::SendLeader.group(),
            source: if leader == defaults.leader {
                Source::Default
            } else {
                Source::Config
            },
        }];
        for table in [Table::Leader, Table::Normal] {
            for (seq, action) in map.bindings(table) {
                let source = if defaults.table(table).get(&seq) == Some(&action) {
                    Source::Default
                } else {
                    Source::Config
                };
                let keys = KeyChord::display_sequence(&seq);
                rows.push(BindingRow {
                    table,
                    keys: match table {
                        Table::Leader => format!("{leader_text} {keys}"),
                        Table::Normal => keys,
                    },
                    action,
                    description: action.description(),
                    group: action.group(),
                    source,
                });
            }
        }
        rows
    }
}

/// Where a binding comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// Built in.
    Default,
    /// Set or changed in `config.toml`.
    Config,
}

impl Source {
    /// `default` or `config`.
    pub fn label(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Config => "config",
        }
    }
}

/// One row of the effective keymap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BindingRow {
    /// `leader` (after the leader, every mode) or `normal`.
    #[serde(rename = "mode")]
    pub table: Table,
    /// The full key sequence as typed, e.g. `ctrl-\ p`.
    pub keys: String,
    /// The action name.
    #[serde(serialize_with = "ser_action")]
    pub action: ActionName,
    /// The registry description.
    pub description: &'static str,
    /// Which-key group.
    #[serde(serialize_with = "ser_group")]
    pub group: Group,
    /// Built in or from config.
    pub source: Source,
}

fn ser_action<S: serde::Serializer>(a: &ActionName, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str((*a).into())
}

fn ser_group<S: serde::Serializer>(g: &Group, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(g.title())
}
