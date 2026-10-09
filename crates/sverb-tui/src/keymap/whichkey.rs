//! §4.5), shown `ui.which_key_delay_ms` after the leader.
//!
//! One entry per action with all of its keys (`h ←  Focus left`); `go_to_tab_1…9`
//! collapse into one `1…9` entry when bound to the digits. The popup itself is drawn
//! by `crate::widgets::which_key`.

use strum::IntoEnumIterator;

use super::{
    action::{ActionName, Group, registry},
    chord::KeyChord,
    keymap::Keymap,
};

/// One which-key entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Keys as shown (`h ←`, `1…9`).
    pub keys: String,
    /// Action description.
    pub label: String,
    /// The actions behind this entry (several for the collapsed tab digits).
    pub actions: Vec<ActionName>,
}

const TABS: [ActionName; 9] = [
    ActionName::GoToTab1,
    ActionName::GoToTab2,
    ActionName::GoToTab3,
    ActionName::GoToTab4,
    ActionName::GoToTab5,
    ActionName::GoToTab6,
    ActionName::GoToTab7,
    ActionName::GoToTab8,
    ActionName::GoToTab9,
];

/// Compact key label for which-key (arrows as symbols).
fn key_label(seq: &[KeyChord]) -> String {
    seq.iter()
        .map(|c| match c.to_string().as_str() {
            "left" => "←".to_owned(),
            "right" => "→".to_owned(),
            "up" => "↑".to_owned(),
            "down" => "↓".to_owned(),
            other => other.to_owned(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The entries of each group, in group and registry order. Unbound actions are left out.
pub fn entries(keymap: &Keymap) -> Vec<(Group, Vec<Entry>)> {
    let digits: Vec<Vec<KeyChord>> = ('1'..='9').map(|d| vec![KeyChord::char(d)]).collect();
    let tabs_collapse = TABS
        .iter()
        .zip(&digits)
        .all(|(a, d)| keymap.after_leader_keys(*a) == vec![d.clone()]);
    Group::iter()
        .map(|group| {
            let mut out = Vec::new();
            for info in registry().iter().filter(|i| i.group == group) {
                if tabs_collapse && TABS.contains(&info.name) {
                    if info.name == ActionName::GoToTab1 {
                        out.push(Entry {
                            keys: "1…9".to_owned(),
                            label: "Go to tab 1…9".to_owned(),
                            actions: TABS.to_vec(),
                        });
                    }
                    continue;
                }
                let keys = keymap.after_leader_keys(info.name);
                if keys.is_empty() {
                    continue;
                }
                let keys: Vec<String> = keys.iter().map(|k| key_label(k)).collect();
                out.push(Entry {
                    keys: keys.join(" "),
                    label: info.description.to_owned(),
                    actions: vec![info.name],
                });
            }
            (group, out)
        })
        .filter(|(_, e)| !e.is_empty())
        .collect()
}

// Drawing moved to `crate::widgets::which_key` (themed, bottom right).
