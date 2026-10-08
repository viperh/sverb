//! The keymap action registry: user-bindable named commands.
//!
//! Successor of the template's `Action` enum. Only commands a user can bind to a
//! key live here (`quit`, `suspend`, `help`, later `palette`, `split_horizontal`, …).
//! Internal events (`Tick`, `Render`, `Resize`, `ClearScreen`, `Resume`, `Error`) are
//! **not** actions: they are `UiEvent`s or effects, so a config file can't bind them.
//!
//! # Append-only convention (hotspot, see `tasks/01-DEPENDENCIES.md` §3)
//! Add new actions **at the end** of [`ActionName`] and of [`REGISTRY`], in one block
//! per task introduced by a `// <task-id>` comment. M0-10 owns the full default list.
//! Every action needs a description and a which-key [`Group`] (test T-22).

use serde::{Deserialize, Deserializer, de};
use strum::{Display, EnumIter, EnumString, IntoStaticStr};

/// A user-bindable command, written in `snake_case` in config and docs.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Display,
    EnumString,
    EnumIter,
    IntoStaticStr,
)]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
pub enum ActionName {
    // M0-08
    /// Quit sverb (asks first when sessions are open and `general.confirm_quit`).
    Quit,
    /// Suspend to shell (Unix job control).
    Suspend,
    /// Show the list of actions.
    Help,
    // M0-10: the after-leader table of `tasks/03-KEYBINDINGS.md` §4.1.
    /// Send the literal leader chord to the focused session (leader pressed twice).
    SendLeader,
    /// Open a new tab, picking a host.
    NewTabPickHost,
    /// Open a new local shell tab.
    NewLocalTab,
    /// Quick connect (`user@host:port`).
    QuickConnect,
    /// Go to tab 1.
    #[strum(to_string = "go_to_tab_1")]
    GoToTab1,
    /// Go to tab 2.
    #[strum(to_string = "go_to_tab_2")]
    GoToTab2,
    /// Go to tab 3.
    #[strum(to_string = "go_to_tab_3")]
    GoToTab3,
    /// Go to tab 4.
    #[strum(to_string = "go_to_tab_4")]
    GoToTab4,
    /// Go to tab 5.
    #[strum(to_string = "go_to_tab_5")]
    GoToTab5,
    /// Go to tab 6.
    #[strum(to_string = "go_to_tab_6")]
    GoToTab6,
    /// Go to tab 7.
    #[strum(to_string = "go_to_tab_7")]
    GoToTab7,
    /// Go to tab 8.
    #[strum(to_string = "go_to_tab_8")]
    GoToTab8,
    /// Go to tab 9.
    #[strum(to_string = "go_to_tab_9")]
    GoToTab9,
    /// Next tab.
    NextTab,
    /// Previous tab.
    PrevTab,
    /// Rename the current tab.
    RenameTab,
    /// Move the current tab left.
    MoveTabLeft,
    /// Move the current tab right.
    MoveTabRight,
    /// Close the focused pane (asks if its session is alive).
    ClosePane,
    /// Close the current tab (asks if any session in it is alive).
    CloseTab,
    /// Split the focused pane horizontally.
    SplitHorizontal,
    /// Split the focused pane vertically.
    SplitVertical,
    /// Focus the pane to the left.
    FocusLeft,
    /// Focus the pane below.
    FocusDown,
    /// Focus the pane above.
    FocusUp,
    /// Focus the pane to the right.
    FocusRight,
    /// Grow the focused pane to the left by one step.
    ResizeLeft,
    /// Grow the focused pane downwards by one step.
    ResizeDown,
    /// Grow the focused pane upwards by one step.
    ResizeUp,
    /// Grow the focused pane to the right by one step.
    ResizeRight,
    /// Enter resize mode.
    ResizeMode,
    /// Zoom the focused pane.
    ZoomPane,
    /// Toggle broadcast input.
    ToggleBroadcast,
    /// Mark the focused pane for broadcast.
    MarkBroadcastPane,
    /// Session details.
    SessionInfo,
    /// Share the focused pane.
    SharePane,
    /// Command palette.
    Palette,
    /// Snippet picker.
    SnippetPicker,
    /// Copy mode.
    CopyMode,
    /// Autocomplete.
    Autocomplete,
    /// Accept the ghost-text suggestion.
    AcceptGhostText,
    /// Start or stop recording the session.
    ToggleRecording,
    /// Switch between section views and the session area.
    ToggleViews,
    /// Show or hide the sidebar.
    ToggleSidebar,
    /// Notification history.
    NotificationHistory,
    /// Show or hide the log pane (`--debug`).
    ToggleLogPane,
    /// Lock the vault.
    LockVault,
    // M3-01
    /// Reset every split of the current tab to equal sizes (unbound by default).
    EqualizePanes,
    // M3-03 (unbound by default; in the palette)
    /// Save the open tabs as a workspace.
    SaveWorkspace,
    /// Open a saved workspace (fuzzy picker).
    OpenWorkspace,
    /// List, rename, delete and duplicate workspaces.
    ManageWorkspaces,
}

/// Which-key popup groups (`tasks/03-KEYBINDINGS.md` §4.5), in display order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, EnumIter)]
pub enum Group {
    /// Sessions and tabs.
    SessionsTabs,
    /// Panes.
    Panes,
    /// Tools.
    Tools,
    /// UI.
    Ui,
    /// App.
    App,
}

impl Group {
    /// Heading shown in which-key, help and the docs.
    pub fn title(self) -> &'static str {
        match self {
            Self::SessionsTabs => "Sessions & tabs",
            Self::Panes => "Panes",
            Self::Tools => "Tools",
            Self::Ui => "UI",
            Self::App => "App",
        }
    }
}

/// One registry row: an action and its human description.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionInfo {
    /// The action.
    pub name: ActionName,
    /// Shown by which-key, help and the command palette.
    pub description: &'static str,
    // M0-10
    /// Which-key group.
    pub group: Group,
}

/// Every action with its description, in display order.
pub const REGISTRY: &[ActionInfo] = &[
    // M0-08
    ActionInfo {
        name: ActionName::Quit,
        description: "Quit sverb",
        group: Group::App,
    },
    ActionInfo {
        name: ActionName::Suspend,
        description: "Suspend to shell",
        group: Group::App,
    },
    ActionInfo {
        name: ActionName::Help,
        description: "Help (all keys)",
        group: Group::Ui,
    },
    // M0-10
    ActionInfo {
        name: ActionName::SendLeader,
        description: "Send leader key",
        group: Group::App,
    },
    ActionInfo {
        name: ActionName::NewTabPickHost,
        description: "New host tab",
        group: Group::SessionsTabs,
    },
    ActionInfo {
        name: ActionName::NewLocalTab,
        description: "New local tab",
        group: Group::SessionsTabs,
    },
    ActionInfo {
        name: ActionName::QuickConnect,
        description: "Quick connect",
        group: Group::SessionsTabs,
    },
    ActionInfo {
        name: ActionName::GoToTab1,
        description: "Go to tab 1",
        group: Group::SessionsTabs,
    },
    ActionInfo {
        name: ActionName::GoToTab2,
        description: "Go to tab 2",
        group: Group::SessionsTabs,
    },
    ActionInfo {
        name: ActionName::GoToTab3,
        description: "Go to tab 3",
        group: Group::SessionsTabs,
    },
    ActionInfo {
        name: ActionName::GoToTab4,
        description: "Go to tab 4",
        group: Group::SessionsTabs,
    },
    ActionInfo {
        name: ActionName::GoToTab5,
        description: "Go to tab 5",
        group: Group::SessionsTabs,
    },
    ActionInfo {
        name: ActionName::GoToTab6,
        description: "Go to tab 6",
        group: Group::SessionsTabs,
    },
    ActionInfo {
        name: ActionName::GoToTab7,
        description: "Go to tab 7",
        group: Group::SessionsTabs,
    },
    ActionInfo {
        name: ActionName::GoToTab8,
        description: "Go to tab 8",
        group: Group::SessionsTabs,
    },
    ActionInfo {
        name: ActionName::GoToTab9,
        description: "Go to tab 9",
        group: Group::SessionsTabs,
    },
    ActionInfo {
        name: ActionName::NextTab,
        description: "Next tab",
        group: Group::SessionsTabs,
    },
    ActionInfo {
        name: ActionName::PrevTab,
        description: "Previous tab",
        group: Group::SessionsTabs,
    },
    ActionInfo {
        name: ActionName::RenameTab,
        description: "Rename tab",
        group: Group::SessionsTabs,
    },
    ActionInfo {
        name: ActionName::MoveTabLeft,
        description: "Move tab left",
        group: Group::SessionsTabs,
    },
    ActionInfo {
        name: ActionName::MoveTabRight,
        description: "Move tab right",
        group: Group::SessionsTabs,
    },
    ActionInfo {
        name: ActionName::ClosePane,
        description: "Close pane",
        group: Group::SessionsTabs,
    },
    ActionInfo {
        name: ActionName::CloseTab,
        description: "Close tab",
        group: Group::SessionsTabs,
    },
    ActionInfo {
        name: ActionName::SplitHorizontal,
        description: "Split horizontal",
        group: Group::Panes,
    },
    ActionInfo {
        name: ActionName::SplitVertical,
        description: "Split vertical",
        group: Group::Panes,
    },
    ActionInfo {
        name: ActionName::FocusLeft,
        description: "Focus left",
        group: Group::Panes,
    },
    ActionInfo {
        name: ActionName::FocusDown,
        description: "Focus down",
        group: Group::Panes,
    },
    ActionInfo {
        name: ActionName::FocusUp,
        description: "Focus up",
        group: Group::Panes,
    },
    ActionInfo {
        name: ActionName::FocusRight,
        description: "Focus right",
        group: Group::Panes,
    },
    ActionInfo {
        name: ActionName::ResizeLeft,
        description: "Resize left",
        group: Group::Panes,
    },
    ActionInfo {
        name: ActionName::ResizeDown,
        description: "Resize down",
        group: Group::Panes,
    },
    ActionInfo {
        name: ActionName::ResizeUp,
        description: "Resize up",
        group: Group::Panes,
    },
    ActionInfo {
        name: ActionName::ResizeRight,
        description: "Resize right",
        group: Group::Panes,
    },
    ActionInfo {
        name: ActionName::ResizeMode,
        description: "Resize mode",
        group: Group::Panes,
    },
    ActionInfo {
        name: ActionName::ZoomPane,
        description: "Zoom pane",
        group: Group::Panes,
    },
    ActionInfo {
        name: ActionName::ToggleBroadcast,
        description: "Toggle broadcast",
        group: Group::Panes,
    },
    ActionInfo {
        name: ActionName::MarkBroadcastPane,
        description: "Mark broadcast",
        group: Group::Panes,
    },
    ActionInfo {
        name: ActionName::SessionInfo,
        description: "Session info",
        group: Group::Panes,
    },
    ActionInfo {
        name: ActionName::SharePane,
        description: "Share pane",
        group: Group::Panes,
    },
    ActionInfo {
        name: ActionName::Palette,
        description: "Command palette",
        group: Group::Tools,
    },
    ActionInfo {
        name: ActionName::SnippetPicker,
        description: "Snippets",
        group: Group::Tools,
    },
    ActionInfo {
        name: ActionName::CopyMode,
        description: "Copy mode",
        group: Group::Tools,
    },
    ActionInfo {
        name: ActionName::Autocomplete,
        description: "Autocomplete",
        group: Group::Tools,
    },
    ActionInfo {
        name: ActionName::AcceptGhostText,
        description: "Accept suggestion",
        group: Group::Tools,
    },
    ActionInfo {
        name: ActionName::ToggleRecording,
        description: "Toggle recording",
        group: Group::Tools,
    },
    ActionInfo {
        name: ActionName::ToggleViews,
        description: "Views / sessions",
        group: Group::Ui,
    },
    ActionInfo {
        name: ActionName::ToggleSidebar,
        description: "Toggle sidebar",
        group: Group::Ui,
    },
    ActionInfo {
        name: ActionName::NotificationHistory,
        description: "Notifications",
        group: Group::Ui,
    },
    ActionInfo {
        name: ActionName::ToggleLogPane,
        description: "Toggle log pane",
        group: Group::Ui,
    },
    ActionInfo {
        name: ActionName::LockVault,
        description: "Lock the vault",
        group: Group::App,
    },
    // M3-01
    ActionInfo {
        name: ActionName::EqualizePanes,
        description: "Equalize pane sizes",
        group: Group::Panes,
    },
    // M3-03
    ActionInfo {
        name: ActionName::SaveWorkspace,
        description: "Save workspace",
        group: Group::SessionsTabs,
    },
    ActionInfo {
        name: ActionName::OpenWorkspace,
        description: "Open workspace",
        group: Group::SessionsTabs,
    },
    ActionInfo {
        name: ActionName::ManageWorkspaces,
        description: "Manage workspaces",
        group: Group::SessionsTabs,
    },
];

// M3-01
/// Actions without a default key (reachable from the palette and `[keys.*]`).
pub const UNBOUND_BY_DEFAULT: &[ActionName] = &[
    ActionName::EqualizePanes,
    // M3-03
    ActionName::SaveWorkspace,
    ActionName::OpenWorkspace,
    ActionName::ManageWorkspaces,
];

/// The static action registry (used by which-key, help and the palette).
pub fn registry() -> &'static [ActionInfo] {
    REGISTRY
}

impl ActionName {
    /// The registry description for this action.
    pub fn description(self) -> &'static str {
        self.info().map_or("", |info| info.description)
    }

    // M0-10
    /// The registry row for this action.
    pub fn info(self) -> Option<&'static ActionInfo> {
        REGISTRY.iter().find(|info| info.name == self)
    }

    /// The which-key group of this action.
    pub fn group(self) -> Group {
        self.info().map_or(Group::App, |info| info.group)
    }

    /// Display order: by [`Group`], then by position in [`REGISTRY`].
    pub fn order(self) -> (Group, usize) {
        let index = REGISTRY
            .iter()
            .position(|info| info.name == self)
            .unwrap_or(usize::MAX);
        (self.group(), index)
    }
}

/// Accepts canonical `snake_case` names. For the template's `config.json`
/// (until M0-06/M0-10 replace it), the legacy `PascalCase` spelling of a *bindable*
/// action (`"Quit"`) is accepted too. Internal events such as `"Render"` are errors.
impl<'de> Deserialize<'de> for ActionName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse()
            .or_else(|_| to_snake_case(&s).parse())
            .map_err(|_| de::Error::custom(format!("unknown action `{s}`")))
    }
}

fn to_snake_case(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for (i, c) in s.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use strum::IntoEnumIterator;

    use super::*;

    // T-10
    #[test]
    fn registry_parses_and_rejects_internal_events() {
        assert_eq!(ActionName::from_str("quit"), Ok(ActionName::Quit));
        assert_eq!(ActionName::from_str("suspend"), Ok(ActionName::Suspend));
        assert_eq!(ActionName::from_str("help"), Ok(ActionName::Help));
        for internal in [
            "Render",
            "render",
            "tick",
            "Tick",
            "resize",
            "Resume",
            "clear_screen",
            "error",
        ] {
            assert!(
                ActionName::from_str(internal).is_err(),
                "{internal} must not parse"
            );
        }
    }

    // M0-10
    #[test]
    fn numbered_tabs_use_spec_names() {
        assert_eq!(ActionName::GoToTab1.to_string(), "go_to_tab_1");
        assert_eq!(
            ActionName::from_str("go_to_tab_9"),
            Ok(ActionName::GoToTab9)
        );
        assert_eq!(<&str>::from(ActionName::GoToTab3), "go_to_tab_3");
        assert_eq!(ActionName::SplitHorizontal.to_string(), "split_horizontal");
    }

    #[test]
    fn display_round_trips() {
        for a in ActionName::iter() {
            assert_eq!(ActionName::from_str(&a.to_string()), Ok(a));
        }
    }

    #[test]
    fn every_action_has_exactly_one_described_registry_entry() {
        for a in ActionName::iter() {
            let rows: Vec<_> = REGISTRY.iter().filter(|r| r.name == a).collect();
            assert_eq!(rows.len(), 1, "{a} must appear once in REGISTRY");
            assert!(
                !a.description().trim().is_empty(),
                "{a} needs a description"
            );
        }
        assert_eq!(REGISTRY.len(), ActionName::iter().count());
    }

    #[test]
    fn deserialize_accepts_legacy_pascal_case_but_not_internal_events() {
        let de = |s: &str| {
            ActionName::deserialize(de::value::StrDeserializer::<de::value::Error>::new(s))
        };
        assert_eq!(de("quit").ok(), Some(ActionName::Quit));
        assert_eq!(de("Quit").ok(), Some(ActionName::Quit));
        assert!(de("Render").is_err());
        assert!(de("Tick").is_err());
    }
}
