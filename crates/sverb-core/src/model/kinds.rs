//! Item kinds (SPEC §4.1).

use std::fmt;

use serde::{Deserialize, Serialize};

/// What an [`ItemBody`](super::ItemBody) describes. Encoded as a stable lowercase string.
///
/// `#[non_exhaustive]`: M5-02 adds `CredentialOverride` (§13.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ItemKind {
    /// §4.2
    Host,
    /// §4.3
    Group,
    /// §4.4
    Identity,
    /// §4.5
    Key,
    /// §4.6
    Certificate,
    /// §4.7
    KnownHost,
    /// §4.8
    PortForward,
    /// §4.9
    Snippet,
    /// §4.10
    Workspace,
    /// §4.11
    Tag,
    /// §4.12
    HistoryEntry,
    /// §4.12
    ConnLog,
}

impl ItemKind {
    /// Every kind this build knows.
    pub const ALL: [ItemKind; 12] = [
        ItemKind::Host,
        ItemKind::Group,
        ItemKind::Identity,
        ItemKind::Key,
        ItemKind::Certificate,
        ItemKind::KnownHost,
        ItemKind::PortForward,
        ItemKind::Snippet,
        ItemKind::Workspace,
        ItemKind::Tag,
        ItemKind::HistoryEntry,
        ItemKind::ConnLog,
    ];

    /// The stable wire string (`"host"`, `"port-forward"`, …).
    pub const fn as_str(&self) -> &'static str {
        match self {
            ItemKind::Host => "host",
            ItemKind::Group => "group",
            ItemKind::Identity => "identity",
            ItemKind::Key => "key",
            ItemKind::Certificate => "certificate",
            ItemKind::KnownHost => "known-host",
            ItemKind::PortForward => "port-forward",
            ItemKind::Snippet => "snippet",
            ItemKind::Workspace => "workspace",
            ItemKind::Tag => "tag",
            ItemKind::HistoryEntry => "history-entry",
            ItemKind::ConnLog => "conn-log",
        }
    }
}

impl fmt::Display for ItemKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_strings_match_serde() -> Result<(), Box<dyn std::error::Error>> {
        for kind in ItemKind::ALL {
            let mut buf = Vec::new();
            ciborium::into_writer(&kind, &mut buf)?;
            let v: ciborium::Value = ciborium::from_reader(buf.as_slice())?;
            assert_eq!(v.as_text(), Some(kind.as_str()));
        }
        Ok(())
    }
}
