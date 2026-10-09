//! Schema versions and read-time migrations (SPEC §4.1).
//!
//! `schema_version` bumps only for breaking changes. Migrations are pure
//! `fn(ItemBody) -> ItemBody` steps that run on read, one version at a time. A body
//! with a newer version than this build understands is opened **read-only**; the store
//! rejects writes to it and the UI shows "Update sverb to edit this item".

use super::body::ItemBody;
use super::kinds::ItemKind;

/// The schema version this build writes, per kind. All kinds start at 1.
pub const CURRENT_SCHEMA: [(ItemKind, u16); 13] = [
    (ItemKind::Host, 1),
    (ItemKind::Group, 1),
    (ItemKind::Identity, 1),
    (ItemKind::Key, 1),
    (ItemKind::Certificate, 1),
    (ItemKind::KnownHost, 1),
    (ItemKind::PortForward, 1),
    (ItemKind::Snippet, 1),
    (ItemKind::Workspace, 1),
    (ItemKind::Tag, 1),
    (ItemKind::HistoryEntry, 1),
    (ItemKind::ConnLog, 1),
    (ItemKind::CredentialOverride, 1),
];

/// The schema version this build understands for `kind`.
pub fn current_schema(kind: ItemKind) -> u16 {
    CURRENT_SCHEMA
        .iter()
        .find(|(k, _)| *k == kind)
        .map_or(1, |(_, v)| *v)
}

/// Whether `body` comes from a newer schema than this build understands.
pub fn is_read_only(body: &ItemBody) -> bool {
    body.schema_version > current_schema(body.kind)
}

/// A migration step from version `n` to `n + 1`.
pub type Migration = fn(ItemBody) -> ItemBody;

/// The steps for `kind`: element `i` migrates version `i + 1` to `i + 2`.
/// Empty while every kind is at version 1.
fn migrations(_kind: ItemKind) -> &'static [Migration] {
    &[]
}

/// What [`migrate`] did.
#[derive(Debug, Clone, PartialEq)]
pub struct MigrateOutcome {
    /// The (possibly migrated) body.
    pub body: ItemBody,
    /// The version the body had before migration, if any step ran.
    pub migrated_from: Option<u16>,
    /// The body is newer than this build: show it, don't edit it.
    pub read_only: bool,
}

/// Runs the pending migrations for `body`'s kind, in order.
pub fn migrate(body: ItemBody) -> MigrateOutcome {
    migrate_with(body, current_schema, migrations)
}

fn migrate_with(
    mut body: ItemBody,
    current: impl Fn(ItemKind) -> u16,
    steps: impl Fn(ItemKind) -> &'static [Migration],
) -> MigrateOutcome {
    let target = current(body.kind);
    if body.schema_version > target {
        return MigrateOutcome {
            body,
            migrated_from: None,
            read_only: true,
        };
    }
    let from = body.schema_version;
    let steps = steps(body.kind);
    while body.schema_version < target {
        let idx = usize::from(body.schema_version.max(1) - 1);
        match steps.get(idx) {
            Some(step) => {
                let next = body.schema_version.max(1) + 1;
                body = step(body);
                body.schema_version = next;
            }
            // No step registered: the layout is compatible; just relabel.
            None => body.schema_version = target,
        }
    }
    MigrateOutcome {
        migrated_from: (from != body.schema_version).then_some(from),
        body,
        read_only: false,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ciborium::Value;

    use super::*;
    use crate::model::{DeviceId, Hlc, Stamped};

    #[test]
    fn current_bodies_are_untouched() {
        let body = ItemBody::new(ItemKind::Host, 1);
        let out = migrate(body.clone());
        assert_eq!(out.body, body);
        assert!(!out.read_only);
        assert_eq!(out.migrated_from, None);
    }

    #[test]
    fn newer_bodies_are_read_only() {
        let out = migrate(ItemBody::new(ItemKind::Snippet, 99));
        assert!(out.read_only);
        assert_eq!(out.body.schema_version, 99);
    }

    fn rename_user(mut b: ItemBody) -> ItemBody {
        if let Some(v) = b.fields.remove("user") {
            b.fields.insert("username".into(), v);
        }
        b
    }

    #[test]
    fn steps_run_in_order() {
        static STEPS: [Migration; 2] = [rename_user, |b| b];
        let mut body = ItemBody::new(ItemKind::Host, 1);
        let stamp = Hlc::from_duration(Duration::from_secs(1));
        body.fields.insert(
            "user".into(),
            Stamped::new(Value::from("root"), stamp, DeviceId::from_bytes([1; 16])),
        );
        let out = migrate_with(body, |_| 3, |_| &STEPS);
        assert_eq!(out.migrated_from, Some(1));
        assert_eq!(out.body.schema_version, 3);
        assert_eq!(out.body.get("username"), Some(&Value::from("root")));
        assert!(!out.read_only);
    }
}
