//! Field-level merge of two replicas of one item (SPEC §12.4).
//!
//! [`merge`] is a pure join of two [`ItemBody`]s:
//!
//! - every key in either body (known or unknown, §4.1) is a last-writer-wins register:
//!   the [`Stamped`] with the higher `(hlc, device)` wins. Two writes with the same stamp
//!   can only be the same write, but to keep the function total (and commutative even
//!   on corrupted input) the CBOR encoding of the value is the final tiebreak;
//! - the tombstone (`deleted`) merges the same way; whether the result is deleted is
//!   then derived by [`ItemBody::is_deleted`] (deleted iff the tombstone is `true` and
//!   newer than every field), so an edit newer than a delete resurrects the item;
//! - list fields (`tags`, `env`, …) are single registers holding the whole list (v1);
//! - `schema_version` is the max of both sides; a result newer than this build is
//!   read-only ([`migrate::is_read_only`](super::migrate::is_read_only));
//! - `kind` should never differ. If it does, the kind of the body with the higher
//!   newest stamp wins (ties broken by the kind itself) and an error is logged.
//!
//! On `body`, the function is commutative, associative and idempotent, so replicas
//! converge whatever the delivery order, duplication or delay
//! (`tests/merge_props.rs`).
//!
//! Merge never touches a clock. The sync engine calls
//! [`HlcClock::observe_stamp`](super::HlcClock::observe_stamp) for every received
//! stamp; a stamp too far ahead triggers the skew warning and only clamps the *local*
//! clock. The stored stamp is kept as-is and still wins merges here, which is what
//! keeps every replica identical (`docs/data-model.md`).

use std::cmp::Ordering;
use std::collections::BTreeMap;

use serde::Serialize;

use super::body::{ItemBody, Stamped};
use super::hlc::Hlc;
use super::ids::DeviceId;
use super::kinds::ItemKind;
use super::migrate::is_read_only;

/// The result of [`merge`].
#[derive(Debug, Clone, PartialEq)]
pub struct MergeOutcome {
    /// The merged body (identical whichever side is `local`).
    pub body: ItemBody,
    /// `local` was deleted and the merged body is not: show the toast
    /// "‘`<label>`’ was restored because it was edited on another device after being
    /// deleted" (§12.4).
    pub resurrected: bool,
    /// Keys whose register in the result differs from `local` (sorted). The tombstone is
    /// not a field and is reported through [`MergeOutcome::deletion_changed`].
    pub changed_fields: Vec<String>,
    /// Whether the merged tombstone register differs from `local`'s.
    pub deletion_changed: bool,
    /// The kinds differed and `remote`'s won (should not happen; logged).
    pub kind_changed: bool,
    /// Schema version of the result.
    pub schema: SchemaOutcome,
}

impl MergeOutcome {
    /// Whether the merge changed anything relative to `local` (the store can skip the
    /// write when it did not).
    pub fn changed(&self) -> bool {
        !self.changed_fields.is_empty()
            || self.deletion_changed
            || self.schema.version != self.schema.local_version
            || self.kind_changed
    }
}

/// Schema version handling of a merge (§4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaOutcome {
    /// `max(local, remote)`.
    pub version: u16,
    /// The version `local` had.
    pub local_version: u16,
    /// The merged version is newer than this build understands: open the item
    /// read-only ("Update sverb to edit this item").
    pub read_only: bool,
}

/// Merges `remote` into `local` (§12.4). Pure; see the module docs.
pub fn merge(local: &ItemBody, remote: &ItemBody) -> MergeOutcome {
    let kind = merge_kind(local, remote);

    let mut fields = BTreeMap::new();
    let mut changed_fields = Vec::new();
    for key in local.fields.keys().chain(remote.fields.keys()) {
        if fields.contains_key(key) {
            continue;
        }
        let l = local.fields.get(key);
        let winner = pick(l, remote.fields.get(key));
        if let Some(w) = winner {
            if l != Some(w) {
                changed_fields.push(key.clone());
            }
            fields.insert(key.clone(), w.clone());
        }
    }
    changed_fields.sort();

    let deleted = pick(local.deleted.as_ref(), remote.deleted.as_ref()).cloned();
    let deletion_changed = deleted != local.deleted;

    let body = ItemBody {
        kind,
        schema_version: local.schema_version.max(remote.schema_version),
        fields,
        deleted,
    };
    let schema = SchemaOutcome {
        version: body.schema_version,
        local_version: local.schema_version,
        read_only: is_read_only(&body),
    };
    let resurrected = local.is_deleted() && !body.is_deleted();
    MergeOutcome {
        kind_changed: kind != local.kind,
        body,
        resurrected,
        changed_fields,
        deletion_changed,
        schema,
    }
}

/// Folds [`merge`] over several replicas (e.g. a backup merged with the vault).
/// Returns `None` for an empty iterator.
pub fn merge_all<'a>(bodies: impl IntoIterator<Item = &'a ItemBody>) -> Option<ItemBody> {
    let mut it = bodies.into_iter();
    let first = it.next()?.clone();
    Some(it.fold(first, |acc, b| merge(&acc, b).body))
}

/// The LWW winner of two optional registers.
fn pick<'a, T: Serialize>(
    a: Option<&'a Stamped<T>>,
    b: Option<&'a Stamped<T>>,
) -> Option<&'a Stamped<T>> {
    match (a, b) {
        (Some(a), Some(b)) => Some(if cmp_register(a, b) == Ordering::Less {
            b
        } else {
            a
        }),
        (a, b) => a.or(b),
    }
}

/// Total order on registers: `(hlc, device)`, then the CBOR bytes of the value.
fn cmp_register<T: Serialize>(a: &Stamped<T>, b: &Stamped<T>) -> Ordering {
    a.cmp_stamp(b)
        .then_with(|| cbor_bytes(&a.value).cmp(&cbor_bytes(&b.value)))
}

fn cbor_bytes<T: Serialize>(v: &T) -> Vec<u8> {
    let mut out = Vec::new();
    // Encoding an in-memory `Value`/`bool` into a `Vec` does not fail.
    let _ = ciborium::into_writer(v, &mut out);
    out
}

/// The newest stamp anywhere in the body (fields and tombstone).
fn newest_stamp(body: &ItemBody) -> Option<(Hlc, DeviceId)> {
    let fields = body.fields.values().map(Stamped::stamp);
    let tomb = body.deleted.as_ref().map(Stamped::stamp);
    fields.chain(tomb).max()
}

/// `kind` of the result. Keyed by `(newest stamp, kind)`, which is itself a join, so the
/// choice stays commutative and associative.
fn merge_kind(local: &ItemBody, remote: &ItemBody) -> ItemKind {
    if local.kind == remote.kind {
        return local.kind;
    }
    tracing::error!(
        local = %local.kind,
        remote = %remote.kind,
        "item kind mismatch while merging; keeping the kind of the newer body",
    );
    let l = (newest_stamp(local), local.kind);
    let r = (newest_stamp(remote), remote.kind);
    l.max(r).1
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ciborium::Value;

    use super::*;
    use crate::model::hlc::{HlcClock, MAX_SKEW, ManualClock};

    const T0: Duration = Duration::from_secs(1_800_000_000);

    fn dev(b: u8) -> DeviceId {
        DeviceId::from_bytes([b; 16])
    }

    fn at(secs: u64) -> Hlc {
        Hlc::from_duration(T0 + Duration::from_secs(secs))
    }

    fn put(b: &mut ItemBody, key: &str, v: impl Into<Value>, hlc: Hlc, d: u8) {
        b.fields
            .insert(key.into(), Stamped::new(v.into(), hlc, dev(d)));
    }

    fn base() -> ItemBody {
        let mut b = ItemBody::new(ItemKind::Host, 1);
        put(&mut b, "label", "web", at(1), 1);
        put(&mut b, "address", "web.example.com", at(1), 1);
        put(&mut b, "port", 22, at(1), 1);
        b
    }

    #[test]
    fn concurrent_edits_to_different_fields_both_survive() {
        let mut a = base();
        let mut b = base();
        put(&mut a, "port", 2222, at(10), 1);
        put(&mut b, "username", "deploy", at(11), 2);

        let out = merge(&a, &b);
        assert_eq!(out.body.get("port"), Some(&Value::from(2222)));
        assert_eq!(out.body.get("username"), Some(&Value::from("deploy")));
        assert_eq!(out.changed_fields, vec!["username".to_owned()]);
        assert_eq!(out.body, merge(&b, &a).body);
        assert!(!out.resurrected);
    }

    #[test]
    fn same_field_higher_hlc_then_higher_device_wins() {
        let mut a = base();
        let mut b = base();
        put(&mut a, "port", 2222, at(10), 9);
        put(&mut b, "port", 2200, at(11), 1);
        assert_eq!(merge(&a, &b).body.get("port"), Some(&Value::from(2200)));
        assert_eq!(merge(&b, &a).body.get("port"), Some(&Value::from(2200)));

        // Equal HLC: the higher device id wins.
        put(&mut a, "port", 2222, at(20), 2);
        put(&mut b, "port", 2200, at(20), 7);
        assert_eq!(merge(&a, &b).body.get("port"), Some(&Value::from(2200)));
        assert_eq!(merge(&b, &a).body.get("port"), Some(&Value::from(2200)));

        // Equal stamp and device (only possible for corrupted input): still total and
        // commutative, decided by the CBOR bytes of the value.
        put(&mut a, "port", 1, at(30), 3);
        put(&mut b, "port", 2, at(30), 3);
        assert_eq!(merge(&a, &b).body, merge(&b, &a).body);
    }

    #[test]
    fn delete_vs_older_edit_stays_deleted() {
        let mut local = base();
        local.deleted = Some(Stamped::new(true, at(20), dev(1)));
        assert!(local.is_deleted());
        let mut remote = base();
        put(&mut remote, "label", "web-old", at(10), 2);

        let out = merge(&local, &remote);
        assert!(out.body.is_deleted());
        assert!(!out.resurrected);
        assert_eq!(out.body, merge(&remote, &local).body);
        // The remote side sees the delete arrive (no toast for a delete).
        let back = merge(&remote, &local);
        assert!(back.deletion_changed);
        assert!(!back.resurrected);
    }

    #[test]
    fn delete_vs_newer_edit_resurrects() {
        let mut local = base();
        local.deleted = Some(Stamped::new(true, at(20), dev(1)));
        let mut remote = base();
        put(&mut remote, "label", "web-new", at(30), 2);

        let out = merge(&local, &remote);
        assert!(!out.body.is_deleted());
        assert!(out.resurrected);
        assert_eq!(out.changed_fields, vec!["label".to_owned()]);
        // The tombstone itself is kept: it's only outranked by the newer edit.
        assert_eq!(out.body.deleted.as_ref().map(|d| d.value), Some(true));
        // The editing side was never deleted, so it gets no toast.
        let back = merge(&remote, &local);
        assert!(!back.resurrected);
        assert_eq!(back.body, out.body);
    }

    #[test]
    fn tombstone_only_envelope_deletes() {
        let local = base();
        let mut tomb = ItemBody::new(ItemKind::Host, 1);
        tomb.deleted = Some(Stamped::new(true, at(5), dev(2)));
        let out = merge(&local, &tomb);
        assert!(out.body.is_deleted());
        assert!(out.deletion_changed);
        assert!(out.changed_fields.is_empty());
        assert_eq!(out.body.get("label"), Some(&Value::from("web")));
    }

    #[test]
    fn unknown_fields_survive() {
        let local = base();
        let mut remote = base();
        put(
            &mut remote,
            "future.thing",
            Value::Array(vec![1.into()]),
            at(3),
            2,
        );
        let out = merge(&local, &remote);
        assert_eq!(
            out.body.get("future.thing"),
            Some(&Value::Array(vec![1.into()]))
        );
        // ...and an old client re-merging its stale copy doesn't drop it.
        assert!(merge(&out.body, &local).body.contains("future.thing"));
    }

    #[test]
    fn list_fields_are_whole_value_lww() {
        let mut a = base();
        let mut b = base();
        put(
            &mut a,
            "tags",
            Value::Array(vec!["x".into(), "y".into()]),
            at(10),
            1,
        );
        put(&mut b, "tags", Value::Array(vec!["z".into()]), at(11), 2);
        assert_eq!(
            merge(&a, &b).body.get("tags"),
            Some(&Value::Array(vec!["z".into()]))
        );
    }

    #[test]
    fn unset_wins_over_older_and_loses_to_newer() {
        let mut a = base();
        let mut b = base();
        put(&mut a, "username", Value::Null, at(10), 1);
        put(&mut b, "username", "root", at(5), 2);
        let out = merge(&a, &b);
        assert!(out.body.contains("username"));
        assert_eq!(out.body.get("username"), None);

        put(&mut b, "username", "root", at(15), 2);
        assert_eq!(
            merge(&a, &b).body.get("username"),
            Some(&Value::from("root"))
        );
    }

    #[test]
    fn schema_version_is_max_and_read_only_propagates() {
        let a = base();
        let mut b = base();
        let out = merge(&a, &b);
        assert_eq!(out.schema.version, 1);
        assert!(!out.schema.read_only);
        assert!(!out.changed());

        b.schema_version = 99;
        let out = merge(&a, &b);
        assert_eq!(out.schema.version, 99);
        assert_eq!(out.schema.local_version, 1);
        assert!(out.schema.read_only);
        assert!(out.changed());
        assert_eq!(merge(&b, &a).body.schema_version, 99);
        assert!(crate::model::migrate::is_read_only(&out.body));
    }

    #[test]
    fn skewed_remote_stamp_warns_but_still_wins() {
        let mut clock = HlcClock::new(ManualClock::new(T0));
        let mut local = base();
        local.set("port", 2222, &mut clock, dev(1));

        let mut remote = base();
        let ahead = at(600);
        put(&mut remote, "port", 8022, ahead, 2);

        // The sync engine observes every incoming stamp before merging.
        let warnings: Vec<_> = remote
            .fields
            .values()
            .filter_map(|s| clock.observe_stamp(s).err())
            .collect();
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].device, dev(2));
        assert!(warnings[0].ahead_by >= Duration::from_secs(599));

        // Merge keeps the original (skewed) stamp: it has the higher HLC.
        let out = merge(&local, &remote);
        assert_eq!(out.body.get("port"), Some(&Value::from(8022)));
        assert_eq!(out.body.get_stamped("port").map(|s| s.hlc), Some(ahead));

        // Clamping only affected the local clock...
        assert!(clock.last() < ahead);
        assert!(clock.last().physical() <= T0 + MAX_SKEW);
        // ...and a later local write still overrides the skewed value.
        let mut merged = out.body;
        assert!(merged.set("port", 22, &mut clock, dev(1)));
        assert!(merged.get_stamped("port").is_some_and(|s| s.hlc > ahead));
        assert_eq!(
            merge(&merged, &remote).body.get("port"),
            Some(&Value::from(22))
        );
    }

    #[test]
    fn kind_mismatch_keeps_newer_kind() {
        let a = base();
        let mut b = ItemBody::new(ItemKind::Snippet, 1);
        put(&mut b, "body", "ls", at(50), 2);
        let out = merge(&a, &b);
        assert_eq!(out.body.kind, ItemKind::Snippet);
        assert!(out.kind_changed);
        assert_eq!(merge(&b, &a).body, out.body);
    }

    #[test]
    fn merge_all_folds() {
        let a = base();
        let mut b = base();
        put(&mut b, "port", 1, at(9), 2);
        assert_eq!(merge_all([&a, &b]), Some(merge(&a, &b).body));
        assert_eq!(merge_all(std::iter::empty()), None);
    }
}
