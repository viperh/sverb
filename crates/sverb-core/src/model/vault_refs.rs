//! M5-02: references across vaults (SPEC §4.12, §13.1, §13.4).
//!
//! Items reference each other by id (16-byte CBOR byte strings: `group_id`,
//! `identity_id`, `key_id`, `jump_chain`, `port_forwards`, …). An item in a
//! **shared** vault must only reference items of the same vault: other members
//! can't resolve anything else. The single exception is the
//! [`CredentialOverride`](super::CredentialOverride), which lives in a personal
//! vault and points at a shared host through `shared_host_id`.
//!
//! * [`item_refs`]: every id reference in a body, by field;
//! * [`check_vault_refs`]: the §13.4 rule for one item about to be written into
//!   a vault (save, move, copy, import);
//! * [`foreign_closure`]: the items a move or copy into a shared vault would have
//!   to bring along (transitively: a host's identity and that identity's key), so
//!   the UI can offer "also copy the identity" instead of blocking;
//! * [`plan_transfer`]: "Move to vault…" / "Copy to vault…" (§13.1): new ids in
//!   the target, references rewritten, and for a move the sources tombstoned.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use ciborium::Value;

use super::body::ItemBody;
use super::hlc::HlcClock;
use super::ids::DeviceId;
use super::ids::{ItemId, VaultId};
use super::kinds::ItemKind;
use super::validate::ValidationError;

/// The field of a [`CredentialOverride`](super::CredentialOverride) that may point
/// into another vault.
pub const OVERRIDE_HOST_FIELD: &str = "shared_host_id";

/// The message of a cross-vault reference from a shared vault (§13.4).
pub const SHARED_CROSS_VAULT_MESSAGE: &str = "items in a shared vault can only reference items of the same vault; \
     move or copy the referenced item into this vault first";

/// The message of a credential override outside a personal vault.
pub const OVERRIDE_NOT_PERSONAL_MESSAGE: &str = "credential overrides live in your personal vault";

/// Whether a vault is the user's own or an org's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VaultScope {
    /// The personal vault.
    Personal,
    /// A shared (org) vault.
    Shared,
}

/// One reference that breaks the rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossVaultRef {
    /// The referencing field (`identity_id`, `jump_chain`, …).
    pub field: String,
    /// The referenced item.
    pub target: ItemId,
    /// Its vault.
    pub target_vault: VaultId,
}

fn collect(field: &str, value: &Value, out: &mut Vec<(String, ItemId)>) {
    match value {
        Value::Bytes(_) => {
            if let Some(id) = ItemId::from_value(value) {
                out.push((field.to_owned(), id));
            }
        }
        Value::Array(items) => {
            for v in items {
                collect(field, v, out);
            }
        }
        Value::Map(entries) => {
            for (_, v) in entries {
                collect(field, v, out);
            }
        }
        Value::Tag(_, inner) => collect(field, inner, out),
        _ => {}
    }
}

/// Every item id referenced by `body`, as `(field, id)` in field order. Deleted
/// bodies reference nothing.
pub fn item_refs(body: &ItemBody) -> Vec<(String, ItemId)> {
    let mut out = Vec::new();
    if body.is_deleted() {
        return out;
    }
    for (field, stamped) in &body.fields {
        collect(field, &stamped.value, &mut out);
    }
    out
}

/// Checks the §13.4 rule for `body` written into `vault` (of `scope`).
/// `vault_of` gives the vault of a live item; references to unknown items pass
/// (they resolve as missing, §12.4).
///
/// * shared vault: every reference must stay in `vault`; a credential override
///   is refused altogether;
/// * personal vault: anything goes (the user can resolve everything they hold).
///
/// # Errors
/// Every offending reference.
pub fn check_vault_refs(
    vault: VaultId,
    scope: VaultScope,
    body: &ItemBody,
    vault_of: impl Fn(ItemId) -> Option<VaultId>,
) -> Result<(), Vec<CrossVaultRef>> {
    if scope == VaultScope::Personal {
        return Ok(());
    }
    let refs = item_refs(body);
    if body.kind == ItemKind::CredentialOverride {
        let target = refs
            .iter()
            .find(|(f, _)| f == OVERRIDE_HOST_FIELD)
            .map_or(ItemId::from_bytes([0; 16]), |(_, id)| *id);
        return Err(vec![CrossVaultRef {
            field: OVERRIDE_HOST_FIELD.to_owned(),
            target,
            target_vault: vault_of(target).unwrap_or(vault),
        }]);
    }
    let bad: Vec<CrossVaultRef> = refs
        .into_iter()
        .filter_map(|(field, target)| {
            let v = vault_of(target)?;
            (v != vault).then_some(CrossVaultRef {
                field,
                target,
                target_vault: v,
            })
        })
        .collect();
    if bad.is_empty() { Ok(()) } else { Err(bad) }
}

/// [`check_vault_refs`] as form errors (one per offending field).
///
/// # Errors
/// [`ValidationError`]s.
pub fn validate_vault_refs(
    vault: VaultId,
    scope: VaultScope,
    body: &ItemBody,
    vault_of: impl Fn(ItemId) -> Option<VaultId>,
) -> Result<(), Vec<ValidationError>> {
    check_vault_refs(vault, scope, body, vault_of).map_err(|bad| {
        let msg = if body.kind == ItemKind::CredentialOverride {
            OVERRIDE_NOT_PERSONAL_MESSAGE
        } else {
            SHARED_CROSS_VAULT_MESSAGE
        };
        let mut fields: Vec<String> = bad.into_iter().map(|b| b.field).collect();
        fields.dedup();
        fields
            .into_iter()
            .map(|f| ValidationError::new(&f, msg))
            .collect()
    })
}

/// The items outside `target` that `roots` reference, directly or through each
/// other (a host → its identity → that identity's key; a group → its parent),
/// in discovery order. `item` gives the vault and body of a live item; unknown
/// ids are skipped. The roots themselves are never included.
pub fn foreign_closure<'a>(
    roots: &[ItemId],
    target: VaultId,
    item: impl Fn(ItemId) -> Option<(VaultId, &'a ItemBody)>,
) -> Vec<ItemId> {
    let root_set: BTreeSet<ItemId> = roots.iter().copied().collect();
    let mut seen: BTreeSet<ItemId> = root_set.clone();
    let mut queue: VecDeque<ItemId> = roots.iter().copied().collect();
    let mut out = Vec::new();
    while let Some(id) = queue.pop_front() {
        let Some((_, body)) = item(id) else {
            continue;
        };
        for (_, r) in item_refs(body) {
            if !seen.insert(r) {
                continue;
            }
            let Some((v, _)) = item(r) else {
                continue;
            };
            if v != target {
                out.push(r);
                queue.push_back(r);
            }
        }
    }
    out
}

/// Move or copy (§13.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferMode {
    /// New ids in the target; the sources are tombstoned.
    Move,
    /// New ids in the target; the sources stay.
    Copy,
}

/// What to do with referenced items that would end up in another vault than
/// the target (only relevant for a shared target, §13.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefPolicy {
    /// Refuse, listing the references ([`TransferError::Blocked`]).
    Block,
    /// Copy the referenced items into the target too (the originals stay).
    Copy,
    /// Move the referenced items too (the originals are tombstoned).
    Move,
}

/// Why a transfer can't be planned.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransferError {
    /// The item would reference items outside the shared target vault.
    #[error("{} referenced item(s) are in another vault", .0.len())]
    Blocked(Vec<CrossVaultRef>),
    /// An item to transfer does not exist (or is deleted).
    #[error("item {0} not found")]
    Unknown(ItemId),
    /// The item is already in the target vault.
    #[error("the item is already in that vault")]
    SameVault,
}

/// The writes of a transfer.
#[derive(Debug, Clone, Default)]
pub struct TransferPlan {
    /// New items of the target vault: `(new id, body)`, roots first.
    pub writes: Vec<(ItemId, ItemBody)>,
    /// Sources to tombstone: `(id, its vault, tombstoned body)`.
    pub tombstones: Vec<(ItemId, VaultId, ItemBody)>,
    /// Old id → new id of every transferred item.
    pub id_map: BTreeMap<ItemId, ItemId>,
    /// The referenced items brought along (old ids), in discovery order.
    pub brought: Vec<ItemId>,
}

fn remap_value(value: &mut Value, map: &BTreeMap<ItemId, ItemId>) {
    match value {
        Value::Bytes(_) => {
            if let Some(new) = ItemId::from_value(value).and_then(|id| map.get(&id)) {
                *value = Value::from(*new);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(|v| remap_value(v, map)),
        Value::Map(entries) => entries.iter_mut().for_each(|(_, v)| remap_value(v, map)),
        Value::Tag(_, inner) => remap_value(inner, map),
        _ => {}
    }
}

/// Rewrites every reference of `body` through `map` (stamps kept: the
/// rewritten item is new, nothing merges against it).
pub fn remap_refs(body: &mut ItemBody, map: &BTreeMap<ItemId, ItemId>) {
    for f in body.fields.values_mut() {
        remap_value(&mut f.value, map);
    }
}

/// Plans "Move to vault…" / "Copy to vault…" of `roots` into `target` (§13.1:
/// a move re-encrypts under the target vault key with a **new id** and tombstones
/// the source). For a shared target, references that would leave the vault are
/// handled by `refs` ([`foreign_closure`]). `item` gives the vault and body of
/// live items; `new_id` makes the target ids.
///
/// # Errors
/// [`TransferError`].
#[allow(clippy::too_many_arguments)]
pub fn plan_transfer<'a>(
    roots: &[ItemId],
    target: VaultId,
    scope: VaultScope,
    mode: TransferMode,
    refs: RefPolicy,
    item: impl Fn(ItemId) -> Option<(VaultId, &'a ItemBody)>,
    mut new_id: impl FnMut() -> ItemId,
    clock: &mut HlcClock,
    device: DeviceId,
) -> Result<TransferPlan, TransferError> {
    for id in roots {
        let (v, body) = item(*id).ok_or(TransferError::Unknown(*id))?;
        if body.is_deleted() {
            return Err(TransferError::Unknown(*id));
        }
        if v == target {
            return Err(TransferError::SameVault);
        }
    }
    let extra = if scope == VaultScope::Shared {
        foreign_closure(roots, target, &item)
    } else {
        Vec::new()
    };
    if !extra.is_empty() && refs == RefPolicy::Block {
        let roots_set: BTreeSet<ItemId> = roots.iter().copied().collect();
        let mut bad = Vec::new();
        for id in roots {
            let Some((_, body)) = item(*id) else { continue };
            for (field, r) in item_refs(body) {
                if roots_set.contains(&r) {
                    continue;
                }
                if let Some((v, _)) = item(r)
                    && v != target
                {
                    bad.push(CrossVaultRef {
                        field,
                        target: r,
                        target_vault: v,
                    });
                }
            }
        }
        return Err(TransferError::Blocked(bad));
    }
    let mut plan = TransferPlan {
        brought: extra.clone(),
        ..TransferPlan::default()
    };
    let all: Vec<ItemId> = roots.iter().copied().chain(extra.iter().copied()).collect();
    for id in &all {
        plan.id_map.insert(*id, new_id());
    }
    let vault_of = |id: ItemId| {
        if plan.id_map.values().any(|n| *n == id) {
            Some(target)
        } else {
            item(id).map(|(v, _)| v)
        }
    };
    let mut writes = Vec::with_capacity(all.len());
    for id in &all {
        let Some((_, body)) = item(*id) else { continue };
        let mut b = body.clone();
        remap_refs(&mut b, &plan.id_map);
        if let Err(bad) = check_vault_refs(target, scope, &b, vault_of) {
            return Err(TransferError::Blocked(bad));
        }
        writes.push((plan.id_map[id], b));
    }
    plan.writes = writes;
    let mut tomb = |id: ItemId, plan: &mut TransferPlan| {
        if let Some((v, body)) = item(id) {
            let mut b = body.clone();
            b.delete(clock, device);
            plan.tombstones.push((id, v, b));
        }
    };
    if mode == TransferMode::Move {
        for id in roots {
            tomb(*id, &mut plan);
        }
    }
    if refs == RefPolicy::Move {
        for id in &extra {
            tomb(*id, &mut plan);
        }
    }
    Ok(plan)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::model::{CredentialOverride, DeviceId, HlcClock};

    fn body(kind: ItemKind, refs: &[(&str, ItemId)]) -> ItemBody {
        let mut clock = HlcClock::default();
        let dev = DeviceId::new();
        let mut b = ItemBody::new(kind, 1);
        b.set("label", "x", &mut clock, dev);
        for (f, id) in refs {
            b.set(f, Value::from(*id), &mut clock, dev);
        }
        b
    }

    // T-08: a shared host referencing a personal key is refused; an override in
    // the personal vault referencing a shared host is allowed.
    #[test]
    fn t08_cross_vault_validation() {
        let personal = VaultId::new();
        let shared = VaultId::new();
        let key = ItemId::new();
        let shared_host = ItemId::new();
        let shared_key = ItemId::new();
        let vaults: BTreeMap<ItemId, VaultId> =
            [(key, personal), (shared_host, shared), (shared_key, shared)].into();
        let vault_of = |id: ItemId| vaults.get(&id).copied();

        let host = body(ItemKind::Host, &[("key_id", key)]);
        let err = check_vault_refs(shared, VaultScope::Shared, &host, vault_of).unwrap_err();
        assert_eq!(
            err,
            vec![CrossVaultRef {
                field: "key_id".into(),
                target: key,
                target_vault: personal
            }]
        );
        let form = validate_vault_refs(shared, VaultScope::Shared, &host, vault_of).unwrap_err();
        assert_eq!(form[0].field, "key_id");
        assert_eq!(form[0].message, SHARED_CROSS_VAULT_MESSAGE);
        // The same host in the personal vault is fine; so is a shared host using a
        // shared key, or a missing reference.
        assert!(check_vault_refs(personal, VaultScope::Personal, &host, vault_of).is_ok());
        let ok = body(ItemKind::Host, &[("key_id", shared_key)]);
        assert!(check_vault_refs(shared, VaultScope::Shared, &ok, vault_of).is_ok());
        let missing = body(ItemKind::Host, &[("key_id", ItemId::new())]);
        assert!(check_vault_refs(shared, VaultScope::Shared, &missing, vault_of).is_ok());

        // The override: personal → shared host (and a personal key) is allowed.
        let mut clock = HlcClock::default();
        let mut o = CredentialOverride::new(shared_host);
        o.key_id = Some(key);
        let ob = o.to_body(&mut clock, DeviceId::new());
        assert!(check_vault_refs(personal, VaultScope::Personal, &ob, vault_of).is_ok());
        // An override stored in a shared vault is refused.
        let e = validate_vault_refs(shared, VaultScope::Shared, &ob, vault_of).unwrap_err();
        assert!(e.iter().all(|e| e.message == OVERRIDE_NOT_PERSONAL_MESSAGE));
    }

    #[test]
    fn refs_in_lists_and_closure() {
        let personal = VaultId::new();
        let shared = VaultId::new();
        let (j1, j2, ident, key) = (ItemId::new(), ItemId::new(), ItemId::new(), ItemId::new());
        let mut clock = HlcClock::default();
        let dev = DeviceId::new();
        let mut host = body(ItemKind::Host, &[("identity_id", ident)]);
        host.set(
            "jump_chain",
            Value::Array(vec![Value::from(j1), Value::from(j2)]),
            &mut clock,
            dev,
        );
        let refs = item_refs(&host);
        assert_eq!(refs.len(), 3);
        assert!(refs.contains(&("jump_chain".into(), j2)));

        let identity = body(ItemKind::Identity, &[("key_id", key)]);
        let k = body(ItemKind::Key, &[]);
        let jump = body(ItemKind::Host, &[]);
        let host_id = ItemId::new();
        let items: BTreeMap<ItemId, (VaultId, &ItemBody)> = [
            (host_id, (personal, &host)),
            (ident, (personal, &identity)),
            (key, (personal, &k)),
            (j1, (shared, &jump)),
        ]
        .into();
        let closure = foreign_closure(&[host_id], shared, |id| items.get(&id).copied());
        // j1 is already in the target; j2 is unknown; identity and its key come along.
        assert_eq!(closure, vec![ident, key]);
    }

    // T-06 (core): a personal host using a personal identity, moved to a shared
    // vault: blocked with the reference listed; with RefPolicy::Copy the host and
    // an identity copy land in the target (new ids, rewired), the host source is
    // tombstoned and the identity stays.
    #[test]
    fn t06_move_with_referenced_identity() {
        let personal = VaultId::new();
        let shared = VaultId::new();
        let (host_id, ident) = (ItemId::new(), ItemId::new());
        let host = body(ItemKind::Host, &[("identity_id", ident)]);
        let identity = body(ItemKind::Identity, &[]);
        let items: BTreeMap<ItemId, (VaultId, &ItemBody)> =
            [(host_id, (personal, &host)), (ident, (personal, &identity))].into();
        let lookup = |id: ItemId| items.get(&id).copied();
        let mut clock = HlcClock::default();
        let dev = DeviceId::new();

        let err = plan_transfer(
            &[host_id],
            shared,
            VaultScope::Shared,
            TransferMode::Move,
            RefPolicy::Block,
            lookup,
            ItemId::new,
            &mut clock,
            dev,
        )
        .unwrap_err();
        let TransferError::Blocked(bad) = err else {
            panic!("expected Blocked")
        };
        assert_eq!(bad[0].field, "identity_id");
        assert_eq!(bad[0].target, ident);

        let plan = plan_transfer(
            &[host_id],
            shared,
            VaultScope::Shared,
            TransferMode::Move,
            RefPolicy::Copy,
            lookup,
            ItemId::new,
            &mut clock,
            dev,
        )
        .unwrap();
        assert_eq!(plan.writes.len(), 2);
        assert_eq!(plan.brought, vec![ident]);
        let new_host = plan.id_map[&host_id];
        let new_ident = plan.id_map[&ident];
        assert_ne!(new_host, host_id);
        let (_, hb) = plan.writes.iter().find(|(id, _)| *id == new_host).unwrap();
        assert_eq!(
            ItemId::from_value(hb.get("identity_id").unwrap()),
            Some(new_ident)
        );
        assert_eq!(plan.tombstones.len(), 1);
        assert_eq!(plan.tombstones[0].0, host_id);
        assert!(plan.tombstones[0].2.is_deleted());

        // Copy into the personal vault needs no reference checks; the same vault
        // is refused.
        let plan = plan_transfer(
            &[host_id],
            VaultId::new(),
            VaultScope::Personal,
            TransferMode::Copy,
            RefPolicy::Block,
            lookup,
            ItemId::new,
            &mut clock,
            dev,
        )
        .unwrap();
        assert_eq!(plan.writes.len(), 1);
        assert!(plan.tombstones.is_empty());
        assert!(matches!(
            plan_transfer(
                &[host_id],
                personal,
                VaultScope::Personal,
                TransferMode::Copy,
                RefPolicy::Block,
                lookup,
                ItemId::new,
                &mut clock,
                dev,
            ),
            Err(TransferError::SameVault)
        ));
    }
}
