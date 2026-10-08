# M4-06 — Field-level merge: LWW per field, tombstones, resurrection, clock skew

| | |
|---|---|
| **Milestone** | M4 |
| **Touches** | `crates/sverb-core/src/model/merge.rs`, `crates/sverb-core/tests/merge_props.rs` |
| **Spec refs** | §12.4, §4.1 (stamped fields, unknown fields), §19 (Merge/sync property tests: N devices converge, tombstone and resurrection cases) |
| **Depends on** | M1-02 |
| **Blocks** | M4-07, M2-11 (backup overwrite merge) |

---

## 1. Current state in the codebase
`ItemBody`, `Stamped`, `Hlc`/`HlcClock` with the skew clamp, and the `is_deleted()` rule exist (M1-02). There's no merge function.

## 2. Detailed description
- `merge(local: &ItemBody, remote: &ItemBody) -> MergeOutcome { body: ItemBody, resurrected: bool, changed_fields:
  Vec<String>, schema: SchemaOutcome }`. It's pure.
- **Per field** (union of keys): take the `Stamped` with the higher `(hlc, device_id)` (§12.4). Ties on both can only happen for identical writes, so
  pick either (deterministically by comparing the CBOR bytes of the value as a final tiebreak, so the function is total).
- **Tombstone:** `deleted` merges the same way (the higher stamp wins). The final deletion status follows the rule "deleted iff `deleted.value == true`
  and `deleted.hlc > max field hlc`" (§12.4). If the local body was deleted and the merged result isn't (an edit newer than the delete exists), then
  `resurrected = true`, and the UI shows a toast "‘<label>’ was restored because it was edited on another device after being deleted".
- **Unknown fields** are merged like known ones (they're just keys), so newer clients' data survives (§4.1).
- **List fields** are whole-value LWW (§12.4, v1). OR-sets are an open question (§22.1).
- **`kind` mismatch** (shouldn't happen) → keep the higher-stamped body's kind and log an error.
- **`schema_version`:** the merged body takes `max(local, remote)`. If that's newer than supported → read-only (M1-02).
- **Properties** that must hold: commutative (`merge(a,b) == merge(b,a)`), associative, idempotent (`merge(a,a) == a`), so replicas converge regardless
  of delivery order (§12.4).
- **HLC observation:** the caller (sync engine) calls `clock.observe(stamp)` for every incoming stamp (M1-02 skew clamp and warning). Merge itself doesn't
  touch clocks.

## 3. Codebase changes
- `merge.rs` plus property tests with a simulation harness: `SimDevice { clock, store: HashMap<ItemId, ItemBody> }` and a `SimNetwork` delivering
  bodies in random order, with duplication and delays.

## 4. Test cases to implement

**T-01 (unit)** Concurrent edits to different fields both survive (port on A, user on B).

**T-02 (unit)** Concurrent edits to the same field → the higher HLC wins. With equal HLC → the higher device id wins.

**T-03 (unit)** Delete vs older edit → deleted. Delete vs newer edit → resurrected with `resurrected = true`.

**T-04 (unit)** Unknown field from a newer client is preserved through merge.

**T-05 (property)** Commutativity, associativity and idempotence over random bodies (field sets from a small alphabet, random stamps).

**T-06 (property, §19)** N = 2..5 simulated devices perform random sequences of set, unset, delete and edit-after-delete operations on a shared set of items while
offline, then exchange bodies in random orders (with duplicates). All devices end with **identical** states. 1,000 cases.

**T-07 (unit)** `unset` (Null) wins over an older value and loses to a newer value.

**T-08 (unit)** Schema version max and read-only propagation.

**T-09 (unit)** Clock skew: a remote stamp 10 min ahead → the caller gets the skew warning. Merge still picks it (it has the higher HLC). Document that clamping only
affects the local clock (M1-02 decision).

## 5. Passing functional characteristics
- [ ] Merge is per-field LWW by `(hlc, device_id)` and commutative, associative and idempotent.
- [ ] Tombstones follow §12.4, newer edits resurrect items, and resurrection is reported for a toast.
- [ ] Unknown fields and list fields (whole-value) merge correctly.
- [ ] Property tests show convergence across N simulated devices with random delivery order.
