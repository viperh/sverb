# M2-02 — Identities

| | |
|---|---|
| **Milestone** | M2 |
| **Touches** | `crates/sverb-core/src/model/identity.rs`, `crates/sverb-tui/src/views/keychain/identities.rs`, host form credentials section (`views/hosts/form.rs`) |
| **Spec refs** | §4.4, §9.3, §8.5 (Keychain sub-tab "identities") |
| **Depends on** | M2-01 (resolution), M2-03 can be parallel (key references) |
| **Blocks** | M2-11 (ssh_config import creates identities?), M5-02 |

---

## 1. Current state in the codebase
The `Identity` typed view exists (M1-02), and resolution expands identities (M2-01). The host form has an identity reference
field, but there's no UI to create identities.

## 2. Detailed description
- `Identity { label, username, password: Option<Secret>, key_id: Option<ItemId> }` (§4.4). Many hosts can reference
  one identity, and editing it changes every referencing host (via resolution, not by copying).
- **Keychain → Identities sub-tab** (§8.5): list (label, username, auth summary "password" / "key: <label>" / "password +
  key"), detail pane with "Used by N hosts" and the list of those hosts (clickable).
- **CRUD:** create, edit, duplicate, delete. **Delete** (§9.3): the dialog warns "This identity is used by N hosts. They will
  fall back to inherited or inline credentials." Deleting tombstones the identity. Host references become dangling and
  resolve as `None` (§12.4). Optionally offer "Convert to inline credentials on those hosts" (a checkbox; copies username,
  password and key into each host before deleting).
- **Host form credentials section** (§9.3): a radio choice "Use identity" (reference picker with a fuzzy list and an inline
  "+ new identity") vs "Inline" (username, password, key). With an identity selected, inline fields are hidden except an
  optional username override (§4.2 inline overrides identity).
- **Vault scoping** (§4.12 end, §13.4): an identity can be referenced only by hosts in the same vault. The picker filters to the host's
  vault. Cross-vault references are rejected on save with a clear error.
- Index: identities are searchable by label and username (not password).

## 3. Codebase changes
- Views and dialogs as listed. The reference counting query `hosts_referencing(identity_id)` goes in `sverb-core` over the
  index (resolving through groups too: count hosts whose **resolved** identity is this one, and report direct vs inherited).

## 4. Test cases to implement

**T-01 (integration)** Create an identity with username + key and assign it to 3 hosts. Resolved usernames match.

**T-02 (integration)** Edit the identity's username → all 3 hosts resolve the new username without any host item changing (stamps
unchanged).

**T-03 (reducer)** Delete dialog shows "used by 3 hosts" (2 direct, 1 via group).

**T-04 (integration)** Delete with "convert to inline" → each host gets inline fields equal to the identity's values, then the identity is
tombstoned.

**T-05 (integration)** Delete without converting → hosts resolve credentials from the next level, and the detail shows the "missing identity"
chip.

**T-06 (reducer)** Host form "Use identity" vs "Inline" toggling hides and shows the correct fields, and the username override is
kept.

**T-07 (unit)** Cross-vault identity reference → validation error.

**T-08 (unit)** The password isn't in the search index (canary).

**T-09 (snapshot)** Identities sub-tab at 160×48.

## 5. Passing functional characteristics
- [ ] Identities can be created, edited, duplicated and deleted, and are reusable across hosts in the same vault.
- [ ] Editing an identity affects all referencing hosts through resolution.
- [ ] Deletion warns with direct and inherited usage counts and can convert to inline credentials.
- [ ] The host form lets users pick an identity or inline credentials, with a username override.
