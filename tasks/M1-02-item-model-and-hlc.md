# M1-02 — Item model: `ItemBody`, `Stamped` fields, HLC, typed views, schema versions

| | |
|---|---|
| **Milestone** | M1 |
| **Touches** | `crates/sverb-core/src/model/{mod.rs, ids.rs, hlc.rs, body.rs, kinds.rs, host.rs, …}` |
| **Spec refs** | §4 (all subsections), §4.1, §11.4 (body is CBOR'd then encrypted), §12.4 (merge relies on stamps) |
| **Depends on** | M1-01 |
| **Blocks** | M1-03, M1-07, M2-*, M4-06 |

---

## 1. Current state in the codebase
After M0-08 removed the `Core` placeholder, `crates/sverb-core/src/lib.rs` contains only module
declarations (`paths`, `secret`, `config`, `error_report`). There is no domain model.

## 2. Detailed description

### 2.1 Identifiers (`model::ids`)
- `ItemId`, `VaultId`, `DeviceId`, `OrgId`, `UserId`, `SessionId`, `ConnId`: newtypes over
  `uuid::Uuid`, **UUIDv7** (`Uuid::now_v7()`), so they sort by time. They serialize as 16 raw bytes in CBOR and
  as canonical hyphenated strings in JSON and CLI. `Display` is the hyphenated form. A `short()` helper gives the first 8 hex
  chars for the UI.
- An `IdGen` trait makes generation injectable for deterministic tests.

### 2.2 Hybrid Logical Clock (`model::hlc`)
- `Hlc` wraps `uhlc::Timestamp` (64-bit NTP-style time + logical counter), with total order
  `(time, logical)`. Ties are broken by `DeviceId` in `Stamped` ordering, not in `Hlc` itself.
- `HlcClock` (one per device, owned by the store layer): `now() -> Hlc` and `observe(remote: Hlc) ->
  Result<(), ClockSkew>`.
- **Skew clamp** (§12.4): a received stamp more than **5 minutes** ahead of local physical time is
  clamped to `local_physical + 5 min` (for clock-update purposes) and returned as `ClockSkew { device,
  ahead_by }`, so the UI can warn "Clock skew detected on device X". The stamp stored on the field is
  still the original. Clamping only protects the local clock. **Clarify with the spec owner** whether
  the stored stamp should also be clamped. This task's proposal: keep the original, for convergence.
- Injectable physical time source for tests.

### 2.3 `ItemBody` (§4.1)
- `kind: ItemKind` (`Host | Group | Identity | Key | Certificate | KnownHost | PortForward |
  Snippet | Workspace | Tag | HistoryEntry | ConnLog`, plus `CredentialOverride` for §13.4, added
  in M5-02, so leave the enum `#[non_exhaustive]`).
- `schema_version: u16`.
- `fields: BTreeMap<String, Stamped<ciborium::Value>>`, with **dotted keys for nested structs**
  (`defaults.port`, `proxy.kind`, `proxy.addr`, `algorithms.kex`).
- `deleted: Option<Stamped<bool>>`.
- `Stamped<T> { value: T, hlc: Hlc, device: DeviceId }`, ordered by `(hlc, device)`.
- **API:**
  - `ItemBody::new(kind, schema_version)`.
  - `set(&mut self, field: &str, value: impl Into<Value>, clock: &mut HlcClock, device)`. Every write
    is stamped. Setting a value equal to the current one is a **no-op** (no new stamp), so the outbox
    sees no spurious changes.
  - `unset(field)`: stores `Value::Null` stamped (an explicit "None" that must win merges against
    older values). It doesn't remove the key.
  - `get(field) -> Option<&Value>`, where `Null` → `None`.
  - `delete(clock, device)` sets the tombstone. `is_deleted()` follows §12.4: deleted iff `deleted.value == true`
    and `deleted.hlc` > max field hlc.
  - `max_hlc()`.
  - `to_cbor() -> Vec<u8>` and `from_cbor(&[u8])`, with deterministic encoding (BTreeMap gives sorted keys).
  - Secret-holding fields (`password`, `private_key`, `passphrase`) are stored as plain CBOR text
    **inside** the encrypted body, and exposed only through typed views as `SecretString` (§11.5).
- **Unknown fields are preserved** (§4.1): typed views never drop keys they don't understand, and
  writing through a typed view only touches the fields it changes.

### 2.4 Typed views (§4.2–§4.12)
`Host`, `Group` (with `HostDefaults`), `Identity`, `Key`, `Certificate`, `KnownHost`,
`PortForward`, `Snippet`, `Workspace`, `Tag`, `HistoryEntry`, `ConnLog`, each with:
- `TryFrom<&ItemBody>` (fails on wrong kind, or on a field of the wrong CBOR type with `FieldTypeError{field}`;
  a missing optional field means `None`),
- `fn apply_to(&self, body: &mut ItemBody, clock, device)`, which writes only changed fields via `set`.
- Field names and types are **exactly** as in §4.2–§4.12. List fields (`tags`, `env`, `jump_chain`,
  `port_forwards`, `certificate_ids`, `variables`, `broadcast_groups`) are **whole values** (one field,
  LWW, §12.4).
- Enum encodings use stable lowercase strings (`"socks5"`, `"del"`, `"ctrl-h"`, `"paste-and-execute"`,
  etc.), documented in a table in `docs/data-model.md`.
- `Host.label` defaults to `address` when empty (computed in the view and not stored).
- Not item fields: `last_connected_at`, frecency and the recording path (device-local, §4.2/§5.2/§4.12).

### 2.5 Validation (§4.2), as pure functions in `model::validate`
- `address`: valid DNS name after IDNA normalization (`idna` crate, UTS-46), or an IPv4 or IPv6 literal
  **without brackets**. Reject empty strings, spaces, `user@host`, and `host:port`.
- `port`: 1..=65535 (`u16` excludes > 65535, so reject 0).
- `env` names match `[A-Za-z_][A-Za-z0-9_]*`.
- `jump_chain` must not contain the host itself. Cycle detection runs a DFS over the resolved chains (needs a lookup
  fn), with a depth limit of 8 (§6.1.4).
- `Group.parent_id` cycles are rejected on write.
- `Snippet` variable syntax `{{name}}`/`{{name:default}}`/`{{name|q}}`: names match
  `[A-Za-z_][A-Za-z0-9_.]*` (dots allowed for built-ins like `host.label`).
- The error type `ValidationError { field, message }` is used by forms for inline errors (M1-06).

### 2.6 Schema versions and migrations (§4.1)
- `CURRENT_SCHEMA: [(ItemKind, u16)]`, all starting at 1.
- `migrate(body) -> MigrateOutcome`: runs pure migration functions in sequence on read. If
  `body.schema_version > CURRENT`, the item is **read-only**. Typed views carry a `read_only: bool`, and the UI
  shows "Update sverb to edit this item". Writes to read-only items are rejected by the store (M1-03).

### 2.7 Out of scope
- Merging (M4-06). This task provides the data structures merging uses, and M4-06 adds `merge(a, b)`.
- Persistence (M1-03).

## 3. Codebase changes
- **Create** `crates/sverb-core/src/model/` with the files listed above, plus `validate.rs` and
  `migrate.rs`. Dependencies: `uuid` (v7, serde), `uhlc`, `ciborium`, `idna`, `serde`.
- **Docs:** `docs/data-model.md` with field tables and enum string encodings.

## 4. Test cases to implement

**T-01 (unit) UUIDv7 ordering.** 1,000 ids generated in sequence sort in generation order.

**T-02 (unit) HLC monotonic.** `now()` is strictly increasing across 10k calls, even with a frozen physical clock
(the logical counter advances).

**T-03 (unit) HLC observe.** After observing a remote stamp ahead by 10 s, the next `now()` is greater than the remote stamp.

**T-04 (unit) Skew clamp.** Observing a stamp 10 min ahead returns `ClockSkew`, and local `now()` stays below
`physical + 5 min + ε`.

**T-05 (unit) Stamped order.** Equal HLC → `device` breaks the tie, deterministically.

**T-06 (unit) `set` stamps and no-ops.** Setting the same value twice doesn't change the stamp, and a
different value gets a newer stamp.

**T-07 (unit) Tombstone rule.** A delete at t=5 and a field at t=3 → deleted. A field edit at t=7 → not deleted
(resurrection).

**T-08 (unit) Unknown fields preserved.** A body with `future_field` is converted to `Host`, its port is
edited and applied back, and `future_field` is unchanged (value and stamp).

**T-09 (unit) Flattening.** `Host.proxy = Socks5{addr, auth}` is written as `proxy.kind`, `proxy.addr`,
`proxy.auth.user`, `proxy.auth.password`. Editing only `proxy.addr` touches only that stamp.

**T-10 (property) CBOR round-trip.** Random `ItemBody` → `to_cbor` → `from_cbor` gives an equal value, and
encoding is deterministic (identical bytes on re-encode).

**T-11 (unit, table) Address validation.** Valid: `example.com`, `xn--bcher-kva.example`,
`bücher.example` (normalized), `10.0.0.1`, `::1`, `fe80::1`. Invalid: `[::1]`, `a b`, `root@x`, `x:22`,
the empty string, a 254-char name, a label over 63 chars.

**T-12 (unit) Port validation.** 0 is rejected, and 1 and 65535 are accepted.

**T-13 (unit) Env names.** `PATH` and `_X1` are OK. `1X`, `A-B` and the empty string are rejected.

**T-14 (unit) Jump chain.** Self-reference is rejected. A→B→A is a cycle and rejected. A chain of depth 9 is rejected, and depth 8 is OK.

**T-15 (unit) Group cycles.** Setting a parent that creates a cycle is rejected.

**T-16 (unit) Schema newer → read-only.** A body with `schema_version = 99` gives a view with `read_only = true`.

**T-17 (unit) Typed view type errors.** `port` stored as text → `FieldTypeError{field:"port"}`, with no panic.

**T-18 (unit) Secrets.** `Host.password` is exposed as `SecretString`, and `Debug` of `Host` doesn't show it.

**T-19 (unit) `unset` beats older values.** After `unset(port)` at t=5, a merge-free read returns `None`, and
the stamp is newer than the earlier set at t=3.

## 5. Passing functional characteristics
- [ ] All entities of §4 exist as typed views over a field-stamped `ItemBody`, with exact field names.
- [ ] Every write is HLC-stamped, idempotent writes create no new stamps, and nested structs use dotted keys.
- [ ] Unknown fields survive round trips through older code paths.
- [ ] Validation rules of §4.2 (address, port, env, jump-chain and group cycles) are enforced with field-level
      errors.
- [ ] A newer schema_version yields read-only items. The migration hook exists.
- [ ] IDs are UUIDv7, and the HLC handles skew with clamping and a warning signal.
- [ ] CBOR encoding is deterministic, and the encoded bytes feed `sverb-crypto::seal_item`.
