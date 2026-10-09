# Data model: item bodies, field names and encodings

This is the reference for the plaintext of synced items (SPEC §4). The code lives in
`crates/sverb-core/src/model/`. Every item is an `ItemBody`; typed views (`Host`, `Group`,
…) are read with `TryFrom<&ItemBody>` and written back with `apply_to`.

## 1. Item body

`ItemBody` is CBOR-encoded with `ItemBody::to_cbor()`. The bytes are what
`sverb_crypto::envelope::seal_item` encrypts (§11.4). The CBOR shape is a map:

| Key | CBOR type | Meaning |
|---|---|---|
| `kind` | text | Item kind (table below). |
| `schema_version` | uint | Bumped only for breaking changes (§4.1). |
| `fields` | map text → `Stamped` | Field-level LWW registers, keys sorted (BTreeMap). |
| `deleted` | `Stamped<bool>` or null | Tombstone (§12.4). |

`Stamped<T>` is the array `[value, hlc, device]`:

- `value`: any CBOR value. `null` means an explicit "None" (`unset`), which wins merges
  against older values like any other write.
- `hlc`: uint, a `uhlc` NTP64 (32 bits of seconds since the Unix epoch, 32 bits of
  fraction, the low 4 bits being the logical counter).
- `device`: 16-byte byte string (the writing device's UUIDv7).

Merge order is `(hlc, device)`. An item is deleted iff `deleted.value == true` and
`deleted.hlc` is greater than every field's `hlc`; a newer edit resurrects it.

Encoding is deterministic: struct keys come in a fixed order, the `fields` map is sorted,
and nested CBOR maps keep their order through a decode/encode round trip.

**Ids** (`ItemId`, `VaultId`, `DeviceId`, `OrgId`, `UserId`, `SessionId`, `ConnId`) are
UUIDv7. In CBOR they are 16-byte byte strings (also inside field values); in JSON, the CLI
and `Display` they are hyphenated strings. `short()` gives the first 8 hex characters.

**Timestamps** (`UnixMillis`) are CBOR integers: milliseconds since the Unix epoch, UTC.

### Writes

- Every write goes through `ItemBody::set`, which stamps it with the device's `HlcClock`.
  Writing the value a field already holds is a no-op (no new stamp).
- `apply_to` writes only fields that changed, and never writes a default (`null`, `""`,
  `false`, `[]`, `0` for counters) into a key that doesn't exist yet.
- Keys a view doesn't know are never touched, so data written by newer clients survives.
- Nested structs are flattened into dotted keys (`proxy.addr`, `defaults.port`).
- List fields are single whole values (one register, LWW): `tags`, `env`, `jump_chain`,
  `port_forwards`, `certificate_ids`, `variables`, `broadcast_groups`, `algorithms.*`.
- Secrets (`password`, `private_key`, `passphrase`, including dotted forms such as
  `proxy.auth.password`) are plain CBOR text **inside** the encrypted body. Views expose
  them only as `SecretString`, and `ItemBody`'s `Debug` redacts them.

### Clock skew (§12.4)

`HlcClock::observe(remote, device)` advances the local clock past a received stamp. A
stamp more than 5 minutes ahead of local physical time only advances the clock to
`physical + 5 min` and returns `ClockSkew { device, ahead_by }` (UI: "Clock skew
detected on device X"). **The stored stamp is not rewritten**, so every replica still
converges; clamping protects only the local clock. A local write over a value with a
skewed (future) stamp is stamped just past that value, so the local edit still wins.

### Schema versions (§4.1)

`CURRENT_SCHEMA` lists the version per kind (all 1). `migrate(body)` runs pure
`fn(ItemBody) -> ItemBody` steps on read. A body with a newer `schema_version` than this
build knows produces views with `read_only = true` ("Update sverb to edit this item"); the
store rejects writes to it.

## 2. Item kinds

| `ItemKind` | `kind` string |
|---|---|
| Host | `host` |
| Group | `group` |
| Identity | `identity` |
| Key | `key` |
| Certificate | `certificate` |
| KnownHost | `known-host` |
| PortForward | `port-forward` |
| Snippet | `snippet` |
| Workspace | `workspace` |
| Tag | `tag` |
| HistoryEntry | `history-entry` |
| ConnLog | `conn-log` |
| CredentialOverride | `credential-override` (M5-02) |

## 3. Fields per kind

"id" means a 16-byte byte string; "[id]" an array of them. A missing key and `null` both
read as `None` (or the stated default).

### Host (§4.2)

| Key | CBOR | View type | Default when missing |
|---|---|---|---|
| `label` | text | `String` | `""` (display falls back to `address`, not stored) |
| `address` | text | `String` | `""` |
| `port` | uint | `Option<u16>` | `None` (22 after resolution) |
| `group_id` | id | `Option<ItemId>` | |
| `tags` | [id] | `Vec<ItemId>` | `[]` |
| `identity_id` | id | `Option<ItemId>` | |
| `username` | text | `Option<String>` | |
| `password` | text (secret) | `Option<SecretString>` | |
| `key_id` | id | `Option<ItemId>` | |
| `jump_chain` | [id] | `Vec<ItemId>` | `[]` |
| `proxy.kind` | text | `Option<Proxy>` (see below) | `None` |
| `proxy.addr` | text | Socks5/Http `addr` | |
| `proxy.auth.user` | text | `ProxyAuth.user` (auth present iff set) | |
| `proxy.auth.password` | text (secret) | `ProxyAuth.password` | |
| `proxy.command` | text | `Command(String)` | |
| `agent_forwarding` | bool | `Option<bool>` | |
| `agent_source` | text | `Option<AgentSource>` | (`builtin` after resolution) |
| `env` | array of `[name, value]` text pairs | `Vec<(String, String)>` | `[]` |
| `startup_snippet_id` | id | `Option<ItemId>` | |
| `keepalive_secs` | uint | `Option<u32>` | |
| `charset` | text | `Option<String>` | (UTF-8) |
| `backspace` | text | `Option<Backspace>` | |
| `color_scheme` | text | `Option<String>` | |
| `port_forwards` | [id] | `Vec<ItemId>` | `[]` |
| `notes` | text | `Option<String>` (Markdown) | |
| `pinned` | bool | `bool` | `false` |
| `algorithms.kex` / `.host_key` / `.cipher` / `.mac` / `.compression` | array of text | `Option<AlgoOverrides>` (`None` when all unset) | |
| `request_pty_for_exec` | bool | `Option<bool>` | |
| `record_sessions` | bool | `Option<bool>` | (inherits: group chain, then `recording.enabled`) — **spec addition** (M3-05) |
| `auto_reconnect` | bool | `Option<bool>` | (inherits: group chain, then `ssh.auto_reconnect`) — **spec addition** (M1-16) |

Switching the proxy kind writes `null` to the sub-keys that no longer apply.
Not item fields (device-local, §5.2): `last_connected_at`, frecency.

### Group (§4.3)

| Key | CBOR | View type |
|---|---|---|
| `name` | text | `String` |
| `parent_id` | id | `Option<ItemId>` (cycles rejected on write) |
| `icon` | text | `Option<String>` |
| `defaults.*` | | `HostDefaults` |
| `is_vault_defaults` | bool | `bool` (default `false`) — M2-01, see "Vault defaults" below |

`HostDefaults` holds the Host settings without `label`, `address`, `group_id`, `tags`,
`notes` and `pinned`, all optional (`None` = inherit), with the same keys and encodings
under the `defaults.` prefix (`defaults.port`, `defaults.proxy.addr`,
`defaults.algorithms.kex`, …). List settings are `Option<Vec<…>>` here.

**Spec addition (M3-05): `record_sessions`.** §7.5 says recording is enabled "globally, per
host, or toggled with `leader R`", but §4.2 lists no host field for it. `record_sessions:
Option<bool>` is added to Host and `HostDefaults` (so groups can set it). Resolution
(`model::host::resolve_record_sessions`): the host's value, else the nearest group in the
chain that sets `defaults.record_sessions`, else the global `recording.enabled`. Recordings
themselves are device-local files (`state_dir/recordings/<conn_id>.cast.sv`, encrypted
with a key derived from the LMK) and never sync.

**Spec addition (M1-16): `auto_reconnect` and `ssh.auto_reconnect`.** §6.1.2 offers an
"optional auto-reconnect" (exponential backoff 1 s → 30 s, at most 10 tries) without naming
a setting. `auto_reconnect: Option<bool>` is added to Host and `HostDefaults`, and the
global `ssh.auto_reconnect = false` to `config.toml`. It is an inheritable setting
(`SettingKey::AutoReconnect`, resolved by `sverb_core::resolve` with provenance: host →
group chain → vault defaults → `ssh.auto_reconnect`). Auto-reconnect never retries after
`HostKey`, `Auth` or a remote exit (`Exited`).

### Settings inheritance (§4.3, §4.13) — M2-01

`sverb_core::resolve` resolves every inheritable setting of a host (the `HostDefaults`
fields, including `record_sessions`) in the order **Host → its group → parent group → … →
vault defaults → global config (`config.toml`) → built-in default**, and records a
provenance (`Source::{Host, Group{id,name}, VaultDefaults, GlobalConfig, BuiltinDefault}`)
per setting. The UI shows it as `2222 (from group "prod")` or `22 (default)`.

- **Global config** supplies `keepalive_secs` (`ssh.keepalive_secs`), `color_scheme`
  (`terminal.color_scheme`), `record_sessions` (`recording.enabled`) and, M1-16,
  `auto_reconnect` (`ssh.auto_reconnect`); the other settings
  fall back to built-in defaults (port 22, agent forwarding off, agent source `builtin`,
  charset UTF-8, backspace `del`, no PTY for exec, empty lists, no references).
- **Lists absent vs empty (decision).** `jump_chain`, `env` and `port_forwards` inherit
  only when the host's key is **absent** (or `null`); a stored empty array `[]` means
  "explicitly none" and stops inheritance. The `Host` view keeps the distinction in
  `Host::explicit_empty` (`ExplicitEmpty { jump_chain, env, port_forwards }`): `apply_to`
  writes `[]` only for a flagged list and clears the key (`null`) for an empty unflagged
  one. In group defaults these lists are already `Option<Vec<…>>`. The host form maps an
  emptied list to "inherit"; an explicit empty list comes from imports / the CLI.
  `tags` are not inheritable: `HostDefaults` has no `tags` field.
- **Credentials (decision).** Username, password and key resolve independently, but an
  identity is expanded at the level where it is set (`host.identity_id` or
  `defaults.identity_id` of a group or the vault defaults): its username, password and key
  count as values of that level, below that level's inline fields. So an identity on a
  group plus an inline username on the host gives the host's username and the group
  identity's password.
- **No secrets in resolution.** A resolved host carries `password: Option<SecretOrigin>`
  (the level and, if any, the identity holding it), never the value; the connector reads
  the secret from the vault.
- **Missing references** (deleted group, identity, key, snippet, jump host, forward) are
  `None` at read time (§12.4), logged at `debug`, and listed in `ResolvedHost::warnings`
  (the Hosts view shows a `missing group` chip). A missing group ends the chain there.
- **Cycles.** Writes reject parent cycles; resolution still stops on a revisited group and
  after 64 groups (`model::group::MAX_GROUP_DEPTH`).

### Vault defaults (§4.13) — M2-01 decision

The vault defaults are stored as a **`group` item with `is_vault_defaults = true`** in that
vault (name `Vault defaults`, no parent; only `defaults.*` matter), so they sync, merge
and encrypt with the same machinery as every item. Such an item is never shown in the
Hosts tree and nothing references it. If a sync race creates two in one vault, the one
with the smallest id wins (deterministic on every device). A host uses the defaults of
its own vault.

### Identity (§4.4)

`label` text, `username` text, `password` text (secret, optional), `key_id` id (optional).

### Key (§4.5)

| Key | CBOR | View type |
|---|---|---|
| `label` | text | `String` |
| `algorithm` | text | `KeyAlgorithm` (required) |
| `private_key` | text (secret) | `SecretString` (OpenSSH format) |
| `public_key` | text | `String` |
| `passphrase` | text (secret) | `Option<SecretString>` |
| `certificate_ids` | [id] | `Vec<ItemId>` |
| `agent_forwardable` | bool | `bool`, default `false` |
| `confirm_on_use` | bool | `bool`, default `false` |
| `agent_ref` | bool | M2-03: derived by `Key::is_agent_ref()` (no `private_key`, a `public_key`): a hardware / agent reference key (§9.4); default `false` |

### Certificate (§4.6)

`label` text, `cert` text (OpenSSH certificate), `key_id` id (optional). Principals,
validity and CA fingerprint are derived, never stored.

### KnownHost (§4.7)

`host_pattern` text, `key_type` text, `public_key` text, `added_at` UnixMillis,
`comment` text (optional), `marker` text (optional; missing = none).

### PortForward (§4.8)

| Key | CBOR | View type |
|---|---|---|
| `label` | text | `String` |
| `kind` | text | `ForwardKind` (required) |
| `host_id` | id | `ItemId` (required) |
| `bind_addr` | text | `String`, default `127.0.0.1` |
| `bind_port` | uint | `u16` (required) |
| `dest_host` | text | `Option<String>` (`None` for dynamic) |
| `dest_port` | uint | `Option<u16>` |
| `auto_start` | bool | `bool` |

### Snippet (§4.9)

`name` text, `script` text, `description` text (optional), `tags` [id],
`variables` array of maps `{"name": text, "default": text|null, "secret": bool}`,
`run_mode` text (default `paste`).

Variable references in scripts: `{{name}}`, `{{name:default}}`, `{{name|q}}` (shell-quote),
`{{name:default|q}}`. Names match `[A-Za-z_][A-Za-z0-9_.]*` (dots for built-ins such as
`host.label`).

### Workspace (§4.10)

`name` text, `layout` map, `broadcast_groups` array. Both are whole-value LWW fields
whose shape is defined by M3-03 (`sverb_core::model::workspace`):

```text
layout = { "v": 1, "active": uint, "tabs": [tab, …] }
  tab  = { "title"?: text, "focused": uint, "leaves": [leaf, …], "tree": node }
  leaf = { "host": bytes(16) } | { "local": null | text(cwd) }
  node = uint (leaf index) | { "dir": "h" | "v", "ratio": [float, …], "children": [node, …] }
broadcast_groups = [ { "tab": uint, "panes": "all" | [uint, …] }, … ]
```

Pane ids inside a saved workspace are leaf indices. Unknown map keys are ignored (a newer
build may add some); a structurally invalid value is an error, never a panic. Ephemeral
panes (quick connect, share viewers) are not saved. A host deleted since opens as a
placeholder pane.

### Tag (§4.11)

`name` text, `color` text (optional).

M2-01: names are unique per vault, compared case-insensitively after trimming, with no
whitespace and no leading `#` (they are typed as `#name` in the filter);
`model::tag::validate_tag` checks it on save (form and service). Colors come from a fixed
palette of 12 names (`model::tag::TAG_COLORS`: red, green, yellow, blue, magenta, cyan,
lightred, lightgreen, lightyellow, lightblue, lightmagenta, gray), rendered through the UI
theme (monochrome shows only `[name]`); a legacy `#rrggbb` stays valid. Deleting a tag
leaves its id on hosts; readers ignore unknown tag ids and they are cleaned up lazily
(§12.4).

### HistoryEntry (§4.12)

`command` text, `host_id` id (optional; none for local shells), `executed_at` UnixMillis,
`exit_code` int (optional).

**M7-01 spec addition:** `verified` bool (optional). `false` marks an entry captured by the
heuristic tier (no OSC 133 shell integration: the cursor line on `Enter`, with the learned
prompt prefix stripped), shown as "unverified". It is written only when `false`; a missing
field reads as `true` (shell-integration captures and snippet runs).

### ConnLog (§4.12)

`host_id` id (optional, see below), `started_at` UnixMillis, `ended_at` UnixMillis (optional),
`result.kind` text (optional while open), `result.message` text (only for
`network-error`), `bytes_in` uint, `bytes_out` uint. The recording path is device-local.

**M3-06 spec additions:**
- `host_id` is optional: local shells and ephemeral quick-connect targets have no host item.
- `label` text: what the attempt was shown as (the host label, or `local`), so the entry still
  reads well after the host is renamed or deleted.
- `target` text (optional): `user@host:port` of an SSH attempt (used to reconnect an
  ephemeral host); absent for local shells.
- `error_detail` array of text (optional): the `ErrorReport` of a failed attempt, short message
  first, then the cause chain (the Logs view's "error details").

**Device-local data:** the recording of an attempt is `device_local.recording_dir` keyed by the
ConnLog id (the full path of `<conn_id>.cast.sv`; the recording's `conn_id` is the ConnLog id).

**Sync (M3-06 decision):** ConnLog items live in the personal vault. With `logs.sync = false`
(the default) they are written without the dirty flag and never enter the outbox, so they stay
on this device. Turning `logs.sync` on later does not retroactively push older entries; only
entries written (created, finalized or deleted) after that are queued. Recordings never sync.

**Retention:** a maintenance task (on unlock and every 24 h) tombstones entries whose
`started_at` is older than `logs.retention_days` (0 = forever), and deletes recording files
older than `recording.retention_days` (spec addition; 0 = keep until deleted).

### CredentialOverride (§13.4) — M5-02

`shared_host_id` id (required), `username` text (optional), `password` secret (optional),
`key_id` id (optional), `identity_id` id (optional).

- Lives in the user's **personal** vault only (a write into a shared vault is refused);
  `shared_host_id` is the one reference allowed to point into another vault.
- Resolution: after the usual chain (host → groups → vault defaults → config), each
  credential the override sets replaces the resolved one, with provenance
  `Source::Override` ("your override"). An identity on the override counts as override
  values below its inline `username` / `password` / `key_id`. If a sync race leaves several
  overrides for one host, the smallest item id wins.

### References across vaults (§13.4) — M5-02

Every 16-byte id in a body is a reference. An item in a **shared** vault may only reference
items of the same vault (`sverb_core::model::vault_refs`); references to items that no longer
exist pass (they resolve as missing). "Move to vault…" / "Copy to vault…" writes the item(s)
under **new ids** in the target (a move tombstones the sources) and rewrites references to
items moved or copied along.

### Local vault metadata (M5-02)

`meta` keys, per shared vault: `vault_name_enc/<uuid>` (the name sealed under the vault key,
as on the server) and `vault_permission/<uuid>` (`read` / `write` / `manage`, recorded from
the vault list for the "Read-only vault" UI).

## 3a. Backup file (`.sverb-backup`, §9.13) — M2-11

`sverb export backup <file>` (and Hosts → `X`) writes one JSON document:

```json
{ "format": "sverb-backup", "version": 1,
  "kdf": { "alg": "argon2id", "m_kib": 262144, "t": 3, "p": 1, "salt_b64": "…" },
  "nonce_b64": "…", "ciphertext_b64": "…",
  "created_at": "2026-10-08T12:00:00Z", "app_version": "0.1.0" }
```

- The ciphertext is XChaCha20-Poly1305 under `Argon2id(export password)` with AAD
  `"sverb-backup-v1"`, over `zstd(cbor(payload))`. The decompressed payload is capped at
  1 GiB (zstd-bomb guard), and import refuses KDF parameters outside sane bounds before
  deriving anything.
- The payload holds every item body **with its stamps** (secrets included) and its id,
  so a restore keeps ids and HLC history. **Spec addition:** each item is
  `{ id, vault, body }` (the id is not part of `ItemBody`), and each vault is
  `{ id, name, kind, defaults }`, where `defaults` is the id of its vault-defaults item,
  if any.
- Device-local data (frecency, approvals, recordings) is not included.
- The export password is typed twice on a terminal, or read from the environment variable
  **`SVERB_EXPORT_PASSWORD`** in scripts (spec addition). `sverb import backup <file>
  [--dry-run]` reads the same variable.

## 4. Enum string encodings

| Enum | Variant → string |
|---|---|
| `AgentSource` | Builtin `builtin`, System `system`, Both `both` |
| `Backspace` | Del `del`, CtrlH `ctrl-h` |
| `Proxy` (`proxy.kind`) | Socks5 `socks5`, Http `http`, Command `command` |
| `KeyAlgorithm` | `ed25519`, `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`, `rsa-2048`, `rsa-3072`, `rsa-4096`, `sk-ed25519`, `sk-ecdsa` |
| `KnownHostMarker` (`marker`) | None (missing/null), CertAuthority `cert-authority`, Revoked `revoked` |
| `ForwardKind` | Local `local`, Remote `remote`, Dynamic `dynamic` |
| `RunMode` | Paste `paste`, PasteAndExecute `paste-and-execute`, Exec `exec` |
| `ConnResult` (`result.kind`) | Ok `ok`, AuthFailed `auth-failed`, HostKeyRejected `host-key-rejected`, NetworkError `network-error` (+ `result.message`) |

An unknown string for a known enum field is a `FieldTypeError` on read.

## 5. Validation (§4.2)

`model::validate` provides pure functions returning `ValidationError { field, message }`:

- `validate_address`: an IPv4/IPv6 literal without brackets, or a DNS name normalized with
  IDNA (UTS-46) to lowercase ASCII. Rejects empty, whitespace, `user@host`, `host:port`,
  labels over 63 and names over 253 characters, and an all-numeric last label. Letters,
  digits, `-` and `_` are allowed in labels.
- `validate_port`: 1..=65535.
- `validate_env_name`: `[A-Za-z_][A-Za-z0-9_]*`.
- `validate_jump_chain(host, chain, lookup)`: rejects the host itself, cycles, and resolved
  chains (jump hosts' own chains expanded recursively) longer than 8 hops (§6.1.4). Missing
  hosts count as having no chain.
- `validate_group_parent(group, parent, parent_of)`: rejects parent cycles.
- `parse_snippet_vars` / `validate_var_name`: snippet variable syntax.
- `validate_host`: address, port and env names together.
