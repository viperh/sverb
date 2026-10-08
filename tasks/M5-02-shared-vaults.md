# M5-02 — Shared vaults: creation, grants, permissions, move/copy items, credential overrides

| | |
|---|---|
| **Milestone** | M5 |
| **Touches** | `crates/sverb-server/src/routes/vaults.rs` (POST, members PUT/DELETE), `crates/sverb-sync/src/vaults.rs`, `crates/sverb-core/src/model/credential_override.rs`, `crates/sverb-core/src/resolve.rs` (override layer), `crates/sverb-tui/src/views/{vault_selector.rs, settings/vaults.rs}`, item move/copy actions |
| **Spec refs** | §13.1, §13.2 (grant, read-only enforcement), §13.4, §11.3, §4.12 (per-vault references), §4.13 (vault selector), §8.1 (top bar vault selector) |
| **Depends on** | M5-01, M5-03 (trust checks before granting) |
| **Blocks** | M5-04 |

---

## 1. Current state in the codebase
The client handles one personal vault, and the top bar shows "Personal ▾" (M0-11). The server's `vault_members` supports multiple rows, but only self-grants exist.

## 2. Detailed description

### 2.1 Create a shared vault
`POST /v1/vaults {id (client UUIDv7), org_id, name_enc, self_grant}` (org admin+). The client generates the VK, encrypts the name, and self-grants with `manage`. Org owners and admins
**implicitly have `manage`** on all org vaults (§13.1). Implement this as: when an admin opens the vault list, vaults without an explicit grant are listed as "needs key", and any
existing `manage` member's client auto-grants admins when it sees them missing (a background reconcile), since the server can't grant by itself.

### 2.2 Grant access (§13.2)
A `manage` user picks a member and a permission (`read`/`write`/`manage`). The client fetches the member's public keys (`/v1/users/{id}/public-keys`), **verifies them per M5-03**
(TOFU pin or verified safety number; refuses with a loud warning on a mismatch), HPKE-wraps the VK (M4-03), signs it, and sends `PUT /v1/vaults/{id}/members/{user}
{permission, key_version, wrapped_vault_key, signature}`. The server checks the granter has `manage` (or is an org admin) and the target is an org member, stores the row,
emits WS `vault_access granted` (M4-05) and writes an audit event.
**Receiving side:** on `vault_access granted` or a vault list refresh, verify the grant signature against the **granter's pinned key**, and that the granter has `manage`
(§13.3). Then open the VK, wrap it under the LMK into the local `vaults` table, and pull.

### 2.3 Permissions
`read`: the server rejects pushes (M4-04), and the client hides edit actions and shows forms read-only (M1-06) with the badge "Read-only vault". `write`: edit items.
`manage`: also grant and revoke. Revoking is the M5-04 flow.

### 2.4 Vault selector (§4.13, §8.1)
The top bar `Personal ▾` opens a picker: "All vaults" (merged view, default per `general.default_vault`) or a specific vault. The lists show a vault badge per item in merged mode.
New items are created in the currently selected vault (or personal when in "All").

### 2.5 Move and copy items (§13.1)
An item action "Move to vault…" / "Copy to vault…": decrypt, re-encrypt under the target VK with a **new id** (copy) or the **same id**? **Decision:** a move uses a new id in the
target and tombstones the source (§13.1 "re-encrypts under the target vault key and tombstones the source"). References inside the moved item that point into the source vault are
checked: a host in a shared vault **must not reference personal items** (§13.4). Offer to move or copy the referenced identity, key and group too, or block with an explanation.

### 2.6 Credential overrides (§13.4)
- A new item kind `CredentialOverride { shared_host_id, username?, password?, key_id?, identity_id? }`, **stored in the user's personal vault**, keyed by
  `shared_host_id`. It's the only allowed cross-vault reference.
- Resolution (M2-01) inserts the override layer **above the shared host's own credential fields** for that user only. Provenance shows "(your override)".
- UI: on a shared host's detail, the action "Use my own credentials…" opens a small form (identity or inline). The override is listed under the host detail with remove.
- The host form for shared vaults restricts reference pickers to the same vault (§13.4).

## 3. Codebase changes
- Server routes for vault create and members. Client vault management, the vault selector widget, move/copy, the override model plus resolution changes, and the read-only UI enforcement.

## 4. Test cases to implement

**T-01 (integration, TestServer, 3 users)** The admin creates a shared vault, grants Bob `write` and Carol `read`. Both receive it via WS and decrypt items.

**T-02** A grant with an unpinned or changed key for Bob → refused client-side with a warning (M5-03 integration).

**T-03** A tampered grant signature (server modifies the row in the test) → Bob's client refuses to use the VK and shows an error.

**T-04** Carol (read) edits → the form is read-only. A forced push via the API → 403.

**T-05** Merged "All vaults" list shows the vault badges. Selecting a vault filters.

**T-06** Moving a host from personal to shared that references a personal identity → blocked with the option to also copy the identity. Proceeding → the host and the identity copy
are in the shared vault, and the source host is tombstoned.

**T-07** Credential override: Bob's override username on a shared host resolves to Bob's value only on Bob's device. Alice still sees the shared value. Provenance "(your override)".

**T-08 (unit)** Cross-vault reference validation: a shared host referencing a personal key → validation error, while an override in personal referencing a shared host → allowed.

**T-09** An org admin without an explicit grant gets auto-granted by a manage member's client reconcile.

**T-10 (M5 exit criterion, part)** A 3-member org scenario: create, grant, edit, sync across all members.

## 5. Passing functional characteristics
- [ ] Org admins can create shared vaults. `manage` members grant access by HPKE-wrapping and signing the VK. The server never holds VKs.
- [ ] Recipients verify grant signatures against pinned granter keys before use.
- [ ] read/write/manage permissions are enforced by the server and reflected in the UI.
- [ ] The vault selector supports the merged and single-vault views. Items can be moved or copied between vaults with reference checks.
- [ ] Per-user credential overrides let team members use their own credentials on shared hosts.
