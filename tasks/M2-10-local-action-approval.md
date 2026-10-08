# M2-10 — Approval of synced items that act locally (§17.1)

| | |
|---|---|
| **Milestone** | M2 (needed before sync, M4, ships) |
| **Touches** | `migrations/client/0002_local_approvals.sql`, `crates/sverb-store/src/approvals.rs`, `crates/sverb-core/src/approval.rs`, `crates/sverb-tui/src/views/dialogs/approve.rs`, `crates/sverb/src/cli/approve.rs` |
| **Spec refs** | §17.1, §6.1.5 (ProxyCommand), §9.6 (non-loopback binds), §6.1.6 (system agent forwarding), §16 (`sverb approve <host>`, exit code 5) |
| **Depends on** | M2-06, M2-07, M2-08 |
| **Blocks** | M4-07 (sync must not ship without this) |

---

## 1. Current state in the codebase
M2-06, M2-07 and M2-08 call an `approvals.check(...)` stub that approves values stamped by the local device. There's no persistent allowlist, UI or
CLI.

## 2. Detailed description

### 2.1 Fields that act locally (§17.1)
| Field | Condition |
|---|---|
| `Host.proxy` | kind = `Command` (runs a local process). Value = the command string. |
| `PortForward` (Remote) | `dest_host` not loopback (127.0.0.0/8, ::1, `localhost`). Value = `dest_host:dest_port`. |
| `PortForward` (Local/Dynamic) | `bind_addr` not loopback. Value = `bind_addr:bind_port`. |
| `Host.agent_forwarding` + `agent_source` | `agent_forwarding = true` and source ∈ {system, both}. Value = `"system"`/`"both"`. |
All of these are evaluated on the **resolved** value (group defaults can carry them too). The approval key uses the item that defines the value
(provenance from M2-01).

### 2.2 Rule
- The first time this device is about to act on such a value, **and whenever the value changes**, show the exact value and ask:
  "This host runs a local command: `ssh -W %h:%p bastion`. Allow?" (or the forward and agent equivalents) with `[a]llow` / `[d]eny`.
- Record `(item_id, field, sha256(value))` in the **device-local** table `local_approvals` (never synced).
- **Pre-approved:** values typed on this device. When the user saves the field via a form on this device, insert the approval row
  at save time. (Don't infer this from the stamp's device id alone: the user could have moved the DB between devices. Explicit rows are
  the source of truth. M2-06's stub logic is replaced.)
- Unapproved values are **never acted on silently**. The connect or forward is paused in a dialog (TUI). **Headless** commands fail with exit 5
  and `error: host "db" uses a local command that has not been approved on this device. Run: sverb approve db` (§17.1).
- **Deny** → the connection or forward fails with "blocked by approval policy", and denial isn't remembered (ask again next time). Is that ok? **Decision:**
  remember the denial for the session only, so the user isn't nagged in a loop. Persistent denial isn't in the spec.
- Imported items (M2-11) count as "typed on this device" only after the import preview, where the user sees the values. Insert approvals for
  them at import confirmation.

### 2.3 Storage
`local_approvals(item_id BLOB, field TEXT, value_sha256 BLOB, approved_at INTEGER, PRIMARY KEY(item_id, field))`. A changed value
has a different hash, so the row no longer matches and the user is asked again. On approval, upsert.

### 2.4 `sverb approve <host>` (§16)
Lists every locally-acting field for the host (resolved, including its forwards and the group-provided values) with status `approved` /
`needs approval` / `changed since approval`, showing the full values. Interactive TTY: approve each `[y/N]`. `--all --yes` for scripts
(prints what it approved). Exit 0. No TTY and no `--yes` → exit 2.

### 2.5 UI
A "Needs approval" badge on hosts and forwards in lists. A Settings → Security → "Local approvals" list with revoke actions.

## 3. Codebase changes
- **Add** migration `0002`, the store repo, the core decision function `requires_approval(resolved, approvals) -> Vec<PendingApproval>`, the dialog
  and the CLI.
- **Replace** the stubs in M2-06, M2-07 and M2-08 with the real check.

## 4. Test cases to implement

**T-01 (unit, table) Classification.** ProxyCommand → needs. SOCKS proxy → no. Remote forward dest `127.0.0.1` → no, `10.0.0.5` →
needs. Local bind `0.0.0.0` → needs, `127.0.0.2` → no, `::1` → no. Agent forwarding builtin → no, system → needs, both → needs.

**T-02 (unit) Hashing.** A changed value → status `changed since approval`.

**T-03 (integration) Typed on this device** → the approval row is created on save, and the connect proceeds without a prompt.

**T-04 (integration) Simulated synced item** (inserted via `apply_remote` with another device's stamp) → the connect pauses on a dialog. Allow →
proceeds and the row is stored. The next connect → no prompt.

**T-05 (integration) Value changed remotely** after approval → asks again.

**T-06 (CLI) Headless connect/forward** with an unapproved value → exit 5 and the exact message.

**T-07 (CLI) `sverb approve db`** lists and approves interactively (PTY test). `--all --yes` approves all.

**T-08 (unit) Group-provided ProxyCommand** → the approval key is the group item id (provenance).

**T-09 (integration) The approvals table is never in the sync outbox** (assert it isn't an item and has no envelope).

**T-10 (integration) Deny** → blocked, and asked again on the next app start, but not again within the same session.

## 5. Passing functional characteristics
- [ ] ProxyCommand, non-loopback remote destinations, non-loopback local/dynamic binds and system-agent forwarding are recognized as locally acting.
- [ ] Such values from other devices (or changed values) are never acted on without explicit approval. Values typed locally are pre-approved.
- [ ] Approvals are device-local, keyed by item, field and the value hash, and re-requested when the value changes.
- [ ] Headless commands fail with exit 5 pointing to `sverb approve <host>`, which reviews and approves the values.
