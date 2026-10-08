# M3-06 — ConnLog entries and the Logs view

| | |
|---|---|
| **Milestone** | M3 |
| **Touches** | `crates/sverb-core/src/model/connlog.rs`, `crates/sverb-conn/src/ssh/connect.rs` (hooks from M1-13), `crates/sverb-tui/src/views/logs/{mod.rs, detail.rs}`, retention job in `services/maintenance.rs` |
| **Spec refs** | §9.12, §4.12 (`ConnLog`, synced only if `logs.sync`), §8.5 (Logs row), §15 `[logs]` |
| **Depends on** | M3-05 |
| **Blocks** | — |

---

## 1. Current state in the codebase
M1-13 placed no-op `ConnLog` hooks at connection start and end. The Logs section is a placeholder.

## 2. Detailed description
- **ConnLog** (§4.12): `host_id, started_at, ended_at, result: Ok | AuthFailed | HostKeyRejected | NetworkError(String),
  bytes_in, bytes_out`. Created at attempt start, finalized at end (or on app quit: `ended_at` = quit time). Byte counters come from
  the transport (session channel data only). Map `DisconnectReason` to `result` (Resolve, Connect, Negotiation, Timeout → NetworkError
  with a short message; Auth → AuthFailed; HostKey → HostKeyRejected; Exited/Closed → Ok).
- **Sync:** ConnLog items are synced only when `logs.sync = true` (§4.12). Otherwise they're stored with a **local-only** flag and excluded from the
  outbox. **Decision:** put them in the personal vault, with outbox enqueue skipped when `logs.sync = false`. Turning sync on later doesn't
  retroactively push old logs. Document it.
- The recording path lives in `device_local.recording_dir` keyed by the ConnLog id (§4.12, §5.2).
- **Logs view** (§9.12): newest first, filterable by host (fuzzy) and result (`r` cycles the filter: all / ok / failed). Columns: time, host, result, duration,
  bytes in/out, recording indicator. Actions: reconnect (opens a new session for the host), view error details (`ErrorReport` chain stored in
  the item as `error_detail`, an additional field: **spec addition**, recorded in data-model docs), replay recording (M3-05), export recording, clear
  (delete selected, or "clear all older than…").
- **Retention** (§9.12): logs older than `logs.retention_days` (90; 0 = forever) are tombstoned by a daily maintenance task (run on unlock and every
  24 h). Recordings are kept until deleted (separately configurable: add `recording.retention_days = 0`? **The spec says "Both are configurable"**, so add
  `recording.retention_days = 0` (keep forever) to config, a spec addition). Deleting a ConnLog asks whether to delete its recording too.
- The `[l] view log` banner action (M1-16) jumps here, focused on the relevant entry.

## 3. Codebase changes
- Model + hooks + view + maintenance service. Config additions in M0-06's table, schema and default file.

## 4. Test cases to implement

**T-01 (unit, table)** DisconnectReason → ConnLog result mapping.

**T-02 (integration)** Successful session → ConnLog Ok with ended_at and non-zero bytes.

**T-03 (integration)** Auth failure → AuthFailed with an error detail.

**T-04 (integration)** `logs.sync = false` → no outbox row for ConnLog. `true` → enqueued.

**T-05 (integration)** Retention: entries at 100 days old and 10 days old with retention 90 → the old one is tombstoned. Retention 0 → kept.

**T-06 (reducer)** Filter by result and by host.

**T-07 (reducer)** Reconnect action → `OpenSession` for the host.

**T-08 (reducer)** Delete with "also delete recording" → the file is removed.

**T-09 (snapshot)** Logs view at 160×48 with mixed results.

## 5. Passing functional characteristics
- [ ] Every connection attempt produces a ConnLog with timing, result and byte counts.
- [ ] The Logs view lists newest first, filters by host and result, and offers reconnect, error details, replay, export and clear.
- [ ] Logs sync only when `logs.sync = true`. Recordings never sync.
- [ ] Retention purges logs after `logs.retention_days`, and recordings are kept until deleted (configurable).
