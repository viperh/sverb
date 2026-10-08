# M4-07 — Client sync engine: token manager, push, pull, conflict retry, full resync, triggering, status

| | |
|---|---|
| **Milestone** | M4 |
| **Touches** | `crates/sverb-sync/src/{lib.rs, engine.rs, http.rs, tokens.rs, push.rs, pull.rs, resync.rs, status.rs}`, `crates/sverb-tui/src/services/sync.rs` (feature `sync`) |
| **Spec refs** | §12 (all), §5.2 (outbox, sync_cursor, sync_state.tokens_enc), §2.1 (blocking work), §12.5 (status bar states), §12.6 (device-local data never synced), §13.2 (409 rotating) |
| **Depends on** | M4-04, M4-05, M4-06, M2-10 (approval gate must exist before synced items can act locally) |
| **Blocks** | M4-08, M4-09, M5-* |

---

## 1. Current state in the codebase
The store has `items.dirty`, `outbox` (coalesced, base revision kept, `rebase`), `vaults.sync_cursor`, `sync_state` and `apply_remote` (M1-03). Local edits already
set `dirty` (M1-07). The `sverb-sync` crate is empty and only linked with feature `sync` (M0-01).

## 2. Detailed description

### 2.1 HTTP client and tokens
- `reqwest` with rustls, `Sverb-Proto: 1`, a 30 s timeout, and the base URL from `sync_state.server_url`. There's **no default server URL** (§1.1, decisions log).
- `TokenManager`: the access and refresh tokens are AEAD'd under the LMK (`wrap` purpose `SyncTokens`) in `sync_state.tokens_enc`. On a 401 or before expiry (60 s
  margin), refresh. **Persist the new tokens atomically before using them** (strict reuse detection, M4-02 §2.2). A refresh failure with `auth_required` →
  state `needs_login` (UI prompts for the password, M4-08) and sync pauses. Only one refresh is in flight (a mutex).
- The vault must be unlocked for sync to run (the tokens and VKs need the LMK). While locked, sync pauses and the WS stays connected? **Decision:** disconnect
  the WS on lock and resume on unlock.

### 2.2 Push (§12.3, §12.5)
- **Debounce:** 2 s after the last local change (`sync.push_debounce_ms`).
- For each vault with outbox rows: build batches (≤ 500 items, ≤ 8 MiB) of `{id, base_revision, key_version, envelope, deleted}` from the items table.
- Handle results:
  - `ok` → set `items.revision = revision`, `dirty = 0`, delete the outbox row (one transaction per batch result), and set `sync_cursor` only if it's contiguous?
    **No:** the cursor is pull-driven. A push doesn't advance the cursor, because other devices' revisions in between would be skipped. Pull will see our own revisions
    and apply them idempotently.
  - `conflict` with `current` → decrypt current, `merge(local, current)` (M4-06), re-seal, set the outbox `base_revision = current.revision`, and retry in the next
    round. **At most 5 rounds** (§12.3), then surface an error for that item (status `error`, toast with the item label) and keep it dirty.
  - `forbidden` → read-only membership: discard the local change? **Decision:** keep it local, mark the item `sync_blocked`, and show "You have read-only access
    to <vault>. Your local change was not uploaded" with actions "Revert to server version" or "Copy to personal vault".
  - `too_large` → error toast, keep dirty and blocked.
- `409 rotating` → pause pushes for that vault until a `vault_access rotated` notification or a poll shows rotation cleared, then refresh the vault key (new
  key_version), **re-encrypt pending items under the new VK**, and retry (§12.3, §13.2).
- `attempts` is incremented on transport errors, with exponential backoff (up to 5 min). **Offline edits queue indefinitely** (§12.5).

### 2.3 Pull (§12.2)
- Triggers (§12.5): on startup (after unlock), on WS `vault_changed {vault_id, head}` when head > cursor, every `sync.poll_fallback_secs` (300 s), and on
  `sverb sync --now`.
- Loop: `GET changes?since=cursor&limit=500`. Per page, in **one SQLite transaction** together with the cursor update (§12.2):
  1. Decrypt each item (the VK for its key_version). Observe stamps in the HLC (skew warning toast once per device).
  2. Not dirty locally → replace the local copy (envelope as received, `revision`).
  3. Dirty locally → `merge(local, remote)`, re-seal locally, keep dirty, and **rebase** the outbox base revision to the incoming revision.
  4. Advance the cursor. Repeat while `more`.
- Update the search index incrementally after commit (M1-05). Emit `IndexUpdated` and resurrection toasts.
- **410 Gone → full resync** (§12.2): pull everything from `since = 0` into a temp set. Delete local clean items absent from the server. **Push again** local dirty
  items absent from the server as **new** items (base 0, same id? The server purged the tombstone, so the same id with base 0 is accepted). Set the cursor to head.
- **Decryption failure** of a remote item (wrong key or tampered) → skip the item, log at warn with the id, and show a status `error` badge "1 item could not be
  decrypted". Never crash the sync loop.

### 2.4 Device-local data (§12.6)
`device_local`, `meta` (except what's documented), `config.toml`, recordings, `local_approvals` and window state are never pushed. Item kinds `HistoryEntry` and `ConnLog` are
pushed only when `history.sync` / `logs.sync` are true (enforce this in the outbox enqueue path, M1-07 item service).

### 2.5 Status (§12.5)
`SyncStatus = Disabled (local-only) | Synced | Syncing | Offline{pending: n} | Error{message} | NeedsLogin`, emitted as `UiEvent::Sync` and rendered in the top
bar and status bar: `⟳ synced` / `syncing` / `offline (3 pending)` / `error`.

### 2.6 Engine structure
One `SyncEngine` task (spawned by the TUI service or by headless `sverb sync`). It owns the HTTP client, WS client (M4-05) and timers, and talks to the store through
its async API. SQLite and crypto work runs in `spawn_blocking`.

## 3. Codebase changes
- Fill `sverb-sync`. TUI service glue under `cfg(feature = "sync")`.
- A **test server harness**: `sverb-e2e` gains `TestServer::start()` running `sverb-server` in-process against a `sqlx::test` database or a Postgres testcontainer, so
  multi-client tests run in CI (§19 "multi-client sync scenarios against a real server").

## 4. Test cases to implement

**T-01 (integration)** Single device: create 3 items → after 2 s, pushed. Server head 3. Local dirty 0, the outbox is empty.

**T-02 (integration)** Debounce: 10 edits within 1 s → one push request.

**T-03 (integration, 2 clients)** A edits port and B edits user on the same host offline. Both reconnect → both converge to port + user (field merge).

**T-04 (integration)** Conflict retry: B pushes with a stale base → conflict → merge → retry succeeds within 2 rounds.

**T-05 (unit, mock server)** Persistent conflicts → after 5 rounds, the error status and the item stays dirty.

**T-06 (integration)** Pull page atomicity: inject a crash (panic hook in a test) after applying 2 of 5 items → after restart, the cursor equals the previous value and
the re-pull applies everything once.

**T-07 (integration)** Dirty local + remote change → merged, still dirty, and the outbox base rebased to the remote revision. The next push succeeds without conflict.

**T-08 (integration)** 410 Gone: run server GC with a short horizon, and a client with an old cursor → full resync. Clean local items deleted on the server disappear,
and a dirty local item absent on the server is re-pushed.

**T-09 (integration)** Offline: the server is down for 3 edits → status `offline (3 pending)`. The server is back → status `synced`, everything pushed.

**T-10 (integration)** WS-triggered pull: B pushes → A applies within 1 s via the notification. With the WS disabled, A applies within the poll interval (shortened in
the test).

**T-11 (integration)** Token refresh on 401, with the new tokens persisted before the next request. A refresh-token reuse scenario → `NeedsLogin`.

**T-12 (integration)** Rotating: a push during rotation → paused. After rotation completes → re-encrypted under the new key_version and pushed.

**T-13 (integration)** Device-local exclusions: ConnLog with `logs.sync=false` is never pushed. `device_local` and approvals are never sent (inspect request bodies via a
mock server).

**T-14 (integration)** Undecryptable remote item → skipped with an error badge, and the other items are applied.

**T-15 (M4 exit criterion)** Two devices edit offline (100 random edits each over 20 items), reconnect, and converge to identical decrypted states.

**T-16 (integration)** Lock pauses sync, and unlock resumes it.

## 5. Passing functional characteristics
- [ ] Local edits push after a 2 s debounce, in batches within the limits. Results update revisions and clear dirty flags.
- [ ] Conflicts merge field-by-field and retry (at most 5 rounds). Read-only and too-large cases are surfaced without data loss.
- [ ] Pull applies pages atomically with the cursor, merges into dirty items, and rebases the outbox.
- [ ] 410 triggers a correct full resync. Offline edits queue indefinitely.
- [ ] Pull is triggered on startup, by WS notifications and by a 5-min fallback poll. Status is shown as synced/syncing/offline (N pending)/error.
- [ ] Tokens are stored encrypted under the LMK and refreshed safely. Device-local data never leaves the device.
- [ ] Two offline devices converge.
