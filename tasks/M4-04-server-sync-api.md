# M4-04 — Server vault/item API: pull, push with gap-free revisions, limits, quota, tombstone GC

| | |
|---|---|
| **Milestone** | M4 |
| **Touches** | `crates/sverb-server/src/routes/vaults.rs`, `crates/sverb-server/src/sync/{pull.rs, push.rs, gc.rs, quota.rs}`, `crates/sverb-proto/src/sync.rs` |
| **Spec refs** | §10.2 (3), §10.3 (vaults, vault_members, items), §10.4 (Vaults and sync table), §10.5, §12.1, §12.2 (pull, 410 Gone), §12.3 (push), §13.2 (`409 rotating`, read members forbidden), §19 (no missed revisions under concurrency) |
| **Depends on** | M4-02 |
| **Blocks** | M4-05, M4-07, M5-* |

---

## 1. Current state in the codebase
Auth works (M4-02). Personal vaults are created at registration. There are no item endpoints.

## 2. Detailed description

### 2.1 `GET /v1/vaults` (§10.4)
The vaults the user belongs to: `[{id, kind, org_id, name_enc, key_version, head_revision, permission, grants: [{key_version,
wrapped_vault_key, wrapped_by, signature}], rotation: {in_progress, new_key_version}?}]`. Grants include previous key versions still
present (needed during rotation, §13.2).

### 2.2 Pull (§12.2)
`GET /v1/vaults/{id}/changes?since=<cursor>&limit=<n≤500, default 500>` → `{ items: [{id, revision, key_version, envelope,
deleted}], head_revision, more }`, ordered by `revision ASC`, where `revision > since`. Requires membership (any permission).
- **410 Gone** (`code: gone`) if `since < vaults.gc_floor_revision` and `since != 0` (§12.2).
- Pulls keep working during rotation (§13.2).

### 2.3 Push (§12.3, §12.1)
`POST /v1/vaults/{id}/changes { changes: [{id, base_revision, key_version, envelope, deleted}] }` →
`{ results: [{id, status: ok|conflict|forbidden|too_large, revision?, current?}] }`.
- Requires `write` or `manage` (read → each result `forbidden`, or the whole request 403? **Decision:** a 403 for the whole request when the user has only
  read (§13.2 "rejects pushes from read members"). Per-item `forbidden` is reserved for future per-item ACLs).
- If `vaults.rotation IS NOT NULL` → **409 `rotating`** for the whole request (§12.3).
- Every change must have `key_version == vaults.key_version`, otherwise that item is `conflict`? **Decision:** `invalid` 400 for the whole batch, because
  it means the client has a stale key version and must refresh vaults first. Document it.
- Limits (§10.5): envelope ≤ 1 MiB (per item `too_large`), batch ≤ 500 items **and** ≤ 8 MiB total (whole request 400 `invalid`), and the per-user quota
  (sum of the user's personal vault envelope bytes, default 100 MiB; shared vault bytes count against… **decision:** the org, tracked per vault and
  configurable; for v1, count shared vault bytes against the vault creator's quota? Leave shared vaults unlimited by quota but limited by a
  per-vault cap of 1 GiB; raise this question). Over quota → `too_large` with the message "quota exceeded".
- **Algorithm, in one transaction per batch:**
  1. `SELECT … FROM items WHERE vault_id=$1 AND id = ANY($ids) FOR UPDATE`.
  2. For each change: accept if (`existing.revision == base_revision`) or (absent and `base_revision == 0`). Otherwise `conflict` with `current`
     = the current server item `{revision, key_version, envelope, deleted}`.
  3. `n` = the accepted count. If `n > 0`: `UPDATE vaults SET head_revision = head_revision + n WHERE id=$1 RETURNING
     head_revision` (takes the row lock until commit → **pushes to the same vault are serialized**, and revisions become visible in assignment
     order, so a reader can't skip a revision, §12.1). Assign revisions `head-n+1 … head` in batch order.
  4. Upsert the accepted items (`updated_at = now()`, `updated_by_device`). Tombstones keep their envelope (§10.3).
  5. Commit, then notify (M4-05).
- **Ordering subtlety:** step 3's row lock must be taken **before** reading conflicts? Two concurrent pushes to the same item: both `SELECT … FOR UPDATE`
  serializes them on the item rows, but pushes to different items in the same vault are serialized only at step 3, which is fine because revisions are
  assigned under the vault lock. Document why gaps can't be observed: the revision assignment and commit happen while holding the vault row lock.

### 2.4 Tombstone GC (§12.2)
`admin gc` (and an optional daily background job, `SVERB_GC_INTERVAL_HOURS`) deletes tombstoned items with `updated_at < now() - horizon` (default 90
days), then raises `vaults.gc_floor_revision` to the highest purged revision (per vault, in one transaction).

### 2.5 Vault creation (§10.4)
`POST /v1/vaults` creates a shared vault, which is M5-02 (org admin+). Personal vaults are only created at registration.

## 3. Codebase changes
- Routes and sync modules. DTOs in `sverb-proto::sync` (shared with the client engine).

## 4. Test cases to implement

**T-01** Push new items with base 0 → ok, revisions 1..n, head = n.

**T-02** Push with a stale base → conflict including `current`. Mixed batch: ok items get consecutive revisions, and **rejected ones consume none** (§12.1).

**T-03** Pull pagination: 1,200 items, limit 500 → three pages with `more` true, true, false, ordered ascending, with no duplicates.

**T-04 (concurrency, §19)** 8 parallel pushers to one vault (each 200 single-item pushes) while a puller loops `since=cursor` and advances. Assert the puller
sees **every** revision 1..1600 exactly once, never skipping (with the cursor monotonic). Run 5 iterations.

**T-05** Read-only member push → 403 forbidden. Pull works.

**T-06** Rotation in progress → push 409 rotating, pull works.

**T-07** Envelope of 1 MiB + 1 → item `too_large`. A batch of 501 → 400. A batch of 8 MiB + 1 → 400.

**T-08** Quota exceeded → `too_large` "quota exceeded", with no partial accept beyond the quota.

**T-09** GC: tombstones older than the horizon are purged and `gc_floor_revision` raised. Pull with `since` below the floor → 410 gone. `since=0` → OK.

**T-10** Non-member → 404 (don't reveal existence).

**T-11** A key_version mismatch in a push → 400 invalid.

**T-12** The server DB contains no plaintext: run a client-side seal of items containing a canary label, push, and grep a `pg_dump` → absent (M4 exit criterion
"Server DB contains no plaintext", together with M4-08 T-xx).

## 5. Passing functional characteristics
- [ ] Pull returns ascending revisions with pagination and returns 410 below the GC floor.
- [ ] Push is optimistic-concurrency per item (base_revision), in one transaction per batch, with gap-free revisions (vault row lock), and rejected changes consume no revisions.
- [ ] Read members can't push, and pushes during rotation return 409 rotating.
- [ ] Item, batch and quota limits from §10.5 are enforced.
- [ ] Tombstone GC raises the floor. A concurrency test proves pullers never miss a revision.
- [ ] The server stores only ciphertext.
