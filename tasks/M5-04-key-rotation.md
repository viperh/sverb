# M5-04 — Vault key rotation on revoke

| | |
|---|---|
| **Milestone** | M5 (exit criterion: "3-member org scenario passes, including revocation + rotation") |
| **Touches** | `crates/sverb-server/src/routes/rotate.rs`, `crates/sverb-server/src/sync/rotation.rs`, `crates/sverb-sync/src/rotation.rs`, `crates/sverb-tui/src/views/dialogs/rotation.rs` |
| **Spec refs** | §13.2 (revoke + rotation steps 1–5), §10.3 (`vaults.rotation`, `items_rotation_staging`), §10.4 (`/rotate`), §12.3 (409 rotating), §19 (kill rotation mid-way and assert recovery) |
| **Depends on** | M5-02, M5-03, M4-05 |
| **Blocks** | — |

---

## 1. Current state in the codebase
Grants work (M5-02). Revocation would only delete the membership. Pushes already return `409 rotating` when `vaults.rotation` is set (M4-04), but nothing sets it.

## 2. Detailed description

### 2.1 Revoke (§13.2)
`DELETE /v1/vaults/{id}/members/{user}`: the server deletes **all** of that user's membership rows for the vault immediately (they can't pull anymore), emits
`vault_access revoked` to them, and records an audit event. The revoking client then **starts a rotation** right away (a progress dialog). Removing an org member (M5-01) triggers
the same for every vault they had.

### 2.2 Rotation protocol
1. `POST /v1/vaults/{id}/rotate {action:"begin", new_key_version}` (manage). The server checks that `new_key_version == key_version + 1` and that no rotation is active (or the
   active one is abandoned), then sets `rotation = {by, new_key_version, started_at}`. From now on pushes get **409 rotating** and pulls keep working.
2. The client generates **VK′**, pulls everything up to `head_revision`, and re-encrypts every item (including tombstones) under VK′ with the **same item id** and AAD
   key_version = new (§13.2).
3. `POST /rotate {action:"upload", items:[{id, envelope}]}` in **chunks ≤ 500**, written to `items_rotation_staging`. Upload is idempotent (upsert by id).
4. `POST /rotate {action:"commit", wrapped_keys:[{user, wrapped, signature}…]}`: one wrapped VK′ per **remaining** member (verified public keys, M5-03, including the
   committer's own and org admins'). In **one transaction**, the server checks that staging covers **every** item currently in `items` for the vault (by id set; also
   check that no new items appeared, which is impossible during rotation because pushes are blocked), moves the staged envelopes into `items` with **fresh revisions** (head +
   count, gap-free as in M4-04), inserts the new `vault_members` rows for key_version′, **deletes the old-version member rows** (§13.2), bumps `vaults.key_version`, clears
   `rotation` and the staging rows, and notifies members with `vault_access rotated`. Response: the new head.
5. **Abandonment:** if the rotating client disappears, after **15 minutes** (`started_at` + 15 min) the rotation counts as abandoned. The next `begin` by any manage client, or
   `admin gc`, discards staging and clears `rotation`. The next manage client to connect sees `rotation.abandoned` in `GET /v1/vaults` and is **prompted to restart it**
   (§13.2).
- During the window, old-version member rows remain so remaining members can still decrypt not-yet-rotated items (§13.2).
- **Members receiving `rotated`:** refresh vaults, verify and open the new grant (M5-03), wrap VK′ under the LMK, then re-pull (the items have new revisions). Pending local
  edits made during rotation (blocked by 409) are re-sealed under VK′ and pushed (M4-07 §2.2).
- The revoked user keeps data already synced, which is unavoidable. Rotation protects only **future** changes (§13.2). The UI says so in the revoke dialog.

## 3. Codebase changes
- Server rotate route and transaction. Client rotation orchestrator (resumable: persist progress in `meta` as `rotation:<vault>` = uploaded ids, so a crash resumes
  instead of restarting). Dialogs.

## 4. Test cases to implement

**T-01 (integration)** Happy path: 3 members (Alice manage, Bob write, Carol read). Alice revokes Carol → rotation completes. Bob decrypts everything with VK′. Carol gets 404 or 403 on pull.
The key_version is bumped and old member rows deleted.

**T-02** A push during rotation → 409. After commit → Bob's pending edit is re-encrypted and pushed successfully.

**T-03** Commit with incomplete staging → 400 with the missing count, and no change applied (the transaction rolled back).

**T-04 (§19)** Kill the rotating client mid-upload. Before 15 min → begin by another client is refused (active). After 15 min (time travel) → the next manage client is prompted,
restarts, and completes. Staging from the first attempt is discarded.

**T-05** Resume: the same client crashes and restarts within 15 min → it resumes the uploads from persisted progress (no duplicate work beyond idempotent upserts) and commits.

**T-06** Revisions after commit are gap-free and greater than the pre-rotation head. A puller with an old cursor receives all rotated items.

**T-07** A wrapped_keys entry for a user with a changed (unpinned) key → the client refuses to include them and warns. Commit then requires the remaining verified members only?
**Decision:** block the commit until resolved. Document it.

**T-08 (M5 exit criterion)** The full 3-member scenario with invite, grant, edits, revoke, rotation and continued sync for the remaining members, end to end via TestServer.

## 5. Passing functional characteristics
- [ ] Revoking a member removes their access immediately and starts a key rotation.
- [ ] Rotation follows begin → re-encrypt → chunked upload → atomic commit (full coverage check, fresh revisions, new grants, old grants removed), with 409 rotating for pushes in between.
- [ ] Abandoned rotations (15 min) are discarded and the next manage client is prompted. The client can resume after a crash.
- [ ] Remaining members transparently switch to the new key, and pending edits are re-encrypted.
