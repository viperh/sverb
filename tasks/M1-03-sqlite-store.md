# M1-03 — `sverb-store`: SQLite schema, migrations, connections, outbox, device-local data

| | |
|---|---|
| **Milestone** | M1 |
| **Touches** | `crates/sverb-store/src/{lib.rs, db.rs, schema.rs, items.rs, vaults.rs, outbox.rs, device_local.rs, meta.rs, sync_state.rs, index.rs, error.rs}`, `migrations/client/0001_init.sql` |
| **Spec refs** | §5.2, §5.1 (DB path), §12.1–12.3 (dirty/outbox semantics), §12.6 |
| **Depends on** | M1-01, M1-02, M0-03 |
| **Blocks** | M1-04, M1-05, M1-07, everything persistent, M4-07 |

---

## 1. Current state in the codebase
`crates/sverb-store` is an empty crate (M0-01). `Paths::db_file()` exists (M0-03). Nothing persists.

## 2. Detailed description

### 2.1 Schema (`migrations/client/0001_init.sql`, verbatim from §5.2)
Tables: `meta(key PK, value BLOB)`, `vaults(id PK, kind, org_id, key_version, wrapped_key NOT NULL,
sync_cursor DEFAULT 0)`, `items(id PK, vault_id FK, revision DEFAULT 0, key_version, envelope,
deleted DEFAULT 0, dirty DEFAULT 0, updated_at)`, `outbox(item_id PK, vault_id, base_revision,
queued_at, attempts DEFAULT 0)`, `device_local(item_id PK, last_connected_at, frecency, recording_dir)`,
`sync_state(id PK CHECK id=1, server_url, device_id, tokens_enc)`.
Add indexes: `items(vault_id)`, `items(dirty) WHERE dirty = 1`, `outbox(vault_id)`.
**Additional tables the spec implies, to be confirmed with the spec owner:**
- `local_approvals(item_id, field, value_sha256, approved_at, PRIMARY KEY(item_id, field))` for §17.1
  (M2-10). Add it in a later migration (`0002`), not here.
- `pinned_keys` for TOFU (M5-03), in a later migration.

### 2.2 Connection management
- Opened at `Paths::db_file()`. The file and its `-wal`/`-shm` siblings get mode `0600` on Unix (set
  the umask before open, or chmod after create).
- PRAGMAs on every connection: `journal_mode = WAL`, `synchronous = NORMAL`, `foreign_keys = ON`,
  `busy_timeout = 5000`, **`temp_store = MEMORY`** (§5.2: decrypted labels must never touch disk).
- **One writer** connection behind `tokio::sync::Mutex`. All writes go through
  `Store::write(|tx| …)`, which runs in `spawn_blocking` and holds the mutex for the duration.
- **Readers**: a small pool of 4 connections (an `r2d2`-style pool or a simple
  `crossbeam::ArrayQueue<Connection>`), used through `Store::read(|conn| …)` in `spawn_blocking`.
- **TEMP table caveat:** a `TEMP` table exists only on the connection that created it.
  `item_index` (§5.2) must therefore live on a **dedicated index connection**, or be replaced by an in-memory Rust
  structure. **Decision:** the decrypted index lives in Rust memory (M1-05, nucleo), and the
  `item_index` TEMP table is created on the writer connection only for SQL-side filtering, if used at
  all. Document that no decrypted data is ever written to a non-TEMP table, and verify it with a test
  (T-12).

### 2.3 Migrations
- `rusqlite_migration` with `M::up(include_str!("../../../migrations/client/0001_init.sql"))`. The path
  goes outside the crate, so either copy the migrations into `crates/sverb-store/migrations/` (preferred,
  keeping the repo-root `migrations/client` as a symlink or doc pointer) or use a build script. **Preferred:** move
  the SQL files inside the crate so `cargo package` works (the same lesson as the template's
  `include_str!("../../../.config/config.json")`).
- Run at startup inside a transaction (`to_latest`).
- **Newer schema refuses to open:** if `PRAGMA user_version` > the latest known version, return
  `StoreError::NewerSchema { found, supported }` with the message "This database was created by a newer
  sverb (schema N). Please update sverb." The DB is never modified.

### 2.4 Repository API (all async, internally `spawn_blocking`)
- **meta**: `get_meta(key) -> Option<Vec<u8>>`, `set_meta(key, value)`. Keys used later: `kdf`,
  `lmk_wrapped_pw`, `lmk_wrapped_keyring`, `unlock_failures`, `unlock_next_allowed_at`,
  `device_id`, `hlc_last`.
- **vaults**: `create_vault(id, kind, org_id, key_version, wrapped_key)`, `list_vaults()`,
  `update_wrapped_key`, `set_sync_cursor(vault, cursor)`, `delete_vault(vault)` (cascades items and outbox
  in one transaction).
- **items**:
  - `put_item(vault, id, key_version, envelope, deleted, mark_dirty: bool)`: upsert, sets
    `updated_at` and, if `mark_dirty`, sets `dirty = 1` and upserts the outbox row (§2.5), all in **one
    transaction**.
  - `get_item(id)`, `list_items(vault)`, `list_all_items()` (for index rebuild), `list_dirty(vault)`.
  - `apply_remote(vault, page: Vec<RemoteItem>, new_cursor)`: one transaction per page, together with the
    cursor update (§12.2). Used by M4-07, defined here.
  - Rejects writes to items flagged read-only (newer schema) with `StoreError::ReadOnlyItem`.
- **outbox** (§5.2): one row per item. `enqueue(item, vault, base_revision)` →
  `INSERT … ON CONFLICT(item_id) DO UPDATE SET queued_at = excluded.queued_at` **keeping the original
  `base_revision`** (ten edits produce one push). `rebase(item, new_base)` (after a pull merge, §12.2 step 3),
  `dequeue(item)`, `bump_attempts(item)`, `pending_count()`.
- **device_local**: `touch_connected(item, at)` updates `last_connected_at` and **frecency**,
  `get(item)`, `set_recording_dir`. Frecency formula: `frecency = frecency * 0.5^(Δdays/14) + 1` on
  each connect (14-day half-life). Document it, since the spec doesn't define one.
- **sync_state**: `get/set` of the single row. `tokens_enc` is stored as given (already AEAD'd under the LMK by
  the caller).
- **Plaintext guarantee:** the store never receives plaintext item bodies. Its API takes envelopes
  (bytes) only. The vault service (M1-04) does encryption.

### 2.5 Time
`updated_at`, `queued_at`, etc. are UNIX milliseconds (`i64`) from an injectable clock.

### 2.6 Errors
`StoreError { NewerSchema, Busy, ReadOnlyItem, NotFound, Corrupt(String), Sqlite(rusqlite::Error) }`.
`SQLITE_CORRUPT`/`NOTADB` map to `Corrupt` with a hint to restore from backup.

### 2.7 Out of scope
- Encryption and decryption (M1-04 vault service), search (M1-05), sync logic (M4-07).

## 3. Codebase changes
- **Create** the files listed in the header in `crates/sverb-store`. Deps: `rusqlite` (bundled),
  `rusqlite_migration`, `tokio` (rt, sync), `thiserror`, `tracing`; internal `sverb-core`,
  `sverb-crypto` (types only).
- **Create** `crates/sverb-store/migrations/0001_init.sql`. Make `migrations/client/` the canonical
  location (copy or symlink, as decided above).

## 4. Test cases to implement

**T-01 (integration) Fresh DB.** Opening in a temp `SVERB_HOME` creates all 6 tables, sets
`user_version = 1`, and the file mode is `0600` (Unix).

**T-02 (integration) PRAGMAs.** On writer and reader connections, `journal_mode = wal`,
`foreign_keys = 1`, `temp_store = 2` (MEMORY).

**T-03 (integration) Newer schema.** Set `user_version = 99` manually, open → `NewerSchema`, and the file bytes are
unchanged (hash before and after).

**T-04 (integration) Migration atomicity.** Inject a failing second migration in a test build. The DB stays at
the previous version, with no partial tables.

**T-05 (integration) Outbox coalescing.** `put_item(mark_dirty)` ten times with base_revision 7, then 9
(simulate) → exactly one outbox row with `base_revision = 7`.

**T-06 (integration) Rebase.** `rebase(item, 12)` updates base_revision, and a later enqueue keeps 12.

**T-07 (integration) apply_remote atomicity.** Simulate a failure mid-page (an error in the 3rd item of 5).
Neither the items nor the cursor change.

**T-08 (integration) delete_vault cascade.** Items and outbox rows for that vault are removed in one tx.

**T-09 (integration) Concurrency.** 8 concurrent readers + 1 writer for 2 s: no `SQLITE_BUSY` errors surface
(busy_timeout + WAL), and the final counts are consistent.

**T-10 (unit) Frecency.** Two connects 14 days apart give frecency `0.5·1 + 1 = 1.5`. Ordering favors recent.

**T-11 (integration) Read-only item.** Marking an item read-only, then `put_item` → `ReadOnlyItem`.

**T-12 (integration) No plaintext on disk.** Insert items whose plaintext labels contain the canary
`PLAINTEXT-CANARY-42`, sealed via sverb-crypto. Grep the DB file, WAL and SHM bytes: the canary is absent.
Repeat after creating and dropping the TEMP index table.

**T-13 (integration) Corrupt DB.** A file of random bytes → `Corrupt`, with a helpful message and no panic.

**T-14 (integration) sync_state singleton.** A second insert with id = 2 violates CHECK, and the API exposes only
get/set of row 1.

## 5. Passing functional characteristics
- [ ] The schema matches §5.2. Migrations run transactionally at startup, and newer DBs refuse to open untouched.
- [ ] WAL, `synchronous=NORMAL`, `foreign_keys=ON`, `temp_store=MEMORY`, one writer, a pool of 4 readers.
- [ ] The outbox holds one row per item and keeps the original base revision. Rebase works.
- [ ] Remote page application and cursor advance are atomic.
- [ ] The store handles only ciphertext, and a canary test proves no plaintext reaches disk.
- [ ] Frecency and last-connected live only in `device_local`.
- [ ] DB files are private (`0600`).
