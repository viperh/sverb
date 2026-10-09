-- sverb client schema v1 (SPEC §5.2). Applied by rusqlite_migration inside one
-- transaction; `PRAGMA user_version` becomes 1.
--
-- Canonical location: crates/sverb-store/migrations/ (inside the crate so that
-- `cargo package` works). migrations/client/ at the repository root holds
-- symlinks to these files. Later migrations: 0002 (local_approvals),
-- 0003 (pinned_keys).
--
-- Item bodies are only ever stored as encrypted envelopes. Decrypted data never
-- goes into a table defined here; the optional `item_index` is a TEMP table
-- (created at unlock time on the writer connection, with temp_store = MEMORY).

CREATE TABLE meta        (key TEXT PRIMARY KEY, value BLOB NOT NULL);

CREATE TABLE vaults      (id BLOB PRIMARY KEY, kind INTEGER, org_id BLOB, key_version INTEGER,
                          wrapped_key BLOB NOT NULL, sync_cursor INTEGER NOT NULL DEFAULT 0);

CREATE TABLE items       (id BLOB PRIMARY KEY, vault_id BLOB NOT NULL REFERENCES vaults(id),
                          revision INTEGER NOT NULL DEFAULT 0,  -- server revision, 0 = never synced
                          key_version INTEGER NOT NULL,
                          envelope BLOB NOT NULL,               -- encrypted ItemBody
                          deleted INTEGER NOT NULL DEFAULT 0,
                          dirty INTEGER NOT NULL DEFAULT 0,     -- pending push
                          updated_at INTEGER NOT NULL);

CREATE TABLE outbox      (item_id BLOB PRIMARY KEY,          -- one row per item: coalesced
                          vault_id BLOB NOT NULL,
                          base_revision INTEGER NOT NULL,     -- server revision the edit is based on
                          queued_at INTEGER NOT NULL,
                          attempts INTEGER NOT NULL DEFAULT 0);

CREATE TABLE device_local(item_id BLOB PRIMARY KEY, last_connected_at INTEGER, frecency REAL,
                          recording_dir TEXT);

CREATE TABLE sync_state  (id INTEGER PRIMARY KEY CHECK (id = 1),
                          server_url TEXT, device_id BLOB,
                          tokens_enc BLOB);                   -- access+refresh tokens, AEAD under LMK

CREATE INDEX items_vault_id ON items(vault_id);
CREATE INDEX items_dirty    ON items(dirty) WHERE dirty = 1;
CREATE INDEX outbox_vault_id ON outbox(vault_id);
