-- sverb client schema v2 (M2-10, SPEC §17.1): the device-local allowlist of values
-- that act on this machine (ProxyCommand, non-loopback forwards, system-agent
-- forwarding). One row per (item, field): the SHA-256 of the exact value the user
-- approved. A changed value hashes differently, so it no longer matches and is asked
-- for again; approving it again upserts the row.
--
-- Never synced: this table is not an item, has no envelope and never reaches the
-- outbox. It holds no decrypted values, only item ids, field names and hashes.

CREATE TABLE local_approvals (item_id      BLOB    NOT NULL,
                              field        TEXT    NOT NULL,
                              value_sha256 BLOB    NOT NULL,
                              approved_at  INTEGER NOT NULL,
                              PRIMARY KEY (item_id, field));
