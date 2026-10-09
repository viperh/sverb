-- sverb client schema v3 (SPEC §13.3): TOFU pins of account public keys.
--
-- One row per user whose keys this device has seen (org members, granters, and this
-- account itself with is_self = 1). The first key seen is pinned; a different key
-- seen later does NOT replace the pin: it is parked in the changed_* columns, the
-- member shows "key changed", grants to them are blocked and grants from them are
-- not trusted until the user compares safety numbers and accepts the new key.
--
-- Device-local and never synced: a malicious server must not be able to poison pins
-- through sync. Rows hold only public keys, fingerprints and the server's display
-- label (untrusted, used for lookups only).

CREATE TABLE pinned_keys (user_id               BLOB    NOT NULL PRIMARY KEY,
                          label                 TEXT,
                          fingerprint           BLOB    NOT NULL,
                          x25519_pub            BLOB    NOT NULL,
                          ed25519_pub           BLOB    NOT NULL,
                          first_seen_at         INTEGER NOT NULL,
                          verified              INTEGER NOT NULL DEFAULT 0,
                          verified_at           INTEGER,
                          is_self               INTEGER NOT NULL DEFAULT 0,
                          changed_fingerprint   BLOB,
                          changed_x25519_pub    BLOB,
                          changed_ed25519_pub   BLOB,
                          changed_at            INTEGER);
