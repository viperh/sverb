-- sverb-server initial schema (M4-01).
--
-- The tables below are SPEC §10.3 verbatim. Additions, each marked
-- "M4-01 addition":
--   * the CITEXT extension (users.email and invites.email are CITEXT);
--   * the `settings` key/value table holding `registration_mode` and the
--     bootstrap setup-token hash (SPEC §10.6).
-- Later schema changes go into new numbered files (0002_… is reserved for
-- M4-02); never edit this file once released, because sqlx checksums it.

-- M4-01 addition: case-insensitive email columns.
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE server_secrets (
  name TEXT PRIMARY KEY,                  -- 'opaque_server_setup'
  value_enc BYTEA NOT NULL                -- AEAD under key derived from SVERB_SERVER_SECRET
);
CREATE TABLE users (
  id UUID PRIMARY KEY, email CITEXT UNIQUE NOT NULL, created_at TIMESTAMPTZ NOT NULL,
  is_instance_admin BOOLEAN NOT NULL DEFAULT false,
  opaque_record BYTEA NOT NULL,           -- OPAQUE registration record
  totp_secret_enc BYTEA,                  -- encrypted with server KMS key
  disabled BOOLEAN NOT NULL DEFAULT false
);
CREATE TABLE account_keys (
  user_id UUID PRIMARY KEY REFERENCES users(id),
  x25519_pub BYTEA NOT NULL, ed25519_pub BYTEA NOT NULL,
  private_bundle_enc BYTEA NOT NULL,      -- encrypted under AKEK (client-side)
  recovery_bundle_enc BYTEA,              -- encrypted under recovery key
  version INT NOT NULL
);
CREATE TABLE devices (
  id UUID PRIMARY KEY, user_id UUID REFERENCES users(id), name TEXT, platform TEXT,
  created_at TIMESTAMPTZ, last_seen_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ
);
CREATE TABLE auth_tokens (
  token_hash BYTEA PRIMARY KEY,           -- SHA-256 of the 256-bit random token
  device_id UUID REFERENCES devices(id),
  kind TEXT CHECK (kind IN ('access','refresh')), expires_at TIMESTAMPTZ NOT NULL,
  family UUID NOT NULL,                   -- refresh-token rotation family
  used_at TIMESTAMPTZ                     -- set when a refresh token is rotated
);
CREATE TABLE orgs (id UUID PRIMARY KEY, name TEXT NOT NULL, created_at TIMESTAMPTZ);
CREATE TABLE org_members (
  org_id UUID REFERENCES orgs(id), user_id UUID REFERENCES users(id),
  role TEXT CHECK (role IN ('owner','admin','member')), PRIMARY KEY (org_id, user_id)
);
CREATE TABLE vaults (
  id UUID PRIMARY KEY,                    -- client-generated (UUIDv7), so local ids survive upload
  kind TEXT CHECK (kind IN ('personal','shared')) NOT NULL,
  owner_user_id UUID, org_id UUID REFERENCES orgs(id),
  key_version INT NOT NULL DEFAULT 1, head_revision BIGINT NOT NULL DEFAULT 0,
  gc_floor_revision BIGINT NOT NULL DEFAULT 0,  -- tombstones at or below this were purged
  rotation JSONB,                         -- non-NULL while a key rotation is in progress (§13.2)
  name_enc BYTEA NOT NULL,                -- vault name encrypted under vault key
  CHECK ((kind = 'personal') = (owner_user_id IS NOT NULL AND org_id IS NULL))
);
CREATE TABLE vault_members (
  vault_id UUID REFERENCES vaults(id), user_id UUID REFERENCES users(id),
  permission TEXT CHECK (permission IN ('read','write','manage')),
  key_version INT NOT NULL, wrapped_vault_key BYTEA NOT NULL,   -- HPKE to member's x25519
  wrapped_by UUID NOT NULL,               -- granting user (for signature verification)
  signature BYTEA NOT NULL,               -- ed25519 by granter over (vault, member, key_version, wrapped key)
  PRIMARY KEY (vault_id, user_id, key_version)
);
CREATE TABLE items (
  vault_id UUID REFERENCES vaults(id), id UUID NOT NULL,
  revision BIGINT NOT NULL, key_version INT NOT NULL,
  envelope BYTEA NOT NULL,                -- always present; tombstones carry a tiny encrypted
                                          -- body with the delete HLC (§12.4)
  deleted BOOLEAN NOT NULL DEFAULT false,
  updated_at TIMESTAMPTZ NOT NULL, updated_by_device UUID,
  PRIMARY KEY (vault_id, id)
);
CREATE UNIQUE INDEX items_vault_rev ON items (vault_id, revision);
CREATE TABLE items_rotation_staging (     -- re-encrypted items uploaded during key rotation
  vault_id UUID, id UUID, key_version INT, envelope BYTEA NOT NULL,
  PRIMARY KEY (vault_id, id)
);
CREATE TABLE invites (
  id UUID PRIMARY KEY, org_id UUID, email CITEXT, role TEXT, token_hash BYTEA,
  created_by UUID, expires_at TIMESTAMPTZ, accepted_at TIMESTAMPTZ
);
CREATE TABLE share_sessions (
  id UUID PRIMARY KEY, owner_user_id UUID, created_at TIMESTAMPTZ, expires_at TIMESTAMPTZ,
  mode TEXT CHECK (mode IN ('view','control')), max_viewers INT, closed_at TIMESTAMPTZ
);
CREATE TABLE audit_events (
  id BIGSERIAL PRIMARY KEY, org_id UUID, actor_user_id UUID, kind TEXT, target UUID,
  at TIMESTAMPTZ NOT NULL, meta JSONB    -- never contains plaintext item data
);

-- M4-01 addition: instance settings (SPEC §10.6 bootstrap). Known keys:
--   registration_mode  'open' | 'invite-only' | 'closed'
--   setup_token_hash   hex SHA-256 of the one-time setup token; present only
--                      until the first account registers with it.
CREATE TABLE settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO settings (key, value) VALUES ('registration_mode', 'invite-only');
