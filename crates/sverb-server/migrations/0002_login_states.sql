--
-- Additions to the SPEC §10.3 schema (never edit once released; sqlx
-- checksums it):
--   * login_states: the OPAQUE server login state between login/start and
--     login/finish (60 s TTL). Kept in Postgres, not in memory, so the two
--     requests may hit different replicas. `state_enc` is AEAD-sealed with
--     the server-secret key; `user_id` is NULL for unknown emails (dummy
--     record, §10.4 enumeration resistance).
--   * users.totp_last_step: the last accepted TOTP time step (replay
--     protection); users.totp_pending_enc: a TOTP secret awaiting its
--     confirmation code (sealed like totp_secret_enc).
--   * reauth_tokens: single-use proofs of a fresh login (5 min) for password
--     change and account deletion (SHA-256 hashes only).
--   * recovery_codes: one-time codes that gate fetching the recovery bundle
--     (SHA-256 hashes only; at most one live code per user).
--   * indexes for token and device lookups.

CREATE TABLE login_states (
  id UUID PRIMARY KEY,
  user_id UUID,
  state_enc BYTEA NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX login_states_expires_at ON login_states (expires_at);

ALTER TABLE users
  ADD COLUMN totp_last_step BIGINT,
  ADD COLUMN totp_pending_enc BYTEA;

CREATE TABLE reauth_tokens (
  token_hash BYTEA PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE recovery_codes (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  code_hash BYTEA NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  attempts INT NOT NULL DEFAULT 0
);

CREATE INDEX auth_tokens_device_id ON auth_tokens (device_id);
CREATE INDEX auth_tokens_family ON auth_tokens (family);
CREATE INDEX devices_user_id ON devices (user_id);
CREATE INDEX vault_members_user_id ON vault_members (user_id);
