-- Terminal-share relay (SPEC §10.4 "Sharing", §14).
-- Whether viewers must authenticate with a sverb account.
ALTER TABLE share_sessions ADD COLUMN require_account BOOLEAN NOT NULL DEFAULT false;
-- `admin gc` deletes closed and expired shares; the owner lookup serves
-- account deletion.
CREATE INDEX share_sessions_owner ON share_sessions (owner_user_id);
