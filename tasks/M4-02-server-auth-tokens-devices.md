# M4-02 — Server authentication: OPAQUE, tokens with rotation, devices, TOTP, account deletion

| | |
|---|---|
| **Milestone** | M4 |
| **Touches** | `crates/sverb-server/src/routes/{auth.rs, account.rs, devices.rs}`, `crates/sverb-server/src/auth/{opaque.rs, tokens.rs, totp.rs, extractor.rs}`, `crates/sverb-proto/src/auth.rs`, `crates/sverb-crypto/src/opaque.rs` (shared cipher suite) |
| **Spec refs** | §10.2 (1, 2, 7), §10.3 (users, devices, auth_tokens), §10.4 (tokens, reuse detection, enumeration resistance, OPAQUE config, auth endpoints), §11.2 |
| **Depends on** | M4-01, M1-01 |
| **Blocks** | M4-04, M4-08 |

---

## 1. Current state in the codebase
The server skeleton exists (M4-01). There's no auth.

## 2. Detailed description

### 2.1 OPAQUE (§10.4)
- `opaque-ke` cipher suite `{ OPRF: Ristretto255, KE: TripleDh<Ristretto255, Sha512>, KSF: Argon2id(m=64 MiB, t=3, p=1) }`, defined
  **once** in `sverb-crypto::opaque` and used by both client and server. The KSF runs **client-side**.
- `ServerSetup`: generated on first start, stored encrypted in `server_secrets` (M4-01).
- **Registration:** `POST /v1/auth/register/start {email, registration_request, invite_token? | setup_token?}` →
  `{registration_response}`. `POST /v1/auth/register/finish {email, registration_upload, account_keys: {x25519_pub,
  ed25519_pub, private_bundle_enc, recovery_bundle_enc, version:1}, personal_vault: {id (client UUIDv7), name_enc,
  self_grant: {wrapped_vault_key, signature, key_version:1}}, device: {name, platform}}` → creates the user, account_keys,
  personal vault (§10.4: "creates the personal vault"; the id comes from the client so local ids survive, §10.3 comment) and vault_members
  self-grant, plus the device and tokens, **atomically**. Policy checks: registration mode and invite/setup token (M4-01). Email normalized (trim,
  lowercase domain; CITEXT handles case).
- **Login:** `POST /v1/auth/login/start {email, credential_request}` → `{credential_response, login_state_id}`, where the server login state is kept
  server-side (in memory with a TTL of 60 s, or in Postgres for multi-replica; **decision:** Postgres table `login_states` with expiry, so it works across
  replicas). **Enumeration resistance:** an unknown email gets a KE2 computed with `ServerLogin::start` using `None` (the dummy record path), with the same
  timing. `POST /v1/auth/login/finish {login_state_id, credential_finalization, totp?, device: {id?|name, platform}}` → `{tokens,
  account_keys: {private_bundle_enc, x25519_pub, ed25519_pub, version}, user_id}`. A failure is identical for unknown and wrong-password (`auth_required`,
  same message). Disabled users → the same failure, logged server-side.
- **TOTP** (§10.2): `POST /v1/account/totp {secret_enc? …}` enable flow: the server generates the secret, returns an otpauth URI, the client confirms
  with a code, and the secret is stored **encrypted under the server secret** (§10.3 comment "server KMS key"). `DELETE` disables it (requires a code). When enabled,
  `login/finish` requires a valid `totp` (±1 step window, replay protection: store the last used step).

### 2.2 Tokens (§10.4)
- Access and refresh tokens are 256-bit random values, sent base64url, **stored as SHA-256 hashes**. Access TTL 15 min. Refresh TTL 30 days, bound to the device,
  **rotated on every use** (`POST /v1/auth/refresh {refresh_token}` → a new pair, and the old one gets `used_at = now()`).
- **Reuse detection:** presenting a refresh token with `used_at IS NOT NULL` → revoke the **whole family** (all tokens with that family), return
  `auth_required`, and audit-log it. To tolerate a client crash between sending and storing the rotated token, add a **grace window of 10 s**? The spec doesn't
  have one. **Decision:** no grace (strict per spec). The client must persist new tokens atomically before using them (M4-07).
- `POST /v1/auth/logout` revokes the current device's tokens.
- **Auth extractor:** `Authorization: Bearer <access>` → hash lookup, not expired, device not revoked, user not disabled → `AuthCtx {user_id,
  device_id}`. Otherwise 401 `auth_required`.

### 2.3 Account
- `POST /v1/account/password` (§11.2.1, implemented with the client in M4-08): requires a fresh auth proof (a login performed within the last 5 minutes: a
  `reauth_token` from login/finish when called with `purpose: "reauth"`). The body is a new OPAQUE registration upload plus the re-encrypted `private_bundle_enc`,
  `version + 1`. **Atomically** replace `opaque_record`, update `account_keys`, **revoke all other devices' tokens** (§11.2.1 "old access tokens are
  revoked"), and emit WS `account_changed` (M4-05).
- `POST /v1/account/recovery` (§10.4): recovery flow. The client proves the recovery key by decrypting the `recovery_bundle_enc` (fetched via
  `POST /v1/account/recovery/start {email}` → `{recovery_bundle_enc}` **only if** an emailed one-time code matches; without SMTP, the operator
  issues a code via `admin user recovery-code <email>`. **The spec doesn't define how a recovery attempt is authenticated**, so this is a proposal. Raise it).
  Then it uploads a new OPAQUE record and the re-encrypted bundle, like a password change.
- `DELETE /v1/account` requires reauth. It deletes the user, devices, tokens, the personal vault and items, and memberships (shared vaults remain), plus an audit event.

### 2.4 Devices (§10.2.7)
`GET /v1/devices` → `[{id, name, platform, created_at, last_seen_at, current: bool, revoked_at}]`. `DELETE /v1/devices/{id}` →
revoke (set `revoked_at` and delete its tokens). `last_seen_at` is updated on token use (throttled to once per 5 min).

## 3. Codebase changes
- Routes, extractor, OPAQUE wrappers, TOTP (`totp-rs`) and the DTOs in `sverb-proto` (with serde, base64url without padding for binary fields).
- A migration `0002_login_states.sql` and a TOTP last-step column.

## 4. Test cases to implement

**T-01** Full OPAQUE register → login round-trip with the real client-side code (`sverb-crypto::opaque`) inside the test. `export_key` is equal across
both client operations (stable per password).

**T-02** Wrong password → `login/finish` 401 `auth_required`. Unknown email → `login/start` succeeds with a valid-looking KE2 and finish fails identically
(compare response bodies and status codes; timing difference < 20% median over 50 runs, as an informational check).

**T-03** Register is atomic: inject a failure in the vault insert → no user row exists.

**T-04** Registration gating: setup token, invite token and mode checks (reuse M4-01 T-10/T-11 with the real flow).

**T-05** Access token expiry after 15 min (time-travel via an injectable clock) → 401.

**T-06** Refresh rotation: the new pair works, and the old refresh token is marked used.

**T-07** Reuse detection: presenting the old refresh token again → 401, **and** the new tokens in the family are revoked too.

**T-08** Logout revokes the current device only.

**T-09** Device revoke → that device's access token gets 401 immediately.

**T-10** TOTP enable/confirm/login: a missing code → 401 with a code hint (`totp_required` sub-reason in the message). Wrong → 401. Correct → ok. Replay of the same step → 401.

**T-11** Password change revokes other devices' tokens, bumps `account_keys.version`, and the old password no longer logs in.

**T-12** Tokens are stored hashed: the DB contains no raw token bytes (grep the DB dump for the token value).

**T-13** Disabled user → login fails identically to a wrong password.

**T-14** Account delete removes the personal vault items, and shared vault items are untouched.

## 5. Passing functional characteristics
- [ ] OPAQUE registration and login with the specified cipher suite. The server never sees the password, and the KSF runs client-side.
- [ ] Unknown emails are indistinguishable from known ones through login/finish.
- [ ] Access tokens (15 min) and rotating refresh tokens (30 days, device-bound) are stored hashed. Reuse revokes the family.
- [ ] Device listing and revocation, optional TOTP, password change (atomic, revoking other devices), recovery and account deletion work.
- [ ] Registration atomically creates the user, keys, personal vault with self-grant, and device.
