# M4-08 — Account flows: register (upgrade local-only), login (new device / existing local data), password change, recovery, logout

| | |
|---|---|
| **Milestone** | M4 (exit criterion: "A local-only vault with 500 items upgrades to synced without loss") |
| **Touches** | `crates/sverb-sync/src/account/{register.rs, login.rs, password.rs, recovery.rs, logout.rs, merge_local.rs}`, `crates/sverb-tui/src/views/settings/sync/*` (feature `sync`), `crates/sverb/src/cli/account.rs` (`login`, `logout`, `register`) |
| **Spec refs** | §11.2, §11.2.1 (all flows), §1.1 (modes; `logout --keep-local`), §5.3 (LMK re-wrap), §11.3 (self-grant), §16 |
| **Depends on** | M4-02, M4-03, M4-07, M1-04 |
| **Blocks** | M4-09 |

---

## 1. Current state in the codebase
Local-only mode works fully (M1–M3). The server auth API (M4-02), key hierarchy (M4-03) and sync engine (M4-07) exist, but nothing connects a local vault to an account.

## 2. Detailed description
All flows are reducer-driven wizards in Settings → Sync, with CLI equivalents. Each long operation shows progress and is resumable or idempotent where noted.

### 2.1 Local-only → register a new account (§11.2.1)
1. The user enters the **server URL** (required; no default) and email. Probe `GET /healthz` and the protocol version first.
2. sverb asks for the **current master password** (not a new one) and verifies it locally (unwrap the LMK). Enforce zxcvbn ≥ 3 (already guaranteed by M1-04).
3. Generate the account keypairs and the **recovery key**. Show the 24 words **once** with a mandatory confirmation step (re-type 3 random words), and say clearly:
   "Without this recovery key **and** without any logged-in device, your data is unrecoverable" (§11.2, required at signup).
4. OPAQUE registration with that password → export_key → AKEK → seal `private_bundle`, seal `recovery_bundle`.
5. The existing **personal vault becomes the account's personal vault**: same vault id, same VK and item ids. Create the **self-grant** (HPKE to own X25519, signed
   with own Ed25519). Send `register/finish` with the bundles, the personal vault `{id, name_enc, self_grant}` and the device.
6. Store `sync_state` (server URL, device id, tokens under the LMK). Mark **every** item dirty with `base_revision = 0` (already dirty from M1-07, but ensure the outbox
   rows exist) → the sync engine pushes everything.
7. Registration needs an invite or setup token if the server isn't `open`. The wizard asks for it when the server says so.

### 2.2 Local-only → log in to an existing account (§11.2.1)
1. URL, email, password → OPAQUE login. Success → decrypt `private_bundle`, fetch `/v1/vaults`, verify and open the grants (the personal self-grant is verified with own
   key; shared grants are verified per M5-03).
2. If the password **differs** from the local master password (detect by trying to unwrap the LMK with it): warn "Your local master password will be changed to your
   account password", then **re-wrap the LMK** under the KEK from the account password (new salt).
3. The local personal vault has a **different VK** from the account's personal vault. **Import** its items: show a **dry-run preview** (§11.2.1) of likely duplicates
   (same `address:port:user` for hosts, same public key for keys, same name for snippets and tags) with the choices **keep both / keep local / keep account** per row
   (and "apply to all"). Then decrypt each local item and re-encrypt it under the account vault's VK with a **new item id**, remapping references (group_id, tags,
   identity_id, key_id, jump_chain, port_forwards, startup_snippet_id, certificate_ids, workspace leaves) through an id map. Push, then **delete the old local
   vault** (and its `device_local` rows are remapped to the new ids so frecency is kept).
4. This is atomic per phase. The import runs in one SQLite transaction, and a crash before commit leaves the local vault intact. After commit, the push is ordinary sync.

### 2.3 New device with no local data
First run offers "Set up locally" (M1-04) **or** "Log in to a sync server". Login uses the account password as the master password for the new local LMK (§11.2.1:
one password).

### 2.4 Password change, online (§11.2.1)
Requires the server to be reachable:
1. OPAQUE login with the old password (reauth purpose, M4-02).
2. Register a new OPAQUE record and re-encrypt `private_bundle` under the new AKEK, uploaded **atomically** via `/v1/account/password` (version + 1).
3. Re-wrap the LMK locally under the new KEK (new salt).
4. The server notifies the other devices (`account_changed`) and revokes their tokens.
Failure between steps 2 and 3 (crash): on the next start, local unlock still uses the **old** password. The app detects `account_keys.version` > local, and login with the new
password then re-wraps (this falls under the 2.5 flow), so no data is lost. Document this recovery path.

### 2.5 Password changed on another device (§11.2.1)
This device still unlocks locally with the **old** password. Sync gets 401 or `account_changed {key_version}` → status `NeedsLogin` with the banner "Your password was changed on
another device", and the user enters the **new** password → OPAQUE login succeeds → the LMK is re-wrapped with the new password → sync resumes.

### 2.6 Password change in local-only mode
Only the LMK is re-wrapped (M1-04 §2.5). When sync is enabled, Settings routes to 2.4.

### 2.7 Forgotten password with the recovery key (§11.2)
Enter the email and the 24 words → the recovery flow (M4-02 §2.3) → decrypt `recovery_bundle` → set a new password (zxcvbn ≥ 3) → new OPAQUE record + re-sealed
`private_bundle` → local LMK re-wrap (if this device has local data, it must also unlock it: the LMK wrap needs the old password **or** the keyring; otherwise the local
DB is unusable, so offer to wipe local data and re-download from the server).

### 2.8 Logout / disable sync (§11.2.1, §1.1)
`sverb logout --keep-local` (and the UI "Disconnect"): revoke tokens (`/v1/auth/logout`), remove **shared vaults** from the device (they belong to the org), keep the
personal vault and password, clear `sync_state`. Items stay dirty-tracked for a later reconnect? **Decision:** reset `revision` to 0 and mark all dirty, so re-registering or
re-logging-in later behaves like 2.1/2.2. `sverb logout` without `--keep-local` → confirm, then also wipe all local data (a fresh start).

### 2.9 CLI (§16)
`sverb register [--server URL] [--email E]`, `sverb login [--server URL] [--email E]`, `sverb logout [--keep-local]`, all with TTY prompts for passwords. The recovery words
are shown only on a TTY, and non-TTY register fails (exit 2) so recovery keys never end up in logs or pipes.

## 3. Codebase changes
- The account flow modules in `sverb-sync`, the wizards in the TUI, and the CLI commands. The id-remapping importer (`merge_local.rs`) reuses the M2-11 preview UI.

## 4. Test cases to implement

**T-01 (integration, TestServer)** Register from local-only with **500 items** (M4 exit criterion): after sync, the server has 500 items with the **same ids**, and a second
device logging in sees all 500 decrypted identically.

**T-02 (integration)** Register uses the existing master password: afterwards, local unlock with the same password works, and `meta.kdf` is unchanged.

**T-03 (reducer)** The recovery confirmation step blocks progress until the 3 words are correct.

**T-04 (integration)** Login to an existing account with a different local password → warning shown. After the flow, the local unlock needs the account password.

**T-05 (integration)** Login with local data: 10 local hosts (2 duplicates of account hosts) → the preview shows 2 likely duplicates. With "keep account" for them → 8 imported
with new ids, references remapped (a host's group and identity point to the new ids), and the old local vault deleted.

**T-06 (integration)** A crash during the import transaction → the local vault is intact, and a retry succeeds.

**T-07 (integration)** Online password change: the old password fails on login, device B gets `account_changed` and `NeedsLogin`. B still unlocks locally with the old password.
After entering the new one, B syncs and its local unlock now needs the new password.

**T-08 (integration)** Password change with the server unreachable → refused with a clear message (online flow required).

**T-09 (integration)** Recovery: reset the password with the 24 words → login with the new password works, and the data is intact.

**T-10 (integration)** `logout --keep-local`: tokens revoked server-side, shared vaults removed locally (with a fixture shared vault), personal items intact, and a later login
re-syncs without duplicates.

**T-11 (CLI)** Non-TTY `sverb register` → exit 2, and no recovery words printed.

**T-12 (integration, M4 exit criterion)** Server DB contains no plaintext: after T-01, `pg_dump` contains none of the item labels, hostnames or passwords (canaries).

## 5. Passing functional characteristics
- [ ] A local-only user can register with their **existing master password**, keeping vault and item ids. Everything uploads without loss (500 items).
- [ ] Logging in to an existing account imports local items with a duplicate preview and id remapping, and adopts the account password locally.
- [ ] Online password change is atomic server-side and re-wraps the LMK. Other devices keep unlocking offline with the old password until they log in with the new one.
- [ ] The recovery key (24 words, shown once, confirmed) can reset a forgotten password.
- [ ] `logout --keep-local` keeps personal data and removes shared vaults. There is only ever one password.
