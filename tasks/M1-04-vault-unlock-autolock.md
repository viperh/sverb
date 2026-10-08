# M1-04 — Vault service: first run, LMK, master-password and keyring unlock, backoff, auto-lock

| | |
|---|---|
| **Milestone** | M1 |
| **Touches** | `crates/sverb-core/src/vault/{mod.rs, unlock.rs, lock.rs, password.rs}` (logic), `crates/sverb-store` (meta keys), `crates/sverb-tui/src/views/{unlock.rs, first_run.rs, lock_overlay.rs}`, `crates/sverb-tui/src/services/vault.rs`, `crates/sverb/src/cli/vault.rs` (`lock`/`unlock`, `require_unlocked`) |
| **Spec refs** | §5.3, §11.2 (password strength zxcvbn ≥ 3, local-only recovery via keyring), §11.2.1 (offline unlock), §11.5, §16 (headless unlock), §17 |
| **Depends on** | M1-01, M1-02, M1-03, M0-11 |
| **Blocks** | M1-05, M1-07, every feature reading items |

---

## 1. Current state in the codebase
There is no notion of locking. After M0-11 the TUI starts straight into the shell. M0-07 left
`require_unlocked()` as a stub that returns "not implemented".

## 2. Detailed description

### 2.1 Key hierarchy (local)
- **LMK**: 256 random bits, generated on first run. It wraps:
  - each vault's VK (`vaults.wrapped_key`, purpose `VaultKey(vault_id)`),
  - sync tokens (`sync_state.tokens_enc`, purpose `SyncTokens`; used in M4),
  - the recording key derivation input (§7.5; derived, not wrapped).
- **Password KEK** = `Argon2id(password, local_salt, m=256 MiB, t=3, p=1)`. `meta.kdf` stores
  `{alg:"argon2id", m_kib, t, p, salt}` (CBOR), and `meta.lmk_wrapped_pw = wrap(KEK, Lmk, LMK)`.
- **Keyring KEK** (optional): a random 32-byte secret stored in the OS keyring (`keyring` crate,
  service `"sverb"`, account `"lmk-kek:<db-uuid>"`, where `<db-uuid>` is a random id in `meta.db_id` so
  several `SVERB_HOME`s don't collide), and `meta.lmk_wrapped_keyring = wrap(keyring_kek, Lmk, LMK)`.
- A wrong password is detected by AEAD failure. **No verifier is stored** (§5.3).

### 2.2 First run (no `meta.kdf`)
1. The TUI shows the first-run screen: a welcome explanation (local-only by default, no account,
   §1.1), master password + confirm, a strength meter (`zxcvbn`), and the checkbox
   "Also unlock with OS keyring" (shown only if the keyring is available, probed by writing and deleting a test
   entry).
2. Strength: the score must be ≥ 3 (§11.2), and the meter shows zxcvbn feedback. A clear warning: "There is no
   way to recover this password. If you forget it, your data is lost unless you enable keyring unlock."
3. On submit (in `spawn_blocking`): generate the LMK, salt and params, derive the KEK, wrap, create the Personal vault
   (random VK wrapped by the LMK, `kind = Personal`, `key_version = 1`), generate `device_id`, init the HLC, and
   write everything in one store transaction.
4. CLI: `sverb unlock` on a fresh home performs the same flow on the TTY. Headless commands on a fresh home exit
   3 with "sverb is not initialized; run `sverb` once to set a master password".

### 2.3 Unlock
- Order at startup: keyring (if `lmk_wrapped_keyring` exists and the keyring returns the KEK) → otherwise
  the password prompt screen.
- The password prompt shows a masked field and the remaining attempts or delay message. Argon2 runs in
  `spawn_blocking` with a spinner ("Unlocking…"). It takes about 0.5–1 s by design (§1 goal).
- **Backoff** (§5.3): the counter `meta.unlock_failures` and the timestamp `meta.unlock_next_allowed_at` are
  persisted, so restarts don't reset them. **Interpretation:** failures 1–4 have no delay. From the 5th
  consecutive failure on, delays are 1 s, 2 s, 4 s, 8 s, 16 s, then 30 s (cap). Success resets the counter. During
  a delay the input is disabled and a countdown is shown. Raise the interpretation question with the spec owner.
- On success: unwrap the vault keys, decrypt all items to build the in-memory index (M1-05), create the TEMP
  table if used, and emit `UiEvent::Unlocked`.
- Keyring unlock failure (entry missing, user cancelled the OS prompt): fall back to the password prompt with an
  info toast.
- **Never contacts the server** (§5.3, §11.2.1).

### 2.4 Lock
Triggers: `leader ctrl-l` (`03-KEYBINDINGS.md` §4.1; the spec's `leader L` collides with resize-right), `sverb lock` (signals a running TUI over the local agent socket; if
no TUI is running, there's nothing to do, exit 0), idle for `general.auto_lock_minutes` (0 disables;
idle = no input events; tracked with a reset-on-input timer effect), and system suspend where detectable
(Linux: logind `PrepareForSleep` over D-Bus via `zbus`, optional feature; macOS/Windows: best effort or
skipped, documented).
On lock:
- zeroize the LMK, VKs and decrypted caches, and drop the in-memory index and the TEMP table,
- **open sessions stay connected** (default): each pane is covered by a lock overlay and input is
  blocked. Keys go to the unlock prompt and are never forwarded to sessions. Only `leader q` (quit) works besides
  the prompt (`03-KEYBINDINGS.md` §4.4). If `general.lock_disconnects_sessions
  = true`, sessions are closed instead,
- the built-in agent refuses signing (`SSH_AGENT_FAILURE`, M2-07),
- forms with unsaved edits are discarded, with a toast after unlock: "Unsaved changes were discarded when the vault locked".
After unlock, overlays are removed and the sessions are unchanged.

### 2.5 Change master password (local-only mode; online flows in M4-08)
Settings → Security → Change password: current password (verified by unwrapping), new password + confirm, zxcvbn ≥
3, re-wrap the LMK under the new KEK with a **new salt**, optionally upgrade the Argon2 params to the current defaults.
The keyring wrap is unaffected. When sync is on, this action routes to the online flow (M4-08).

### 2.6 Keyring-based recovery for local-only (§11.2)
If keyring unlock is enabled and the user forgot the password: the unlock screen offers "Forgot password?
Unlock with keyring and set a new password", which performs a keyring unlock and then the change-password flow
without the current password.

### 2.7 Headless (`require_unlocked`, M0-07)
Keyring → TTY prompt (same backoff) → exit 3. `sverb unlock` only validates the password (useful to check
the backoff state) and doesn't persist an unlocked state, because there's no daemon in v1.

### 2.8 Memory hygiene
The LMK and VKs are `Key32` (zeroize on drop) inside `UnlockedVault`, owned by the vault service, never by
`App`. The reducer only knows `LockState { Locked | Unlocking | Unlocked }`.

## 3. Codebase changes
- **Create** `sverb-core::vault` (pure logic: params, backoff schedule, state machine) and a
  `sverb-tui` vault service (executes Argon2 and keyring calls, owns the keys).
- **Create** views `first_run.rs`, `unlock.rs`, `lock_overlay.rs`.
- **Implement** the `Effect::{Unlock, Lock, ChangePassword}` handling.
- **Implement** `crates/sverb/src/cli/vault.rs` (`lock`, `unlock`, `require_unlocked`).
- Deps: `keyring`, `zxcvbn`, optional `zbus` (feature `suspend-detect`).

## 4. Test cases to implement
Use small Argon2 params in tests via a `#[cfg(test)]` params override (m = 19456, t = 1), so tests stay fast.

**T-01 (integration) First run.** Creates meta.kdf, lmk_wrapped_pw, one Personal vault and device_id.
The DB contains no plaintext LMK (grep for the LMK bytes).

**T-02 (unit) Weak password rejected.** `"password123"` → score < 3, and the error shows zxcvbn feedback.

**T-03 (integration) Unlock success** with the correct password. The VKs unwrap and an item round-trips.

**T-04 (integration) Wrong password** → `Auth` failure and `unlock_failures` incremented, with no distinguishable
error type.

**T-05 (unit, table) Backoff schedule.** Failure count → delay: 1–4 → 0, 5 → 1 s, 6 → 2 s, 7 → 4 s,
8 → 8 s, 9 → 16 s, 10 → 30 s, 20 → 30 s.

**T-06 (integration) Backoff persists across restart.** After 6 failures, reopen the store: the next attempt
before `next_allowed_at` is refused without running Argon2.

**T-07 (integration) Success resets the counter.**

**T-08 (integration, mock keyring) Keyring unlock** works with no password prompt. With the entry deleted, it falls
back to the prompt.

**T-09 (integration) Two SVERB_HOMEs** use distinct keyring accounts.

**T-10 (reducer) Auto-lock.** With `auto_lock_minutes = 1`: no input for 60 s (virtual) → `Effect::Lock`.
Input at 59 s resets the timer. `0` → never locks.

**T-11 (reducer) Lock overlay.** While locked, keys in a session pane produce no `SendToSession`, the lock
overlay renders (snapshot), and after unlock input flows again.

**T-12 (reducer) `lock_disconnects_sessions = true`** → `CloseSession` for all sessions on lock.

**T-13 (unit) Zeroization.** After lock, the vault service holds no `Key32`. Assert via a test hook counting
live key instances (a drop counter).

**T-14 (integration) Change password.** The old password fails and the new one unlocks. The salt changed and the keyring
still works.

**T-15 (integration) Keyring recovery flow** sets a new password without the old one.

**T-16 (CLI) Headless.** With the keyring disabled and no TTY → exit 3 (completes M0-07 T-08). With a TTY (PTY test)
→ prompt, then success.

**T-17 (perf, informative)** Unlock with the production params on CI hardware takes 0.3–2 s. Log it, but don't fail the build.

**T-18 (integration) Offline.** Unlock performs no network I/O (run with sync feature on, server URL
configured, and no network namespace or a blocked port; assert no connection attempt via a mock HTTP client
counter).

## 5. Passing functional characteristics
- [ ] First run creates the LMK, Argon2id-wrapped under a master password with zxcvbn ≥ 3, and the Personal vault.
- [ ] Unlock works by password (0.5–1 s) or keyring, and never contacts any server.
- [ ] Wrong passwords are detected by AEAD failure, with persisted exponential backoff capped at 30 s.
- [ ] Lock (manual, idle, suspend) zeroizes keys and caches, keeps sessions behind an overlay (or
      disconnects them if configured), and blocks input.
- [ ] Password change re-wraps the LMK with a new salt. Keyring recovery works for local-only users.
- [ ] Headless commands unlock via keyring or TTY, and otherwise fail fast with exit 3.
- [ ] Key material never lives in `App` state.
