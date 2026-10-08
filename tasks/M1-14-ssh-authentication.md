# M1-14 — SSH authentication chain and interactive prompts

| | |
|---|---|
| **Milestone** | M1 |
| **Touches** | `crates/sverb-conn/src/ssh/auth.rs`, `crates/sverb-conn/src/agent_client.rs` (system agent signer), `crates/sverb-tui/src/views/dialogs/auth_prompt.rs` |
| **Spec refs** | §6.1.1 step 4, §4.2/§4.4/§4.5 (credentials), §9.4 (hardware keys via agent), §15 `ssh.max_auth_attempts`, `ssh.use_system_agent` |
| **Depends on** | M1-13, M1-06 (dialogs) |
| **Blocks** | M2-03, M2-04, M2-05, M2-07 |

---

## 1. Current state in the codebase
M1-13 connects and handshakes, with a stub auth step. The `Key` and `Identity` item views exist (M1-02). Generating and
importing keys is M2-03, so in M1 keys can only be used by importing a private-key file through a minimal path (see §2.6).

## 2. Detailed description

### 2.1 Credential resolution
From `ResolvedHost`: username (inline → identity → `$USER`), password (inline → identity), key (inline `key_id`
→ identity `key_id`), certificate(s) attached to that key (`certificate_ids`), and passphrase (stored on the Key item or
prompted).

### 2.2 Method order (§6.1.1), skipping methods the server didn't list
On the first `USERAUTH_FAILURE` continuation, remember the server's allowed method list and skip unlisted methods
afterwards.
1. **publickey with certificate** (`authenticate_openssh_cert`) if the key has an attached, valid (not expired) certificate.
2. **publickey with the configured key** (`authenticate_publickey`). For RSA keys choose `rsa-sha2-512`, then
   `rsa-sha2-256`, based on the server's `server-sig-algs` (RFC 8308 ext-info). **Never** use `ssh-rsa` (SHA-1)
   unless the host's legacy override allows it.
3. **publickey via the system agent** (`SSH_AUTH_SOCK`, or the OpenSSH named pipe `\\.\pipe\openssh-ssh-agent` or Pageant on
   Windows) with `authenticate_publickey_with` and an agent signer. Try each agent identity in turn. **Skipped
   entirely when a key is configured for the host** (IdentitiesOnly semantics, avoiding MaxAuthTries). Also skipped
   when `ssh.use_system_agent = false`. FIDO/`sk-*` and hardware keys work through this path.
4. **password**: the stored password, or else a prompt dialog ("Password for user@host", with a "save to vault"
   checkbox that stores it inline on the host).
5. **keyboard-interactive**: each info request becomes a dialog showing the name, instruction and prompts (echo vs
   non-echo fields). Auto-answer rule: if a stored password exists **and** the request contains exactly one non-echo
   prompt matching `/password/i`, answer it automatically **once** per connection. All other prompts (OTP, 2FA, a
   second password prompt) are shown to the user.
- **Attempt cap:** `ssh.max_auth_attempts` (default 5) counts every request sent (each key and agent identity counts
  as one). When the cap is reached → `Disconnected{Auth}` "Permission denied (methods tried: publickey, password)".
- **Encrypted private key without a stored passphrase:** a passphrase prompt dialog with the checkbox "Save passphrase
  to vault". A wrong passphrase → re-prompt (3 tries) → skip the key.
- While waiting for a dialog the state is `AwaitingUser(AuthPrompt)`. Answers flow back through
  `SessionCmd::AuthAnswer`. Cancel → skip that method, or close the session if it's the last method.
- **Prompt timeouts:** none (the user may be fetching a 2FA token). Lock (M1-04) cancels outstanding prompts.

### 2.3 Prompt UI
- One dialog per request, with the title "Authenticate to <label>", the server-provided name and instruction (sanitized:
  control chars stripped, length capped at 512, because server-provided text is untrusted), and fields.
- Secret fields use the Secret widget (M1-06). Answers are `SecretString`, zeroized after sending.
- Multiple sessions prompting at once: dialogs queue per pane, and the focused pane's dialog shows first. A pane with a pending
  prompt shows a `🔑` marker in the tab bar.

### 2.4 Agent client (`agent_client.rs`)
Implements the russh agent client over a Unix socket (`SSH_AUTH_SOCK`) or a Windows named pipe, listing identities and
signing. It's shared with M2-07 (system agent passthrough). Connection failures are non-fatal: log at debug and skip
the method.

### 2.5 Saving credentials
"Save password/passphrase" emits `Effect::SaveItem` changing only that field (stamped). This only happens after the auth
**succeeds**, so wrong passwords aren't stored.

### 2.6 Minimal key import for M1
Until the keychain (M2-03) exists, the host form's key field accepts a path. On save it imports an OpenSSH private key
file into a `Key` item (OpenSSH format only, via the `ssh-key` crate). M2-03 replaces this with the full keychain.

## 3. Codebase changes
- **Create** `ssh/auth.rs`, `agent_client.rs` and the auth prompt dialog.
- Deps: `ssh-key` (parsing and decrypting), and named-pipe support via `tokio::net::windows::named_pipe`.

## 4. Test cases to implement
Unit tests use a scripted fake auth server (a trait over russh's auth calls). e2e uses the M1-18 containers.

**T-01 (unit) Order.** With key, cert, password and agent available, the attempt order is cert → key → password (agent skipped
because a key is configured).

**T-02 (unit) IdentitiesOnly.** No configured key → agent identities are tried after the cert/key steps. A configured key → no agent
attempts.

**T-03 (unit) Skip unlisted.** The server lists only `publickey,keyboard-interactive` → password is never tried.

**T-04 (unit) RSA sig alg.** `server-sig-algs` with `rsa-sha2-256` only → uses 256. Neither offered and no legacy override
→ the RSA key is skipped with a debug log. With a legacy override → `ssh-rsa`.

**T-05 (unit) Attempt cap.** `max_auth_attempts = 2` with 4 agent identities → exactly 2 attempts, then an `Auth` failure listing the methods
tried.

**T-06 (unit) kbd-interactive auto-answer.** One non-echo prompt "Password:" plus a stored password → answered once without
a dialog. A second identical request in the same connection → a dialog is shown.

**T-07 (unit) kbd-interactive OTP.** Prompts "Verification code:" → a dialog is shown even with a stored password.

**T-08 (unit) Sanitization.** Server instruction text with `\x1b[2J` and 2,000 chars → stripped and capped.

**T-09 (reducer) Prompt queueing** across two panes, with the focused one first.

**T-10 (reducer) Save password only after success.** A wrong password typed with "save" checked → no SaveItem effect. The right
one → SaveItem with only `password` changed.

**T-11 (e2e) Password auth** (container with `PasswordAuthentication yes`).

**T-12 (e2e) Key auth** (ed25519, and RSA 4096 → verify `rsa-sha2-512` is used from server logs).

**T-13 (e2e) Encrypted key with passphrase prompt.** Save the passphrase. The next connect needs no prompt.

**T-14 (e2e) Certificate auth.** Container with `TrustedUserCAKeys` and a cert attached to the key → succeeds via
cert.

**T-15 (e2e) keyboard-interactive** via PAM with a test OTP module (or `ChallengeResponseAuthentication` with a scripted
PAM conversation) → the dialog flow completes.

**T-16 (e2e) `MaxAuthTries 2` server.** 5 agent identities and no configured key → fails gracefully after the server limit
with the correct message. With a configured key → succeeds (proves IdentitiesOnly matters).

**T-17 (e2e) Agent auth.** Run `ssh-agent` in the test with a key loaded and no key configured on the host → success.

**T-18 (unit) Secrets zeroized.** Answer buffers are dropped after use (a drop-counter test hook).

## 5. Passing functional characteristics
- [ ] The auth chain follows §6.1.1: cert → key → agent (only without a configured key) → password → keyboard-interactive, skipping
      unlisted methods.
- [ ] RSA uses SHA-2 signatures per `server-sig-algs`, and SHA-1 only with legacy opt-in.
- [ ] The total attempts are capped (default 5, configurable), with a clear "methods tried" error.
- [ ] Passwords, passphrases and kbd-interactive prompts are shown in dialogs. The single password prompt is auto-answered once.
- [ ] Credentials can be saved to the vault after a successful auth.
- [ ] Hardware and FIDO keys work through the system agent on Unix and Windows.
- [ ] Server-provided prompt text is sanitized.
