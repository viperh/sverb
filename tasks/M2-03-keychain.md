# M2-03 — Keychain: generate, import, export, certificates, hardware-key references

| | |
|---|---|
| **Milestone** | M2 (PuTTY `.ppk` import parsing is delivered in M7-03, but the import pipeline hook is here) |
| **Touches** | `crates/sverb-core/src/keychain/{generate.rs, import.rs, export.rs, cert.rs, formats/{openssh.rs, pem.rs, pkcs8.rs}}`, `crates/sverb-tui/src/views/keychain/{mod.rs, keys.rs, certs.rs, generate_form.rs, import_dialog.rs}`, `crates/sverb/src/cli/keys.rs` |
| **Spec refs** | §4.5, §4.6, §9.4 (except install-on-host → M2-04), §16 (`sverb keys …`) |
| **Depends on** | M1-07, M1-14 (replaces its minimal import path) |
| **Blocks** | M2-04, M2-07, M2-11, M7-03 |

---

## 1. Current state in the codebase
M1-14 §2.6 added a minimal "path → OpenSSH key import" in the host form. There's no Keychain view (sidebar placeholder from
M0-11). The `Key` and `Certificate` typed views exist (M1-02).

## 2. Detailed description

### 2.1 Data (§4.5, §4.6)
- `Key { label, algorithm, private_key: Secret<String> (OpenSSH format, optionally passphrase-encrypted), public_key
  (OpenSSH line), passphrase: Option<Secret>, certificate_ids, agent_forwardable (default false), confirm_on_use }`.
- **Hardware/FIDO reference keys** (§9.4): `private_key` absent, `public_key` present, plus a flag `agent_ref = true`. Auth
  then asks the system agent to sign with that public key (M1-14 agent path, now targeted at this key, so IdentitiesOnly still
  holds).
- `Certificate { label, cert (OpenSSH cert line), key_id }`. Parsed fields (principals, valid_after/before, CA fingerprint, key
  id, serial, cert type) are **derived on read** and never stored (§4.6).

### 2.2 Generate (§9.4)
- Types: Ed25519 (default), ECDSA P-256/384/521, RSA 2048/3072/4096, using the `ssh-key` crate with `OsRng`. RSA generation
  runs in `spawn_blocking` with a progress dialog (RSA-4096 can take seconds).
- Options: label (default `"<type> <date>"`), comment (default `user@hostname-sverb`), optional passphrase (with confirm; if set,
  the private key is stored **encrypted in OpenSSH format** with bcrypt-pbkdf as `ssh-keygen` does; "remember passphrase in vault"
  is a checkbox, default on).
- The form shows the public key and fingerprint after generation, with actions copy and install on host (M2-04).

### 2.3 Import (§9.4)
- Sources: a file picker (a path prompt with tab-completion of paths, plus `~` expansion) or paste (a multiline field).
- Formats detected by content:
  - OpenSSH (`-----BEGIN OPENSSH PRIVATE KEY-----`), encrypted or not,
  - PEM PKCS#1 RSA (`BEGIN RSA PRIVATE KEY`), including legacy encrypted PEM (`Proc-Type: 4,ENCRYPTED`, DEK-Info AES-128-CBC) if
    supported by the libraries. Otherwise give a clear "unsupported encrypted PEM; convert with ssh-keygen -p" message,
  - PEM SEC1 EC (`BEGIN EC PRIVATE KEY`),
  - PKCS#8 (`BEGIN PRIVATE KEY`, and `BEGIN ENCRYPTED PRIVATE KEY` via the `pkcs8` crate's PBES2),
  - PuTTY `.ppk` v2/v3 → handled by M7-03's parser through the `KeyImporter` trait registered here (until then: "PuTTY keys
    are supported from version X").
- Encrypted keys prompt for the passphrase (3 tries). The stored form: re-serialize to OpenSSH format. Keep it encrypted with
  the same passphrase if the user chooses "keep passphrase", or store it decrypted (still protected by vault encryption) and
  optionally store the passphrase. **Decision:** default to storing OpenSSH-encrypted plus the passphrase in the vault, which
  matches §4.5 "optionally passphrase-encrypted".
- A public key file (`.pub`) alone → creates an `agent_ref` key ("hardware/agent key") after confirmation.
- Duplicate detection: an existing key with the same public key → offer "Use existing" instead of creating a duplicate.

### 2.4 Export (§9.4)
- **Public key:** OpenSSH line to the clipboard (OSC 52/arboard, M1-11) or to a file.
- **Private key:** to a file, after a confirmation dialog ("This writes your private key to disk unencrypted by sverb"), with an optional
  passphrase re-encrypt (new passphrase prompt) or keeping the existing encryption. File mode `0600`. Refuse to overwrite without
  confirmation.

### 2.5 Change passphrase
Decrypt with the old passphrase (or the stored one) and re-encrypt with the new one (or none). Update the `passphrase` field if
remembered.

### 2.6 Certificates (§9.4)
- Import an OpenSSH certificate (file or paste) and attach it to a key (validate that the cert's public key equals the key's
  public key, otherwise reject).
- Show the principals, validity window (local time via `ui.date_format`), CA fingerprint, key id and serial. **Warn** with a
  yellow badge when it expires within 7 days and a red badge when expired. The Keychain list shows the badge on the key.

### 2.7 Keychain view (§8.5)
Sub-tabs **Keys | Certificates | Identities** (M2-02). Key actions: generate, import (file/paste), export public, copy
public, install on host (M2-04), change passphrase, attach cert, toggle `agent_forwardable`, toggle `confirm_on_use`,
delete (warn when referenced by hosts or identities: "used by N").

### 2.8 CLI (§16)
- `sverb keys list [--json]`: label, algorithm, fingerprint, cert status. No private material.
- `sverb keys generate [--type ed25519] [--label L]`: prints the public key and id. The passphrase prompt is TTY-only
  (`--no-passphrase` for scripts).
- `sverb keys import <file>`: prompts for the passphrase on a TTY. Non-TTY + encrypted → exit 3 with a message.
- `sverb keys export <key> [--public]`: `--public` prints the public key to stdout. Without it, export the private key to stdout
  **only if stdout is not a TTY** (prevents accidental display), otherwise require `--output <file>`.

## 3. Codebase changes
- **Create** the `sverb-core::keychain` modules. Deps: `ssh-key` (features: `ed25519`, `p256`, `p384`, `p521`, `rsa`,
  `encryption`), `pkcs8`, `pkcs1`, `sec1`.
- **Create** the Keychain views and dialogs, and **remove** the M1-14 minimal import path (route it through `keychain::import`).
- **Implement** `cli/keys.rs` (except `--dump`, done in M0-10).

## 4. Test cases to implement

**T-01 (unit, table) Generate** each of the 7 types → a parseable OpenSSH private key, a matching public key, and a correct algorithm field.

**T-02 (unit) Generated passphrase-encrypted key** decrypts with the passphrase and fails without it. Compatibility: `ssh-keygen -y
-f` (in the e2e container) accepts it.

**T-03 (unit, fixtures) Import formats.** `tests/fixtures/keys/` contains OpenSSH (plain and encrypted), PKCS#1 RSA, SEC1 EC, PKCS#8 (plain and
encrypted), each for the relevant algorithms → the imported public key equals the expected fingerprint.

**T-04 (unit) Wrong passphrase** ×3 → import aborted with a clear message. No partial item is created.

**T-05 (unit) `.pub` import** → an agent_ref key without private material.

**T-06 (unit) Duplicate public key** → "Use existing" offered.

**T-07 (unit) Certificate parsing.** A fixture cert → principals, validity and CA fingerprint as expected. Mismatched key → rejected.

**T-08 (unit) Expiry badges.** Expires in 3 days → warn. Expired → error. 30 days → none (injectable clock).

**T-09 (integration) Export private** → file mode 0600, and the content round-trips with re-import. Re-encrypt with a new passphrase works.

**T-10 (integration) Change passphrase** → the old one fails, the new one works, and the stored passphrase field is updated.

**T-11 (CLI) `keys list --json`** contains no `PRIVATE KEY` substring (canary).

**T-12 (CLI) `keys export k`** to a TTY without `--output` → refused (exit 1). Piped → outputs the key.

**T-13 (e2e) Generated key → install (M2-04) → auth works** (covered jointly with M2-04).

**T-14 (snapshot)** Keychain Keys tab with an expiring-cert badge at 160×48.

## 5. Passing functional characteristics
- [ ] Ed25519 (default), ECDSA P-256/384/521 and RSA 2048/3072/4096 keys can be generated with optional passphrase and comment.
- [ ] Imports support OpenSSH, PEM (PKCS#1, SEC1) and PKCS#8, from a file or paste, with passphrase prompts. PuTTY plugs in via the importer hook.
- [ ] Public keys export to the clipboard or a file. Private keys export only after confirmation, with mode 0600 and optional re-encryption.
- [ ] Certificates attach to matching keys, show their derived fields, and warn when expiring within 7 days.
- [ ] Agent and hardware reference keys exist and are used through the system agent.
- [ ] `sverb keys list|generate|import|export` work as specified without leaking private material by accident.
