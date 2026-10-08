# M7-03 — PuTTY sessions import and `.ppk` key parser

| | |
|---|---|
| **Milestone** | M7 |
| **Touches** | `crates/sverb-core/src/importers/putty_sessions.rs`, `crates/sverb-core/src/keychain/formats/ppk.rs`, `crates/sverb/src/cli/import.rs` (`putty`), `tests/fixtures/putty/*` |
| **Spec refs** | §9.13 (PuTTY sessions row), §9.4 (PuTTY `.ppk` v2/v3, in-house parser), §19 (fuzz ppk parser) |
| **Depends on** | M2-11, M2-03 |
| **Blocks** | — |

---

## 1. Current state in the codebase
The import pipeline with previews (M2-11) and the `KeyImporter` hook for `.ppk` (M2-03) exist. `sverb import putty` is a stub.

## 2. Detailed description

### 2.1 `.ppk` parser (in-house, §9.4)
- **v2:** the header `PuTTY-User-Key-File-2: <alg>`, `Encryption: none | aes256-cbc`, `Comment`, `Public-Lines` + base64, `Private-Lines` + base64,
  `Private-MAC` (HMAC-SHA1). Key derivation for encrypted files: AES key = `SHA1(00000000 || pass) || SHA1(00000001 || pass)` truncated to 32 bytes, IV zero. MAC key
  = `SHA1("putty-private-key-file-mac-key" || pass)`, and the MAC covers `alg, encryption, comment, public blob, private blob` (each length-prefixed).
- **v3:** `PuTTY-User-Key-File-3`, `Key-Derivation: Argon2id|Argon2i|Argon2d`, `Argon2-Memory`, `Argon2-Passes`, `Argon2-Parallelism`, `Argon2-Salt`. Argon2 output of
  80 bytes → AES-256 key (32) + IV (16) + MAC key (32). `Private-MAC` is HMAC-SHA256.
- Algorithms: `ssh-ed25519`, `ecdsa-sha2-nistp256/384/521`, `ssh-rsa` (private blob: d, p, q, iqmp; reconstruct the key), `ssh-dss` → rejected as unsupported.
- **The MAC is verified before use.** A wrong passphrase → MAC mismatch → "wrong passphrase". Unencrypted files still verify the MAC (with the empty-passphrase key).
- Output: `ssh_key::PrivateKey` → stored as OpenSSH (M2-03 policy). Register it as the `.ppk` `KeyImporter`.
- Bound inputs: max file size 64 KiB, max line count, and base64 limits.

### 2.2 PuTTY sessions (§9.13)
- **Linux/macOS:** `~/.putty/sessions/*`: one file per session (URL-encoded name), `Key=Value` lines.
- **Windows:** the registry `HKCU\Software\SimonTatham\PuTTY\Sessions\<encoded name>` (the `winreg` crate, `cfg(windows)`).
- Mapping: `HostName` (may contain `user@host`), `PortNumber`, `UserName`, `Protocol` (only `ssh`; others are skipped with the reason "non-SSH protocol not supported"),
  `PublicKeyFile` (→ import the .ppk after confirmation, as with ssh_config IdentityFile), `ProxyMethod`/`ProxyHost`/`ProxyPort`/`ProxyUsername`
  (`ProxyMethod` 1 = SOCKS4 → unsupported, 2 = SOCKS5 → socks5, 3 = HTTP → http; `ProxyPassword` is ignored since PuTTY stores it in plain text; prompt instead, and
  `ProxyTelnetCommand` → skipped), `AgentFwd`, `PortForwardings` (`L8080=host:80,R…,D1080` → forward rules), and `TerminalType`.
- Session names are URL-decoded (`%20` etc.) for labels. `Default%20Settings` → group defaults or skipped.
- Same preview flow as M2-11.

## 3. Codebase changes
- The parser plus the importer. `winreg` for Windows. Fixtures: v2 and v3 `.ppk` files for each algorithm (encrypted and plain, created with `puttygen`, passphrase `fixture`) and sample
  session files.

## 4. Test cases to implement

**T-01 (unit, fixtures)** Each `.ppk` fixture (v2/v3 × ed25519/ecdsa-256/rsa-2048, plain and encrypted) → the public key fingerprint equals the expected value (recorded via `puttygen -l`).

**T-02 (unit)** A wrong passphrase → MAC mismatch error. A tampered private blob → MAC error. A tampered MAC line → error.

**T-03 (unit)** `ssh-dss` → unsupported. A truncated file → error, with no panic.

**T-04 (unit)** v3 Argon2 parameters out of sane bounds (memory > 1 GiB) → rejected (DoS guard).

**T-05 (snapshot)** Sessions fixture directory → `ImportPlan` snapshot (including skipped telnet and SOCKS4 sessions, a URL-decoded label, forwards).

**T-06 (unit, cfg windows)** The registry reader with a temporary key under `HKCU\Software\sverb-test\…` (inject the root path).

**T-07 (fuzz stub)** `fuzz_targets/ppk_parse.rs` (§19).

**T-08 (CLI)** `sverb import putty --dry-run` prints the preview.

## 5. Passing functional characteristics
- [ ] `.ppk` v2 and v3 keys (Ed25519, ECDSA, RSA), encrypted or not, import with MAC verification and Argon2/SHA1 key derivation per format.
- [ ] PuTTY SSH sessions import from `~/.putty/sessions` or the Windows registry, with proxies, forwards, agent forwarding and key files mapped, and other protocols skipped with reasons.
- [ ] The parser is fuzzed and bounded against hostile input.
