# M2-11 — Import and export: `ssh_config`, `known_hosts`, CSV, encrypted backup

| | |
|---|---|
| **Milestone** | M2 (backup is needed by M4's "encrypted backup export"; PuTTY import is M7-03) |
| **Touches** | `crates/sverb-core/src/importers/{mod.rs, ssh_config/{lexer.rs, parser.rs, include.rs, map.rs}, known_hosts.rs, csv.rs, backup.rs, preview.rs}`, `crates/sverb-core/src/exporters/{backup.rs, ssh_config.rs, csv.rs}`, `crates/sverb-tui/src/views/import_wizard.rs`, `crates/sverb/src/cli/{import.rs, export.rs}`, `tests/fixtures/ssh_config/*` |
| **Spec refs** | §9.13, §9.5 (known_hosts), §19 (fixtures + insta snapshots, fuzzing), §16 (`import`/`export`), §1.1 (backup to move data manually) |
| **Depends on** | M2-01, M2-03, M2-08, M1-15 |
| **Blocks** | M7-03 |

---

## 1. Current state in the codebase
The `import`/`export` CLI subcommands are stubs (M0-07). The known_hosts parser exists (M1-15) and the key importer exists (M2-03).

## 2. Detailed description

### 2.1 Common pipeline (§9.13)
Every import is **a dry run first**: `Importer::parse(source) -> ImportPlan { items: Vec<PlannedItem { kind, fields,
status: New | Duplicate(existing_id) | Conflict(existing_id, diffs) }>, skipped: Vec<Skipped{ source_line, reason }>,
warnings }`. The UI (import wizard) and CLI (`--dry-run`) show a **preview table** (new / duplicate / conflict counts plus
rows). The user then picks the **target vault and group** (§9.13), chooses the conflict policy (skip / overwrite / keep both), and confirms. Only
then are items written. One transaction per import, with rollback on failure.
- Duplicate detection: hosts by `(address, port, user)`, keys by public key, known hosts by `(pattern, key)`.
- Imported locally-acting values (ProxyCommand etc.) count as user-approved at confirmation (M2-10 §2.2).

### 2.2 `~/.ssh/config` (§9.13)
- **Lexer and parser** following OpenSSH rules: case-insensitive keywords, `Keyword value` or `Keyword=value`, quoted args,
  comments, `Host` and `Match` blocks (Match is **skipped with a reason**), first-match-wins semantics for **values** (the first obtained
  value for a keyword is used).
- **Supported keywords** (§9.13): `Host`, `HostName`, `User`, `Port`, `IdentityFile`, `ProxyJump`, `ProxyCommand`,
  `LocalForward`, `RemoteForward`, `DynamicForward`, `ForwardAgent`, `SetEnv`, `ServerAliveInterval`, `Include`. Others are
  ignored with a per-keyword "unsupported, skipped" summary (not per line).
- **Include:** relative paths resolve against `~/.ssh/`, with globbing supported and a recursion limit of 16, plus cycle detection.
- **Mapping:**
  - Each concrete `Host` alias (no wildcards) → a host: label = the alias, address = `HostName` (with `%h` substitution) or the alias,
    port, user, IdentityFile → key import (after a separate **confirmation** listing the files, §9.13; encrypted ones prompt for the passphrase
    or are skipped), ProxyJump → `jump_chain` (resolving hops to imported hosts by alias, or creating hosts for `user@host:port`
    specs), ProxyCommand → proxy Command, the forwards → `PortForward` items with `auto_start = true`, `ForwardAgent yes` →
    agent_forwarding true, `SetEnv` → env, `ServerAliveInterval` → keepalive_secs.
  - **Wildcard `Host` blocks** (`Host *`, `Host *.prod`) become **group defaults where expressible** (§9.13): `Host *` → vault
    defaults (or a group "Imported defaults"), and `Host *.prod` → a group "*.prod" containing the hosts whose aliases match, with the block's
    settings as defaults. Patterns with negation, or settings that can't be represented, → skipped with a reason.
  - Multiple aliases in one `Host a b` line → two hosts.
- Live read-only mode (`ssh.read_ssh_config`, §15, §22.2) is an **open question**. This task only provides the parser so it can be reused.

### 2.3 `known_hosts` (§9.5, §9.13)
Reuse the M1-15 parser. Hashed entries stay hashed, and markers are preserved. Duplicates are skipped.

### 2.4 CSV (§9.13)
Columns `label,address,port,username,group,tags`, with a header row required (case-insensitive, any order, unknown columns → warning).
`group` is a path `a/b/c` (created if missing, after a preview note). `tags` are separated by `;` or `|` (document it), and unknown tags are created.
RFC 4180 quoting via the `csv` crate. Invalid rows (bad address or port) are skipped with the line number.

### 2.5 sverb backup (§9.13)
- **Format** `.sverb-backup`: JSON `{ "format": "sverb-backup", "version": 1, "kdf": {"alg":"argon2id", m_kib, t, p,
  salt_b64}, "nonce_b64", "ciphertext_b64", "created_at", "app_version" }`. The ciphertext is XChaCha20-Poly1305 (key = Argon2id(export
  password)) over `zstd(cbor({ vaults: [{name, kind, defaults}], items: [ItemBody…] }))`, with AAD = `"sverb-backup-v1"`.
  It contains **all item bodies, including secrets, with stamps**, so a restore preserves HLC history.
- The export password is separate from the master password (it may be the same; zxcvbn ≥ 3 enforced). The export includes the personal vault, and shared
  vaults are optional (checkbox, with a warning that they belong to the org).
- **Import** decrypts (wrong password → clear error), previews like other importers, then writes into a target vault. Items keep their ids if
  absent locally, otherwise follow the conflict policy (overwrite = merge by HLC via M4-06 if available, else replace). Device-local data is not
  included.

### 2.6 Exports (§9.13)
- **sverb backup** (above).
- **ssh_config** (lossy): `Host <label-sanitized>` blocks with HostName, User, Port, ProxyJump (labels of hop hosts),
  ProxyCommand, Local/Remote/DynamicForward, ForwardAgent, SetEnv, ServerAliveInterval. IdentityFile only when the key has a known source path.
  The file starts with a header comment: **"Secrets (passwords, private keys stored in sverb) are NOT exported."** (§9.13 warning, also
  shown in the UI before writing).
- **CSV:** the same columns as import.
- Files are written with mode 0600 (backup, ssh_config) and never overwritten without confirmation (`--force` in the CLI).

### 2.7 CLI (§16)
`sverb import ssh-config [path] | known-hosts [path] | putty | csv <file> | backup <file> [--dry-run] [--vault V]
[--group G] [--on-conflict skip|overwrite|keep-both] [--yes]` and `sverb export backup|ssh-config|csv <file>` (`export
recording` is M3-05). Without `--yes` on a TTY: show the preview and ask. No TTY and no `--yes` → print the preview and exit 0 when `--dry-run`, otherwise exit 2.

## 3. Codebase changes
- **Create** the importer and exporter modules and the import wizard view (Settings → Import/Export, plus Known Hosts and Hosts view entry
  points). Deps: `csv`, `glob`.
- **Fixtures:** `tests/fixtures/ssh_config/{basic, wildcard, include/, proxyjump, forwards, match_block, quoting, weird_whitespace}`,
  `tests/fixtures/csv/*`, `tests/fixtures/known_hosts/*`.

## 4. Test cases to implement

**T-01 (snapshot) ssh_config fixtures.** Each fixture → `insta` snapshot of the `ImportPlan` (§19).

**T-02 (unit) First-match-wins.** `Host web` then `Host *` with `User a` / `User b` → user `a` for web.

**T-03 (unit) Include with glob and cycle** → included, and the cycle detected with a warning.

**T-04 (unit) Wildcard → group defaults.** `Host *.prod` + `User deploy` → a group with default user deploy containing the matching hosts.
`Host !x *` → skipped with a reason.

**T-05 (unit) ProxyJump `user@bastion:2222,inner`** → hosts created or linked, and the jump_chain is ordered.

**T-06 (unit) Forwards.** `LocalForward 5432 db:5432`, `RemoteForward 0 localhost:80`, `DynamicForward 1080` → 3 rules with the right kinds.

**T-07 (unit) Unsupported keywords** summarized once with counts.

**T-08 (unit) CSV.** Valid rows, reordered columns, quoted commas, a bad port on line 4 → skipped(4), tags via `;`.

**T-09 (unit) Duplicate and conflict detection** against existing hosts (same address:port:user, different label → conflict with a diff).

**T-10 (integration) Dry run writes nothing** (DB hash unchanged).

**T-11 (integration) Backup round-trip.** Export, wipe the home, import → identical item bodies (fields and stamps) and the same ids.

**T-12 (unit) Backup wrong password** → a clear error. A tampered ciphertext → auth error. A newer `version` → unsupported error.

**T-13 (snapshot) ssh_config export** → contains the secrets warning and never a password (canary).

**T-14 (integration) Export file modes** 0600, and refusal to overwrite.

**T-15 (CLI) `import ssh-config --dry-run`** prints the preview table (snapshot). `import csv f --yes` imports.

**T-16 (fuzz stub)** `fuzz_targets/ssh_config_parse.rs`.

**T-17 (integration) Approvals.** Importing a ProxyCommand host creates its approval row at confirmation.

## 5. Passing functional characteristics
- [ ] `~/.ssh/config` imports with the listed keywords, Include, first-match semantics and wildcard blocks as group defaults (or reported as skipped), and asks
      before importing identity files.
- [ ] known_hosts, CSV and sverb backup import. Every import is previewed (new / duplicate / conflict) before writing into a chosen vault and group.
- [ ] Backups are Argon2id + XChaCha20-Poly1305 encrypted, preserve ids and stamps, and round-trip losslessly.
- [ ] Exports to backup, ssh_config (with a secrets warning) and CSV work with safe file handling.
- [ ] The parser is fixture-snapshot-tested and fuzzable.
