# M1-07 — Hosts: CRUD, Hosts view, quick connect, copy-as-command, CLI `hosts`

| | |
|---|---|
| **Milestone** | M1 |
| **Touches** | `crates/sverb-core/src/model/host.rs` (from M1-02), new `crates/sverb-core/src/quick_connect.rs`, `crates/sverb-core/src/ssh_command.rs`, `crates/sverb-tui/src/views/hosts/{mod.rs, form.rs, detail.rs}`, `crates/sverb-tui/src/services/items.rs`, `crates/sverb/src/cli/hosts.rs`, `crates/sverb/src/cli/mod.rs` (`connect`) |
| **Spec refs** | §4.2, §8.5 (Hosts row), §9.1, §16 (`hosts list/add/rm`, `connect`) |
| **Depends on** | M1-04, M1-05, M1-06 |
| **Blocks** | M1-13 (connect action), M2-01 … |

---

## 1. Current state in the codebase
After M0-11 the Hosts section shows an empty-state placeholder. The `Host` typed view exists (M1-02), the store and vault
work (M1-03/04), and list and form widgets exist (M1-06). The CLI `hosts` subcommands are stubs (M0-07).

## 2. Detailed description

### 2.1 Item service (`services/items.rs`)
Shared by all item kinds: `save(kind, vault, id?, FieldChanges)` → load the existing body (or create
`ItemBody::new`), apply the typed changes via `set` (stamped), validate, seal with the VK, `put_item(mark_dirty =
sync_enabled)`, update the index, and emit `EffectDone`. `delete(id)` stamps the tombstone the same way.
`duplicate(id)` copies all fields to a new id, labeled `"<label> (copy)"`, with fresh stamps.
**Outbox rule:** in local-only mode `dirty` still gets set (so enabling sync later pushes everything, §11.2.1),
but no push happens.

### 2.2 Hosts view
- The list (M1-06) shows `label`, `user@address:port` (port only if not 22), tags as colored chips, and a pinned star.
  Groups appear as tree nodes once M2-01 exists; until then the list is flat.
- **Ordering** (§9.1): pinned, then frecency (`device_local`), then alphabetical. A **"Recent"**
  pseudo-group at the top shows the last 10 connected hosts (by `last_connected_at`). It's collapsible and hidden
  when empty.
- The **detail pane** shows all fields, with resolved values and provenance (after M2-01), notes rendered as plain
  Markdown text (bold/italic/code/list styling only, with links shown but not clickable), last connected (relative),
  and the vault.
- **Actions** (§8.5): `Enter` connect, `ctrl-enter`/`v` connect in a split (after M1-17), `a` add, `e` edit, `y`
  duplicate, `d` delete (confirm: "Delete N hosts?"), `m` move to group (after M2-01), `t` tag (after M2-01), `p`
  pin/unpin, `c` copy the `ssh` command. Bulk (§9.1): move, tag add/remove, delete, connect all (each in a new tab, or
  as splits in one tab when the user chooses in a dialog), run snippet on all (M2-09).

### 2.3 Host form
Sections:
1. **General:** label, address (required), port, group (reference), tags (multiselect), pinned.
2. **Credentials:** identity (reference) **or** inline username / password (secret) / key (reference).
   Picking an identity dims the inline fields, but the user can still override the username (§4.2: inline overrides
   the identity).
3. **Connection:** jump chain (ordered reference list, M2-05), proxy (select + fields, M2-06), keepalive,
   agent forwarding + agent source (M2-07), algorithms (M1-13 §2.6 overrides), request PTY for exec.
4. **Terminal:** charset (select from the `encoding_rs` labels), backspace (DEL / Ctrl-H), color scheme (select,
   M1-10), startup snippet (reference, M2-09), environment (kv list).
5. **Forwards:** port forward references (M2-08).
6. **Notes:** multiline Markdown.
Fields belonging to later tasks are hidden until those tasks land, behind a feature registry, not cfg flags.

### 2.4 Quick connect (`leader o`, §9.1)
- An input dialog with a fuzzy host list under it. Typing filters the saved hosts, and `Enter` on a highlighted host
  connects to it.
- Typed text that isn't a selected host is parsed with `quick_connect::parse`:
  - `host`, `user@host`, `host:port`, `user@host:port`, `[v6addr]:port`, `user@[v6addr]:port`, a bare v6
    address without a port (`::1`, `fe80::1%eth0` with a zone id),
  - `ssh://[user@]host[:port]`, with percent-decoding of the user and an optional trailing `/`.
  - Invalid input gives an inline error.
- It connects as an ephemeral host (not saved). After a **successful** connection, a toast offers "Save as host?
  [s]". Pressing `s` opens the host form prefilled.
- The CLI `sverb connect <target>` uses the same parser, after first trying host resolution (M1-05).

### 2.5 Copy as command (§9.1)
`ssh_command::render(resolved: &ResolvedHost) -> String`, producing e.g.
`ssh -J bastion,user@jump2:2222 -p 2222 -i ~/.ssh/id_ed25519 -o ProxyCommand='…' user@host`:
- `-J` from the jump chain (`[user@]addr[:port]`, comma-separated),
- `-p` only if not 22,
- `-i` only if the key has a known source path. Otherwise add a comment `# key stored in sverb vault`,
- `-o ProxyCommand=…` with POSIX single-quote escaping,
- `-A` if agent forwarding,
- `-o SetEnv=…` for env pairs,
- IPv6 addresses are not bracketed in the destination (ssh accepts them bare), but they are bracketed in `-J` hop specs with ports.
Copied via OSC 52 / `arboard` (M1-11 clipboard service). Until then, show it in a dialog.

### 2.6 CLI (§16)
- `sverb hosts list [--json] [--tag t]... [--group g]`: a table of label, address, port, user, group and tags.
  JSON is `{"version":1,"data":[{id,label,address,port,user,group,tags}]}`. Secrets are never printed.
- `sverb hosts add <address> [--label] [--user] [--port] [--group] [--tag]...`: validates (exit 2 on
  invalid), creates missing tags (by name) and **errors** on unknown groups (exit 4) unless `--create-group`
  (an extra flag; document it). Prints the new id.
- `sverb hosts rm <host>`: resolves (M1-05), confirms on a TTY (`--yes` to skip), tombstones.
- `sverb connect <target>`: launches the TUI with a session (M1-13).

## 3. Codebase changes
- **Create** `views/hosts/*`, `services/items.rs`, `sverb-core::{quick_connect, ssh_command}`.
- **Implement** `cli/hosts.rs` and the `connect` intent handling.
- **Update** the README with a "Managing hosts" section.

## 4. Test cases to implement

### Core
**T-01 (unit, table) Quick-connect parser.** At least 25 rows: `h` → {h, None, None}; `u@h` → {h, u}; `h:2222`;
`u@h:2222`; `[::1]:22`; `u@[fe80::1]:2200`; `::1` → host `::1`, port None; `fe80::1%eth0`;
`ssh://u@h:2222`; `ssh://u%40corp@h` → user `u@corp`; `ssh://h/`; `u@` → error; `h:0` → error;
`h:99999` → error; `[::1` → error; the empty string → error; `user@host@x` → error.

**T-02 (unit, table) ssh command render.** Plain host; non-22 port; jump chain of 2 with ports; ProxyCommand
containing a `'`; IPv6 target; agent forwarding; env. Compare to expected strings.

**T-03 (unit) Ordering.** Pinned first, then frecency, then alpha. The Recent pseudo-group lists the last 10 by
`last_connected_at`, descending.

### Services and reducer
**T-04 (integration)** Save a new host → the item is persisted encrypted, the index is updated, and the list shows it.

**T-05 (integration)** Edit only the port → only `port`'s stamp changes, and other fields keep their stamps.

**T-06 (integration)** Duplicate → a new id with label `"x (copy)"` and identical other fields.

**T-07 (integration)** Delete → tombstoned, gone from the index and list, and still present in the DB as `deleted = 1`.

**T-08 (reducer)** Bulk delete of 3 marked hosts → a confirm with "Delete 3 hosts?" → 3 delete effects.

**T-09 (reducer)** Address validation in the form: `root@x` → inline error, and save is blocked.

**T-10 (reducer)** Quick connect: typing `deploy@10.0.0.5:2222` + Enter → `OpenSession` with an ephemeral host.
After a `Connected` event a "Save as host" toast appears, and `s` opens a prefilled form.

**T-11 (snapshot)** The Hosts view at 80×24 (no detail pane) and 160×48 (detail pane) with 20 sample hosts including
pinned and recent ones.

**T-12 (snapshot)** The host form, all sections, at 160×48.

### CLI
**T-13 (CLI)** `hosts add 10.0.0.1 --user root --port 2222 --tag web` then `hosts list --json` → contains
the host with tags `["web"]`. The JSON snapshot matches.

**T-14 (CLI)** `hosts add "bad host"` → exit 2 with the validation message.

**T-15 (CLI)** `hosts add x --group nope` → exit 4. With `--create-group` → success.

**T-16 (CLI)** `hosts rm web` (ambiguous) → exit 4 listing the candidates. `hosts rm prod-web-1 --yes` → removed.

**T-17 (CLI)** `hosts list` output never contains passwords (canary).

## 5. Passing functional characteristics
- [ ] Hosts can be created, edited, duplicated, deleted, pinned and listed in the TUI and CLI, with validation
      per §4.2.
- [ ] Ordering is pinned → frecency → alpha, and a Recent pseudo-group shows the last 10.
- [ ] Quick connect accepts `[user@]host[:port]`, bracketed IPv6 and `ssh://` URLs, and offers to save
      after a successful connection.
- [ ] Copy-as-command produces a correct, shell-safe `ssh` line.
- [ ] Every write is stamped and encrypted, and marked dirty for a future sync.
- [ ] Secrets never appear in CLI output or logs.
