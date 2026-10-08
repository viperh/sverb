# M2-04 — Non-interactive exec channels and "install key on host"

| | |
|---|---|
| **Milestone** | M2 |
| **Touches** | `crates/sverb-conn/src/ssh/exec.rs`, `crates/sverb-core/src/shell_quote.rs`, `crates/sverb-tui/src/views/keychain/install.rs`, `crates/sverb-tui/src/widgets/results_table.rs` (shared with M2-09) |
| **Spec refs** | §6.1.7, §9.4 (install on host), §4.2 `request_pty_for_exec`, §15 `ssh.exec_timeout_secs` |
| **Depends on** | M1-14, M2-03 |
| **Blocks** | M2-09 (multi-host snippet exec) |

---

## 1. Current state in the codebase
Only interactive shell channels exist (M1-13). There's no exec API, and "install on host" is a disabled action in the Keychain (M2-03).

## 2. Detailed description

### 2.1 Exec API (§6.1.7)
`exec(conn: &SshConnection, command: &str, opts: ExecOpts { timeout, request_pty, stdin: Option<Bytes> }) ->
ExecResult { stdout: Bytes, stderr: Bytes, exit: Option<u32>, signal: Option<String>, truncated: bool, duration }`.
- Opens a session channel, then `exec(command)`. No PTY unless `request_pty_for_exec` (or `opts.request_pty`). With a PTY,
  stdout and stderr are **merged** (as with `ssh -t`), so all output ends up in `stdout` and `stderr` is empty.
- **Output cap:** 1 MiB per stream. When the cap is reached, keep reading and discarding (so the remote isn't blocked on window space)
  and set `truncated = true`.
- **Timeout:** default `ssh.exec_timeout_secs` (60). On timeout, send `signal("TERM")`, wait 2 s, then close the channel. The result
  has `exit = None`, `signal = Some("TERM (timeout)")`.
- **Connection:** reuses an existing connection to the same `ResolvedHost` via the multiplexer (M3-07). Until M3-07, it opens a
  dedicated connection (with the full auth flow, which may prompt) and closes it after the run. Host-key prompts and auth prompts
  surface in a dialog attributed to the exec run ("Authenticating to db-1 for: Install key").

### 2.2 Install key on host (§9.4)
- Flow: Keychain → key → `Install on host…` → pick hosts (multi-select over hosts, groups and tags) → confirm (shows the
  command) → run concurrently (max 10 at a time) → results table.
- Command (exactly per §9.4), where `<pub>` is the public key line passed through **POSIX single-quote escaping** (`'` →
  `'\''`):
  `umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && (grep -qxF '<pub>' ~/.ssh/authorized_keys || printf '%s\n' '<pub>' >> ~/.ssh/authorized_keys)`.
  To distinguish "installed" from "already present", wrap the grep result: `… && (grep -qxF '<pub>' … && echo SVERB_PRESENT || (printf … && echo SVERB_INSTALLED))`
  and parse the marker. (This is an implementation-detail extension of the spec's command and must keep its semantics.
  Document the final command in `docs/`.)
- **POSIX shell requirement:** before installing, run `uname` (exec). If it fails (non-zero exit, or stdout doesn't
  look like a Unix kernel name), report "unsupported: remote shell is not POSIX (Windows OpenSSH?)" (§9.4).
- The results table shows per host: `installed` / `already present` / `error: <short>` (expandable stderr), and the duration.
  Re-run failed hosts with `r`.
- Install requires an existing way to authenticate (password or another key). That's normal SSH auth via prompts.

### 2.3 `shell_quote` (core)
`posix_single_quote(s) -> String` wraps in `'…'` and replaces each `'` with `'\''`. Used here and by the snippet `|q` filter (M2-09)
and copy-as-command (M1-07). It handles newlines safely by quoting them literally inside single quotes. NUL bytes are rejected.

## 3. Codebase changes
- **Create** `sverb-conn::ssh::exec`, `sverb-core::shell_quote`, the install view and the shared results table widget.

## 4. Test cases to implement

**T-01 (unit, table) shell quote.** `abc` → `'abc'`. `it's` → `'it'\''s'`. The empty string → `''`. `a\nb` → `'a\nb'` (a literal newline
inside). A NUL → error. Property: for random strings without NUL, `sh -c "printf %s <quoted>"` outputs the original (run in the e2e
container for 200 cases).

**T-02 (e2e) exec basic.** `echo hi; echo err >&2; exit 3` → stdout `hi\n`, stderr `err\n`, exit 3.

**T-03 (e2e) Output cap.** `head -c 3000000 /dev/zero` → stdout length 1 MiB, `truncated = true`, and the command still completes
(exit 0).

**T-04 (e2e) Timeout.** `sleep 100` with a 1 s timeout → `signal = TERM (timeout)` within about 3 s.

**T-05 (e2e) PTY merge.** With `request_pty`, `echo a; echo b >&2` → both in stdout, and stderr is empty.

**T-06 (e2e) Install key.** Fresh `password` profile container → `installed`. Run again → `already present`. Then key auth works
(M1-14 path).

**T-07 (e2e) Key with a quote in the comment** (`comment = "bob's key"`) installs correctly (quoting).

**T-08 (e2e) Windows-like profile** → `unsupported: remote shell is not POSIX`.

**T-09 (e2e) authorized_keys permissions** after install: dir `700`, file `600` (umask 077).

**T-10 (reducer) Results table:** statuses rendered, `r` re-runs failed hosts only.

**T-11 (unit) Concurrency cap.** 25 hosts → never more than 10 in flight (instrumented fake executor).

## 5. Passing functional characteristics
- [ ] Exec returns stdout, stderr, exit and signal, caps each stream at 1 MiB with a `truncated` flag, enforces the timeout with TERM then close,
      and merges streams with a PTY.
- [ ] Install-on-host runs the §9.4 command with correct POSIX quoting, detects non-POSIX shells, and reports installed / already
      present / error per host.
- [ ] Runs are concurrent (max 10) with a results table and re-run of failures.
