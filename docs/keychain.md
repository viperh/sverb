# Keychain: install key on host

M2-04 implements SPEC §9.4 "Install on host" (Keychain → key → `H`).

## Flow

1. Pick targets: hosts, groups (every host in the group and its subgroups) and tags
   (every host carrying the tag). The filter uses the search index (`#tag`, `@vault`
   and fuzzy words work). `space`/`tab` mark, `enter` continues (with nothing marked,
   the row under the cursor is used).
2. Confirm: the dialog lists the hosts and shows the exact command.
3. Run: at most 10 hosts at a time. Each host gets a dedicated SSH connection (until
   connection sharing, M3-07) with the normal authentication chain. Host-key and
   password / passphrase / keyboard-interactive prompts appear in the usual dialogs,
   titled "Authenticating to <host> for: Install key".
4. Results: `installed`, `already present`, `unsupported: remote shell is not POSIX
   (Windows OpenSSH?)` or `error: <short>` per host, with the duration. `enter` expands
   a row's error output, `r` re-runs the failed hosts only, `esc` closes the table and
   cancels hosts that are still running.

## The remote commands

First `uname` runs over exec. If it fails, or its output doesn't look like a Unix kernel
name (`Linux`, `Darwin`, `FreeBSD`, `CYGWIN_NT-10.0`, …), the host is reported as
unsupported: the install command needs a POSIX `sh` login shell.

Then, with `<pub>` the key's OpenSSH public key line, POSIX single-quoted (`'` becomes
`'\''`, see `sverb_core::shell_quote::posix_single_quote`):

```sh
umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && (grep -qxF '<pub>' ~/.ssh/authorized_keys && echo SVERB_PRESENT || (printf '%s\n' '<pub>' >> ~/.ssh/authorized_keys && echo SVERB_INSTALLED))
```

This is the §9.4 command with two markers added so sverb can tell "installed" from
"already present". The semantics are unchanged: the line is appended only when no
existing line equals it exactly, and new files and directories get mode 0700/0600
(`umask 077`). Existing `~/.ssh` permissions are not changed.

Notes:

- If `authorized_keys` doesn't end with a newline, the appended key is joined to its
  last line (as with the spec command). `ssh-copy-id` repairs this case; sverb doesn't
  yet.
- Both exec runs request no PTY, so stdout carries only the markers.

## Exec channels (SPEC §6.1.7)

`sverb_conn::ssh::exec` returns stdout, stderr, the exit status and the signal. Each
stream keeps at most 1 MiB; the rest is read and dropped, and `truncated` is set. The
timeout (`ssh.exec_timeout_secs`, default 60 s) sends `signal TERM`, waits 2 s, then
closes the channel; the result has no exit status and the signal `TERM (timeout)`. With
a PTY (`request_pty_for_exec`, or per run), stderr is merged into stdout.
