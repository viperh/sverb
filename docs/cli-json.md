# `--json` output

Commands that accept `--json` (`hosts list`, `snippet run`, `keys --dump`, …) print
exactly one JSON document on **stdout**, on one line, followed by a newline:

```json
{"version":1,"data":…}
```

- `version` is the envelope version, currently `1`. It changes only when a
  command's `data` changes incompatibly; adding fields is not a version change, so
  consumers must ignore unknown fields.
- `data` is the command's payload. Its shape is documented below as each command
  is implemented.
- Errors are never printed as JSON: they go to **stderr** as `error: …` with
  `  caused by: …` lines, and the exit code says what happened (see
  `sverb --help`: 0 ok, 1 failure, 2 usage, 3 vault locked, 4 not found,
  5 approval required, 6 network, 7 partial failure).
- Nothing else is written to stdout, so the output can be piped into `jq`.

The envelope is produced by `crates/sverb/src/cli/output.rs` and snapshot-tested
in `crates/sverb/src/cli/tests.rs` (`json_envelope`).

## Commands

| Command | `data` | Since |
|---|---|---|
| `sverb hosts list --json` | array of `{id, label, address, port, user, group, tags}` (`port` is the effective port, 22 by default; `user`/`group` may be `null`; `tags` are names; no secrets) | M1-07 |
| `sverb snippet run … --json` | per-host results | M2-09 |
| `sverb keys --dump --json` | array of bindings | M0-10 |
