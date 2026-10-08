# M2-09 — Snippets: variables, run modes, multi-host exec, startup snippets

| | |
|---|---|
| **Milestone** | M2 |
| **Touches** | `crates/sverb-core/src/snippet/{template.rs, vars.rs}`, `crates/sverb-tui/src/views/snippets/{mod.rs, form.rs, picker.rs, run_dialog.rs, results.rs}`, `crates/sverb/src/cli/snippet.rs` |
| **Spec refs** | §9.7, §4.9, §9.1 (run snippet on hosts), §9.8 (broadcast of snippet runs), §6.1.1 step 6 (startup snippet), §16 (`sverb snippet run`) |
| **Depends on** | M2-04, M1-11 (paste encoding) |
| **Blocks** | M3-02 (broadcast snippets), M7-01 (snippets as suggestion source) |

---

## 1. Current state in the codebase
The `Snippet` typed view exists (M1-02). The Snippets section is a placeholder, `leader e` is bound but unimplemented, and the startup snippet hook in
M1-13 is a stub.

## 2. Detailed description

### 2.1 Template syntax (§4.9, §9.7)
- `{{name}}`, `{{name:default}}`, and in Exec-on-hosts mode the `{{name|q}}` filter (POSIX single-quote via M2-04's `shell_quote`).
  Whitespace inside the braces is allowed (`{{ name }}`). `{{{{` or `\{{` → a literal `{{`? **Decision:** `{{{{` is not special.
  Support `\{{` as an escape for a literal `{{`, and document it.
- **Built-ins:** `{{host.label}}`, `{{host.address}}`, `{{host.user}}`, `{{date}}` (ISO `YYYY-MM-DD`), resolved per target host.
- Parsing produces `Template { parts: Vec<Literal | Var{name, default, filter}> }`. Undeclared variables used in the script are
  auto-added as variables when saving (with a prompt).
- **Substitution is literal** (no escaping) except with `|q` (§9.7). The final text is always shown in a preview before running.
- `VarDef { name, default, secret: bool }`. **Secret variables** are masked in the form and preview (`••••`), and are **never saved to
  history** (M7-01) or logs. The preview shows `{{password}}` placeholders masked.

### 2.2 Run modes (§9.7)
- **Paste:** type the text into the focused pane **without a trailing newline**. If the remote enabled bracketed paste (2004), wrap it in
  `ESC[200~ … ESC[201~` (using M1-11 paste logic, including terminator stripping).
- **Paste & execute:** send each line followed by `\r`, **without** bracketed paste, so the shell runs each one. Lines are sent in order,
  waiting for nothing in between (it's a paste). Document that interactive prompts mid-script may consume subsequent lines.
- **Exec on hosts:** pick hosts, tags or groups (multi-select picker), then run via `exec` channels concurrently (**default concurrency 10**),
  with each host substituting its own built-ins. The results view (§9.7) shows a per-host status (running / ok / exit N / timeout / error), exit
  code, duration and expandable stdout/stderr (with a truncated badge), plus **export** results as JSON or Markdown (to a file or the
  clipboard).
- Snippet runs in a pane in broadcast mode (M3-02) are broadcast: each target pane gets the same text, with paste encoding per pane.

### 2.3 UI
- **Snippets view** (§8.5): list with preview (detail pane shows the script with variables highlighted). Actions: run here (default
  `Enter`, using the snippet's `run_mode`), run on hosts…, paste, edit, duplicate, delete. Organized by tags (`#tag` filter).
- **Snippet picker** (`leader e`, §9.7): a fuzzy list overlay with a preview pane. `Enter` runs in the current pane with the snippet's
  default mode (Paste or Paste & execute; Exec mode from the picker opens the host picker).
- **Variable form:** before running, a modal with one field per variable (defaults prefilled, secret fields masked), plus a live
  preview of the final text (masked secrets). `Enter` runs and `Esc` cancels.
- **Form editor:** name, description, tags, run_mode, script (multiline), variables (kv-style list with a secret toggle).
- **Startup snippets** (§9.7, §6.1.1): a host's `startup_snippet_id` runs after the shell opens: sent as typed input (Paste & execute
  semantics) once the first output arrives or after 500 ms. If the snippet has variables without defaults, show the variable form in the pane
  at connect time (non-blocking for other panes).

### 2.4 CLI (§16)
`sverb snippet run <snippet> --on <host|#tag|group>... [--json] [--var name=value]... [--concurrency N] [--timeout S]`:
- Always uses Exec-on-hosts mode, regardless of the snippet's `run_mode`.
- Target resolution: `#tag` → hosts with that tag, a group label → all hosts in the group (recursive), otherwise host resolution.
  Deduplicate.
- Variables without defaults and without `--var`: prompt on a TTY (secret ones without echo). With no TTY → exit 2, listing the missing vars.
- Output: per-host blocks (`== host (exit 0, 1.2s) ==` then stdout/stderr), or `--json`
  (`{"version":1,"data":[{host, exit, signal, stdout, stderr, truncated, duration_ms}]}`, with stdout/stderr as UTF-8-lossy strings plus
  `stdout_b64` when not valid UTF-8).
- Exit code 0 if all ok, 7 (partial) if some failed, 1 if all failed.

## 3. Codebase changes
- **Create** `sverb-core::snippet` (pure template engine) and the snippet views. **Implement** `cli/snippet.rs`. Wire the startup hook in
  `sverb-conn::ssh::connect`.

## 4. Test cases to implement

**T-01 (unit, table) Template parsing.** `{{a}}`, `{{ a }}`, `{{a:def}}`, `{{a:with:colons}}` (default `with:colons`), `{{a|q}}`,
`{{host.label}}`, `\{{literal}}`, `{{` unclosed → error with position, `{{1bad}}` → invalid name.

**T-02 (unit) Substitution literal.** `echo {{x}}` with `x = "a; rm -rf /"` → `echo a; rm -rf /` (literal, as specified). With `|q` → `echo 'a; rm -rf /'`.

**T-03 (unit) Built-ins per host** in exec mode differ per host.

**T-04 (unit) Secret masking** in the preview. A secret value never appears in the history sink (mock) or logs (canary).

**T-05 (unit) Paste encoding.** Bracketed on → wrapped, with no trailing newline. Off → raw, with no trailing newline.

**T-06 (unit) Paste & execute.** 3 lines → `l1\rl2\rl3\r`, never bracketed even if 2004 is on.

**T-07 (reducer) `leader e` picker** → fuzzy filter, preview, Enter → variable form → run → `SendToSession` bytes as expected.

**T-08 (reducer) Startup snippet** sent after the first output, or after 500 ms with no output (virtual time).

**T-09 (e2e) Exec on 3 hosts** (3 containers), with one command failing on one host → the results view shows 2 ok and 1 exit N. JSON and Markdown export snapshots.

**T-10 (unit) Concurrency default 10** (fake executor with 30 targets).

**T-11 (CLI) `snippet run uptime --on #web --json`** → JSON snapshot (with a fake executor), exit 0. One failure → exit 7.

**T-12 (CLI) Missing variables with no TTY** → exit 2 listing the names. `--var` supplies them.

**T-13 (unit) Target resolution** of `#tag`, group (recursive) and host, with deduplication.

## 5. Passing functional characteristics
- [ ] Snippets support `{{name}}`, `{{name:default}}`, built-in host variables, and the `|q` quoting filter in exec mode. Substitution is otherwise literal and
      previewed.
- [ ] Secret variables are masked and never stored in history or logs.
- [ ] The Paste, Paste & execute and Exec on hosts modes behave per §9.7, including bracketed-paste rules.
- [ ] Multi-host exec runs concurrently (default 10) with a results view and JSON/Markdown export.
- [ ] The `leader e` picker, startup snippets and `sverb snippet run` (with exit codes 0/7/1) work.
