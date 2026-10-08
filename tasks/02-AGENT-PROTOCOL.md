# Agent protocol: file locks, copies, merges

Every agent working on a task in this repository **must** follow this protocol. Several agents share one
working tree (`/home/viperh/Projects/sverb`) at the same time. The lockfile is how they avoid overwriting
each other.

## 1. The lockfile

- Location: **`/home/viperh/Projects/sverb/LOCKS.csv`** (the repository root).
- Format: CSV with this header (never change it):
  `path,agent,task,status,timestamp,copy_path,note`
  - `path`: file path **relative to the repo root**, using forward slashes (e.g. `crates/sverb/src/main.rs`).
  - `agent`: your agent id. Use the task id you were assigned, e.g. `agent-M0-03`.
  - `task`: the task id (e.g. `M0-03`).
  - `status`: one of
    - `locked`: you intend to modify (or create, delete, move) this file and nobody else holds it,
    - `modified`: you have actually changed the file. You keep ownership until the orchestrator merges or releases,
    - `copy`: the file is held by another agent, so your changes are in `copy_path` and await merging,
    - `released`: you didn't end up changing the file, and you give up the lock.
  - `timestamp`: UTC ISO-8601 (`date -u +%Y-%m-%dT%H:%M:%SZ`).
  - `copy_path`: only for `copy` rows, the path of your copy (see §3).
  - `note`: a short free text (what you changed, why you needed the file). Must not contain commas (use `;`).
- **The file is append-only.** Never edit or delete existing rows. To change your status, append a new row. The
  **latest row for a given (path, agent)** is that agent's current state.
- **Always** use the helper script, which appends under an exclusive `flock`, so concurrent agents can't corrupt the
  file:
  ```
  scripts/lock.sh check   <path>                              # prints current holders of <path>
  scripts/lock.sh acquire <path> <agent> <task> [note]        # appends 'locked', or exits 3 if held by another agent
  scripts/lock.sh mark    <path> <agent> <task> <status> [copy_path] [note]   # appends modified|copy|released
  scripts/lock.sh mine    <agent>                             # lists your current rows
  ```
  `acquire` exits **0** when you got the lock (or already hold it), and **3** when another agent holds the file
  (status `locked`, `modified` or `copy`-owner) and you must use a copy.

## 2. Before touching any file

1. Run `scripts/lock.sh acquire <path> <agent> <task> "<why>"` for **every** file you are about to create,
   modify, delete or move. For a move, lock **both** the source and destination paths. For a new file, lock its path
   too, because two agents might create the same file.
2. Exit 0 → edit the file in place. Right after your first change to it, append
   `scripts/lock.sh mark <path> <agent> <task> modified "" "<what changed>"`.
3. Exit 3 → **don't touch the original.** Follow §3.
4. Lock files **just in time** (when you're about to edit them), not your whole task's file list up front. That keeps
   contention low.
5. Reading files never needs a lock.

## 3. When the file is held by another agent: work on a copy

1. Copy the current original to **`.merge/<agent>/<path>`**, mirroring the directory structure. For example,
   `crates/sverb/src/main.rs` becomes `.merge/agent-M0-04/crates/sverb/src/main.rs`. Create the directories as needed.
2. Make your changes in the copy only. Keep them minimal and clearly scoped to your task. Mark each block you add or
   change with a comment `// <task-id>:` (or `# <task-id>:` in TOML/YAML/shell) so the merge is easy.
3. Record it: `scripts/lock.sh mark <path> <agent> <task> copy .merge/<agent>/<path> "<what you changed>"`.
4. Also write a short merge note to **`.merge/<agent>/MERGE-NOTES.md`**: for each copied file, what you changed, why,
   and anything the merger must preserve (e.g. "adds variant `UiEvent::Config` at end of enum; adds match arm in
   handle()").
5. Copies aren't compiled. Where possible, put most of your logic into **new files you own** (new modules) and keep
   the edits to shared files to small "wiring" changes (a `mod` line, an enum variant, a match arm, a dependency
   line). Then the copy is tiny and the bulk of your work compiles and tests on its own.
6. If you can't build or test because your wiring lives only in a copy, say so in your final report. List
   which tests you ran and which are blocked on the merge.

## 4. Things agents must NOT do

- Don't edit, reorder or delete rows in `LOCKS.csv` except through `scripts/lock.sh`.
- Don't modify a file whose latest row belongs to another agent with status `locked`, `modified` or `copy`, not
  even "just one line".
- **Don't run git commands that change state**: no `commit`, `add`, `stash`, `reset`, `checkout`, `restore`,
  `rebase`, `merge` or `clean`. Read-only git (`status`, `diff`, `log`) is fine. The orchestrator commits.
- Don't run `cargo fmt` on the whole workspace (it rewrites files you don't hold). Format only your files:
  `rustfmt --edition 2024 <file>`.
- `Cargo.lock` is a **derived file**: don't lock it, and don't make copies of it. Normal `cargo build/test --offline` runs may
  add entries to it, which is fine. Never run `cargo update` (that changes versions for everyone).
- Don't "fix" build errors in files owned by other agents. Other agents' work in progress may temporarily break the
  build. Report it, and scope your verification with `cargo test -p <your crate>` or `cargo check -p <crate>`.
- Don't spawn further sub-agents.

## 5. Finishing a task

1. For files you locked but didn't change: `mark … released`.
2. Leave `modified` and `copy` rows as they are. The orchestrator releases them after merging.
3. Final report to the orchestrator (your last message) must contain:
   - the task id and a 3–5 line summary of what was implemented,
   - **files modified in place** (with the `modified` rows) and **files changed via copies** (with copy paths),
   - test cases from the task file: implemented and passing / implemented but blocked / not implemented (and why),
   - commands run to verify (`cargo test -p …`) and their results, quoted honestly. Don't claim passing tests you
     didn't run,
   - any deviation from the task file or the spec, and any open questions.

## 6. Orchestrator's merge procedure (for reference)

After a wave finishes, the orchestrator:
1. reads `LOCKS.csv` and all `.merge/*/MERGE-NOTES.md`,
2. applies each copy onto the original with a three-way merge (base = the original at copy time, so agents should
   avoid editing a copy's base; if needed, `git diff --no-index` between the copy and the original),
3. builds and tests the workspace, and fixes merge fallout,
4. appends `released` rows for all merged paths (`agent=orchestrator`), deletes the merged `.merge/<agent>/` directories,
   and commits the wave.
