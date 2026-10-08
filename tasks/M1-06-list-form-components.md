# M1-06 — Shared UI components: list view, forms, field widgets, modal dialogs

| | |
|---|---|
| **Milestone** | M1 |
| **Touches** | `crates/sverb-tui/src/widgets/{list.rs, form/{mod.rs, text.rs, secret.rs, number.rs, select.rs, multiselect.rs, reference.rs, kv_list.rs, multiline.rs}, dialog.rs, confirm.rs}` |
| **Spec refs** | §8.5 (shared list component), §8.6 (forms and dialogs), §8.2 (Insert mode), §8.8 (monochrome) |
| **Depends on** | M0-11, M1-05 |
| **Blocks** | M1-07 and every view with lists or editors |

---

## 1. Current state in the codebase
After M0-11 there are a shell, a sidebar and placeholder section views. The template contained no list or form
widgets (`components/home.rs` was a paragraph). Everything here is new, built on the `View` trait from
M0-08.

## 2. Detailed description

### 2.1 Shared list component (`ListView<T>`) (§8.5)
One generic component used by Hosts, Keychain, Forwards, Snippets, Known Hosts and Logs:
- **Data source:** `Vec<Row>` from an `IndexSnapshot` query (M1-05), plus a `RowRenderer` trait per view
  (columns, icons, secondary text).
- **Virtualized rendering:** only visible rows are rendered, and scrolling keeps the selection in view (scrolloff 2).
- **Fuzzy filter:** `/` opens a filter line at the top (Insert mode), with live results as you type and match
  highlights. `Esc` clears and closes it, and `Enter` keeps the filter and returns focus to the list.
- **Multi-select:** `Space` toggles the mark on the current row, `V`/`ctrl-a` selects all visible rows, and `Esc`
  clears the marks. A marked count is shown in the title (`3 selected`). Bulk actions operate on the marks if any exist,
  otherwise on the cursor row.
- **Sorting:** `s` cycles the sort keys defined by the view (e.g. name, last connected, address), and `S` reverses.
- **Grouping:** an optional tree mode (Hosts → groups) with collapsible nodes (`h/l`, `←/→`), and
  expanded state persisted per session (not synced).
- **Detail pane:** on the right when the width is ≥ 100 columns (split 55/45), showing the selected item's
  details through a `DetailRenderer`. Below that width, `Enter`-on-detail or `i` opens a full-screen detail.
- **Navigation:** `j/k`, arrows, `g/G`, `ctrl-d/ctrl-u` (half page), `PageUp/PageDown`, mouse wheel and click
  (if mouse is enabled).
- **Empty state:** custom message per view, with key hints.

### 2.2 Forms (§8.6)
- Full-screen editor framework: `Form` = ordered sections of `Field`s, a title, a dirty flag, and validation
  hooks.
- **Field widgets:**
  - `Text` (single line, with cursor, word motions, `ctrl-w`, `ctrl-u`),
  - `Secret` (masked with `•`; `ctrl-r` toggles reveal for **that field only** and auto-hides when the field
    loses focus; never logged; held as `SecretString`),
  - `Number` (with range, rejects non-digits),
  - `Select` (single choice; `←/→` cycles; `Enter` opens a dropdown list),
  - `MultiSelect` (checklist popup),
  - `Reference` (picks an item of a kind from the index with a fuzzy picker, e.g. identity, key, group; shows the
    label; `Del` clears it),
  - `KeyValueList` (for `env`: add `a`, delete `d`, edit inline),
  - `Multiline` (`tui-textarea`, for notes and snippet scripts).
- **Inherited placeholders:** an empty optional field shows the resolved inherited value dimmed, with the source
  (`22 (default)`, `2222 (from group "prod")`), using the provenance from settings resolution (M2-01). Until
  M2-01 exists, only global defaults are shown.
- **Validation:** inline, per field, on blur and on save, using `sverb-core::model::validate`
  (M1-02). Errors render under the field in the `error` theme color, plus an `!` marker so monochrome works.
  Saving is blocked while errors exist, and focus jumps to the first error.
- **Keys:** `tab`/`shift-tab` move between fields, `ctrl-s` saves, `Esc` cancels (a confirm dialog "Discard
  changes?" if dirty). While a field is being edited the mode is Insert (M0-10).
- **Read-only forms** (newer schema, §4.1, or the `read` permission in shared vaults, §13.2): all fields are disabled,
  with the banner "Update sverb to edit this item" or "Read-only vault".
- Save emits `Effect::SaveItem { vault, item_id, changes: FieldChanges }`. On `EffectDone(Ok)` the form
  closes with a toast, and on `Err` the form stays open with an error toast.

### 2.3 Modal dialogs
- `Dialog` stack in `App` (M0-08 dispatch order: top dialog first).
- Generic types: `Confirm { title, body, buttons, default, danger: bool }`, `Prompt` (text/secret
  input), `Choice` (list), `Progress` (spinner + cancel), `Info`. Specialized dialogs (host key, auth prompt,
  snippet variables, agent confirm) build on these in later tasks.
- Centered, max 80% width, wrapped text. Buttons are reachable by underlined mnemonic letters
  (`[a]ccept`), `tab` and `Enter`. A `danger` dialog's default button is the safe one.
- Dialogs can carry a timeout (used by the host-key prompt's 120 s, M1-15) that shows a countdown.

### 2.4 Accessibility
Every widget works in `NO_COLOR` (focus and selection by reverse + bold, errors with an `!` prefix). No
information is conveyed by color alone.

## 3. Codebase changes
- **Create** the widget modules listed in the header. Add the `tui-textarea` dep (pinned to a version compatible
  with ratatui 0.30).
- Each widget is a pure-state struct + `View` impl, so reducer tests can drive it.

## 4. Test cases to implement

### List
**T-01 (reducer)** `j/k/g/G` move the selection, and scrolling keeps the selection visible with 2 rows of scrolloff
(snapshot at 80×24 with 100 rows).

**T-02 (reducer)** `/web` filters, and highlights render. `Esc` restores the full list and keeps the selection on the
same item if still visible.

**T-03 (reducer)** Space marks 3 rows. The title shows `3 selected`, and a bulk action receives those 3 ids.

**T-04 (reducer)** `s` cycles sort keys and `S` reverses. Ordering is verified.

**T-05 (reducer)** Tree mode: collapsing a group hides its children, and expanding restores them.

**T-06 (snapshot)** The detail pane is visible at 160×48 and hidden at 80×24.

**T-07 (perf)** Rendering a 10k-row list at 160×48 takes < 2 ms (only visible rows are rendered).

### Forms
**T-08 (reducer)** Tab order follows the field order, and shift-tab goes backwards.

**T-09 (reducer)** A Secret field renders masked. `ctrl-r` reveals it, and focus leaving re-masks it. The rendered buffer
never contains the secret while it's masked.

**T-10 (reducer)** A Number field rejects letters and enforces the range (port 70000 → inline error).

**T-11 (reducer)** `ctrl-s` with an invalid field blocks the save and focuses the first error. With valid fields → a `SaveItem`
effect with only the changed fields.

**T-12 (reducer)** `Esc` on a dirty form shows a confirm. "Discard" closes it with no effect. On a clean form `Esc` closes immediately.

**T-13 (reducer)** A Reference field picker filters items of the right kind only.

**T-14 (reducer)** KeyValueList add/edit/delete entries, and invalid env names show inline errors.

**T-15 (snapshot)** The inherited placeholder `22 (default)` is shown dimmed for an empty port.

**T-16 (reducer)** A read-only form disables editing, shows the banner, and `ctrl-s` is a no-op.

**T-17 (reducer)** `EffectDone(Err)` keeps the form open with the user's edits intact.

### Dialogs
**T-18 (reducer)** A dialog captures all keys, and the underlying view gets nothing.

**T-19 (reducer)** Mnemonic keys trigger buttons. `Enter` on a danger dialog defaults to the safe button.

**T-20 (reducer)** A timeout dialog fires its timeout result after the duration (virtual time) and shows the countdown.

**T-21 (snapshot)** Every dialog type at 80×24, normal and `NO_COLOR`.

## 5. Passing functional characteristics
- [ ] One list component provides fuzzy filter, multi-select, sorting, grouping/tree, a detail pane at ≥ 100 cols, and
      virtualization.
- [ ] Forms support all typed field widgets in §8.6, inline validation, inherited placeholders, `ctrl-s`/`Esc`
      semantics and a dirty-confirm.
- [ ] Secret fields are masked by default, reveal per field, and never appear in renders while masked.
- [ ] Modal dialogs stack, capture input, support mnemonics, danger defaults and timeouts.
- [ ] Everything is usable in monochrome.
- [ ] Widgets are reducer-testable and snapshot-tested.
