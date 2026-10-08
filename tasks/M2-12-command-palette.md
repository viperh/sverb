# M2-12 — Command palette

| | |
|---|---|
| **Milestone** | M2 |
| **Touches** | `crates/sverb-tui/src/views/palette.rs`, `crates/sverb-tui/src/keymap/action.rs` (registry metadata), `crates/sverb-core/src/search` (scope `Palette`) |
| **Spec refs** | §8.3 (`leader p` / `Ctrl-k` in normal mode: "fuzzy over every action, host and snippet"), §14.1 (paste share link into palette), §8.2 (discoverability) |
| **Depends on** | M1-05, M0-10, M2-09 |
| **Blocks** | M6-03 (join via palette) |

---

## 1. Current state in the codebase
The action `palette` is registered and bound (M0-10) but opens nothing. The keymap registry has names and descriptions. The search index covers
items (M1-05).

## 2. Detailed description
- **Overlay:** a centered box (60% width, up to 20 result rows) with an input line, results grouped by source with headers (Actions, Hosts,
  Snippets, Tabs, Recent), and the key hint shown per action (from the effective keymap, M0-10 `Keymap::effective`).
- **Sources:**
  1. **Actions:** every registry action that's currently **available** (an `is_enabled(&App)` predicate per action, e.g. `zoom_pane` only
     with panes, sync actions only in synced mode, `toggle_log_pane` only with `--debug`). Shows the description and key binding.
  2. **Hosts:** `Enter` connects in a new tab. `ctrl-enter` connects in a split. `tab` opens a secondary action menu (edit, copy ssh command,
     run snippet on it).
  3. **Snippets:** `Enter` runs in the current pane (the variable form if needed).
  4. **Open tabs and panes:** switch to them.
  5. **Settings pages:** "Settings: Appearance", etc.
- **Ranking:** fuzzy score (nucleo), with a recency boost (the last 20 palette picks, stored device-local in `meta`, never synced) and a source prior
  (Actions slightly above items when the query is short (< 3 chars)? **Decision:** with no query, show Recent then Actions. With a query, use pure score with a recency
  boost).
- **Prefixes:** `>` actions only, `@` hosts only, `!` snippets only, `#tag` filter (hosts and snippets).
- **Special inputs:** pasting a `sverb://join/...` or `https://<server>/s/<id>#key` link → the top result is "Join shared terminal" (M6-03).
  Typing `user@host[:port]` that parses as quick-connect → the top result is "Connect to user@host:port" (M1-07).
- **Keys:** `↑/↓` or `ctrl-p/ctrl-n` move, `Enter` executes, `Esc` closes, `tab` opens the secondary menu.
- Executing an action dispatches exactly as its keybinding would (the same reducer path), so behavior is identical.

## 3. Codebase changes
- **Create** `views/palette.rs` and add an `is_enabled` predicate plus a `category` to every registry entry.

## 4. Test cases to implement

**T-01 (reducer)** `ctrl-k` in Normal mode and `leader p` in Terminal mode both open the palette.

**T-02 (reducer)** Typing `split` lists `split_horizontal`/`split_vertical` with their key hints. Enter → the same effects as `leader -`.

**T-03 (unit)** Disabled actions are hidden (`zoom_pane` with no panes).

**T-04 (reducer)** `@web` shows only hosts. Enter → `OpenSession` in a new tab. `ctrl-enter` → a split.

**T-05 (reducer)** `!deploy` shows snippets, and Enter → the variable form.

**T-06 (reducer)** Typing `root@10.0.0.9:2200` → the first result is "Connect to …".

**T-07 (reducer)** Pasting a `sverb://join/...` link → the first result is "Join shared terminal" (stub action until M6-03).

**T-08 (unit)** Recency boost: after picking X twice, X ranks above an equally scored Y.

**T-09 (snapshot)** The palette open with mixed results at 80×24 and 160×48.

**T-10 (unit)** Palette recents are stored in `meta` (device-local) and never in an item.

## 5. Passing functional characteristics
- [ ] `leader p` and `Ctrl-k` open a fuzzy palette over available actions, hosts, snippets, tabs and settings pages.
- [ ] Results show key hints. Execution is identical to the keybinding path.
- [ ] The `>`, `@`, `!` and `#tag` prefixes, quick-connect input and share-link input are supported.
- [ ] Recently used entries rank higher (device-local).
