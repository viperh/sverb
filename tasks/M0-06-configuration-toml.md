# M0-06 — `config.toml` model replacing the template's layered config

| | |
|---|---|
| **Milestone** | M0 — Skeleton |
| **Touches** | `crates/sverb/src/config.rs` (split and mostly deleted), `.config/config.json` (deleted), new `crates/sverb-core/src/config/{mod,model,validate,default_config.toml,watch}.rs`, workspace deps (`config`, `json5` removed; `toml`, `schemars`, `notify` added) |
| **Spec refs** | §15, §4.3 (global config = last resolution tier), §8.3 (keymap overrides), §12.6 (never synced) |
| **Depends on** | M0-03 |
| **Blocks** | M0-07, M0-10, M0-11, nearly every feature task |

---

## 1. Current state in the codebase
`crates/sverb/src/config.rs` (603 lines) mixes four concerns:
1. **Loading** (lines 13-104): uses the `config` crate to layer `config.json5`, `.json`, `.yaml`,
   `.toml` and `.ini` from the config dir over the embedded `.config/config.json`
   (`include_str!` at line 15). Problems:
   - The spec allows **only** `config.toml`.
   - `json5::from_str(CONFIG).unwrap()` (line 57) and `to_str().unwrap()` (61-62) can panic.
   - Unknown keys are silently ignored, so typos are never reported.
   - Line 82 logs at **error** level when no config file exists, which is the normal case for new users.
   - Keybinding defaults are merged per key (lines 87-94), but there is no validation.
2. **Paths** (17-53, 106-128): removed by M0-03.
3. **Keybinding parsing** (130-323): `KeyBindings(HashMap<Mode, HashMap<Vec<KeyEvent>, Action>>)`
   with `<ctrl-a><b>` syntax. Its custom `Deserialize` `unwrap()`s parse errors (line 145).
   This file uses crossterm's `KeyEvent`, which **must not** enter `sverb-core`. M0-10 takes over this code.
4. **Styles** (325-452): `Styles(HashMap<Mode, HashMap<String, Style>>)` with a free-form
   `"underline red on blue"` parser. It has a bug: `parse_color("bright color5")` computes
   `c.wrapping_shl(8)` (line 398). On a `u8` the shift amount is masked to 0, so it returns the
   same index, which is not a bright color. The spec replaces styles with a `UiTheme` (M0-11).

`AppConfig { data_dir, config_dir }` (22-28) is replaced by `Paths`.

## 2. Detailed description

### 2.1 Where the code lives
- `sverb-core::config`: the typed model, defaults, parsing, validation, schema and file watching. No
  ratatui and no crossterm.
- Key chords in the config are kept as **strings** in core (`KeyChordSpec(String)`), and validated
  through a `KeymapValidator` trait object that `sverb-tui` provides (M0-10). This keeps
  crossterm out of core while still reporting bad chords at load time.
- Theme names are validated against a `ThemeCatalog` trait, provided by the TUI (UI themes, M0-11) and
  `sverb-term` (color schemes, M1-10).

### 2.2 Model (must match §15 exactly)
One struct per table, every field defaulted, `#[serde(default, deny_unknown_fields)]`.

| Table.key | Type | Default | Validation / notes | Applies |
|---|---|---|---|---|
| general.leader | KeyChordSpec | `"ctrl-\\"` (TOML-escaped `ctrl-\`; **changed from the spec's `ctrl-g`**, see `03-KEYBINDINGS.md` §3.2) | must parse; rules in `03-KEYBINDINGS.md` §5.2 (reject `ctrl-c/d/z`, enter, tab, esc; warn on `ctrl-a/b/e/k/r/u/w/l`) | live |
| general.confirm_quit | bool | true | | live |
| general.auto_lock_minutes | u32 | 15 | 0 disables | live |
| general.lock_disconnects_sessions | bool | false | | live |
| general.default_vault | String | `"personal"` | resolved at unlock; unknown → warning toast and fallback | next unlock |
| ui.theme | String | `"default-dark"` | known UI theme | live |
| ui.sidebar | enum auto/always/never | auto | | live |
| ui.mouse | bool | true | | live (toggles capture) |
| ui.truecolor | enum auto/on/off | auto | | live |
| ui.show_which_key | bool | true | | live |
| ui.which_key_delay_ms | u32 | 400 | 0..=10000 | live |
| ui.date_format | String | `"%Y-%m-%d %H:%M"` | must compile with the chosen formatter | live |
| terminal.term | String | `"xterm-256color"` | ASCII, no whitespace, ≤ 64 chars | new sessions |
| terminal.scrollback | u32 | 10000 | ≤ 1,000,000 | new sessions |
| terminal.color_scheme | String | `"terminal"` | known scheme, else warning + fallback | live for panes without a per-host scheme |
| terminal.bell | enum none/visual/audible | visual | | live |
| terminal.paste_confirm_multiline | bool | true | | live |
| terminal.use_osc_title | bool | false | | live |
| terminal.word_separators | String | `` " ,│`|:\"'()[]{}<>" `` | | live |
| clipboard.osc52 | bool | true | | live |
| clipboard.allow_remote_write | enum never/ask/always | ask | | live |
| ssh.multiplex | bool | true | | new connections |
| ssh.keepalive_secs | u32 | 30 | 0 disables | new connections |
| ssh.host_key_policy | enum strict/ask/accept-new | ask | | new connections |
| ssh.use_system_agent | bool | true | | new connections |
| ssh.read_ssh_config | bool | false | | live |
| ssh.hash_known_hosts | bool | false | | live |
| ssh.exec_timeout_secs | u32 | 60 | ≥ 1 | new runs |
| ssh.max_auth_attempts | u32 | 5 | 1..=20 | new connections |
| ssh.connect_timeout_secs | u32 | 15 | ≥ 1 | new connections |
| recording.enabled | bool | false | | new sessions |
| recording.include_input | bool | false | | new sessions |
| history.enabled | bool | true | | live |
| history.sync | bool | false | | live |
| history.max_entries_per_host | u32 | 5000 | | live |
| sync.push_debounce_ms | u32 | 2000 | ≥ 100 | live |
| sync.poll_fallback_secs | u32 | 300 | ≥ 30 | live |
| logs.retention_days | u32 | 90 | 0 = forever | live |
| logs.sync | bool | false | | live |
| ~~ai.*~~ | | | | removed 2026-10-08: the `[ai]` section was dropped together with M7-02 |
| keys.terminal | map KeyChordSpec → action name | `{p=palette, "-"=split_horizontal, "\|"=split_vertical}` merged over built-ins | chord valid, action exists | live |
| keys.normal | map | `{ctrl-k=palette}` | same | live |

- The "Applies" column is exposed as a `const` table (`key → ApplyScope`), used by the reload diff
  and printed as comments by `--print-default`.
- **No secrets in the config.** `[sync] server_url`, `token`, etc. are unknown-key errors with a hint:
  "server URL and tokens are set with `sverb login` and stored encrypted in the database".
- Unknown `keys.*` sub-tables (e.g. `keys.copy`) are allowed only if M0-10 defines that mode.

### 2.3 Parsing and error reporting
- Use the `toml` crate (`toml::de` with spans). Each error carries `ConfigError { path:
  "ssh.keepalive_sec", line, col, message, hint: Option<String> }`.
- For unknown keys, suggest the nearest known key in the same table (Levenshtein ≤ 2).
- Semantic validation runs after a successful parse and **collects all** errors.
- `Config::load(&Paths, &Validators) -> LoadOutcome { config: Config, errors: Vec<ConfigError>,
  source: Defaults | File }`. On any error, `config` is `Config::default()` at startup, or the last good
  config on reload. Never a partially applied file.
- Missing file → defaults, **no log above `debug`** (fixes `config.rs:82`).

### 2.4 Defaults as a checked-in file
`crates/sverb-core/src/config/default_config.toml` is a verbatim copy of §15 with comments, embedded
with `include_str!`. A test asserts it parses to `Config::default()`. This replaces
`.config/config.json`, which is deleted. The `include_str!("../../../.config/config.json")` path
(`config.rs:15`) also reached outside the crate, which breaks `cargo package`. The new file lives inside
the crate.

### 2.5 Hot reload (§15)
- `ConfigWatcher` uses `notify` (`RecommendedWatcher`) on the **parent dir** of `config.toml`,
  filtered to that file name (editors save by rename), debounced 200 ms.
- It emits `ConfigEvent::Reloaded(Arc<Config>)`, `ConfigEvent::Invalid(Vec<ConfigError>)` or
  `ConfigEvent::Removed` (→ defaults) into the TUI event stream (M0-08 wires it to
  `UiEvent::Config`).
- The reducer computes `ConfigDiff` (changed keys) and applies the live ones. Keys scoped to new
  sessions or connections show a one-time info toast: "Some changes apply to new sessions".
- A watcher failure (e.g. inotify limit) degrades to "no hot reload" with a warning toast, not a crash.

### 2.6 JSON Schema
`schemars::JsonSchema` on all config types, with doc comments as descriptions. A hidden CLI flag
`sverb config --schema` prints it. `docs/config.schema.json` is committed, and a test fails if it's stale.

### 2.7 CLI (§15/§16), implemented in M0-07 using this API
- `sverb config --check [--file <path>]`: exit 0 with `OK`, or 1 listing every error as
  `path:line:col: message (hint)`.
- `sverb config --print-default`: prints `default_config.toml` byte-for-byte.
- `sverb config --path`: prints `Paths::config_file()`.

### 2.8 Out of scope
- Keymap semantics (M0-10), UI themes (M0-11) and color schemes (M1-10). This task only validates names
  through the injected catalogs.

## 3. Codebase changes
- **Create** `crates/sverb-core/src/config/` (`mod.rs`, `model.rs`, `validate.rs`, `watch.rs`,
  `default_config.toml`, `schema.rs`).
- **Delete** from `crates/sverb/src/config.rs` everything except the keybinding parser and its
  tests. Move those to `sverb-tui/src/keymap/` in M0-10. Delete `Styles`, `parse_style`, `parse_color` and
  `process_color_string` together with their tests (lines 325-452, 461-505), since M0-11 replaces them
  with `UiTheme`.
- **Delete** `.config/config.json` and `.config/` (move `.config/` usage in `.envrc` to
  `SVERB_HOME`, see M0-03).
- **Deps:** remove `config` and `json5`. Add `toml`, `schemars`, `notify`, `strsim` (suggestions).
- **Modify** `crates/sverb/src/app.rs:49` (`Config::new()?`) to receive the loaded config from `main`.
- **Docs:** README "Configuration" section rewritten for TOML.

## 4. Test cases to implement

### Parsing
**T-01 (unit) Defaults table.** `Config::default()` matches every default in §15. One table-driven
test row per key (≈45 rows).

**T-02 (unit) Embedded default file round-trips** to `Config::default()`.

**T-03 (unit) Empty string and missing file → defaults**, no errors, `source = Defaults`.

**T-04 (unit) Partial override.** `[ssh]\nkeepalive_secs = 10` changes that field only (compare the rest
to the default).

**T-05 (unit) Unknown key with suggestion.** `[ssh]\nkeepalive_sec = 1` gives path `ssh.keepalive_sec`,
line 2, col 1, hint `keepalive_secs`.

**T-06 (unit) Unknown table.** `[colours]` gives an error, with hint `ui`? (Only if distance ≤ 2, otherwise no hint.)

**T-07 (unit) Type error.** `scrollback = "lots"` gives an error at `terminal.scrollback` with the expected type.

**T-08 (unit) Enum error.** `host_key_policy = "yolo"` gives an error listing `strict, ask, accept-new`.

**T-09 (unit) Aggregation.** A file with 3 independent semantic errors reports exactly 3.

**T-10 (unit) Leader validation (with the M0-10 validator, or a stub for now).** `"g"` is an error. `"ctrl-c"` is an error.
`"ctrl-a"` is OK with a warning. `"ctrl-\\"` (default) and `"ctrl-g"` are OK.

**T-11 (unit) Keymap action names.** `[keys.normal]\nx = "nope"` is an error, `x = "palette"` is OK.

**T-12 (unit) Secrets rejected.** `[sync]\nserver_url = "https://x"` gives an unknown-key error whose
hint mentions `sverb login`.

**T-13 (unit) Ranges.** `which_key_delay_ms = 20000` is an error, `max_auth_attempts = 0` is an error,
`auto_lock_minutes = 0` is OK.

**T-14 (unit) All-or-nothing.** A file with one valid change and one error leaves `config ==
default` (no partial application).

### Hot reload
**T-15 (integration) Valid change.** Write `ui.theme = "default-light"` under a temp `SVERB_HOME`.
A `Reloaded` event arrives within 1 s with that value.

**T-16 (integration) Invalid change keeps last good.** After T-15, write `[[[`. An `Invalid` event
arrives and the reducer still has `default-light`.

**T-17 (integration) Rename-save.** Write `config.toml.swp`, then rename it over `config.toml`. The change is detected.

**T-18 (integration) Debounce.** 5 writes within 100 ms produce 1 event.

**T-19 (integration) Removal.** Deleting the file produces `Removed`, and the reducer reverts to defaults.

**T-20 (reducer) Diff classification.** Changing `terminal.term` and `ui.theme` together applies the
theme and emits a "new sessions" info toast.

### Schema
**T-21 (unit) Schema freshness.** The generated schema equals `docs/config.schema.json`.

**T-22 (unit) Schema accepts the defaults** (validate with `jsonschema` dev-dep).

### Regression (template bugs)
**T-23 (unit) No panics on hostile input.** Feed 1,000 `proptest`-generated random TOML documents.
`Config::load` never panics.

## 5. Passing functional characteristics
- [ ] `config.toml` is the only config file. Other formats and the `config`/`json5` crates are gone.
- [ ] Every key, type and default in §15 is implemented, and a table-driven test checks them.
- [ ] Unknown keys, wrong types and invalid values are all reported with path, line/col and hint, and none
      of them panic.
- [ ] A bad file never partially applies. Startup falls back to defaults and reload keeps the last good config.
- [ ] Hot reload works with editor rename-saves, is debounced, and distinguishes live keys from
      new-session keys.
- [ ] The config model lives in `sverb-core` without crossterm or ratatui.
- [ ] No secrets or server URLs can be stored in `config.toml`.
- [ ] A JSON schema is generated and kept fresh.

## 6. Notes and spec questions
- §8.2 vs §15 which-key timing: see `00-README.md` §4 item 1. M0-10 resolves this.
