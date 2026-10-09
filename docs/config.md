<!-- Generated from the config model (crates/sverb-core/src/config). Do not edit:
     run `SVERB_BLESS_SCHEMA=1 cargo test -p sverb-core config::schema` to regenerate. -->

# Configuration reference

sverb reads one TOML file, `config.toml`, from the config directory (`~/.config/sverb/` on Linux, `~/Library/Application Support/sverb/` on macOS, `%APPDATA%\sverb\` on Windows, or `$SVERB_HOME/config` when `SVERB_HOME` is set; `sverb config --path` prints it). Every key is optional. Unknown keys are errors with a "did you mean" hint, and an invalid file keeps the last good config in effect (a toast reports the problem). The file is reloaded when it changes; the *Applies* column says when a new value takes effect.

- `sverb config --check` validates the file, `sverb config --print-default` prints the defaults below as a commented file.
- `docs/config.schema.json` is the JSON schema, for editor completion (for example with taplo: `#:schema ./config.schema.json`).
- Keys marked *spec addition* are not in SPEC.md draft v0.3; they are recorded in the SPEC decisions log.

## `[general]`

General behaviour: leader key, quitting and the vault lock.

| Key | Type | Default | Applies | Description |
|---|---|---|---|---|
| `leader` | string | `"ctrl-\\"` | live | The leader (command) key. `"ctrl-\\"` by default; `"ctrl-g"` is recommended where `\` needs AltGr. |
| `confirm_quit` | boolean | `true` | live | Ask before quitting while sessions are open. |
| `auto_lock_minutes` | integer | `15` | live | Lock the vault after this many idle minutes. 0 disables auto-lock. |
| `lock_disconnects_sessions` | boolean | `false` | live | Disconnect all sessions when the vault locks. |
| `default_vault` | string | `"personal"` | next unlock | Vault selected at unlock. |

## `[ui]`

The look of the sverb UI.

| Key | Type | Default | Applies | Description |
|---|---|---|---|---|
| `theme` | string | `"default-dark"` | live | UI chrome theme (built-in or a file in `themes/`). |
| `sidebar` | `"auto"` \| `"always"` \| `"never"` | `"auto"` | live | When the sidebar is shown: auto, always or never. |
| `mouse` | boolean | `true` | live | Capture the mouse. |
| `truecolor` | `"auto"` \| `"on"` \| `"off"` | `"auto"` | live | 24-bit color: auto, on or off. |
| `show_which_key` | boolean | `true` | live | Show the which-key popup after the leader. |
| `which_key_delay_ms` | integer | `400` | live | Delay before the which-key popup appears, in milliseconds (0..=10000). |
| `date_format` | string | `"%Y-%m-%d %H:%M"` | live | strftime-style format for dates shown in the UI. |
| `ascii` | `"auto"` \| `"on"` \| `"off"` | `"auto"` | live | ASCII glyph fallback: auto (non-UTF-8 locale or `TERM=linux`), on or off. *(spec addition)* |
| `reduce_motion` | boolean | `false` | live | No animated glyphs (spinners show a static marker). *(spec addition)* |

## `[terminal]`

Defaults for terminal panes.

| Key | Type | Default | Applies | Description |
|---|---|---|---|---|
| `term` | string | `"xterm-256color"` | new sessions | `TERM` sent to the remote side. ASCII, no whitespace, at most 64 characters. |
| `scrollback` | integer | `10000` | new sessions | Scrollback lines per pane (at most 1000000). |
| `color_scheme` | string | `"terminal"` | live | Color scheme for hosts without one. |
| `bell` | `"none"` \| `"visual"` \| `"audible"` | `"visual"` | live | What the bell does: none, visual or audible. Only `visual` (the tab's bell marker) is implemented yet; other values warn. |
| `paste_confirm_multiline` | boolean | `true` | live | Ask before pasting text that contains newlines. |
| `use_osc_title` | boolean | `false` | live | Let the remote side set the tab title with OSC 0/2. |
| `word_separators` | string | `` " ,│`\|:\"'()[]{}<>" `` | live | Characters that end a word for double-click selection. |

## `[clipboard]`

Clipboard integration.

| Key | Type | Default | Applies | Description |
|---|---|---|---|---|
| `osc52` | boolean | `true` | live | Copy through the outer terminal with OSC 52. |
| `allow_remote_write` | `"never"` \| `"ask"` \| `"always"` | `"ask"` | live | Remote clipboard writes: never, ask or always. |

## `[ssh]`

SSH connection defaults.

| Key | Type | Default | Applies | Description |
|---|---|---|---|---|
| `multiplex` | boolean | `true` | new connections | Reuse one connection for several sessions to the same host. |
| `keepalive_secs` | integer | `30` | new connections | Keepalive interval in seconds. 0 disables keepalives. |
| `host_key_policy` | `"strict"` \| `"ask"` \| `"accept-new"` | `"ask"` | new connections | Unknown host keys: strict, ask or accept-new. |
| `use_system_agent` | boolean | `true` | new connections | Also offer keys from the system ssh-agent. |
| `read_ssh_config` | boolean | `false` | live | Also resolve hosts from `~/.ssh/config` (read-only). Not implemented yet (a warning when on; use `sverb import ssh-config`). |
| `hash_known_hosts` | boolean | `false` | live | Store new known_hosts entries hashed. |
| `exec_timeout_secs` | integer | `60` | new runs | Timeout for remote commands run by sverb, in seconds (at least 1). |
| `max_auth_attempts` | integer | `5` | new connections | Authentication attempts per connection (1..=20). |
| `connect_timeout_secs` | integer | `15` | new connections | TCP and handshake timeout in seconds (at least 1). |
| `auto_reconnect` | boolean | `false` | new connections | Reconnect dropped sessions automatically (exponential backoff 1 s → 30 s, at most 10 tries). A host's `auto_reconnect` overrides it. *(spec addition)* |

## `[recording]`

Session recording defaults.

| Key | Type | Default | Applies | Description |
|---|---|---|---|---|
| `enabled` | boolean | `false` | new sessions | Record new sessions. |
| `include_input` | boolean | `false` | new sessions | Also record keyboard input. |
| `retention_days` | integer | `0` | live | Delete recordings this many days old. 0 keeps them until deleted. *(spec addition)* |

## `[history]`

Command history.

| Key | Type | Default | Applies | Description |
|---|---|---|---|---|
| `enabled` | boolean | `true` | live | Keep a per-host command history. |
| `sync` | boolean | `false` | live | Sync the history between devices. |
| `max_entries_per_host` | integer | `5000` | live | History entries kept per host. |
| `ghost_text` | boolean | `false` | live | Show an inline ghost-text suggestion after the cursor (needs shell integration, OSC 133). Accepted with `leader Tab` only. *(spec addition)* |

## `[sync]`

Sync tuning knobs. The server URL and tokens are set with `sverb login`, never here.

| Key | Type | Default | Applies | Description |
|---|---|---|---|---|
| `push_debounce_ms` | integer | `2000` | live | Wait this long after a change before pushing, in milliseconds (at least 100). |
| `poll_fallback_secs` | integer | `300` | live | Poll interval when push notifications are unavailable, in seconds (at least 30). |

## `[logs]`

Connection log retention.

| Key | Type | Default | Applies | Description |
|---|---|---|---|---|
| `retention_days` | integer | `90` | live | Keep connection logs this many days. 0 keeps them forever. |
| `sync` | boolean | `false` | live | Sync connection logs between devices. |

## `[keys.<mode>]`

Key binding overrides, one table per mode: `[keys.terminal]` (after the leader, in every mode; the name is historical), `[keys.normal]` (sverb views focused) and `[keys.copy]` (copy mode). Each entry maps a chord (`"ctrl-k"`, `"p"`, `"shift-tab"`) to an action name; `"none"` unbinds a default. Changes apply live. The actions and their default keys are listed in [keybindings.md](keybindings.md).

## The default file

```toml
# sverb configuration: ~/.config/sverb/config.toml (SPEC §15).
# Every key is optional; the values below are the defaults.
# Check a file with `sverb config --check`. Changes are picked up live.

[general]
leader = "ctrl-\\"               # Ctrl-\ ; "ctrl-g" recommended where \ needs AltGr
confirm_quit = true
auto_lock_minutes = 15
lock_disconnects_sessions = false
default_vault = "personal"

[ui]
theme = "default-dark"          # UI chrome theme
sidebar = "auto"                # auto | always | never
mouse = true
truecolor = "auto"              # auto | on | off
show_which_key = true
which_key_delay_ms = 400
date_format = "%Y-%m-%d %H:%M"
ascii = "auto"                  # auto | on | off: ASCII glyphs (auto: non-UTF-8 locale or TERM=linux)
reduce_motion = false           # no animated spinners

[terminal]
term = "xterm-256color"
scrollback = 10000
color_scheme = "terminal"       # default for hosts without one
bell = "visual"                 # none | visual | audible
paste_confirm_multiline = true
use_osc_title = false
word_separators = " ,│`|:\"'()[]{}<>"

[clipboard]
osc52 = true
allow_remote_write = "ask"      # never | ask | always

[ssh]
multiplex = true
keepalive_secs = 30
host_key_policy = "ask"         # strict | ask | accept-new
use_system_agent = true
read_ssh_config = false         # also resolve hosts from ~/.ssh/config live (read-only)
hash_known_hosts = false        # store new known_hosts entries hashed
exec_timeout_secs = 60
max_auth_attempts = 5
connect_timeout_secs = 15
auto_reconnect = false          # reconnect dropped sessions (backoff 1s→30s, 10 tries); hosts can override

[recording]
enabled = false
include_input = false
retention_days = 0              # delete recordings after N days; 0 = keep until deleted

[history]
enabled = true
sync = false
max_entries_per_host = 5000
ghost_text = false              # inline suggestion after the cursor (needs shell integration); leader Tab accepts

[sync]
# Server URL, device id and tokens are set by `sverb login` and stored encrypted in the
# database (§5.2), not in this file. These are tuning knobs only.
push_debounce_ms = 2000
poll_fallback_secs = 300

[logs]
retention_days = 90
sync = false

[keys.terminal]                 # bindings after leader
"p" = "palette"
"-" = "split_horizontal"
"|" = "split_vertical"

[keys.normal]
"ctrl-k" = "palette"

[keys.copy]                     # copy mode (leader [); see docs/keybindings.md
"y" = "yank"
"/" = "search_forward"
"o" = "open_link"
```
