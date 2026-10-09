# FAQ and troubleshooting

Start with `sverb doctor`. It checks the terminal, the clipboard path, the SSH agent,
the OS keyring and the sync server, and it prints a hint for every warning. Add
`--json` for machine-readable output, or `--ascii` for `[ok]`/`[warn]`/`[fail]` instead
of symbols (this is automatic when the locale isn't UTF-8).

## Common `doctor` findings

| Finding | What to do |
|---|---|
| `TERM` not set, or `dumb` | Run sverb from a real terminal emulator. The TUI needs cursor addressing and colors. |
| No truecolor or 256 colors advertised | Set `COLORTERM=truecolor` if your terminal supports 24-bit color, or set `ui.truecolor = "on"`. Otherwise RGB colors are downsampled to 256. |
| kitty keyboard protocol not supported | Some chords look the same (`ctrl-i`/`tab`, `ctrl-m`/`enter`). The default bindings avoid them. Don't bind them yourself, or use a terminal with the kitty protocol (kitty, WezTerm, foot, Ghostty, Alacritty). |
| OSC 52 clipboard unlikely or unknown | Copies may not reach the system clipboard over SSH. Locally, sverb falls back to `wl-copy`, `xclip`, `xsel`, `pbcopy` or `clip.exe`. Inside tmux, see below. |
| Unicode width mismatch | CJK and emoji may misalign. Check the terminal's font and its "ambiguous width" setting. |
| tmux | Add `set -g set-clipboard on` and `set -g allow-passthrough on` to `tmux.conf`. |
| GNU screen | OSC 52 and the kitty keyboard protocol don't pass through screen. Run sverb outside it, or use tmux. |
| `SSH_AUTH_SOCK` not set / agent has no keys | Start `ssh-agent` and `ssh-add` your keys, or use keys from the sverb vault. |
| Stale agent socket | A crashed `sverb agent` left its socket behind. It is replaced on the next start. |
| OS keyring unavailable | On Linux, run a Secret Service provider (gnome-keyring, KeePassXC). Without one, sverb asks for the master password on every unlock. |
| Sync server unreachable or token expired | Check the URL with `sverb sync --status`, then `sverb login` again. Tokens are checked after the vault is unlocked. |

## The leader key doesn't work

The default leader is `Ctrl-\`. On keyboard layouts where `\` needs AltGr, set

```toml
[general]
leader = "ctrl-g"
```

`sverb keys --dump` prints the effective bindings. To send the leader itself to the
remote side, press it twice.

## Windows Terminal

- Use a current Windows Terminal, which has OSC 52 clipboard and truecolor. The legacy
  console host works with reduced colors. The Windows build is compiled in CI, but it
  has had less manual testing than Linux and macOS.
- `Ctrl-\` reaches sverb by default. If a Windows Terminal action is bound to it, remove
  that binding or change `general.leader`.
- The built-in agent listens on the named pipe `\\.\pipe\sverb-agent`, and only the
  current user can access it.
- PowerShell completions: dot-source `completions\_sverb.ps1` (from the release zip)
  in your `$PROFILE`.

## macOS: Gatekeeper says the binary can't be opened

Release binaries are signed and notarized only when the release had the Apple signing
secrets. An unsigned download is quarantined. Remove the quarantine flag once:

```sh
xattr -d com.apple.quarantine ./sverb
```

You can also install with Homebrew (`brew install viperh/sverb/sverb`) or
`cargo install sverb`, which don't quarantine the binary.

## Colors are wrong, or I want no colors

`NO_COLOR=1 sverb` turns every color off. Focus and selection then use reverse video and
bold, and every status indicator still has a text label. `ui.theme = "high-contrast"`
is the high-contrast theme. If boxes or symbols show as garbage, set `ui.ascii = "on"`
(see [accessibility.md](accessibility.md)).

## `ssh.read_ssh_config` or `terminal.bell` gives a warning

Both keys are accepted, but they have no effect in 1.0 (SPEC decisions log, 2026-10-09):

- `ssh.read_ssh_config` would show live `~/.ssh/config` hosts. Use
  `sverb import ssh-config` (or `I` in Hosts) instead.
- `terminal.bell` currently supports only `"visual"`, the bell marker on the tab.

## Headless commands exit with code 3

The vault is locked, and there is no terminal to ask for the master password on. Either
turn on keyring unlock (offered on the first run), or run the command from a terminal. `SVERB_KEYRING=off` disables the keyring on purpose.

## Where are the logs and crash reports?

They are in the state directory (`sverb --version` prints it): one log file per day,
7 kept, and crash reports in `crash/`. Logs at `info` never contain hostnames,
usernames or commands. `sverb --debug` logs more and warns that hostnames may appear.

## Backups

`sverb export backup <file>` writes an encrypted `.sverb-backup` file. You choose the
password, or set it with `SVERB_EXPORT_PASSWORD` in scripts. `sverb import backup
<file> --dry-run` previews a restore. Recordings and device-local settings are not
included.
