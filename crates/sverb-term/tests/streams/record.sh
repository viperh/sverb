#!/usr/bin/env bash
#
# Requirements: util-linux `script`, python3, and for the program fixtures: nvim (or vim), htop,
# tmux, less, man. Every recording runs in a fresh pty at 80x24 with TERM=xterm-256color.
#
#   crates/sverb-term/tests/streams/record.sh            # re-record everything
#   crates/sverb-term/tests/streams/record.sh htop less  # only some
#
# Afterwards, review and accept the new snapshots:
#   INSTA_UPDATE=always cargo test -p sverb-term --test replay   (or `cargo insta review`)
#
# Interactive programs are stopped with SIGKILL while running (`exec timeout --foreground -s KILL`;
# --foreground keeps them in the tty's foreground process group, `exec` avoids a "Killed" notice) so the final grid
# shows the program's screen, not the shell after it restored the primary screen. Keystrokes are
# piped to `script`, which forwards them to the pty.
#
# `script` writes a "Script started…" header line and a "Script done…" footer to its log; they
# are stripped so a .bin contains only what the program wrote to the terminal.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/src"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"; tmux -L sverb-rec kill-server 2>/dev/null || true' EXIT

VIM="$(command -v nvim || command -v vim)"

# record <name> <input-script> <command>
#   <input-script> is a shell snippet whose stdout is fed to the pty ("" for none).
record() {
  local name="$1" input="$2" cmd="$3"
  local log="$WORK/$name.log"
  echo "recording $name"
  (eval "${input:-sleep 0}"; sleep 0.2) |
    env -i HOME="$WORK" PATH="$PATH" LANG=C.UTF-8 LC_ALL=C.UTF-8 TERM=xterm-256color \
      script -q -E never -c "stty rows 24 cols 80; $cmd" --log-out "$log" >/dev/null || true
  python3 -I - "$log" "$HERE/$name.bin" <<'PY'
import sys
data = open(sys.argv[1], "rb").read()
start = data.index(b"\n") + 1                      # drop "Script started ..." line
end = data.rfind(b"\nScript done")                 # drop "\nScript done ..." footer
open(sys.argv[2], "wb").write(data[start:end if end >= 0 else len(data)])
PY
}

ARGS=("$@")
sel() { [[ ${#ARGS[@]} -eq 0 ]] && return 0; local a; for a in "${ARGS[@]}"; do [[ "$a" == "$1" ]] && return 0; done; return 1; }

if sel vim; then
  cp "$SRC/sample.txt" "$WORK/sample.rs"
  record vim "sleep 1.5; printf 'Go    // edited in vim\033'; sleep 1" \
    "cd '$WORK' && exec timeout --foreground -s KILL 3.5 '$VIM' --clean -n sample.rs"
fi

if sel htop; then
  mkdir -p "$WORK/htop"
  record htop "" \
    "sleep 5 & HTOPRC='$WORK/htop/htoprc' exec timeout --foreground -s KILL 1.5 htop -d 10 -p \$!"
fi

if sel tmux_split; then
  # The tmux *server* writes to the client's tty and resets it when the client dies, so both
  # are SIGKILLed together to keep the split screen as the final state.
  record tmux_split "sleep 3" \
    "(sleep 2; pkill -KILL -f '^tmux -L sverb-rec') & \
     exec tmux -L sverb-rec -f '$SRC/tmux.conf' new-session -n rec \
       'printf \"left pane\\n\"; sleep 10' \; split-window -h 'printf \"right pane\\n\"; sleep 10'"
  tmux -L sverb-rec kill-server 2>/dev/null || true
fi

if sel less_man; then
  MANWIDTH=80 MAN_KEEP_FORMATTING=1 man -l "$SRC/sverb-demo.1" >"$WORK/page.txt" 2>/dev/null
  record less_man "sleep 0.8; printf ' '; sleep 0.5" \
    "LESS= LESSOPEN= LESSHISTFILE=- exec timeout --foreground -s KILL 2 less '$WORK/page.txt'"
fi

if sel color_test; then
  record color_test "" "bash '$HERE/gen.sh' color"
fi
if sel utf8_test; then
  record utf8_test "" "bash '$HERE/gen.sh' utf8"
fi
if sel decstbm; then
  record decstbm "" "bash '$HERE/gen.sh' decstbm"
fi

echo "done; now run: INSTA_UPDATE=always cargo test -p sverb-term --test replay"
