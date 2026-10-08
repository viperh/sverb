#!/usr/bin/env bash
# Append-only file-lock registry for parallel agents. See tasks/02-AGENT-PROTOCOL.md.
#
#   scripts/lock.sh check   <path>
#   scripts/lock.sh acquire <path> <agent> <task> [note]
#   scripts/lock.sh mark    <path> <agent> <task> <modified|copy|released> [copy_path] [note]
#   scripts/lock.sh mine    <agent>
#
# Exit codes: 0 ok, 2 usage error, 3 path held by another agent (acquire only).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCKS="$ROOT/LOCKS.csv"
GUARD="$ROOT/.LOCKS.csv.flock"
HEADER="path,agent,task,status,timestamp,copy_path,note"

usage() { sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }

[[ -f "$LOCKS" ]] || echo "$HEADER" > "$LOCKS"

# Normalize a path to repo-relative form with forward slashes.
norm() {
  local p="${1//\\//}"
  p="${p#./}"
  [[ "$p" == "$ROOT/"* ]] && p="${p#"$ROOT/"}"
  printf '%s' "$p"
}

clean() { printf '%s' "${1//,/;}" | tr -d '\n\r'; }

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# Latest status per agent for a path, as "agent status copy_path" lines; excludes released.
holders() {
  awk -F, -v p="$1" 'NR>1 && $1==p { last[$2]=$4 "," $6 } END { for (a in last) { split(last[a], s, ","); if (s[1] != "released") print a, s[1], s[2] } }' "$LOCKS"
}

cmd="${1:-}"; shift || true
case "$cmd" in
  check)
    [[ $# -eq 1 ]] || usage
    p="$(norm "$1")"
    h="$(holders "$p")"
    if [[ -z "$h" ]]; then echo "free: $p"; else echo "held: $p"; echo "$h" | sed 's/^/  /'; fi
    ;;
  acquire)
    [[ $# -ge 3 ]] || usage
    p="$(norm "$1")"; agent="$(clean "$2")"; task="$(clean "$3")"; note="$(clean "${4:-}")"
    exec 9>"$GUARD"; flock -x 9
    others="$(holders "$p" | awk -v me="$agent" '$1 != me')"
    if [[ -n "$others" ]]; then
      echo "HELD by another agent — work on a copy at .merge/$agent/$p" >&2
      echo "$others" | sed 's/^/  /' >&2
      exit 3
    fi
    mine="$(holders "$p" | awk -v me="$agent" '$1 == me')"
    if [[ -z "$mine" ]]; then
      printf '%s,%s,%s,locked,%s,,%s\n' "$p" "$agent" "$task" "$(now)" "$note" >> "$LOCKS"
    fi
    echo "locked: $p"
    ;;
  mark)
    [[ $# -ge 4 ]] || usage
    p="$(norm "$1")"; agent="$(clean "$2")"; task="$(clean "$3")"; status="$4"
    copy="$(clean "$(norm "${5:-}")")"; note="$(clean "${6:-}")"
    case "$status" in modified|copy|released) ;; *) echo "bad status: $status" >&2; exit 2;; esac
    [[ "$status" != copy || -n "$copy" ]] || { echo "copy status needs copy_path" >&2; exit 2; }
    exec 9>"$GUARD"; flock -x 9
    printf '%s,%s,%s,%s,%s,%s,%s\n' "$p" "$agent" "$task" "$status" "$(now)" "$copy" "$note" >> "$LOCKS"
    echo "$status: $p"
    ;;
  mine)
    [[ $# -eq 1 ]] || usage
    awk -F, -v a="$1" 'NR>1 && $2==a { last[$1]=$0 } END { for (p in last) print last[p] }' "$LOCKS" | sort
    ;;
  *) usage ;;
esac
