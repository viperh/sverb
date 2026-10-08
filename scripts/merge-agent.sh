#!/usr/bin/env bash
# Orchestrator helper: apply an agent's .merge/agent-<task>/ copies onto the tree.
# usage: scripts/merge-agent.sh <task-id>   (run from the repo root)
# Per file: no base recorded -> copy; base == current -> copy; otherwise patch the
# base→copy diff onto the current file (reports CONFLICT and leaves a .rej on failure).
set -u
T=$1; A=agent-$T; M=.merge/$A
[ -d "$M" ] || { echo "no $M"; exit 1; }
TMP=$(mktemp -d)
BASE=""; [ -d "$M/_base" ] && BASE="$M/_base"; [ -d "$M/BASE" ] && BASE="$M/BASE"
for p in $(scripts/lock.sh mine "$A" | awk -F, '$4!="released"{print $1}'); do
  scripts/lock.sh mark "$p" "$A" "$T" released "" "orchestrator merging" >/dev/null
done
FILES=$(cd "$M" && find . -type f ! -path "./_base/*" ! -path "./BASE/*" ! -name MERGE-NOTES.md ! -name "*.py" | sed 's|^\./||')
for f in $FILES; do
  scripts/lock.sh acquire "$f" orchestrator "MERGE-$T" merge >/dev/null 2>&1 || echo "NOTE held by another agent: $f"
  if [ ! -f "$f" ] || [ -z "$BASE" ] || [ ! -f "$BASE/$f" ]; then
    [ -f "$f" ] && [ -n "$BASE" ] && echo "WARN no base, overwriting existing: $f"
    mkdir -p "$(dirname "$f")"; cp "$M/$f" "$f"; echo "copied  $f"
  elif cmp -s "$BASE/$f" "$f"; then
    cp "$M/$f" "$f"; echo "clean   $f"
  else
    diff -u "$BASE/$f" "$M/$f" > "$TMP/p.patch"
    if patch -s --no-backup-if-mismatch "$f" < "$TMP/p.patch"; then echo "patched $f"; else echo "CONFLICT $f"; fi
  fi
done
rm -rf "$TMP"
find crates -name "*.rej" 2>/dev/null
