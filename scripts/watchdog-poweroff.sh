#!/usr/bin/env bash
# User-requested: power the machine off when the sverb project folder has had no file
# changes for IDLE_SECS (default 30 minutes). Any file in the folder counts, including target/.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IDLE_SECS="${IDLE_SECS:-1800}"
LOG="$ROOT/.watchdog.log"
echo "$(date -u +%FT%TZ) watchdog started pid $$ idle=${IDLE_SECS}s" >> "$LOG"
while sleep 30; do
  newest=$(find "$ROOT" -path "$ROOT/.git" -prune -o -type f -newermt "-${IDLE_SECS} seconds" -print -quit 2>/dev/null)
  if [[ -z "$newest" ]]; then
    echo "$(date -u +%FT%TZ) no changes for ${IDLE_SECS}s -> poweroff" >> "$LOG"
    systemctl poweroff
    exit 0
  fi
done
