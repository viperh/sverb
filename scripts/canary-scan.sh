#!/usr/bin/env bash
# M7-05 (SPEC §17 "Secrets in logs", §19): canary scan.
#
# Test fixtures plant canary values (see CONTRIBUTING.md, "Canary secrets"):
#   CANARY-PW-…, CANARY-KEY-…, CANARY-PASS-…, CANARY-TOKEN-…, any other CANARY-…  secrets
#   CANARY-HOST-…                                                              hostnames
# (case-insensitive, so hostnames lowercased by IDNA still match).
#
# After a test run with SVERB_LOG=trace, this script walks the given directories and
# checks every artifact sverb writes:
#   log files (sverb.*.log), crash reports (crash/), SQLite files (*.db, -wal, -shm,
#   -journal), recordings (recordings/), backups (*.sverb-backup), and server DB dumps
#   (*.sql, *.dump).
# Rules:
#   - a secret canary must not appear in any of them (they are plaintext, or must be
#     encrypted: a canary in a DB, recording or backup means encryption was bypassed);
#   - a hostname canary must not appear in log lines at INFO, WARN or ERROR (debug and
#     trace may contain hostnames, SPEC §17), in crash reports (built from the info+
#     ring), or anywhere in DB files, recordings, backups or dumps.
#
# Usage: scripts/canary-scan.sh [--self-test] [DIR...]
#   default DIR: target/tmp (CARGO_TARGET_TMPDIR, where the binary's tests keep their
#   SVERB_HOMEs) plus $SVERB_CANARY_DIRS (colon-separated).
# Exit: 0 clean, 1 canary found, 2 usage error / nothing scanned with --require-files.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECRET_RE='canary-[a-z0-9_]'
HOST_RE='canary-host-'

classify() { # <path> -> log|crash|db|recording|backup|dump|""
  local p="$1" base
  base="$(basename "$p")"
  case "/$p" in
    */crash/*) echo crash; return ;;
    */recordings/*) echo recording; return ;;
  esac
  case "$base" in
    *.sverb-backup) echo backup ;;
    *.db|*.db-wal|*.db-shm|*.db-journal|*.sqlite|*.sqlite3|*.sqlite-wal|*.sqlite-shm) echo db ;;
    *.sql|*.dump|*.pgdump) echo dump ;;
    *.log|*.log.*|sverb.*.log|sverb.log*) echo log ;;
    *) echo "" ;;
  esac
}

# Prints "line: text" for every secret canary in a file (any canary that is not a host).
secret_hits() {
  grep -a -n -i -E "$SECRET_RE" "$1" 2>/dev/null \
    | while IFS= read -r hit; do
        # A line may hold a host canary and a secret: drop host canaries, re-check.
        stripped="$(printf '%s' "$hit" | sed -E "s/[Cc][Aa][Nn][Aa][Rr][Yy]-[Hh][Oo][Ss][Tt]-[A-Za-z0-9._-]*//g")"
        if printf '%s' "${stripped#*:}" | grep -a -q -i -E "$SECRET_RE"; then
          printf '%s\n' "$hit"
        fi
      done
}

# Prints "line: text" for host canaries on INFO/WARN/ERROR lines of a sverb log file.
# Format: "<timestamp> <LEVEL> <target>: …"; continuation lines inherit the level.
host_info_hits() {
  awk -v re="$HOST_RE" '
    {
      if (match($0, /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[^ ]+ +(TRACE|DEBUG|INFO|WARN|ERROR) /)) {
        split(substr($0, RSTART, RLENGTH), parts, / +/)
        level = parts[2]
      }
      if ((level == "INFO" || level == "WARN" || level == "ERROR") && index(tolower($0), re) > 0) {
        print NR ": " $0
      }
    }' "$1"
}

scan() { # <dirs...>
  local found=0 files=0 dir f class hits
  declare -A counts=()
  for dir in "$@"; do
    [[ -d "$dir" ]] || continue
    while IFS= read -r -d '' f; do
      class="$(classify "${f#"$dir"/}")"
      [[ -n "$class" ]] || continue
      files=$((files + 1))
      counts[$class]=$(( ${counts[$class]:-0} + 1 ))
      hits="$(secret_hits "$f")"
      if [[ -n "$hits" ]]; then
        found=1
        printf 'SECRET canary in %s (%s):\n%s\n' "$f" "$class" "$(head -n 5 <<<"$hits" | cut -c1-300)" >&2
      fi
      case "$class" in
        log) hits="$(host_info_hits "$f")" ;;
        *) hits="$(grep -a -n -i -F "$HOST_RE" "$f" 2>/dev/null || true)" ;;
      esac
      if [[ -n "$hits" ]]; then
        found=1
        printf 'HOSTNAME canary in %s (%s):\n%s\n' "$f" "$class" "$(head -n 5 <<<"$hits" | cut -c1-300)" >&2
      fi
    done < <(find "$dir" -type f -print0 2>/dev/null)
  done
  local summary="" k
  for k in log crash db recording backup dump; do
    summary+=" $k=${counts[$k]:-0}"
  done
  echo "canary scan: $files files scanned ($summary )"
  SCANNED_FILES=$files
  return $found
}

self_test() {
  local tmp rc
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/canary-self-test.XXXXXX")"
  mkdir -p "$tmp/clean/state" "$tmp/clean/data"
  {
    echo '2026-10-09T10:00:00.000001Z DEBUG sverb_conn::ssh: connect.rs:10: connecting to canary-host-1.example'
    echo '2026-10-09T10:00:00.000002Z  INFO sverb_conn::ssh: connect.rs:11: connected'
    echo '2026-10-09T10:00:00.000003Z TRACE sverb_tui: x.rs:1: password=[REDACTED]'
  } > "$tmp/clean/state/sverb.2026-10-09.log"
  printf 'SQLite format 3\0encrypted\0' > "$tmp/clean/data/sverb.db"
  if ! scan "$tmp/clean" >/dev/null 2>&1; then echo "self-test: clean tree flagged" >&2; rm -rf "$tmp"; return 1; fi

  local case_name
  for case_name in info-secret debug-secret info-host crash-host db-secret wal-host backup-secret; do
    rm -rf "$tmp/dirty"; mkdir -p "$tmp/dirty/state/crash" "$tmp/dirty/data/recordings"
    case "$case_name" in
      info-secret) echo '2026-10-09T10:00:00Z  INFO sverb: a.rs:1: password CANARY-PW-7f3a' > "$tmp/dirty/state/sverb.2026-10-09.log" ;;
      debug-secret) echo '2026-10-09T10:00:00Z DEBUG sverb: a.rs:1: key CANARY-KEY-1' > "$tmp/dirty/state/sverb.2026-10-09.log" ;;
      info-host) printf '%s\n%s\n' '2026-10-09T10:00:00Z  WARN sverb: a.rs:1: cannot reach' '  host = Canary-Host-2.example' > "$tmp/dirty/state/sverb.2026-10-09.log" ;;
      crash-host) echo 'panicked at x: canary-host-3.example' > "$tmp/dirty/state/crash/crash-1.txt" ;;
      db-secret) printf 'SQLite\0CANARY-TOKEN-x\0' > "$tmp/dirty/data/sverb.db" ;;
      wal-host) printf 'WAL\0canary-host-4\0' > "$tmp/dirty/data/sverb.db-wal" ;;
      backup-secret) echo '{"ciphertext_b64":"CANARY-PASS-9"}' > "$tmp/dirty/x.sverb-backup" ;;
    esac
    rc=0; scan "$tmp/dirty" >/dev/null 2>&1 || rc=$?
    if [[ $rc -ne 1 ]]; then echo "self-test: $case_name not detected" >&2; rm -rf "$tmp"; return 1; fi
  done
  rm -rf "$tmp"
  echo "canary scan self-test passed"
}

main() {
  if [[ "${1:-}" == "--self-test" ]]; then
    self_test
    return
  fi
  local require=0
  if [[ "${1:-}" == "--require-files" ]]; then require=1; shift; fi
  local dirs=("$@")
  if [[ ${#dirs[@]} -eq 0 ]]; then
    dirs=("$ROOT/target/tmp")
    if [[ -n "${SVERB_CANARY_DIRS:-}" ]]; then
      IFS=: read -r -a extra <<<"$SVERB_CANARY_DIRS"
      dirs+=("${extra[@]}")
    fi
  fi
  SCANNED_FILES=0
  local rc=0
  scan "${dirs[@]}" || rc=$?
  if [[ $rc -ne 0 ]]; then
    echo "canary scan FAILED: planted secrets or hostnames leaked (see above)" >&2
    return 1
  fi
  if [[ $require -eq 1 && $SCANNED_FILES -eq 0 ]]; then
    echo "canary scan: no artifacts found in ${dirs[*]}" >&2
    return 2
  fi
}

main "$@"
