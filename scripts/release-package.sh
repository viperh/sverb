#!/usr/bin/env bash
# Build one release archive (SPEC §20; used by .github/workflows/cd.yml).
#
#   scripts/release-package.sh <sverb|sverb-server> <version> <label> <binary> <out-dir> [assets-dir]
#
#   <label>       platform label: linux-x86_64, linux-aarch64, macos-universal, windows-x86_64
#   <binary>      the built executable (sverb, sverb.exe or sverb-server)
#   <assets-dir>  for sverb: a directory with man/sverb.1 and completions/* made by
#                 `sverb generate` (the release workflow builds it once on Linux)
#
# Produces <out-dir>/<name>-<version>-<label>.tar.gz (a .zip for windows-* labels) and a
# matching .sha256 file. The archive holds one top-level directory with the binary,
# LICENSE, README.md, CHANGELOG.md and, for sverb, the man page and completions.
#
# The archive is reproducible: entries are sorted, owned by 0:0, dated
# SOURCE_DATE_EPOCH (default: the last commit's time, else 0), and gzip stores no
# name or time. Run it twice on the same inputs and the bytes match (cd.yml checks).
set -euo pipefail

if [[ $# -lt 5 ]]; then
  sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
fi

name=$1 version=$2 label=$3 binary=$4 out=$5 assets=${6:-}
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "$name" in sverb|sverb-server) ;; *) echo "unknown package: $name" >&2; exit 2 ;; esac
[[ -f "$binary" ]] || { echo "no such binary: $binary" >&2; exit 2; }
if [[ "$name" == sverb && -z "$assets" ]]; then
  echo "sverb archives need the assets directory (man page, completions)" >&2
  exit 2
fi

if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
  SOURCE_DATE_EPOCH=$(git -C "$root" log -1 --format=%ct 2>/dev/null || echo 0)
fi
export SOURCE_DATE_EPOCH

stem="$name-$version-$label"
mkdir -p "$out"
out=$(cd "$out" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/sverb-release.XXXXXX")
trap 'rm -rf "$work"' EXIT
stage="$work/$stem"
mkdir -p "$stage"

install -m 0755 "$binary" "$stage/$(basename "$binary")"
for f in LICENSE README.md CHANGELOG.md; do
  [[ -f "$root/$f" ]] && install -m 0644 "$root/$f" "$stage/$f"
done
if [[ "$name" == sverb ]]; then
  mkdir -p "$stage/man" "$stage/completions"
  install -m 0644 "$assets/man/sverb.1" "$stage/man/sverb.1"
  for f in "$assets"/completions/*; do
    install -m 0644 "$f" "$stage/completions/$(basename "$f")"
  done
fi
# Same mtime everywhere (zip and tar both record it).
find "$stage" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} + 2>/dev/null \
  || find "$stage" -exec touch -t "$(date -u -r "$SOURCE_DATE_EPOCH" +%Y%m%d%H%M.%S)" {} +

sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi \
    | awk '{print $1}'
}

case "$label" in
  windows-*)
    file="$stem.zip"
    rm -f "$out/$file"
    (
      cd "$work"
      if command -v zip >/dev/null; then
        # -X: no extra attributes (uid/gid, extended timestamps).
        find "$stem" | LC_ALL=C sort | zip -X -q "$out/$file" -@
      else
        7z a -tzip -mtc=off "$out/$file" "$stem" >/dev/null
      fi
    )
    ;;
  *)
    file="$stem.tar.gz"
    tar=tar
    command -v gtar >/dev/null && tar=gtar
    (
      cd "$work"
      "$tar" --sort=name --owner=0 --group=0 --numeric-owner \
        --mtime="@$SOURCE_DATE_EPOCH" --format=gnu -cf - "$stem" \
        | gzip -n -9 >"$out/$file"
    )
    ;;
esac

printf '%s  %s\n' "$(sha256 "$out/$file")" "$file" >"$out/$file.sha256"
echo "$out/$file"
