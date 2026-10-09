#!/usr/bin/env bash
# M7-05: build the seed corpus of every fuzz target in fuzz/corpus/<target>/ from the
# repository's test fixtures plus a few hand-written inputs. Idempotent; existing
# corpus entries (found by earlier runs) are kept.
#
#   fuzz/seed-corpus.sh [corpus-dir]      # default: fuzz/corpus
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$ROOT/fuzz/corpus}"

seed_files() { # <target> <files...>
  local target="$1"; shift
  mkdir -p "$OUT/$target"
  local f
  for f in "$@"; do
    [[ -f "$f" ]] || continue
    cp -f "$f" "$OUT/$target/fixture-$(basename "$(dirname "$f")")-$(basename "$f")"
  done
}

seed_bytes() { # <target> <name> <printf-format>
  mkdir -p "$OUT/$1"
  # shellcheck disable=SC2059
  printf "$3" > "$OUT/$1/$2"
}

shopt -s nullglob

seed_files ssh_config_parse "$ROOT"/tests/fixtures/ssh_config/* "$ROOT"/tests/fixtures/ssh_config/*/*
seed_files known_hosts_parse "$ROOT"/tests/fixtures/known_hosts/*
seed_files ppk_parse "$ROOT"/tests/fixtures/putty/keys/*.ppk
seed_files envelope_open "$ROOT"/crates/sverb-crypto/tests/fixtures/envelopes/*/*
seed_files emulator_feed "$ROOT"/crates/sverb-term/tests/streams/*.bin
seed_files osc133_scan "$ROOT"/crates/sverb-term/tests/streams/bash_osc133.bin
seed_files key_event_encode "$ROOT"/crates/sverb-term/tests/streams/utf8_test.bin

# SOCKS: v5 greeting, v5 CONNECT by domain / IPv4 / IPv6, v4 and v4a.
seed_bytes socks5_request hello5 '\x05\x02\x00\x02'
seed_bytes socks5_request connect5-domain '\x05\x01\x00\x03\x0bexample.com\x00\x16'
seed_bytes socks5_request connect5-ipv4 '\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x16'
seed_bytes socks5_request connect5-ipv6 '\x05\x01\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x16'
seed_bytes socks5_request connect4 '\x04\x01\x00\x16\x7f\x00\x00\x01user\x00'
seed_bytes socks5_request connect4a '\x04\x01\x00\x16\x00\x00\x00\x01\x00example.com\x00'

# HTTP CONNECT answers (the first byte picks the read size and header limit).
seed_bytes http_connect_response ok '\x00HTTP/1.1 200 Connection established\r\n\r\nSSH-2.0-OpenSSH_9.9\r\n'
seed_bytes http_connect_response auth '\x05HTTP/1.0 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="x"\r\n\r\n'
seed_bytes http_connect_response error '\x1fHTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n'

# Emulator: queries, OSC 52 / 8 / 7 / titles, alternate screen.
seed_bytes emulator_feed queries '\x50\x18\x07\033[c\033[>c\033[6n\033]11;?\007\033]4;1;?\033\\'
seed_bytes emulator_feed osc '\x50\x18\x03\033]52;c;aGVsbG8=\007\033]52;c;?\007\033]8;;https://example.com\033\\link\033]8;;\033\\\033]7;file://h/tmp\007\033]2;title\007'
seed_bytes emulator_feed altscreen '\x50\x18\x10\033[?1049h\033[2J\033[10;5Hx\033[?1049l'
seed_bytes osc133_scan marks '\x1fecho hi\r\nhi\r\n'

# Key encoder: every mode bit, a few keys.
seed_bytes key_event_encode modes '\xff\x1f\x00a\x00\x05\x02\x0f\x0c\x10\x03\x07'
seed_bytes key_event_encode paste '\x08\x00\033[20\033[201~1~ rm -rf ~\033[200~'

# Backup: a header-shaped file (the KDF is never run).
seed_bytes backup_decrypt header '{"format":"sverb-backup","version":1,"created_at":0,"kdf":{"alg":"argon2id","m_kib":19456,"t":2,"p":1,"salt_b64":"AAAAAAAAAAAAAAAAAAAAAA=="},"nonce_b64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","ciphertext_b64":"AAAA"}'

# Share frames, envelopes, account bundles, grants: version bytes and empty input.
for t in share_frame_decode envelope_open bundle_open grant_open; do
  seed_bytes "$t" empty ''
  seed_bytes "$t" v1 '\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
done

for d in "$OUT"/*/; do
  echo "$(basename "$d"): $(find "$d" -type f | wc -l) seeds"
done
