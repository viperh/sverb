#!/usr/bin/env bash
# Deterministic test-pattern programs for the M1-09 replay fixtures. Run under a pty by
# record.sh (so the kernel's onlcr turns "\n" into "\r\n", as with any real program).
#   gen.sh color | utf8 | decstbm
set -euo pipefail

case "${1:-}" in
color)
  # 16 colors fg/bg, attributes, 256-color cube sample, truecolor gradient.
  printf '\033[2J\033[H\033[1mSGR test\033[0m\n'
  for c in 30 31 32 33 34 35 36 37; do printf '\033[%sm fg%s \033[0m' "$c" "$c"; done; printf '\n'
  for c in 90 91 92 93 94 95 96 97; do printf '\033[%sm fg%s \033[0m' "$c" "$c"; done; printf '\n'
  for c in 40 41 42 43 44 45 46 47; do printf '\033[%sm bg%s \033[0m' "$c" "$c"; done; printf '\n'
  for c in 100 101 102 103 104 105 106 107; do printf '\033[%sm b%s \033[0m' "$c" "$c"; done; printf '\n'
  printf '\033[1mbold\033[0m \033[2mdim\033[0m \033[3mitalic\033[0m \033[4munder\033[0m '
  printf '\033[4:3mcurly\033[0m \033[21mdouble\033[0m \033[5mblink\033[0m \033[7minverse\033[0m '
  printf '\033[8mhidden\033[0m \033[9mstrike\033[0m\n'
  for i in $(seq 16 51); do printf '\033[48;5;%sm  ' "$i"; done; printf '\033[0m\n'
  for i in $(seq 232 255); do printf '\033[48;5;%sm  ' "$i"; done; printf '\033[0m\n'
  for i in $(seq 0 8 255); do printf '\033[48;2;%s;0;%sm ' "$i" "$((255 - i))"; done; printf '\033[0m\n'
  printf '\033[38;2;255;128;0;48;5;17morange on navy\033[0m \033[58;5;196;4mred underline color\033[0m\n'
  printf '\033[44m\033[Kbce: erased with blue\033[0m\n'
  printf 'done\n'
  ;;
utf8)
  printf '\033[2J\033[HUTF-8 test\n'
  printf 'Latin: café naïve façade Ærøskøbing\n'
  printf 'Greek: Ελληνικά  Cyrillic: Привет мир\n'
  printf 'CJK: 中文字符 日本語テキスト 한국어\n'
  printf 'Emoji: 😀 🚀 👍🏽 🇷🇴 ❤️\n'
  printf 'Combining: e\xcc\x81 a\xcc\x8a o\xcc\x88\xcc\x81 n\xcc\x83\n'
  printf 'Box: ┌──┬──┐\n     │ab│cd│\n     └──┴──┘\n'
  printf 'DEC graphics: \033(0lqqk x x mqqj\033(B back to ASCII\n'
  printf 'Wide at edge:\033[11;79H中x\n'
  printf 'RTL: שלום עולם\n'
  ;;
decstbm)
  printf '\033[2J\033[H'
  printf 'header line (outside region)\n'
  printf '\033[24;1Hfooter line (outside region)'
  printf '\033[3;20r'   # scroll region rows 3..20
  printf '\033[3;1H'
  for i in $(seq 1 40); do printf 'scrolled line %02d\n' "$i"; done
  printf '\033[3;1H\033[2L'            # insert 2 lines at top of region
  printf 'inserted A\ninserted B'
  printf '\033[10;1H\033[3M'           # delete 3 lines in region
  printf '\033[20;1H\033M\033M'        # reverse index at a non-top row
  printf '\033[3;1H\033M'              # reverse index at top of region: scrolls down
  printf 'after RI'
  printf '\033[r\033[22;1Hregion reset'
  ;;
*)
  echo "usage: $0 color|utf8|decstbm" >&2
  exit 2
  ;;
esac
