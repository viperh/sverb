#!/bin/bash
# Validate the base sshd_config with every profile using the local `sshd -t`
# (no Docker, no root). Paths are rewritten into a temporary directory with freshly
# generated host keys. Used by `cargo test -p sverb-e2e --test fixtures` when an
# `sshd` binary is available; the image itself runs `sshd -t` at every start.
#
# Usage: check-configs.sh [sshd-binary]
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sshd="${1:-$(command -v sshd || echo /usr/sbin/sshd)}"
work="$(mktemp -d "${TMPDIR:-/tmp}/sverb-sshd-check.XXXXXX")"
trap 'rm -rf "$work"' EXIT

for t in ed25519 ecdsa rsa; do
    ssh-keygen -q -t "$t" -N '' -f "$work/ssh_host_${t}_key"
done
# A checkout doesn't keep the CA key's 0600 mode, and ssh-keygen refuses a readable key.
install -m 0600 "$here/keys/host_ca" "$work/host_ca"
ssh-keygen -q -s "$work/host_ca" -I check -h -n localhost -V always:forever \
    "$work/ssh_host_ed25519_key.pub"
cp "$here/keys/user_ca.pub" "$work/user_ca.pub"
chmod 600 "$work"/ssh_host_*_key

rewrite() {
    sed -e "s#/etc/ssh/sverb-profile.conf#$work/profile.conf#" \
        -e "s#/etc/ssh/ssh_host_#$work/ssh_host_#g" \
        -e "s#/etc/ssh/user_ca.pub#$work/user_ca.pub#" \
        -e "s#/run/sshd.pid#$work/sshd.pid#" \
        -e "s#/usr/local/bin/#$here/bin/#" "$1"
}

rewrite "$here/sshd_config" > "$work/sshd_config"
status=0
for profile in "$here"/profiles/*.conf; do
    name="$(basename "$profile" .conf)"
    rewrite "$profile" > "$work/profile.conf"
    if out="$("$sshd" -t -f "$work/sshd_config" 2>&1)"; then
        echo "ok      $name"
    else
        echo "FAILED  $name"
        echo "$out" | sed 's/^/        /'
        status=1
    fi
done
exit $status
