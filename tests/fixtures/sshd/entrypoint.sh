#!/bin/bash
# M1-18: start sshd with the profile named by $SSHD_PROFILE (default: password).
#
# - Host keys are generated on the first start only (a `docker restart` keeps them;
#   `sverb-regen-hostkeys` replaces them on purpose).
# - The `cert` profile gets a host certificate signed by the TEST-ONLY host CA, for
#   the principals localhost, 127.0.0.1, the container's hostname and
#   $SVERB_HOST_CERT_PRINCIPALS (comma-separated, set by the harness).
# - Small services for forwarding tests run in every profile: an HTTP echo on
#   0.0.0.0:8080 and a TCP echo on 0.0.0.0:7777 (reachable only from inside the
#   container network unless published).
# - `--check` (CI): set the profile up, run `sshd -t`, and exit instead of serving.
set -euo pipefail

profile="${SSHD_PROFILE:-password}"
src="/etc/ssh/sverb/profiles/${profile}.conf"
if [[ ! -f "$src" ]]; then
    echo "sverb-sshd: unknown profile '${profile}'" >&2
    ls /etc/ssh/sverb/profiles >&2
    exit 64
fi
cp "$src" /etc/ssh/sverb-profile.conf
echo "$profile" > /etc/ssh/sverb/active-profile
mkdir -p /run/sshd

ssh-keygen -A >&2
/usr/local/bin/sverb-regen-hostkeys --certs-only

if [[ "${1:-}" == "--check" ]]; then
    /usr/sbin/sshd -t
    echo "sverb-sshd: profile ${profile} ok" >&2
    exit 0
fi

/usr/local/bin/sverb-http-echo 8080 >/dev/null 2>&1 &
socat TCP-LISTEN:7777,fork,reuseaddr EXEC:cat >/dev/null 2>&1 &

echo "sverb-sshd: profile ${profile}" >&2
/usr/sbin/sshd -t
exec /usr/sbin/sshd -D -e
