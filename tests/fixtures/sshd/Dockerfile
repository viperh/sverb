# OpenSSH server image for the sverb e2e suite (SPEC §19).
#
# One image, many scenarios: the sshd profile is chosen at container start with
# `SSHD_PROFILE=<name>` (see profiles/ and entrypoint.sh). Host keys are generated
# per container at first start, so every container has its own host key.
#
# Build: docker build -t sverb-e2e-sshd:local tests/fixtures/sshd
# The harness (crates/sverb-e2e) builds it on demand, tagged with a hash of this
# directory, unless SVERB_E2E_IMAGE names a prebuilt image (CI).
#
# Everything under keys/ is TEST-ONLY key material. Never trust it anywhere.
FROM debian:bookworm-slim

# Debian generates host keys during install; they are deleted (they would be shared
# by every container) and generated per container by the entrypoint.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      openssh-server openssh-client \
      bash zsh fish \
      htop vim tmux less \
      netcat-openbsd socat python3 procps \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/ssh/ssh_host_* \
 && mkdir -p /run/sshd /etc/ssh/sverb

# Users: `test`/`test` (bash), plus zsh and fish variants with the same password and keys.
RUN set -eu; \
    for spec in test:/bin/bash testzsh:/usr/bin/zsh testfish:/usr/bin/fish; do \
      user="${spec%%:*}"; shell="${spec#*:}"; \
      useradd --create-home --shell "$shell" "$user"; \
      echo "$user:test" | chpasswd; \
      install -d -m 0700 -o "$user" -g "$user" "/home/$user/.ssh"; \
    done

COPY keys/authorized_keys /etc/ssh/sverb/authorized_keys
COPY keys/user_ca.pub /etc/ssh/user_ca.pub
COPY keys/host_ca /etc/ssh/sverb/host_ca
COPY keys/host_ca.pub /etc/ssh/sverb/host_ca.pub
COPY sshd_config /etc/ssh/sshd_config
COPY profiles/ /etc/ssh/sverb/profiles/
COPY pam/sshd /etc/pam.d/sshd
COPY pam/sverb-otp-check /usr/local/bin/sverb-otp-check
COPY bin/ /usr/local/bin/
COPY entrypoint.sh /usr/local/bin/sverb-sshd-entrypoint

RUN set -eu; \
    chmod 0600 /etc/ssh/sverb/host_ca; \
    chmod 0644 /etc/ssh/user_ca.pub /etc/ssh/sverb/host_ca.pub /etc/ssh/sshd_config /etc/pam.d/sshd; \
    chmod 0755 /usr/local/bin/sverb-*; \
    for user in test testzsh testfish; do \
      install -m 0600 -o "$user" -g "$user" /etc/ssh/sverb/authorized_keys "/home/$user/.ssh/authorized_keys"; \
    done

# No EXPOSE: the harness publishes port 22 only for containers the test runner
# should reach (a JumpNet's inner host stays unpublished).
ENTRYPOINT ["/usr/local/bin/sverb-sshd-entrypoint"]
