# OpenSSH e2e fixtures (M1-18)

> **WARNING: everything under `keys/` is TEST-ONLY key material.**
> The private keys and both CAs are committed to a public repository and protect
> nothing. Never add them to an agent, an `authorized_keys`, a `known_hosts` or a CA
> trust store outside these test containers. Secret scanners skip this directory
> (`.github/secret_scanning.yml`, `.gitleaks.toml`).

One Docker image (`Dockerfile`, Debian bookworm-slim) with OpenSSH, bash, zsh, fish,
htop, vim, tmux, less, netcat, socat and python3. The sshd configuration is picked at
container start with `SSHD_PROFILE=<profile>`; the harness in `crates/sverb-e2e`
(`Sshd::start(Profile::…)`) does that for you.

## Users

| User | Shell | Password | Keys |
|---|---|---|---|
| `test` | bash | `test` | `keys/authorized_keys` |
| `testzsh` | zsh | `test` | same |
| `testfish` | fish | `test` | same |

## Profiles (`profiles/<name>.conf`)

`sshd_config` includes the profile first; for most keywords sshd keeps the first value,
so a profile overrides the base. Profiles must not use `Match`.

| Profile | Essentials | Used by |
|---|---|---|
| `password` | `PasswordAuthentication yes` | M1-13/14 |
| `key` | public keys only | M1-14 |
| `cert` | `TrustedUserCAKeys` (user CA), host certificate from the host CA | M1-14/15 |
| `kbd` | keyboard-interactive via PAM; `pam_exec` OTP check, code `424242` (prompt `Password: `) | M1-14 |
| `maxauth2` | `MaxAuthTries 2`, keys only | M1-14 |
| `legacy` | `diffie-hellman-group14-sha1`, `ssh-rsa`, `aes128-cbc`, `hmac-sha1` only | M1-13 |
| `env` | `AcceptEnv FOO` | M1-13 |
| `forward` | TCP/agent/streamlocal forwarding, `GatewayPorts clientspecified` | M2-07/08 |
| `jump` | `AllowTcpForwarding yes`; bastion + inner of a `JumpNet` | M2-05 |
| `windows-like` | `ForceCommand` that makes `uname` fail | M2-04 |

Every container also runs an HTTP echo on port 8080 (`bin/sverb-http-echo`) and a TCP
echo on 7777 (socat), for forwarding tests. They are not published.

Host keys are generated per container on first start (a restart keeps them);
`sverb-regen-hostkeys` replaces them and makes sshd re-execute (`Sshd::regenerate_host_key`).
sshd logs at `DEBUG1` to stderr (`docker logs`), which the harness dumps on failure.

## Keys (`keys/`)

| File | What |
|---|---|
| `id_ed25519`, `id_ecdsa` (P-256), `id_rsa` (4096) | user keys, authorized |
| `id_ed25519_encrypted` | user key, passphrase `fixture`, authorized |
| `id_cert`, `id_cert-cert.pub` | user key **not** authorized; certificate from `user_ca`, principal `test`, valid forever |
| `user_ca` | user CA (`TrustedUserCAKeys` in the `cert` profile) |
| `host_ca` | host CA; signs the `cert` profile's host key at start; `known_hosts_ca` is its `@cert-authority *` line |
| `authorized_keys` | the four authorized public keys |

Regenerate (then update anything that pinned a fingerprint):

```sh
cd tests/fixtures/sshd/keys
C=sverb-e2e-fixture-TEST-ONLY
ssh-keygen -t ed25519 -N '' -C "$C" -f id_ed25519
ssh-keygen -t ecdsa -b 256 -N '' -C "$C" -f id_ecdsa
ssh-keygen -t rsa -b 4096 -N '' -C "$C" -f id_rsa
ssh-keygen -t ed25519 -N fixture -C "$C-encrypted" -f id_ed25519_encrypted
ssh-keygen -t ed25519 -N '' -C "$C-cert" -f id_cert
ssh-keygen -t ed25519 -N '' -C sverb-e2e-user-ca-TEST-ONLY -f user_ca
ssh-keygen -t ed25519 -N '' -C sverb-e2e-host-ca-TEST-ONLY -f host_ca
ssh-keygen -s user_ca -I sverb-e2e-test-user -n test -V always:forever id_cert.pub
cat id_ed25519.pub id_ecdsa.pub id_rsa.pub id_ed25519_encrypted.pub > authorized_keys
echo "@cert-authority * $(cat host_ca.pub)" > known_hosts_ca
```

## Checking without Docker

`./check-configs.sh` runs the local `sshd -t` over the base config with every profile
(paths rewritten into a temp dir). `cargo test -p sverb-e2e --test fixtures` runs it
when `sshd` is installed, and checks profiles, keys and the Dockerfile.

## Running the e2e suite

```sh
SVERB_E2E=1 cargo test -p sverb-e2e -- --ignored
```

The harness builds the image on first use (tag = hash of this directory) unless
`SVERB_E2E_IMAGE=name:tag` names a prebuilt one (CI). Without `SVERB_E2E=1`, or
without a reachable Docker daemon, the container tests print `skipped: …` and pass.
