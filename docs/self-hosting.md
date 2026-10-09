# Self-hosting sverb-server

`sverb-server` is the optional sync backend for sverb (SPEC §10). It stores only
end-to-end-encrypted data: it never sees hosts, passwords or keys in plaintext.
It needs **PostgreSQL 15+** and ships as one static binary or a distroless Docker
image.

> **Back up the database and `SVERB_SERVER_SECRET` together.**
> The secret encrypts the OPAQUE server setup kept in the database (and TOTP
> secrets). Losing either one, or restoring a database with a different secret,
> invalidates every login: the server refuses to start with
> `cannot decrypt server_secrets row … Refusing to start.` User data stays safe
> (it is end-to-end encrypted and recoverable from any logged-in device), but
> every user would have to re-register and re-upload.

## 1. Quick start (Docker Compose)

```sh
git clone https://github.com/viperh/sverb && cd sverb
export SVERB_SERVER_SECRET="$(openssl rand -base64 48)"   # store this in your password manager
export SVERB_PUBLIC_URL=https://sync.example.com          # the URL clients will use
docker compose -f deploy/docker-compose.yml up -d --build
curl -fsS http://localhost:8080/healthz
```

The compose file starts `postgres:16` (data in the `pgdata` volume) and
`sverb-server serve --migrate` on port 8080, which waits for Postgres to be
healthy. The image runs as the unprivileged `nonroot` user and has a built-in
`HEALTHCHECK` (`sverb-server healthcheck`).

### First account (bootstrap)

On first start, while no account exists, the server logs a one-time **setup
token** at `warn` level:

```sh
docker compose -f deploy/docker-compose.yml logs sverb-server | grep setup_token
```

Register the first account from sverb and enter that token when asked. That
account becomes the **instance admin**, and the token stops working. Until
someone registers, every restart prints a fresh token (the previous one is
replaced).

Registration starts as `invite-only`. Afterwards, new users need an invite
(`sverb-server admin invite <email>` or an org invite), unless you switch to
`open`.

### Using the published image

Releases publish `ghcr.io/viperh/sverb-server:<version>` and `:latest`. Both are
multi-arch (linux/amd64 and linux/arm64), distroless, run as non-root, and are built from
the same static binaries as the release archives (`deploy/Dockerfile.server.release`). To
use the image instead of building locally, replace the `build:` block of the
`sverb-server` service in `deploy/docker-compose.yml` with

```yaml
    image: ghcr.io/viperh/sverb-server:1.0.0   # pin a version; :latest follows releases
```

and start the stack with `docker compose -f deploy/docker-compose.yml up -d` (no
`--build`). Release archives `sverb-server-<version>-linux-{x86_64,aarch64}.tar.gz` hold the
same static binary for running without Docker. Check them against `SHA256SUMS`.

## 2. Running the binary directly

```sh
export DATABASE_URL=postgres://sverb:…@db.internal:5432/sverb
export SVERB_SERVER_SECRET=…   SVERB_PUBLIC_URL=https://sync.example.com
sverb-server migrate        # apply schema migrations
sverb-server serve          # refuses to start while migrations are pending
```

`serve --migrate` applies pending migrations at startup instead of refusing.
The binary is static (musl, rustls), so it runs on any x86_64 or aarch64 Linux.

## 3. Configuration

Settings come from environment variables or a TOML file (`--config FILE`, else
`$SVERB_SERVER_CONFIG`, else `./sverb-server.toml`). **Environment variables win.**
Empty variables count as unset.

| Environment | TOML key | Default | Meaning |
|---|---|---|---|
| `DATABASE_URL` | `database_url` | — | Postgres URL (needed by `serve`, `migrate`, `admin`) |
| `SVERB_BIND` | `bind` | `0.0.0.0:8080` | Listen address |
| `SVERB_PUBLIC_URL` | `public_url` | **required** | Public base URL for invite and share links |
| `SVERB_SERVER_SECRET` | `server_secret` | **required** | ≥ 32 random bytes, hex or base64 |
| `SVERB_TLS_CERT`, `SVERB_TLS_KEY` | `tls_cert`, `tls_key` | off | PEM files for built-in TLS (both or neither) |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_STARTTLS` | `[smtp]` `host`, `port`, `user`, `password`, `from`, `starttls` | off; `587`, `true` | Invite mail. Without SMTP, invites are copy-paste links. `starttls = false` means implicit TLS (port 465). |
| `SVERB_STORAGE_QUOTA_MIB` | `storage_quota_mib` | `100` | Per-user storage quota (envelope bytes in the user's personal vault; shared vaults are capped at 1 GiB each instead) |
| `SVERB_SHARE_MAX_VIEWERS` | `share_max_viewers` | `10` | Viewers per terminal share |
| `SVERB_SHARE_TTL_HOURS` | `share_ttl_hours` | `24` | Default share lifetime |
| `SVERB_TOMBSTONE_HORIZON_DAYS` | `tombstone_horizon_days` | `90` | Deleted items are purged by GC after this |
| `SVERB_GC_INTERVAL_HOURS` | `gc_interval_hours` | `24` | Hours between in-process `admin gc` runs; `0` disables them |
| `SVERB_METRICS_TOKEN` | `metrics_token` | off | Bearer token for `/metrics` on the main port (≥ 16 chars) |
| `SVERB_METRICS_BIND` | `metrics_bind` | off | Separate address that serves only `/metrics` |
| `SVERB_LOG_FORMAT` | `log_format` | `json` | `json` or `pretty` |
| `SVERB_TRUSTED_PROXIES` | `trusted_proxies` | none | Comma list of proxy IPs/CIDRs whose `X-Forwarded-For` is trusted |
| `SVERB_CORS_ORIGINS` | `cors_allowed_origins` | none | Origins allowed by CORS (deny by default) |
| `SVERB_REQUEST_TIMEOUT_S` | `request_timeout_s` | `30` | Per-request timeout |
| `SVERB_LOG` / `RUST_LOG` | — | `info` | Log filter (`tracing` syntax) |

Example `sverb-server.toml`:

```toml
public_url = "https://sync.example.com"
database_url = "postgres://sverb:secret@localhost/sverb"
server_secret = "…"        # or keep it only in the environment
trusted_proxies = ["127.0.0.1"]

[smtp]
host = "smtp.example.com"
user = "sverb"
password = "…"
from = "sverb <sverb@example.com>"
```

Request bodies are limited to 12 MiB (a sync push carries up to 500 items and
8 MiB of encrypted items, 1 MiB per item, base64-encoded). Login attempts are limited to 5 per minute
per email and 50 per minute per client IP.

## 4. TLS

**Built in:** set `SVERB_TLS_CERT` and `SVERB_TLS_KEY` (PEM). rustls serves HTTPS
on `SVERB_BIND`. Restart the server after renewing certificates.

**Reverse proxy (recommended for ACME):** terminate TLS in the proxy, keep
`sverb-server` on plain HTTP on a private address, and set
`SVERB_TRUSTED_PROXIES` to the proxy's address so rate limits see real client
IPs. The proxy must pass WebSocket upgrades (`/v1/ws`, `/v1/shares/*`).

Caddy:

```caddyfile
sync.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

(Caddy proxies WebSockets and sets `X-Forwarded-For` by default.)

nginx:

```nginx
map $http_upgrade $connection_upgrade { default upgrade; '' close; }

server {
    listen 443 ssl http2;
    server_name sync.example.com;
    ssl_certificate     /etc/letsencrypt/live/sync.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sync.example.com/privkey.pem;

    client_max_body_size 9m;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 120s;   # > the 30 s WebSocket ping interval
    }
}
```

### Several replicas

The server is stateless except for WebSockets and terminal-share relays.
Change notifications fan out between replicas through Postgres
`LISTEN/NOTIFY`, so `/v1/ws` can go to any replica. **Terminal shares
(`/v1/shares/*`) need sticky routing**: the host and its viewers must reach the
same replica. Route by share id, for example with nginx:

```nginx
upstream sverb       { server 10.0.0.11:8080; server 10.0.0.12:8080; }
upstream sverb_share { hash $share_id consistent; server 10.0.0.11:8080; server 10.0.0.12:8080; }

map $uri $share_id { ~^/v1/shares/(?<id>[^/]+) $id; default ""; }

server {
    # … TLS as above …
    location /v1/shares/ { proxy_pass http://sverb_share; include proxy_ws.conf; }
    location /           { proxy_pass http://sverb;       include proxy_ws.conf; }
}
```

(`proxy_ws.conf` holds the `proxy_http_version`/`Upgrade`/`Connection`/
`X-Forwarded-For` lines from the single-server example.) All replicas must
share the same database **and** the same `SVERB_SERVER_SECRET`.

## 5. Operations

| Endpoint | Purpose |
|---|---|
| `GET /healthz` | Process alive (always 200) |
| `GET /readyz` | 200 when the database is reachable and migrations are current, 503 otherwise (JSON says why) |
| `GET /metrics` | Prometheus metrics; needs `Authorization: Bearer $SVERB_METRICS_TOKEN`, or is served only on `SVERB_METRICS_BIND`. Disabled when neither is set. |

Metrics include `http_requests_total{method,route,status}`,
`http_request_duration_seconds`, `sverb_ws_connections_active`,
`sverb_sync_push_*`/`sverb_sync_pull_*` (items and bytes) and
`sverb_share_relays_active`/`sverb_share_viewers_active`.

Logs are JSON lines on stdout with a `request_id` per request. Clients can send
`x-request-id`; it is echoed in every response, which helps match a client error
to a server log line. Every error response has the form
`{"error": {"code": "…", "message": "…"}}`.

## 6. Admin CLI

Run these where the server's environment is available, e.g.
`docker compose -f deploy/docker-compose.yml exec sverb-server sverb-server admin user list`.

```text
sverb-server serve [--migrate]                 run the server
sverb-server migrate                           apply database migrations
sverb-server admin user list                   email, created, disabled, admin, device count
sverb-server admin user create <email>         create a registration invite and print the link
sverb-server admin user disable <email>        disable the account and revoke all its tokens
sverb-server admin user recovery-code <email>  one-time account-recovery code (24 h; mailed with SMTP)
sverb-server admin invite <email> [--no-email] invite link (also mailed when SMTP is set)
sverb-server admin registration open|invite-only|closed
sverb-server admin gc                          purge expired tokens, invites, finished shares and old tombstones
sverb-server healthcheck [--addr HOST:PORT]    probe /healthz (used by the Docker HEALTHCHECK)
```

Passwords are never set on the server: sverb uses OPAQUE, so the account
password is chosen on the client. `user create` and `invite` hand out a
single-use, email-bound link (`<public_url>/invite/<token>`, valid for 7 days).
`closed` blocks all registrations, including invites.

Forgotten passwords: a user with their 24-word recovery phrase needs a
one-time recovery code. With SMTP configured, sverb requests it by mail;
otherwise verify the person out of band and run `admin user recovery-code
<email>`. The code alone is useless without the recovery phrase, and five
wrong attempts discard it. A recovery logs out every device of the account.

The server runs the same GC every `SVERB_GC_INTERVAL_HOURS` (default daily);
with that set to `0`, run `admin gc` from cron or a scheduled container to keep
tables small. Purging tombstones (deleted items older than
`SVERB_TOMBSTONE_HORIZON_DAYS`) makes devices that have been offline longer
than that do a full resync on their next sync.

## 7. Backups and upgrades

- **Backup:** `pg_dump` (or volume snapshots) **plus** a copy of
  `SVERB_SERVER_SECRET`, stored together. Test restores with the same secret.
- **Upgrade:** back up, pull/build the new image, then either let
  `serve --migrate` apply migrations or run `sverb-server migrate` first.
  Without `--migrate`, a newer binary refuses to start on an older schema, and
  `/readyz` reports pending migrations.
- **Downgrade:** not supported once a newer migration has been applied (the
  older binary refuses to start on the unknown migration). Restore the backup
  instead.
- The client sends `Sverb-Proto`; the server accepts the current protocol version
  and the previous one, so upgrade the server first and clients afterwards.
