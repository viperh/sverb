# M4-01 — `sverb-server` skeleton: config, DB/migrations, error format, request IDs, rate limiting, health/metrics, admin CLI, bootstrap, deployment

| | |
|---|---|
| **Milestone** | M4 — Sync (personal) |
| **Touches** | `crates/sverb-server/src/{main.rs, lib.rs, config.rs, db.rs, error.rs, middleware/{request_id.rs, rate_limit.rs, proto_version.rs}, routes/ops.rs, admin/*.rs, secrets.rs}`, `migrations/server/0001_init.sql`, `deploy/{Dockerfile.server, docker-compose.yml}`, `docs/self-hosting.md` |
| **Spec refs** | §10.1, §10.2, §10.3, §10.4 (error format, request IDs, ops endpoints), §10.5, §10.6, §10.7, §18 (JSON logs, Prometheus), §20 (`Sverb-Proto` header, N/N-1) |
| **Depends on** | M0-01, M0-02 (server-db CI job), M1-01 (AEAD for server_secrets) |
| **Blocks** | M4-02 … M6-01 |

---

## 1. Current state in the codebase
`crates/sverb-server` has an empty lib and main (M0-01). Its layering forbids client crates (it depends on `sverb-proto` and `sverb-crypto` only).
`migrations/server/` is empty, and `deploy/` has placeholders.

## 2. Detailed description

### 2.1 Configuration (§10.1, §10.7)
Env vars or `sverb-server.toml` (env wins): `DATABASE_URL`, `SVERB_BIND` (default `0.0.0.0:8080`), `SVERB_PUBLIC_URL` (required; used for
invite and share links), `SVERB_SERVER_SECRET` (required, ≥ 32 bytes, base64 or hex; refuse to start otherwise), optional
`SVERB_TLS_CERT`/`SVERB_TLS_KEY` (rustls built in, §10.1), `SMTP_*` (host, port, user, password, from, starttls), limits (§10.5:
`SVERB_STORAGE_QUOTA_MIB` = 100, `SVERB_SHARE_MAX_VIEWERS` = 10, `SVERB_SHARE_TTL_HOURS` = 24), `SVERB_METRICS_TOKEN` or
`SVERB_METRICS_BIND`, `SVERB_TOMBSTONE_HORIZON_DAYS` = 90, `SVERB_LOG_FORMAT` = json.

### 2.2 Database
- `sqlx` with Postgres 15+. **Migrations** in `migrations/server/0001_init.sql` contain the full §10.3 schema verbatim, plus the CITEXT extension
  (`CREATE EXTENSION IF NOT EXISTS citext`), plus a `settings(key, value)` table for `registration_mode` and the setup token hash (an addition, needed by
  §10.6 bootstrap). `sverb-server migrate` applies them, and `serve` refuses to start on pending migrations unless `--migrate` is given.
- **`server_secrets`:** values are AEAD (XChaCha20-Poly1305 from `sverb-crypto`) under `HKDF(SVERB_SERVER_SECRET, info="sverb/server-secret/v1")`, AAD =
  the row name. The OPAQUE `ServerSetup` is generated on first start (M4-02) and stored here. A wrong secret at startup (decrypt failure) → refuse to
  start with a clear message (§10.7: back up the DB and secret together).

### 2.3 HTTP framework (§10.1, §10.4)
- `axum` router under `/v1`, plus `tower-http` layers: tracing (JSON), compression, CORS (deny by default; allow-list config for the future web viewer),
  request body limit (9 MiB, covering the push batch's 8 MiB + JSON overhead), timeout.
- **Request IDs:** accept an incoming `x-request-id` (≤ 128 chars, `[A-Za-z0-9-]`) or generate a UUIDv7. Echo it in the response and attach it to log spans.
- **Error format** (all endpoints): `{ "error": { "code": "conflict|forbidden|not_found|rate_limited|invalid|gone|rotating|auth_required",
  "message": "…", "retry_after_s"?: n } }`, with `429` carrying a `Retry-After` header. One `ApiError` enum maps to status codes
  (409, 403, 404, 429, 400, 410, 409 for rotating, 401).
- **Protocol version** (§20): the client sends `Sverb-Proto: 1`. The server supports N and N-1. Missing header → assume the current version. Unsupported →
  `400 invalid` "client protocol too old/new". The response carries `Sverb-Proto`.
- **Rate limiting** (`governor`, §10.5): login 5/min per email and 50/min per IP (keyed state with periodic cleanup). Behind a reverse proxy, trust
  `X-Forwarded-For` only if `SVERB_TRUSTED_PROXIES` is configured (CIDR list).

### 2.4 Ops endpoints (§10.4)
`GET /healthz` (process alive), `GET /readyz` (DB reachable, migrations current), and `GET /metrics` (Prometheus via `metrics-exporter-prometheus`), guarded by
a bearer admin token **or** served only on a separate bind address. Metrics (§18): HTTP requests by route and status, latency histograms, active WS
connections, sync push and pull item counts and bytes, active share relays and viewers.

### 2.5 Admin CLI (§10.6)
`sverb-server serve | migrate | admin user create|disable|list | admin registration open|invite-only|closed | admin gc |
admin invite <email>` (the last one is used by §10.6 bootstrap text but missing from the list, so add it):
- `admin user create <email>`: creates an invite-style registration token for that email (OPAQUE registration must happen client-side, so the server
  can't set a password) and prints the link. `disable <email>` sets `disabled = true` and revokes tokens. `list` shows email, created, disabled,
  admin, device count.
- `admin gc` runs the GC (M4-04 tombstones, expired tokens, closed or expired shares, abandoned rotations > 15 min, M5-04).

### 2.6 Bootstrap (§10.6)
On first start (no users), generate a one-time **setup token**, store only its hash in `settings`, and print it to the log at `warn` level with
instructions. Registration starts as `invite-only`. The first account that registers presenting the setup token becomes the **instance admin**
(`is_instance_admin = true`), and the token is invalidated. Afterwards, new accounts need an invite (org admin, M5-01, or `admin invite`) unless
the mode is `open`. `closed` → no registrations at all.

### 2.7 Deployment (§10.7)
- `deploy/Dockerfile.server`: multi-stage, a static musl build (`x86_64-unknown-linux-musl`, rustls only), and a **distroless** final image
  (`gcr.io/distroless/static`), running as non-root, with a `HEALTHCHECK` via `/healthz` (distroless has no curl, so add a `sverb-server healthcheck` subcommand).
- `deploy/docker-compose.yml`: `postgres:16` with a volume, and `sverb-server` with env, `depends_on` with a healthcheck, a volume note about backing up the DB and
  secret together.
- `docs/self-hosting.md`: install, TLS options (built in vs reverse proxy, with Caddy/nginx examples including WebSocket upgrade and sticky routing for
  `/v1/shares/*` with multiple replicas), the backup warning (§10.7), upgrades, admin CLI.
- **Multiple instances** (§10.7): stateless except WS and share relays. `LISTEN/NOTIFY` fan-out is done in M4-05.

## 3. Codebase changes
- Fill `sverb-server`. Deps: `axum`, `tower`, `tower-http`, `sqlx` (postgres, runtime-tokio, tls-rustls, macros, migrate), `governor`,
  `metrics`, `metrics-exporter-prometheus`, `rustls`, `axum-server` (TLS), `tracing-subscriber` (json), `lettre` (SMTP, rustls).
- Shared DTOs (error envelope, version header constant) in `sverb-proto`.

## 4. Test cases to implement
Use `sqlx::test` (a per-test DB) and `tower::ServiceExt::oneshot` against the router (§19).

**T-01** Missing or short `SVERB_SERVER_SECRET` → startup error.

**T-02** Migrations apply cleanly. `readyz` is 200 after and 503 with pending migrations.

**T-03** The error envelope shape for every code (table-driven through test routes). 429 includes the `Retry-After` header and `retry_after_s`.

**T-04** Request ID: echoed when provided and valid, generated when absent, replaced when invalid.

**T-05** `Sverb-Proto: 0` (N-1) is accepted, `5` is rejected with 400 invalid.

**T-06** Rate limit: the 6th login/start for the same email within a minute → 429. 51 from one IP → 429.

**T-07** `X-Forwarded-For` is ignored unless the proxy is trusted.

**T-08** `/metrics` without a token → 401. With the token → Prometheus text including `http_requests_total`.

**T-09** server_secrets: written, then decryption with another secret fails at startup with the documented message.

**T-10** Bootstrap: first start logs a setup token. Registering with it → instance admin. The token is reusable? → no (second use → forbidden).

**T-11** Registration mode `closed` → register/start forbidden. `invite-only` without an invite → forbidden. `open` → allowed.

**T-12** Admin CLI `user list` / `disable` behave (integration against the test DB).

**T-13 (docker)** `docker compose up` in CI → `/healthz` 200 within 60 s. The image runs as non-root (inspect).

**T-14** The body limit rejects a 10 MiB request with 413 → mapped to `invalid` with a "too large" message.

## 5. Passing functional characteristics
- [ ] The server starts from env or a TOML config, refuses insecure or missing secrets, and applies the §10.3 schema via migrations.
- [ ] Uniform JSON errors, request IDs, protocol-version negotiation (N and N-1) and rate limits per §10.5.
- [ ] `/healthz`, `/readyz` and a protected `/metrics` work. Logs are structured JSON.
- [ ] The admin CLI covers serve, migrate, user, registration, gc and invite. The setup-token bootstrap makes the first user the instance admin.
- [ ] A static musl binary, a distroless image and a docker-compose deployment work, with the self-hosting docs written.
