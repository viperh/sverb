# M4-05 — WebSocket notifications (`/v1/ws`) and multi-replica fan-out via Postgres LISTEN/NOTIFY

| | |
|---|---|
| **Milestone** | M4 |
| **Touches** | `crates/sverb-server/src/ws/{mod.rs, hub.rs, pg_notify.rs}`, `crates/sverb-proto/src/ws.rs`, `crates/sverb-sync/src/ws.rs` (client side) |
| **Spec refs** | §10.4 (WebSocket protocol), §10.7 (multiple instances), §12.5 (WS reconnect with backoff), §13.2 (`vault_access`), §11.2.1 (`account_changed`), §14 (share_join_request) |
| **Depends on** | M4-04 |
| **Blocks** | M4-07, M5-04, M6-01 |

---

## 1. Current state in the codebase
Push commits (M4-04) have a notify hook that does nothing. There's no WS endpoint.

## 2. Detailed description

### 2.1 Server
- `GET /v1/ws` upgrade (axum WS). **Authentication:** the first client message must be `{"type":"auth","token":"<access>"}` within **5 s**, otherwise
  the server closes with code **4401** (§10.4). The token is never put in the URL.
- After auth, subscribe the socket to: the user's vault ids (membership), the user id (account events) and owned share ids.
- **Server → client messages:** `vault_changed {vault_id, head_revision}`, `vault_access {vault_id, change: granted|revoked|rotated}`,
  `account_changed {key_version}`, `share_join_request {share_id, viewer}` (M6-01).
- **Heartbeat:** `ping`/`pong` every 30 s in both directions. **2 missed pongs → close** (§10.4).
- **Token expiry:** when the access token expires (15 min), close with **4401**. The client refreshes and reconnects (§10.4).
- Device revoked or user disabled → close 4401 immediately (via an internal event).
- **Hub:** an in-process `HashMap<Topic, broadcast::Sender<Msg>>`. Membership changes (grant or revoke) update subscriptions live.
- **Fan-out across replicas** (§10.7, "implemented from the start"): on commit, `NOTIFY sverb_events, '<json>'` (payload < 8 KB: ids only).
  Each replica `LISTEN`s on a dedicated connection and dispatches to its local hub. A single-replica deployment uses the same path (one code path).
  Reconnect the listener with backoff, and while disconnected, mark readiness degraded.
- Notifications are **hints only**. Correctness comes from pull (§10.4), so missed messages are harmless and nothing is persisted.
- Metrics: active WS connections, messages sent.

### 2.2 Client (`sverb-sync::ws`)
- Connects with `tokio-tungstenite` (rustls), sends auth, and handles messages by emitting `SyncEvent`s to the sync engine (M4-07).
- **Reconnect with exponential backoff** (1 s → 60 s, with jitter, unbounded attempts, §12.5). On 4401: refresh tokens (M4-07 token manager) then reconnect.
- Answers pings, sends its own pings every 30 s, and closes and reconnects after 2 missed pongs.

## 3. Codebase changes
- Server WS module and NOTIFY integration. Client WS module. DTOs in `sverb-proto::ws` (`#[serde(tag = "type", rename_all = "snake_case")]`).

## 4. Test cases to implement

**T-01** No auth message within 5 s → close 4401 (with time control).

**T-02** Invalid token → 4401. Valid token → subscribed.

**T-03** Push to a vault → the members' sockets receive `vault_changed` with the new head, and non-members don't.

**T-04** Two server instances (two routers sharing one Postgres in the test). A push on instance A → a socket on instance B receives `vault_changed` (LISTEN/NOTIFY).

**T-05** Token expiry → close 4401 at expiry.

**T-06** Missed pongs → closed after about 60 s (time control).

**T-07** Grant during a connection → the socket starts receiving that vault's events. Revoke → stops, and `vault_access revoked` is delivered.

**T-08** Device revoked → immediate 4401.

**T-09 (client)** Backoff sequence on a refused connection (1, 2, 4… capped at 60, with jitter bounds). On 4401 → a refresh is called once, then reconnect.

**T-10 (client)** A missed notification is harmless: the fallback poll (M4-07) still converges (tested in M4-07).

## 5. Passing functional characteristics
- [ ] `/v1/ws` authenticates via a first message within 5 s (else 4401). Tokens never go in URLs.
- [ ] `vault_changed`, `vault_access`, `account_changed` and `share_join_request` are delivered to the right subscribers.
- [ ] 30 s ping/pong with 2-miss closing. Token expiry or revocation closes with 4401.
- [ ] Multi-replica fan-out works through Postgres LISTEN/NOTIFY.
- [ ] The client reconnects with backoff and handles 4401 by refreshing.
