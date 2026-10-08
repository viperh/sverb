# M6-01 — Terminal-share relay on the server

| | |
|---|---|
| **Milestone** | M6 — Terminal sharing |
| **Touches** | `crates/sverb-server/src/share/{mod.rs, routes.rs, relay.rs, sessions.rs}`, `crates/sverb-proto/src/share.rs` (RelayEnvelope, control messages) |
| **Spec refs** | §14.1 (steps 2, 4, 5, 6), §14.2 (relay framing), §14.3 (end conditions), §10.3 (share_sessions), §10.4 (Sharing endpoints), §10.5 (max viewers 10, TTL 24 h), §10.7 (sticky routing) |
| **Depends on** | M4-05 |
| **Blocks** | M6-03 |

---

## 1. Current state in the codebase
The WS infrastructure exists (M4-05). The `share_sessions` table exists (M4-01) but is unused.

## 2. Detailed description
- `POST /v1/shares {mode: view|control, expires_in_s (≤ configured max, default 24 h), max_viewers (≤ 10), require_account: bool}`
  → `{share_id, expires_at}`. The server **never receives the share key** (it's in the URL fragment, §14.1). An audit event `share started` is written if the owner belongs to orgs?
  **Decision:** audit only for org members, in each of their orgs. Raise this, since the spec's audit is per org.
- `DELETE /v1/shares/{id}` (owner) → `closed_at`, notify and disconnect everyone.
- `GET /v1/shares/{id}/host` (WS, owner-authenticated via the first auth message as in M4-05): exactly one host connection. Reconnects replace the previous one.
- `GET /v1/shares/{id}/join` (WS): auth is **optional** depending on `require_account` (§10.4). If required, the first message must be auth. If not, the first message is
  `{"type":"join","name": "…"}`. The server assigns a `viewer_id: u32`, rejects when at `max_viewers` (close code 4429), and sends the host a control message
  `{type:"viewer_joined", viewer_id, name, account: Option<email>, ip_hint}`. The IP hint is coarse: a /24 or /48 prefix or the country if GeoIP is configured. It shows "an IP
  hint from the server" (§14.1). Also notify the owner on the general WS as `share_join_request` (§10.4) so they see it even when the host stream isn't focused.
- **Relay framing** (§14.2): each binary WS message carries `RelayEnvelope { viewer_id: u32 (BE), payload }`. Host → server: the server routes the payload to
  `viewer_id` (or broadcast if `viewer_id == 0xFFFFFFFF`? The spec has per-viewer channel keys, so frames are per viewer, and there's no broadcast; reserve 0 for control). Viewer → server:
  the server stamps the viewer's own `viewer_id` (ignoring what the viewer claims, which prevents spoofing) and forwards to the host. The server **only sees the routing header**; payloads are
  opaque (§14.2).
- **Host control messages** (JSON text frames): `kick {viewer_id}` → close that viewer, and `approve`/`deny` are end-to-end between host and viewer inside the encrypted channel, so
  the server doesn't need them. Kick is needed server-side.
- **Ending** (§14.3): the host deletes the share, the host's WS stays closed > 60 s (session ended), or the expiry passes → close all viewers with code 4410 and a reason, and set
  `closed_at`. `admin gc` purges closed and expired rows.
- **Limits:** message size ≤ 1 MiB, per-viewer send queue bounded (256 messages). A slow viewer exceeding it is disconnected (4408) rather than slowing the host.
- **Sticky routing** for multiple replicas (§10.7): document it. Optionally return `409` with a `replica` hint if the host is connected to another replica (an advanced
  feature; out of scope for v1).

## 3. Codebase changes
- The share module, routes and DTOs. Metrics: active relays and viewers, bytes relayed.

## 4. Test cases to implement

**T-01** Create a share → id and expiry. Over-limit params are clamped or rejected per config.

**T-02** Host WS auth required (owner only). Another user → 4401/403.

**T-03** A viewer joins without an account when `require_account=false`, and is rejected when true and unauthenticated.

**T-04** Routing: a host message to viewer 1 isn't delivered to viewer 2. A viewer message arrives at the host stamped with the correct viewer_id, even if the viewer forged another id.

**T-05** max_viewers: the 11th → 4429.

**T-06** Kick closes the viewer.

**T-07** Expiry → all closed with 4410 and `closed_at` set. Delete → same.

**T-08** A slow viewer (never reads) → disconnected after the queue fills, and the host stream is unaffected (the other viewer still receives).

**T-09** `share_join_request` is delivered on the owner's general WS.

**T-10** The server never logs payload bytes (log capture canary).

## 5. Passing functional characteristics
- [ ] Owners create and delete share sessions with mode, expiry (≤ 24 h default) and max viewers (≤ 10). Viewers may be anonymous if allowed.
- [ ] The relay routes opaque payloads by `viewer_id`, stamping viewer ids server-side. Kick, expiry and end close connections.
- [ ] Join requests notify the host with name or account and an IP hint.
- [ ] Slow viewers can't stall the host. Limits are enforced.
