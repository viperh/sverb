# M5-01 — Orgs, roles, invites and the audit log (server + client plumbing)

| | |
|---|---|
| **Milestone** | M5 — Teams |
| **Touches** | `crates/sverb-server/src/routes/{orgs.rs, invites.rs, audit.rs}`, `crates/sverb-server/src/audit.rs`, `crates/sverb-server/src/mail.rs`, `crates/sverb-proto/src/orgs.rs`, `crates/sverb-sync/src/teams.rs`, `crates/sverb-tui/src/views/settings/team.rs`, `crates/sverb/src/cli/team.rs` |
| **Spec refs** | §13.1, §13.2 (invite), §13.5, §10.3 (orgs, org_members, invites, audit_events), §10.4 (Orgs and members table), §10.7 (SMTP optional), §16 (`sverb team list | invite`) |
| **Depends on** | M4-04, M4-09 |
| **Blocks** | M5-02 |

---

## 1. Current state in the codebase
Personal sync works. The `orgs`, `org_members`, `invites` and `audit_events` tables exist from the M4-01 migration but are unused.

## 2. Detailed description
- **Orgs:** `POST /v1/orgs {name}` → the creator becomes `owner`. `GET /v1/orgs` → the orgs the user belongs to, with their role. Roles: `owner` (one or more), `admin`, `member`
  (§13.1). An org must always keep ≥ 1 owner (demoting or removing the last owner → 400).
- **Members:** `PATCH /v1/orgs/{id}/members/{user} {role}` (admin+; only owners can create or demote owners), `DELETE` (admin+; or self-leave). Removing a member also
  revokes all their vault memberships in that org and triggers rotation prompts for the affected vaults (M5-04).
- **Invites** (§13.2): `POST /v1/orgs/{id}/invites {email?, role}` (admin+) → a 256-bit token (stored hashed), expiry 7 days, delivered via **SMTP if configured**, otherwise a
  copy-paste link `<SVERB_PUBLIC_URL>/invite/<token>` (§10.7). An email-bound invite must be accepted by the same email. A link invite has no email and is single-use.
  `POST /v1/invites/{token}/accept` (authenticated) → adds membership with the role, sets `accepted_at`. Also allowed as part of **registration** (an invite token
  lets you register in invite-only mode, M4-02).
- **Public keys:** `GET /v1/users/{id}/public-keys` → `{x25519_pub, ed25519_pub, version}` for users sharing an org with the caller (otherwise 404).
- **Audit log** (§13.5): server-side `audit::record(org_id, actor, kind, target, meta)` for: member added/removed/role changed, vault created/rotated, invite
  sent/accepted, share started/ended, device added/revoked, grants given and revoked, and item-level events (push to a shared vault) recording **only `item_id` and the actor**,
  never content (§10.3 comment). `GET /v1/orgs/{id}/audit?before=&limit=` (admin+), shown in Settings → Team (§13.5).
- **Client:** Settings → Team (only in synced mode): org list, create org, members (role, verified ✓ from M5-03), invite (email or link; the link is copied), change role,
  remove, the audit log viewer (admins), and accept an invite by pasting a link (also via the palette).
- **CLI** (§16): `sverb team list` (orgs + members), `sverb team invite <email> [--org O] [--role member]`. `team verify` is M5-03.

## 3. Codebase changes
- Routes, a mail module (`lettre`, rustls; disabled when no SMTP), DTOs, client API wrappers, the team views, the CLI.

## 4. Test cases to implement

**T-01** Create an org → creator owner. List orgs.

**T-02** Role permissions matrix (table): member can't invite; admin can invite and change member↔admin; only an owner can promote to owner; removing the last owner → 400.

**T-03** Invite by email: token hashed in the DB, expiry enforced (time travel), wrong email accepting → 403, link invite single-use.

**T-04** Without SMTP → the response contains the link. With a mock SMTP (a `mailhog`-style container or a fake transport) → an email is sent with the link.

**T-05** Public keys are visible only to users sharing an org.

**T-06** Audit events are recorded for each listed action, and `meta` never contains envelope bytes or names (inspect rows).

**T-07** Audit endpoint pagination, admin-only.

**T-08 (reducer)** Team settings hidden in local-only mode. In synced mode, invite → link copied toast.

**T-09 (CLI)** `team invite` prints the link when no SMTP is configured.

## 5. Passing functional characteristics
- [ ] Orgs with owner/admin/member roles, with role-change rules and at least one owner always kept.
- [ ] Invites by email (SMTP) or link (no SMTP), expiring and hashed, accepted by authenticated users or during registration.
- [ ] Member public keys are discoverable only within shared orgs.
- [ ] A metadata-only audit log covers the §13.5 events and is viewable by admins in Settings → Team.
- [ ] `sverb team list` and `team invite` work.
