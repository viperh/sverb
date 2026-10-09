//! Orgs, members, invites and the audit log (SPEC §10.4 "Orgs and
//! members", §13.1, §13.2, §13.5).
//!
//! | Endpoint | Request | Response |
//! |---|---|---|
//! | `POST /v1/orgs` | [`CreateOrgRequest`] | [`OrgView`] |
//! | `GET /v1/orgs` | – | `[`[`OrgView`]`]` |
//! | `GET /v1/orgs/{id}/members` | – | `[`[`MemberView`]`]` |
//! | `PATCH /v1/orgs/{id}/members/{user}` | [`UpdateMemberRequest`] | 204 |
//! | `DELETE /v1/orgs/{id}/members/{user}` | – | 204 |
//! | `POST /v1/orgs/{id}/invites` | [`CreateInviteRequest`] | [`InviteCreated`] |
//! | `POST /v1/invites/{token}/accept` | – | [`InviteAccepted`] |
//! | `GET /v1/orgs/{id}/audit?before=&limit=` | [`AuditQuery`] | [`AuditPage`] |
//!
//! Errors (the §10.4 envelope): `404 not_found` for an org the caller is not a
//! member of (existence is not revealed), `403 forbidden` for a role that may
//! not do this, `400 invalid` for removing or demoting the last owner.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A member's role in an org (§13.1). Ordered by power.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Uses the org's vaults it is granted.
    Member,
    /// Invites, changes member ↔ admin, removes members, reads the audit log.
    Admin,
    /// Everything; only owners create or demote owners. Always ≥ 1 per org.
    Owner,
}

impl Role {
    /// The database / wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::Admin => "admin",
            Self::Owner => "owner",
        }
    }

    /// The inverse of [`Role::as_str`].
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "member" => Some(Self::Member),
            "admin" => Some(Self::Admin),
            "owner" => Some(Self::Owner),
            _ => None,
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `POST /v1/orgs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateOrgRequest {
    /// Display name (1–100 characters).
    pub name: String,
}

/// An org the caller belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgView {
    /// Org id.
    pub id: Uuid,
    /// Name.
    pub name: String,
    /// The caller's role.
    pub role: Role,
    /// Creation time.
    pub created_at: Option<DateTime<Utc>>,
}

/// A member of an org.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberView {
    /// The user.
    pub user_id: Uuid,
    /// Their account email.
    pub email: String,
    /// Their role.
    pub role: Role,
}

/// `PATCH /v1/orgs/{id}/members/{user}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateMemberRequest {
    /// The new role.
    pub role: Role,
}

/// `POST /v1/orgs/{id}/invites`. Without `email` the invite is a single-use
/// link anyone can accept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateInviteRequest {
    /// Bind the invite to this email (it must be accepted by that account).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// The role it grants.
    pub role: Role,
}

/// The created invite. The token itself is never stored on the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteCreated {
    /// Invite id.
    pub id: Uuid,
    /// Its org.
    pub org_id: Uuid,
    /// Bound email, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Granted role.
    pub role: Role,
    /// Expiry (7 days).
    pub expires_at: DateTime<Utc>,
    /// The link `<SVERB_PUBLIC_URL>/invite/<token>`, unless it was mailed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    /// It was sent by mail (SMTP configured and an email given).
    pub emailed: bool,
}

/// `POST /v1/invites/{token}/accept`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteAccepted {
    /// The org joined.
    pub org_id: Uuid,
    /// The role held now (an existing higher role is kept).
    pub role: Role,
}

/// `GET /v1/orgs/{id}/audit` query.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditQuery {
    /// Only events with an id below this (the previous page's `next_before`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<i64>,
    /// Page size (default 50, at most [`MAX_AUDIT_PAGE`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// The largest audit page.
pub const MAX_AUDIT_PAGE: u32 = 200;

/// One audit event (metadata only: never item contents or names, §13.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEventView {
    /// Monotonic id.
    pub id: i64,
    /// What happened (`member.added`, `invite.sent`, …).
    pub kind: String,
    /// Who did it.
    pub actor: Option<Uuid>,
    /// What it was done to (a user, invite, vault, item or device id).
    pub target: Option<Uuid>,
    /// When.
    pub at: DateTime<Utc>,
    /// Kind-specific details (roles, counts).
    pub meta: serde_json::Value,
}

/// A page of the audit log, newest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditPage {
    /// Events.
    pub events: Vec<AuditEventView>,
    /// Pass as `before` for the next (older) page; `None` at the end.
    pub next_before: Option<i64>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn roles() {
        assert!(Role::Owner > Role::Admin && Role::Admin > Role::Member);
        for r in [Role::Member, Role::Admin, Role::Owner] {
            assert_eq!(Role::parse(r.as_str()), Some(r));
            assert_eq!(serde_json::to_string(&r).unwrap(), format!("\"{r}\""));
        }
        assert_eq!(Role::parse("root"), None);
    }

    #[test]
    fn invite_request_email_is_optional() {
        let r: CreateInviteRequest = serde_json::from_str(r#"{"role":"admin"}"#).unwrap();
        assert_eq!(r.email, None);
        assert_eq!(r.role, Role::Admin);
    }
}
