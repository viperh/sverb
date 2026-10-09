//!
//! * The role rules are pure functions ([`check_invite`], [`check_set_role`],
//!   [`check_remove`], [`check_audit`]) shared by both backends, which call them
//!   after locking the org's member rows, so concurrent changes can't leave an org
//!   without an owner.
//! * [`OrgStore`] mirrors [`AuthStore`]: PostgreSQL ([`pg`], every change one
//!   transaction with its audit rows) and the in-memory model ([`mem`]).
//! * Audit events are metadata only (§13.5): kinds, ids, roles and counts; never
//!   names, emails or item contents.
//!
//! Invites (§13.2) carry a 256-bit token stored only as its SHA-256, expire after
//! 7 days, and are single-use; an email-bound invite must be accepted by the
//! account with that email. An org invite can also be presented at registration
//! (invite-only servers); the membership is added once the account exists.

pub mod mem;
pub mod pg;

use std::sync::Arc;

use chrono::{DateTime, Utc};
use sqlx_postgres::PgPool;
use sverb_proto::orgs::Role;
use uuid::Uuid;

use crate::auth::AuthStore;
use crate::auth::store::mem::MemStore;
use crate::error::ApiError;

/// Invite lifetime (§13.2).
pub const INVITE_TTL_DAYS: i64 = 7;

/// Longest org name.
pub const MAX_ORG_NAME: usize = 100;

/// Audit event kinds (§13.5).
pub mod kinds {
    /// An org was created (target: the org).
    pub const ORG_CREATED: &str = "org.created";
    /// A member joined (target: the user; meta: role).
    pub const MEMBER_ADDED: &str = "member.added";
    /// A member was removed or left (target: the user; meta: revoked vault grants).
    pub const MEMBER_REMOVED: &str = "member.removed";
    /// A role changed (target: the user; meta: from, to).
    pub const MEMBER_ROLE_CHANGED: &str = "member.role_changed";
    /// An invite was created (target: the invite; meta: role, email-bound, mailed).
    pub const INVITE_SENT: &str = "invite.sent";
    /// An invite was accepted (target: the invite).
    pub const INVITE_ACCEPTED: &str = "invite.accepted";
    /// A member's device was added (target: the device).
    pub const DEVICE_ADDED: &str = "device.added";
    /// A member's device was revoked (target: the device).
    pub const DEVICE_REVOKED: &str = "device.revoked";
}

type Res<T> = Result<T, ApiError>;

fn forbidden(what: &str) -> ApiError {
    ApiError::Forbidden(format!("your role can't {what}"))
}

/// May `actor` invite someone as `role`? Admins and owners invite; only owners
/// invite owners.
///
/// # Errors
/// [`ApiError::Forbidden`].
pub fn check_invite(actor: Role, role: Role) -> Res<()> {
    if actor < Role::Admin {
        return Err(forbidden("invite members"));
    }
    if role == Role::Owner && actor != Role::Owner {
        return Err(forbidden("invite owners"));
    }
    Ok(())
}

/// May `actor` change a member from `current` to `new`? Admins change member ↔
/// admin; only owners create or demote owners; the last owner can't be demoted.
///
/// # Errors
/// [`ApiError::Forbidden`], [`ApiError::Invalid`] for the last owner.
pub fn check_set_role(actor: Role, current: Role, new: Role, owners: usize) -> Res<()> {
    if actor < Role::Admin {
        return Err(forbidden("change roles"));
    }
    if (current == Role::Owner || new == Role::Owner) && actor != Role::Owner {
        return Err(forbidden("promote or demote owners"));
    }
    if current == Role::Owner && new != Role::Owner && owners <= 1 {
        return Err(ApiError::Invalid(
            "an org must keep at least one owner".into(),
        ));
    }
    Ok(())
}

/// May `actor` remove a member whose role is `target`? Anyone may leave;
/// admins remove members and admins, owners anyone; the last owner stays.
///
/// # Errors
/// [`ApiError::Forbidden`], [`ApiError::Invalid`] for the last owner.
pub fn check_remove(actor: Role, is_self: bool, target: Role, owners: usize) -> Res<()> {
    if !is_self {
        if actor < Role::Admin {
            return Err(forbidden("remove members"));
        }
        if target == Role::Owner && actor != Role::Owner {
            return Err(forbidden("remove owners"));
        }
    }
    if target == Role::Owner && owners <= 1 {
        return Err(ApiError::Invalid(
            "an org must keep at least one owner".into(),
        ));
    }
    Ok(())
}

/// May `actor` read the audit log? Admins and owners.
///
/// # Errors
/// [`ApiError::Forbidden`].
pub fn check_audit(actor: Role) -> Res<()> {
    if actor < Role::Admin {
        return Err(forbidden("read the audit log"));
    }
    Ok(())
}

/// A validated org name.
///
/// # Errors
/// [`ApiError::Invalid`].
pub fn org_name(name: &str) -> Res<String> {
    let n = name.trim();
    if n.is_empty() || n.chars().count() > MAX_ORG_NAME || n.chars().any(char::is_control) {
        return Err(ApiError::Invalid(format!(
            "an org name has 1 to {MAX_ORG_NAME} characters"
        )));
    }
    Ok(n.to_owned())
}

/// An org with the caller's role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgRow {
    /// Id.
    pub id: Uuid,
    /// Name.
    pub name: String,
    /// The caller's role.
    pub role: Role,
    /// Creation time.
    pub created_at: Option<DateTime<Utc>>,
}

/// A member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberRow {
    /// User.
    pub user_id: Uuid,
    /// Email.
    pub email: String,
    /// Role.
    pub role: Role,
}

/// An invite to create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewInvite {
    /// Id.
    pub id: Uuid,
    /// Org.
    pub org_id: Uuid,
    /// Normalised bound email.
    pub email: Option<String>,
    /// Granted role.
    pub role: Role,
    /// SHA-256 of the token.
    pub token_hash: [u8; 32],
    /// Creator.
    pub created_by: Uuid,
    /// Expiry.
    pub expires_at: DateTime<Utc>,
    /// It is mailed (recorded in the audit meta).
    pub mailed: bool,
}

/// An audit row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRow {
    /// Id.
    pub id: i64,
    /// Kind.
    pub kind: String,
    /// Actor.
    pub actor: Option<Uuid>,
    /// Target.
    pub target: Option<Uuid>,
    /// Time.
    pub at: DateTime<Utc>,
    /// Metadata.
    pub meta: serde_json::Value,
}

/// The orgs persistence backend: the same storage as auth.
#[derive(Debug, Clone)]
pub enum OrgStore {
    /// PostgreSQL.
    Postgres(PgPool),
    /// The in-memory model (tests), sharing the auth model's tables.
    Memory(Arc<MemStore>),
}

macro_rules! dispatch {
    ($self:ident, $method:ident ( $($arg:expr),* )) => {
        match $self {
            OrgStore::Postgres(pool) => pg::$method(pool, $($arg),*).await,
            OrgStore::Memory(m) => m.$method($($arg),*),
        }
    };
}

impl OrgStore {
    /// The org store on the same backend as `auth`.
    #[must_use]
    pub fn for_auth(auth: &AuthStore) -> Self {
        match auth {
            AuthStore::Postgres(pool) => Self::Postgres(pool.clone()),
            AuthStore::Memory(m) => Self::Memory(Arc::clone(m)),
        }
    }

    /// Creates an org; `owner` becomes its owner.
    ///
    /// # Errors
    /// Database errors.
    pub async fn create_org(
        &self,
        id: Uuid,
        name: &str,
        owner: Uuid,
        now: DateTime<Utc>,
    ) -> Res<OrgRow> {
        dispatch!(self, create_org(id, name, owner, now))
    }

    /// The orgs `user` belongs to, by name.
    ///
    /// # Errors
    /// Database errors.
    pub async fn list_orgs(&self, user: Uuid) -> Res<Vec<OrgRow>> {
        dispatch!(self, list_orgs(user))
    }

    /// `user`'s role in `org`; `None` when not a member (or no such org).
    ///
    /// # Errors
    /// Database errors.
    pub async fn role_of(&self, org: Uuid, user: Uuid) -> Res<Option<Role>> {
        dispatch!(self, role_of(org, user))
    }

    /// The members of `org`, owners first.
    ///
    /// # Errors
    /// Database errors.
    pub async fn members(&self, org: Uuid) -> Res<Vec<MemberRow>> {
        dispatch!(self, members(org))
    }

    /// Changes `target`'s role (checked with [`check_set_role`] under the lock).
    ///
    /// # Errors
    /// [`ApiError::NotFound`] (caller or target not a member), the rule errors.
    pub async fn set_role(
        &self,
        org: Uuid,
        actor: Uuid,
        target: Uuid,
        role: Role,
        now: DateTime<Utc>,
    ) -> Res<()> {
        dispatch!(self, set_role(org, actor, target, role, now))
    }

    /// Removes `target` (or `actor` leaves): also revokes their grants on the org's
    /// vaults. Returns how many vault grants were revoked.
    ///
    /// # Errors
    /// [`ApiError::NotFound`], the rule errors of [`check_remove`].
    pub async fn remove_member(
        &self,
        org: Uuid,
        actor: Uuid,
        target: Uuid,
        now: DateTime<Utc>,
    ) -> Res<u64> {
        dispatch!(self, remove_member(org, actor, target, now))
    }

    /// Stores an invite (checked with [`check_invite`]).
    ///
    /// # Errors
    /// [`ApiError::NotFound`] (not a member), [`ApiError::Forbidden`].
    pub async fn create_invite(&self, invite: &NewInvite, now: DateTime<Utc>) -> Res<()> {
        dispatch!(self, create_invite(invite, now))
    }

    /// Accepts the org invite with `token_hash` for `user` (whose account email is
    /// `email`). Returns the org and the role held now.
    ///
    /// # Errors
    /// [`ApiError::NotFound`] (no such, expired or used invite),
    /// [`ApiError::Forbidden`] (bound to another email).
    pub async fn accept_invite(
        &self,
        token_hash: [u8; 32],
        user: Uuid,
        email: &str,
        now: DateTime<Utc>,
    ) -> Res<(Uuid, Role)> {
        dispatch!(self, accept_invite(token_hash, user, email, now))
    }

    /// Accepts the org invite `id` presented at registration (already checked by
    /// the registration policy).
    ///
    /// # Errors
    /// [`ApiError::NotFound`] when it was used or expired meanwhile.
    pub async fn accept_invite_id(
        &self,
        id: Uuid,
        user: Uuid,
        now: DateTime<Utc>,
    ) -> Res<(Uuid, Role)> {
        dispatch!(self, accept_invite_id(id, user, now))
    }

    /// Appends an audit event for `org`.
    ///
    /// # Errors
    /// Database errors.
    pub async fn record(
        &self,
        org: Uuid,
        actor: Option<Uuid>,
        kind: &str,
        target: Option<Uuid>,
        meta: serde_json::Value,
        now: DateTime<Utc>,
    ) -> Res<()> {
        dispatch!(self, record(org, actor, kind, target, meta, now))
    }

    /// Appends an audit event to every org `user` belongs to (device events).
    ///
    /// # Errors
    /// Database errors.
    pub async fn record_for_user_orgs(
        &self,
        user: Uuid,
        kind: &str,
        target: Option<Uuid>,
        now: DateTime<Utc>,
    ) -> Res<()> {
        dispatch!(self, record_for_user_orgs(user, kind, target, now))
    }

    /// Audit events of `org` with an id below `before`, newest first.
    ///
    /// # Errors
    /// Database errors.
    pub async fn audit_page(
        &self,
        org: Uuid,
        before: Option<i64>,
        limit: u32,
    ) -> Res<Vec<AuditRow>> {
        dispatch!(self, audit_page(org, before, limit))
    }

    /// Whether `a` and `b` share an org (or are the same user).
    ///
    /// # Errors
    /// Database errors.
    pub async fn share_an_org(&self, a: Uuid, b: Uuid) -> Res<bool> {
        if a == b {
            return Ok(true);
        }
        dispatch!(self, share_an_org(a, b))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn code(r: Res<()>) -> &'static str {
        match r {
            Ok(()) => "ok",
            Err(ApiError::Forbidden(_)) => "403",
            Err(ApiError::Invalid(_)) => "400",
            Err(_) => "other",
        }
    }

    // The role permission matrix.
    #[test]
    fn t02_permission_matrix() {
        use Role::{Admin as A, Member as M, Owner as O};
        // Invites: (actor, invited role) → outcome.
        for (actor, role, want) in [
            (M, M, "403"),
            (A, M, "ok"),
            (A, A, "ok"),
            (A, O, "403"),
            (O, O, "ok"),
        ] {
            assert_eq!(
                code(check_invite(actor, role)),
                want,
                "invite {actor}->{role}"
            );
        }
        // Role changes: (actor, current, new, owners) → outcome.
        for (actor, cur, new, owners, want) in [
            (M, M, A, 1, "403"),
            (A, M, A, 1, "ok"),
            (A, A, M, 1, "ok"),
            (A, M, O, 1, "403"),
            (A, O, M, 2, "403"),
            (O, M, O, 1, "ok"),
            (O, O, A, 2, "ok"),
            (O, O, A, 1, "400"),
        ] {
            assert_eq!(
                code(check_set_role(actor, cur, new, owners)),
                want,
                "{actor}: {cur}->{new} with {owners} owner(s)"
            );
        }
        // Removal: (actor, self, target, owners) → outcome.
        for (actor, me, target, owners, want) in [
            (M, false, M, 1, "403"),
            (M, true, M, 1, "ok"),
            (A, false, M, 1, "ok"),
            (A, false, A, 1, "ok"),
            (A, false, O, 2, "403"),
            (O, false, O, 2, "ok"),
            (O, true, O, 1, "400"),
            (O, false, O, 1, "400"),
        ] {
            assert_eq!(
                code(check_remove(actor, me, target, owners)),
                want,
                "{actor} removes {target} (self: {me}) with {owners} owner(s)"
            );
        }
        assert_eq!(code(check_audit(M)), "403");
        assert_eq!(code(check_audit(A)), "ok");
    }

    #[test]
    fn names() {
        assert_eq!(org_name("  Acme  ").unwrap(), "Acme");
        assert!(org_name("").is_err());
        assert!(org_name(&"x".repeat(101)).is_err());
        assert!(org_name("a\nb").is_err());
    }
}
