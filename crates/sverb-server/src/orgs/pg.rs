//! The PostgreSQL backend of [`super::OrgStore`]. Every change is one
//! transaction together with its audit rows; changes to members lock the org's
//! member rows first, so the "at least one owner" rule holds under concurrency.

use chrono::{DateTime, Utc};
use sqlx_core::query::query;
use sqlx_core::query_as::query_as;
use sqlx_core::query_scalar::query_scalar;
use sqlx_postgres::{PgConnection, PgPool};
use sverb_proto::orgs::Role;
use uuid::Uuid;

use super::{
    AuditRow, MemberRow, NewInvite, OrgRow, check_invite, check_remove, check_set_role, kinds,
};
use crate::error::ApiError;

type Res<T> = Result<T, ApiError>;

fn role(s: &str) -> Res<Role> {
    Role::parse(s).ok_or_else(|| {
        ApiError::internal(std::io::Error::other(format!("bad role {s:?} in database")))
    })
}

fn no_org() -> ApiError {
    ApiError::NotFound("no such org".into())
}

fn bad_invite() -> ApiError {
    ApiError::NotFound("invalid, expired or already used invite".into())
}

pub(super) async fn insert_audit(
    conn: &mut PgConnection,
    org: Uuid,
    actor: Option<Uuid>,
    kind: &str,
    target: Option<Uuid>,
    meta: serde_json::Value,
    now: DateTime<Utc>,
) -> Res<()> {
    query(
        "INSERT INTO audit_events (org_id, actor_user_id, kind, target, at, meta) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(org)
    .bind(actor)
    .bind(kind)
    .bind(target)
    .bind(now)
    .bind(meta)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// The org's members with their roles, locked until the transaction ends.
async fn lock_members(conn: &mut PgConnection, org: Uuid) -> Res<Vec<(Uuid, Role)>> {
    let rows: Vec<(Uuid, String)> = query_as(
        "SELECT user_id, role FROM org_members WHERE org_id = $1 ORDER BY user_id FOR UPDATE",
    )
    .bind(org)
    .fetch_all(&mut *conn)
    .await?;
    rows.into_iter().map(|(u, r)| Ok((u, role(&r)?))).collect()
}

fn find(members: &[(Uuid, Role)], user: Uuid) -> Option<Role> {
    members.iter().find(|(u, _)| *u == user).map(|(_, r)| *r)
}

fn owners(members: &[(Uuid, Role)]) -> usize {
    members.iter().filter(|(_, r)| *r == Role::Owner).count()
}

pub(super) async fn create_org(
    pool: &PgPool,
    id: Uuid,
    name: &str,
    owner: Uuid,
    now: DateTime<Utc>,
) -> Res<OrgRow> {
    let mut tx = pool.begin().await?;
    query("INSERT INTO orgs (id, name, created_at) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(name)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    query("INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, 'owner')")
        .bind(id)
        .bind(owner)
        .execute(&mut *tx)
        .await?;
    let meta = serde_json::json!({});
    insert_audit(
        &mut tx,
        id,
        Some(owner),
        kinds::ORG_CREATED,
        Some(id),
        meta,
        now,
    )
    .await?;
    let meta = serde_json::json!({ "role": "owner" });
    insert_audit(
        &mut tx,
        id,
        Some(owner),
        kinds::MEMBER_ADDED,
        Some(owner),
        meta,
        now,
    )
    .await?;
    tx.commit().await?;
    Ok(OrgRow {
        id,
        name: name.to_owned(),
        role: Role::Owner,
        created_at: Some(now),
    })
}

pub(super) async fn list_orgs(pool: &PgPool, user: Uuid) -> Res<Vec<OrgRow>> {
    let rows: Vec<(Uuid, String, String, Option<DateTime<Utc>>)> = query_as(
        "SELECT o.id, o.name, m.role, o.created_at FROM orgs o \
         JOIN org_members m ON m.org_id = o.id WHERE m.user_id = $1 \
         ORDER BY lower(o.name), o.id",
    )
    .bind(user)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|(id, name, r, created_at)| {
            Ok(OrgRow {
                id,
                name,
                role: role(&r)?,
                created_at,
            })
        })
        .collect()
}

pub(super) async fn role_of(pool: &PgPool, org: Uuid, user: Uuid) -> Res<Option<Role>> {
    let r: Option<String> =
        query_scalar("SELECT role FROM org_members WHERE org_id = $1 AND user_id = $2")
            .bind(org)
            .bind(user)
            .fetch_optional(pool)
            .await?;
    r.as_deref().map(role).transpose()
}

pub(super) async fn members(pool: &PgPool, org: Uuid) -> Res<Vec<MemberRow>> {
    let rows: Vec<(Uuid, String, String)> = query_as(
        "SELECT m.user_id, u.email::text, m.role FROM org_members m \
         JOIN users u ON u.id = m.user_id WHERE m.org_id = $1",
    )
    .bind(org)
    .fetch_all(pool)
    .await?;
    let mut out = rows
        .into_iter()
        .map(|(user_id, email, r)| {
            Ok(MemberRow {
                user_id,
                email,
                role: role(&r)?,
            })
        })
        .collect::<Res<Vec<_>>>()?;
    out.sort_by(|a, b| {
        b.role
            .cmp(&a.role)
            .then_with(|| a.email.to_lowercase().cmp(&b.email.to_lowercase()))
    });
    Ok(out)
}

pub(super) async fn set_role(
    pool: &PgPool,
    org: Uuid,
    actor: Uuid,
    target: Uuid,
    new: Role,
    now: DateTime<Utc>,
) -> Res<()> {
    let mut tx = pool.begin().await?;
    let members = lock_members(&mut tx, org).await?;
    let actor_role = find(&members, actor).ok_or_else(no_org)?;
    let current =
        find(&members, target).ok_or_else(|| ApiError::NotFound("no such member".into()))?;
    check_set_role(actor_role, current, new, owners(&members))?;
    if current != new {
        query("UPDATE org_members SET role = $3 WHERE org_id = $1 AND user_id = $2")
            .bind(org)
            .bind(target)
            .bind(new.as_str())
            .execute(&mut *tx)
            .await?;
        let meta = serde_json::json!({ "from": current, "to": new });
        insert_audit(
            &mut tx,
            org,
            Some(actor),
            kinds::MEMBER_ROLE_CHANGED,
            Some(target),
            meta,
            now,
        )
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub(super) async fn remove_member(
    pool: &PgPool,
    org: Uuid,
    actor: Uuid,
    target: Uuid,
    now: DateTime<Utc>,
) -> Res<u64> {
    let mut tx = pool.begin().await?;
    let members = lock_members(&mut tx, org).await?;
    let actor_role = find(&members, actor).ok_or_else(no_org)?;
    let target_role =
        find(&members, target).ok_or_else(|| ApiError::NotFound("no such member".into()))?;
    check_remove(actor_role, actor == target, target_role, owners(&members))?;
    query("DELETE FROM org_members WHERE org_id = $1 AND user_id = $2")
        .bind(org)
        .bind(target)
        .execute(&mut *tx)
        .await?;
    let revoked = query(
        "DELETE FROM vault_members WHERE user_id = $2 \
         AND vault_id IN (SELECT id FROM vaults WHERE org_id = $1)",
    )
    .bind(org)
    .bind(target)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    let meta = serde_json::json!({ "left": actor == target, "revoked_grants": revoked });
    insert_audit(
        &mut tx,
        org,
        Some(actor),
        kinds::MEMBER_REMOVED,
        Some(target),
        meta,
        now,
    )
    .await?;
    tx.commit().await?;
    Ok(revoked)
}

pub(super) async fn create_invite(pool: &PgPool, inv: &NewInvite, now: DateTime<Utc>) -> Res<()> {
    let mut tx = pool.begin().await?;
    let actor: Option<String> =
        query_scalar("SELECT role FROM org_members WHERE org_id = $1 AND user_id = $2")
            .bind(inv.org_id)
            .bind(inv.created_by)
            .fetch_optional(&mut *tx)
            .await?;
    let actor = role(actor.as_deref().ok_or_else(no_org)?)?;
    check_invite(actor, inv.role)?;
    query(
        "INSERT INTO invites \
         (id, org_id, email, role, token_hash, created_by, expires_at, accepted_at) \
         VALUES ($1, $2, $3::citext, $4, $5, $6, $7, NULL)",
    )
    .bind(inv.id)
    .bind(inv.org_id)
    .bind(inv.email.as_deref())
    .bind(inv.role.as_str())
    .bind(&inv.token_hash[..])
    .bind(inv.created_by)
    .bind(inv.expires_at)
    .execute(&mut *tx)
    .await?;
    let meta = serde_json::json!({
        "role": inv.role,
        "email_bound": inv.email.is_some(),
        "mailed": inv.mailed,
    });
    insert_audit(
        &mut tx,
        inv.org_id,
        Some(inv.created_by),
        kinds::INVITE_SENT,
        Some(inv.id),
        meta,
        now,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

type InviteRow = (
    Uuid,
    Uuid,
    Option<String>,
    String,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
);

/// Adds (or upgrades) the membership and marks the invite accepted.
async fn join(
    conn: &mut PgConnection,
    (id, org, _, r, expires_at, accepted_at): InviteRow,
    user: Uuid,
    now: DateTime<Utc>,
) -> Res<(Uuid, Role)> {
    if accepted_at.is_some() || expires_at.is_some_and(|e| e <= now) {
        return Err(bad_invite());
    }
    let granted = role(&r)?;
    let existing: Option<String> =
        query_scalar("SELECT role FROM org_members WHERE org_id = $1 AND user_id = $2 FOR UPDATE")
            .bind(org)
            .bind(user)
            .fetch_optional(&mut *conn)
            .await?;
    let existing = existing.as_deref().map(role).transpose()?;
    let held = existing.map_or(granted, |e| e.max(granted));
    if existing != Some(held) {
        query(
            "INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, $3) \
             ON CONFLICT (org_id, user_id) DO UPDATE SET role = EXCLUDED.role",
        )
        .bind(org)
        .bind(user)
        .bind(held.as_str())
        .execute(&mut *conn)
        .await?;
    }
    query("UPDATE invites SET accepted_at = $2 WHERE id = $1")
        .bind(id)
        .bind(now)
        .execute(&mut *conn)
        .await?;
    let meta = serde_json::json!({});
    insert_audit(
        conn,
        org,
        Some(user),
        kinds::INVITE_ACCEPTED,
        Some(id),
        meta,
        now,
    )
    .await?;
    match existing {
        None => {
            let meta = serde_json::json!({ "role": held });
            insert_audit(
                conn,
                org,
                Some(user),
                kinds::MEMBER_ADDED,
                Some(user),
                meta,
                now,
            )
            .await?;
        }
        Some(e) if e != held => {
            let meta = serde_json::json!({ "from": e, "to": held });
            insert_audit(
                conn,
                org,
                Some(user),
                kinds::MEMBER_ROLE_CHANGED,
                Some(user),
                meta,
                now,
            )
            .await?;
        }
        Some(_) => {}
    }
    Ok((org, held))
}

const INVITE_COLS: &str = "id, org_id, email::text, role, expires_at, accepted_at";

pub(super) async fn accept_invite(
    pool: &PgPool,
    token_hash: [u8; 32],
    user: Uuid,
    email: &str,
    now: DateTime<Utc>,
) -> Res<(Uuid, Role)> {
    let mut tx = pool.begin().await?;
    let row: Option<InviteRow> = query_as(&format!(
        "SELECT {INVITE_COLS} FROM invites \
         WHERE token_hash = $1 AND org_id IS NOT NULL FOR UPDATE"
    ))
    .bind(&token_hash[..])
    .fetch_optional(&mut *tx)
    .await?;
    let row = row.ok_or_else(bad_invite)?;
    if let Some(bound) = &row.2
        && !bound.eq_ignore_ascii_case(email.trim())
    {
        return Err(ApiError::Forbidden(
            "this invite is for another email address".into(),
        ));
    }
    let out = join(&mut tx, row, user, now).await?;
    tx.commit().await?;
    Ok(out)
}

pub(super) async fn accept_invite_id(
    pool: &PgPool,
    id: Uuid,
    user: Uuid,
    now: DateTime<Utc>,
) -> Res<(Uuid, Role)> {
    let mut tx = pool.begin().await?;
    let row: Option<InviteRow> = query_as(&format!(
        "SELECT {INVITE_COLS} FROM invites WHERE id = $1 AND org_id IS NOT NULL FOR UPDATE"
    ))
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let out = join(&mut tx, row.ok_or_else(bad_invite)?, user, now).await?;
    tx.commit().await?;
    Ok(out)
}

pub(super) async fn record(
    pool: &PgPool,
    org: Uuid,
    actor: Option<Uuid>,
    kind: &str,
    target: Option<Uuid>,
    meta: serde_json::Value,
    now: DateTime<Utc>,
) -> Res<()> {
    let mut conn = pool.acquire().await?;
    insert_audit(&mut conn, org, actor, kind, target, meta, now).await
}

pub(super) async fn record_for_user_orgs(
    pool: &PgPool,
    user: Uuid,
    kind: &str,
    target: Option<Uuid>,
    now: DateTime<Utc>,
) -> Res<()> {
    query(
        "INSERT INTO audit_events (org_id, actor_user_id, kind, target, at, meta) \
         SELECT org_id, $1, $2, $3, $4, '{}'::jsonb FROM org_members WHERE user_id = $1",
    )
    .bind(user)
    .bind(kind)
    .bind(target)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

type AuditDbRow = (
    i64,
    Option<String>,
    Option<Uuid>,
    Option<Uuid>,
    DateTime<Utc>,
    Option<serde_json::Value>,
);

pub(super) async fn audit_page(
    pool: &PgPool,
    org: Uuid,
    before: Option<i64>,
    limit: u32,
) -> Res<Vec<AuditRow>> {
    let rows: Vec<AuditDbRow> = query_as(
        "SELECT id, kind, actor_user_id, target, at, meta FROM audit_events \
             WHERE org_id = $1 AND ($2::bigint IS NULL OR id < $2) \
             ORDER BY id DESC LIMIT $3",
    )
    .bind(org)
    .bind(before)
    .bind(i64::from(limit))
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, kind, actor, target, at, meta)| AuditRow {
            id,
            kind: kind.unwrap_or_default(),
            actor,
            target,
            at,
            meta: meta.unwrap_or(serde_json::Value::Null),
        })
        .collect())
}

pub(super) async fn share_an_org(pool: &PgPool, a: Uuid, b: Uuid) -> Res<bool> {
    Ok(query_scalar(
        "SELECT EXISTS (SELECT 1 FROM org_members x JOIN org_members y ON x.org_id = y.org_id \
         WHERE x.user_id = $1 AND y.user_id = $2)",
    )
    .bind(a)
    .bind(b)
    .fetch_one(pool)
    .await?)
}
