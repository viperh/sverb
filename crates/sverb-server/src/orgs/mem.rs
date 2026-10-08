//! The in-memory backend of [`super::OrgStore`], on the auth model's tables
//! ([`MemData`]). Every operation validates under the one lock before it changes
//! anything, so it is atomic like the PostgreSQL transactions.

use chrono::{DateTime, Utc};
use sverb_proto::orgs::Role;
use uuid::Uuid;

use super::{
    AuditRow, MemberRow, NewInvite, OrgRow, check_invite, check_remove, check_set_role, kinds,
};
use crate::auth::store::mem::{MemAudit, MemData, MemInvite, MemOrg, MemStore};
use crate::error::ApiError;

type Res<T> = Result<T, ApiError>;

fn no_org() -> ApiError {
    ApiError::NotFound("no such org".into())
}

fn bad_invite() -> ApiError {
    ApiError::NotFound("invalid, expired or already used invite".into())
}

impl MemData {
    fn org_audit(
        &mut self,
        org: Uuid,
        actor: Option<Uuid>,
        kind: &str,
        target: Option<Uuid>,
        meta: serde_json::Value,
        now: DateTime<Utc>,
    ) {
        let id = i64::try_from(self.audit.len()).unwrap_or(i64::MAX) + 1;
        self.audit.push(MemAudit {
            id,
            org_id: Some(org),
            at: Some(now),
            actor,
            kind: kind.to_owned(),
            target,
            meta,
        });
    }

    fn org_role(&self, org: Uuid, user: Uuid) -> Option<Role> {
        self.org_members.get(&(org, user)).copied()
    }

    fn owners(&self, org: Uuid) -> usize {
        self.org_members
            .iter()
            .filter(|((o, _), r)| *o == org && **r == Role::Owner)
            .count()
    }

    fn join_invite(&mut self, i: usize, user: Uuid, now: DateTime<Utc>) -> Res<(Uuid, Role)> {
        let inv = &self.invites[i];
        let (Some(org), Some(granted)) = (inv.org_id, inv.role) else {
            return Err(bad_invite());
        };
        if inv.accepted || inv.expires_at.is_some_and(|e| e <= now) {
            return Err(bad_invite());
        }
        let id = inv.id;
        let existing = self.org_role(org, user);
        let held = existing.map_or(granted, |e| e.max(granted));
        self.org_members.insert((org, user), held);
        self.invites[i].accepted = true;
        let meta = serde_json::json!({});
        self.org_audit(org, Some(user), kinds::INVITE_ACCEPTED, Some(id), meta, now);
        match existing {
            None => {
                let meta = serde_json::json!({ "role": held });
                self.org_audit(org, Some(user), kinds::MEMBER_ADDED, Some(user), meta, now);
            }
            Some(e) if e != held => {
                let meta = serde_json::json!({ "from": e, "to": held });
                self.org_audit(
                    org,
                    Some(user),
                    kinds::MEMBER_ROLE_CHANGED,
                    Some(user),
                    meta,
                    now,
                );
            }
            Some(_) => {}
        }
        Ok((org, held))
    }
}

impl MemStore {
    pub(super) fn create_org(
        &self,
        id: Uuid,
        name: &str,
        owner: Uuid,
        now: DateTime<Utc>,
    ) -> Res<OrgRow> {
        let mut d = self.lock();
        if d.orgs.contains_key(&id) {
            return Err(ApiError::Conflict("an org with this id exists".into()));
        }
        d.orgs.insert(
            id,
            MemOrg {
                name: name.to_owned(),
                created_at: now,
            },
        );
        d.org_members.insert((id, owner), Role::Owner);
        d.org_audit(
            id,
            Some(owner),
            kinds::ORG_CREATED,
            Some(id),
            serde_json::json!({}),
            now,
        );
        let meta = serde_json::json!({ "role": "owner" });
        d.org_audit(id, Some(owner), kinds::MEMBER_ADDED, Some(owner), meta, now);
        Ok(OrgRow {
            id,
            name: name.to_owned(),
            role: Role::Owner,
            created_at: Some(now),
        })
    }

    pub(super) fn list_orgs(&self, user: Uuid) -> Res<Vec<OrgRow>> {
        let d = self.lock();
        let mut out: Vec<OrgRow> = d
            .org_members
            .iter()
            .filter(|((_, u), _)| *u == user)
            .filter_map(|((org, _), role)| {
                d.orgs.get(org).map(|o| OrgRow {
                    id: *org,
                    name: o.name.clone(),
                    role: *role,
                    created_at: Some(o.created_at),
                })
            })
            .collect();
        out.sort_by(|a, b| {
            a.name
                .to_lowercase()
                .cmp(&b.name.to_lowercase())
                .then(a.id.cmp(&b.id))
        });
        Ok(out)
    }

    pub(super) fn role_of(&self, org: Uuid, user: Uuid) -> Res<Option<Role>> {
        Ok(self.lock().org_role(org, user))
    }

    pub(super) fn members(&self, org: Uuid) -> Res<Vec<MemberRow>> {
        let d = self.lock();
        let mut out: Vec<MemberRow> = d
            .org_members
            .iter()
            .filter(|((o, _), _)| *o == org)
            .map(|((_, user), role)| MemberRow {
                user_id: *user,
                email: d
                    .users
                    .get(user)
                    .map(|u| u.email.clone())
                    .unwrap_or_default(),
                role: *role,
            })
            .collect();
        out.sort_by(|a, b| {
            b.role
                .cmp(&a.role)
                .then_with(|| a.email.to_lowercase().cmp(&b.email.to_lowercase()))
        });
        Ok(out)
    }

    pub(super) fn set_role(
        &self,
        org: Uuid,
        actor: Uuid,
        target: Uuid,
        new: Role,
        now: DateTime<Utc>,
    ) -> Res<()> {
        let mut d = self.lock();
        let actor_role = d.org_role(org, actor).ok_or_else(no_org)?;
        let current = d
            .org_role(org, target)
            .ok_or_else(|| ApiError::NotFound("no such member".into()))?;
        check_set_role(actor_role, current, new, d.owners(org))?;
        if current != new {
            d.org_members.insert((org, target), new);
            let meta = serde_json::json!({ "from": current, "to": new });
            d.org_audit(
                org,
                Some(actor),
                kinds::MEMBER_ROLE_CHANGED,
                Some(target),
                meta,
                now,
            );
        }
        Ok(())
    }

    pub(super) fn remove_member(
        &self,
        org: Uuid,
        actor: Uuid,
        target: Uuid,
        now: DateTime<Utc>,
    ) -> Res<u64> {
        let mut d = self.lock();
        let actor_role = d.org_role(org, actor).ok_or_else(no_org)?;
        let target_role = d
            .org_role(org, target)
            .ok_or_else(|| ApiError::NotFound("no such member".into()))?;
        check_remove(actor_role, actor == target, target_role, d.owners(org))?;
        d.org_members.remove(&(org, target));
        let org_vaults: Vec<Uuid> = d
            .vaults
            .iter()
            .filter(|(_, v)| v.org_id == Some(org))
            .map(|(id, _)| *id)
            .collect();
        let before = d.vault_members.len();
        d.vault_members
            .retain(|m| !(m.user_id == target && org_vaults.contains(&m.vault_id)));
        let revoked = u64::try_from(before - d.vault_members.len()).unwrap_or(u64::MAX);
        let meta = serde_json::json!({ "left": actor == target, "revoked_grants": revoked });
        d.org_audit(
            org,
            Some(actor),
            kinds::MEMBER_REMOVED,
            Some(target),
            meta,
            now,
        );
        Ok(revoked)
    }

    pub(super) fn create_invite(&self, inv: &NewInvite, now: DateTime<Utc>) -> Res<()> {
        let mut d = self.lock();
        let actor = d.org_role(inv.org_id, inv.created_by).ok_or_else(no_org)?;
        check_invite(actor, inv.role)?;
        d.invites.push(MemInvite {
            id: inv.id,
            token_hash: inv.token_hash,
            email: inv.email.clone(),
            org_id: Some(inv.org_id),
            role: Some(inv.role),
            created_by: Some(inv.created_by),
            expires_at: Some(inv.expires_at),
            accepted: false,
        });
        let meta = serde_json::json!({
            "role": inv.role,
            "email_bound": inv.email.is_some(),
            "mailed": inv.mailed,
        });
        d.org_audit(
            inv.org_id,
            Some(inv.created_by),
            kinds::INVITE_SENT,
            Some(inv.id),
            meta,
            now,
        );
        Ok(())
    }

    pub(super) fn accept_invite(
        &self,
        token_hash: [u8; 32],
        user: Uuid,
        email: &str,
        now: DateTime<Utc>,
    ) -> Res<(Uuid, Role)> {
        let mut d = self.lock();
        let i = d
            .invites
            .iter()
            .position(|i| i.token_hash == token_hash && i.org_id.is_some())
            .ok_or_else(bad_invite)?;
        if let Some(bound) = &d.invites[i].email
            && !bound.eq_ignore_ascii_case(email.trim())
        {
            return Err(ApiError::Forbidden(
                "this invite is for another email address".into(),
            ));
        }
        d.join_invite(i, user, now)
    }

    pub(super) fn accept_invite_id(
        &self,
        id: Uuid,
        user: Uuid,
        now: DateTime<Utc>,
    ) -> Res<(Uuid, Role)> {
        let mut d = self.lock();
        let i = d
            .invites
            .iter()
            .position(|i| i.id == id && i.org_id.is_some())
            .ok_or_else(bad_invite)?;
        d.join_invite(i, user, now)
    }

    pub(super) fn record(
        &self,
        org: Uuid,
        actor: Option<Uuid>,
        kind: &str,
        target: Option<Uuid>,
        meta: serde_json::Value,
        now: DateTime<Utc>,
    ) -> Res<()> {
        self.lock().org_audit(org, actor, kind, target, meta, now);
        Ok(())
    }

    pub(super) fn record_for_user_orgs(
        &self,
        user: Uuid,
        kind: &str,
        target: Option<Uuid>,
        now: DateTime<Utc>,
    ) -> Res<()> {
        let mut d = self.lock();
        let orgs: Vec<Uuid> = d
            .org_members
            .keys()
            .filter(|(_, u)| *u == user)
            .map(|(o, _)| *o)
            .collect();
        for org in orgs {
            d.org_audit(org, Some(user), kind, target, serde_json::json!({}), now);
        }
        Ok(())
    }

    pub(super) fn audit_page(
        &self,
        org: Uuid,
        before: Option<i64>,
        limit: u32,
    ) -> Res<Vec<AuditRow>> {
        let d = self.lock();
        Ok(d.audit
            .iter()
            .rev()
            .filter(|a| a.org_id == Some(org) && before.is_none_or(|b| a.id < b))
            .take(usize::try_from(limit).unwrap_or(usize::MAX))
            .map(|a| AuditRow {
                id: a.id,
                kind: a.kind.clone(),
                actor: a.actor,
                target: a.target,
                at: a.at.unwrap_or(DateTime::<Utc>::MIN_UTC),
                meta: a.meta.clone(),
            })
            .collect())
    }

    pub(super) fn share_an_org(&self, a: Uuid, b: Uuid) -> Res<bool> {
        let d = self.lock();
        Ok(d.org_members
            .keys()
            .filter(|(_, u)| *u == a)
            .any(|(org, _)| d.org_members.contains_key(&(*org, b))))
    }
}
