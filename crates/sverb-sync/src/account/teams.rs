//! Orgs, members, invites and the audit log for the CLI (`sverb team`) and
//! Settings → Team. Like [`super::devices`], every call needs the unlocked vault
//! (the tokens are sealed under the LMK) and refreshes the access token once on 401.

use sverb_crypto::Key32;
use sverb_proto::orgs::{
    AuditPage, CreateInviteRequest, InviteAccepted, InviteCreated, MemberView, OrgView, Role,
};
use sverb_store::Store;
use uuid::Uuid;

use super::devices::{call, session};
use super::{AccountConfig, AccountError};

/// The invite token in a pasted link (`https://server/invite/<token>`) or the bare
/// token.
#[must_use]
pub fn invite_token(link: &str) -> Option<&str> {
    let t = link.trim().trim_end_matches('/');
    let t = t.rsplit_once("/invite/").map_or(t, |(_, tok)| tok);
    let t = t.split(['?', '#']).next().unwrap_or("");
    (!t.is_empty()
        && t.len() <= 128
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
    .then_some(t)
}

/// The orgs this account belongs to.
///
/// # Errors
/// [`AccountError`].
pub async fn list_orgs(
    store: &Store,
    lmk: &Key32,
    cfg: &AccountConfig,
) -> Result<Vec<OrgView>, AccountError> {
    let t = session(store, lmk, cfg).await?;
    Ok(call(&t, |api, tok| async move { api.list_orgs(&tok).await }).await?)
}

/// Creates an org (the caller becomes its owner).
///
/// # Errors
/// [`AccountError`].
pub async fn create_org(
    store: &Store,
    lmk: &Key32,
    cfg: &AccountConfig,
    name: &str,
) -> Result<OrgView, AccountError> {
    let t = session(store, lmk, cfg).await?;
    let name = name.to_owned();
    Ok(call(&t, |api, tok| {
        let name = name.clone();
        async move { api.create_org(&tok, &name).await }
    })
    .await?)
}

/// The members of `org`.
///
/// # Errors
/// [`AccountError`].
pub async fn members(
    store: &Store,
    lmk: &Key32,
    cfg: &AccountConfig,
    org: Uuid,
) -> Result<Vec<MemberView>, AccountError> {
    let t = session(store, lmk, cfg).await?;
    Ok(call(
        &t,
        |api, tok| async move { api.org_members(&tok, org).await },
    )
    .await?)
}

/// Invites `email` (or anyone with the link when `None`) as `role`.
///
/// # Errors
/// [`AccountError`].
pub async fn invite(
    store: &Store,
    lmk: &Key32,
    cfg: &AccountConfig,
    org: Uuid,
    email: Option<&str>,
    role: Role,
) -> Result<InviteCreated, AccountError> {
    let t = session(store, lmk, cfg).await?;
    let req = CreateInviteRequest {
        email: email.map(ToOwned::to_owned),
        role,
    };
    Ok(call(&t, |api, tok| {
        let req = req.clone();
        async move { api.create_invite(&tok, org, &req).await }
    })
    .await?)
}

/// Accepts a pasted invite link (or token).
///
/// # Errors
/// [`AccountError::Local`] for text that is not an invite, else [`AccountError`].
pub async fn accept_invite(
    store: &Store,
    lmk: &Key32,
    cfg: &AccountConfig,
    link: &str,
) -> Result<InviteAccepted, AccountError> {
    let token = invite_token(link)
        .ok_or_else(|| AccountError::Local("that is not an invite link".into()))?
        .to_owned();
    let t = session(store, lmk, cfg).await?;
    Ok(call(&t, |api, tok| {
        let token = token.clone();
        async move { api.accept_invite(&tok, &token).await }
    })
    .await?)
}

/// Changes a member's role.
///
/// # Errors
/// [`AccountError`].
pub async fn set_role(
    store: &Store,
    lmk: &Key32,
    cfg: &AccountConfig,
    org: Uuid,
    user: Uuid,
    role: Role,
) -> Result<(), AccountError> {
    let t = session(store, lmk, cfg).await?;
    Ok(call(&t, |api, tok| async move {
        api.set_member_role(&tok, org, user, role).await
    })
    .await?)
}

/// Removes a member (or leaves, for one's own id).
///
/// # Errors
/// [`AccountError`].
pub async fn remove_member(
    store: &Store,
    lmk: &Key32,
    cfg: &AccountConfig,
    org: Uuid,
    user: Uuid,
) -> Result<(), AccountError> {
    let t = session(store, lmk, cfg).await?;
    Ok(call(&t, |api, tok| async move {
        api.remove_member(&tok, org, user).await
    })
    .await?)
}

/// A page of `org`'s audit log (admins).
///
/// # Errors
/// [`AccountError`].
pub async fn audit(
    store: &Store,
    lmk: &Key32,
    cfg: &AccountConfig,
    org: Uuid,
    before: Option<i64>,
    limit: u32,
) -> Result<AuditPage, AccountError> {
    let t = session(store, lmk, cfg).await?;
    Ok(call(&t, |api, tok| async move {
        api.org_audit(&tok, org, before, limit).await
    })
    .await?)
}

#[cfg(test)]
mod tests {
    use super::invite_token;

    #[test]
    fn invite_links() {
        let tok = "AbC-12_x";
        assert_eq!(
            invite_token("https://sync.example/invite/AbC-12_x"),
            Some(tok)
        );
        assert_eq!(
            invite_token(" https://sync.example/invite/AbC-12_x/ "),
            Some(tok)
        );
        assert_eq!(invite_token("AbC-12_x"), Some(tok));
        assert_eq!(invite_token("https://sync.example/invite/"), None);
        assert_eq!(invite_token("not a token!"), None);
        assert_eq!(invite_token(""), None);
    }
}
