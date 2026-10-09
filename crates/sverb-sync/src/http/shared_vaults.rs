//! M5-02: the shared vault endpoints of [`ApiClient`] (SPEC §10.4, §13.2; DTOs
//! in [`sverb_proto::vaults`]).

use sverb_proto::sync::VaultView;
use sverb_proto::vaults::{CreateVaultRequest, GrantRequest, OrgVaultView, VaultMembersView};
use uuid::Uuid;

use super::ApiClient;
use crate::error::SyncError;

impl ApiClient {
    /// `POST /v1/vaults`: creates a shared vault (org admin+).
    ///
    /// # Errors
    /// [`SyncError::Api`] (`403`, `404`, `409`) / [`SyncError::Transport`].
    pub async fn create_vault(
        &self,
        token: &str,
        req: &CreateVaultRequest,
    ) -> Result<VaultView, SyncError> {
        self.post_json("/vaults", req, Some(token)).await
    }

    /// `GET /v1/vaults/{id}/members`.
    ///
    /// # Errors
    /// [`SyncError::Api`] (`404`) / [`SyncError::Transport`].
    pub async fn vault_members(
        &self,
        token: &str,
        vault: Uuid,
    ) -> Result<VaultMembersView, SyncError> {
        let rb = self.authed(
            self.http.get(self.url(&format!("/vaults/{vault}/members"))),
            token,
        );
        self.send(rb).await
    }

    /// `PUT /v1/vaults/{id}/members/{user}`: grant or change access.
    ///
    /// # Errors
    /// [`SyncError::Api`] (`403`, `400`, `409 rotating`) / [`SyncError::Transport`].
    pub async fn grant_vault_member(
        &self,
        token: &str,
        vault: Uuid,
        user: Uuid,
        req: &GrantRequest,
    ) -> Result<(), SyncError> {
        let url = self.url(&format!("/vaults/{vault}/members/{user}"));
        let rb = self.authed(self.http.put(url).json(req), token);
        self.fetch(rb).await.map(drop)
    }

    /// `DELETE /v1/vaults/{id}/members/{user}` (also leaving: `user` = self).
    ///
    /// # Errors
    /// [`SyncError::Api`] (`403`, `404`) / [`SyncError::Transport`].
    pub async fn revoke_vault_member(
        &self,
        token: &str,
        vault: Uuid,
        user: Uuid,
    ) -> Result<(), SyncError> {
        let url = self.url(&format!("/vaults/{vault}/members/{user}"));
        let rb = self.authed(self.http.delete(url), token);
        self.fetch(rb).await.map(drop)
    }

    /// `GET /v1/orgs/{id}/vaults`: the org's vaults visible to the caller.
    ///
    /// # Errors
    /// [`SyncError::Api`] (`404`) / [`SyncError::Transport`].
    pub async fn org_vaults(&self, token: &str, org: Uuid) -> Result<Vec<OrgVaultView>, SyncError> {
        let rb = self.authed(
            self.http.get(self.url(&format!("/orgs/{org}/vaults"))),
            token,
        );
        self.send(rb).await
    }
}
