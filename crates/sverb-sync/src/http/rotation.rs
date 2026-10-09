//! M5-04: `POST /v1/vaults/{id}/rotate` (SPEC §13.2; DTOs in
//! [`sverb_proto::rotation`]).

use sverb_proto::rotation::{RotateRequest, RotateResponse};
use uuid::Uuid;

use super::ApiClient;
use crate::error::SyncError;

impl ApiClient {
    /// One rotate action (`begin`, `upload` or `commit`).
    ///
    /// # Errors
    /// [`SyncError::Api`] (`400`, `403`, `404`, `409 rotating`) /
    /// [`SyncError::Transport`].
    pub async fn rotate(
        &self,
        token: &str,
        vault: Uuid,
        req: &RotateRequest,
    ) -> Result<RotateResponse, SyncError> {
        self.post_json(&format!("/vaults/{vault}/rotate"), req, Some(token))
            .await
    }
}
