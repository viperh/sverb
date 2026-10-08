//! Opening vault grants with the account keys (§11.3): the HPKE
//! implementation of the engine's [`VaultKeySource`] (M4-07).
//!
//! A grant is used only after its Ed25519 signature verifies against a
//! granter key the client trusts. The account's own key is always trusted
//! (personal-vault self-grants, §11.3); keys of other users come from a
//! [`TrustedGranters`] lookup (TOFU pinning and safety numbers, M5-03). With
//! no lookup, grants by other users are refused.

use std::fmt;
use std::sync::Arc;

use sverb_crypto::Key32;
use sverb_crypto::account::AccountKeys;
use sverb_crypto::grant::{Grant, verify_and_open_grant};
use sverb_crypto::sign::SIGNATURE_LEN;
use sverb_proto::sync::VaultView;
use uuid::Uuid;

use crate::keys::VaultKeySource;

/// The Ed25519 public key of a granter the client trusts (M5-03).
pub trait TrustedGranters: Send + Sync + fmt::Debug {
    /// The trusted key of `user`, or `None` (grant refused).
    fn ed25519_pub(&self, user: Uuid) -> Option<[u8; 32]>;
}

/// Opens grants addressed to this account.
#[derive(Clone)]
pub struct GrantKeySource {
    user_id: Uuid,
    keys: Arc<AccountKeys>,
    trusted: Option<Arc<dyn TrustedGranters>>,
}

impl fmt::Debug for GrantKeySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrantKeySource")
            .field("user_id", &self.user_id)
            .field("trusted", &self.trusted)
            .finish_non_exhaustive()
    }
}

impl GrantKeySource {
    /// A source for account `user_id` holding `keys`.
    #[must_use]
    pub fn new(user_id: Uuid, keys: AccountKeys) -> Self {
        Self {
            user_id,
            keys: Arc::new(keys),
            trusted: None,
        }
    }

    /// Also accepts grants signed by users `trusted` vouches for.
    #[must_use]
    pub fn with_trusted(mut self, trusted: Arc<dyn TrustedGranters>) -> Self {
        self.trusted = Some(trusted);
        self
    }

    /// The account keys.
    #[must_use]
    pub fn keys(&self) -> &AccountKeys {
        &self.keys
    }

    /// Verifies and opens the grant for key `version` in `view`.
    ///
    /// # Errors
    /// A description: no grant for that version, untrusted granter, bad
    /// signature, or a wrap that does not open.
    pub fn open(&self, view: &VaultView, version: u32) -> Result<Key32, String> {
        let g = view
            .grants
            .iter()
            .find(|g| g.key_version == version)
            .ok_or_else(|| format!("no grant for key version {version}"))?;
        let granter = if g.wrapped_by == self.user_id {
            self.keys.public().ed25519
        } else {
            self.trusted
                .as_ref()
                .and_then(|t| t.ed25519_pub(g.wrapped_by))
                .ok_or_else(|| format!("grant signed by an untrusted user {}", g.wrapped_by))?
        };
        let signature: [u8; SIGNATURE_LEN] = g
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| "grant signature length".to_owned())?;
        let grant = Grant {
            wrapped: g.wrapped_vault_key.clone(),
            signature,
        };
        verify_and_open_grant(
            &grant,
            view.id.as_bytes(),
            version,
            self.user_id.as_bytes(),
            &self.keys,
            &granter,
        )
        .map_err(|e| e.to_string())
    }
}

impl VaultKeySource for GrantKeySource {
    fn open_grant(&self, view: &VaultView, version: u32) -> Option<Key32> {
        match self.open(view, version) {
            Ok(k) => Some(k),
            Err(e) => {
                tracing::warn!(vault = %view.id, version, error = %e, "vault grant refused");
                None
            }
        }
    }
}
