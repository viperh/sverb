//! The OPAQUE configuration shared by the client and the server (§10.4,
//! §11.2).
//!
//! # Cipher suite (defined only here)
//!
//! ```text
//! OPRF: Ristretto255
//! KE:   TripleDh<Ristretto255, Sha512>
//! KSF:  Argon2id(m = 64 MiB, t = 3, p = 1), run on the client
//! ```
//!
//! Both sides use [`SverbSuite`]. The server never runs the KSF: the
//! records it stores and the messages it computes do not depend on the KSF
//! parameters, so the server side is unaffected by the (client-only) cost.
//!
//! # Protocol bindings
//!
//! * **Credential identifier**: [`credential_identifier`] of the account
//!   email (trimmed, lowercased). The server derives the per-user OPRF key
//!   from it, also for unknown emails (the dummy-record path), so repeated
//!   probes for one unknown email look like a stable real account.
//! * **Context**: [`CONTEXT`] (`"sverb/opaque/v1"`) on both sides of the key
//!   exchange.
//! * **Identities**: the OPAQUE defaults (the client and server public keys).
//!
//! # Randomness bridge
//!
//! `opaque-ke` 4.0 is built on the older `rand` 0.8 / `rand_core` 0.6
//! generation (and `curve25519-dalek` 4), while the rest of this crate uses
//! `rand_core` 0.10. The public functions here take our `rand_core` 0.10
//! [`CryptoRng`] like every other function in the crate and adapt it with the
//! private `Rng06` wrapper, which forwards every call to the 0.10 generator.
//! `try_fill_bytes` cannot fail because our generators are infallible
//! (`CryptoRng: Rng<Error = Infallible>`), so no entropy is ever silently
//! dropped. Nothing in the public API exposes `opaque-ke` or `rand` 0.8 types.
//!
//! # Wire format
//!
//! Every message and the stored record are the `opaque-ke` serializations
//! (`RegistrationRequest`, `RegistrationResponse`, `RegistrationUpload` =
//! the record, `CredentialRequest` (KE1), `CredentialResponse` (KE2),
//! `CredentialFinalization` (KE3)), carried as raw bytes.

use opaque_ke::argon2::{Algorithm, Argon2, Params, Version};
use opaque_ke::generic_array::{ArrayLength, GenericArray};
use opaque_ke::ksf::Ksf;
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, Identifiers, RegistrationRequest, RegistrationResponse, RegistrationUpload,
    Ristretto255, ServerLogin, ServerLoginParameters, ServerRegistration, TripleDh,
};
use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::account::EXPORT_KEY_LEN;
use crate::canon::{Canon, Id16};
use crate::error::{CryptoError, Result};

/// Key-exchange context bound into every OPAQUE login (both sides).
pub const CONTEXT: &[u8] = b"sverb/opaque/v1";

/// KSF memory cost in KiB (64 MiB, §10.4).
pub const KSF_M_COST_KIB: u32 = 64 * 1024;
/// KSF time cost (iterations, §10.4).
pub const KSF_T_COST: u32 = 3;
/// KSF parallelism (§10.4).
pub const KSF_P_COST: u32 = 1;

/// Length of the OPAQUE session key (SHA-512 output).
pub const SESSION_KEY_LEN: usize = 64;

const KSF_PARAMS: Params = match Params::new(KSF_M_COST_KIB, KSF_T_COST, KSF_P_COST, None) {
    Ok(p) => p,
    // Evaluated at compile time: constant, valid parameters.
    Err(_) => panic!("invalid Argon2id parameters"),
};

/// The key-stretching function: Argon2id with the §10.4 parameters.
///
/// `Default` is the production configuration. With the
/// `insecure-test-ksf` feature, `SverbKsf::insecure_for_tests()` gives a
/// cheap variant so test suites can run many logins; it produces different
/// export keys and records, and must never be used outside tests.
pub struct SverbKsf(Argon2<'static>);

impl Default for SverbKsf {
    fn default() -> Self {
        Self(Argon2::new(Algorithm::Argon2id, Version::V0x13, KSF_PARAMS))
    }
}

impl core::fmt::Debug for SverbKsf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("SverbKsf").field(self.0.params()).finish()
    }
}

#[cfg(feature = "insecure-test-ksf")]
impl SverbKsf {
    /// Argon2id with 8 KiB and one pass. **Tests only.**
    #[must_use]
    pub fn insecure_for_tests() -> Self {
        const WEAK: Params = match Params::new(8, 1, 1, None) {
            Ok(p) => p,
            Err(_) => panic!("invalid Argon2id parameters"),
        };
        Self(Argon2::new(Algorithm::Argon2id, Version::V0x13, WEAK))
    }
}

impl Ksf for SverbKsf {
    fn hash<L: ArrayLength<u8>>(
        &self,
        input: GenericArray<u8, L>,
    ) -> core::result::Result<GenericArray<u8, L>, opaque_ke::errors::InternalError> {
        self.0.hash(input)
    }
}

/// The sverb OPAQUE cipher suite (see the module docs).
#[derive(Debug, Clone, Copy)]
pub struct SverbSuite;

impl CipherSuite for SverbSuite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, sha2_010::Sha512>;
    type Ksf = SverbKsf;
}

/// Adapts a `rand_core` 0.10 generator to the `rand_core` 0.6 traits that
/// `opaque-ke` 4 expects (see the module docs).
struct Rng06<'a, R: ?Sized>(&'a mut R);

impl<R: CryptoRng + ?Sized> opaque_ke::rand::RngCore for Rng06<'_, R> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }

    fn try_fill_bytes(
        &mut self,
        dest: &mut [u8],
    ) -> core::result::Result<(), opaque_ke::rand::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

impl<R: CryptoRng + ?Sized> opaque_ke::rand::CryptoRng for Rng06<'_, R> {}

/// The OPAQUE credential identifier for an account email: trimmed and
/// lowercased, so it matches the case-insensitive (`CITEXT`) lookup.
#[must_use]
pub fn credential_identifier(email: &str) -> Vec<u8> {
    email.trim().to_lowercase().into_bytes()
}

const MALFORMED: CryptoError = CryptoError::Malformed("OPAQUE message");

fn export_key(bytes: &[u8]) -> Result<Zeroizing<[u8; EXPORT_KEY_LEN]>> {
    let arr: [u8; EXPORT_KEY_LEN] = bytes
        .try_into()
        .map_err(|_| CryptoError::Malformed("OPAQUE export key length"))?;
    Ok(Zeroizing::new(arr))
}

// ---------------------------------------------------------------- client --

/// Client state between registration start and finish.
pub struct ClientRegistrationState(ClientRegistration<SverbSuite>);

impl core::fmt::Debug for ClientRegistrationState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ClientRegistrationState([REDACTED])")
    }
}

/// Output of [`ClientRegistrationState::finish`].
pub struct ClientRegistrationFinish {
    /// `RegistrationUpload`, sent to the server (it becomes the record).
    pub upload: Vec<u8>,
    /// The export key (64 B, stable per password and record; never sent).
    pub export_key: Zeroizing<[u8; EXPORT_KEY_LEN]>,
}

impl core::fmt::Debug for ClientRegistrationFinish {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientRegistrationFinish")
            .field("upload_len", &self.upload.len())
            .field("export_key", &"[REDACTED]")
            .finish()
    }
}

/// Starts a registration: returns the state and the `RegistrationRequest`.
///
/// # Errors
/// [`CryptoError::InvalidParams`] if blinding fails (practically never).
pub fn client_registration_start<R: CryptoRng + ?Sized>(
    rng: &mut R,
    password: &[u8],
) -> Result<(ClientRegistrationState, Vec<u8>)> {
    let res = ClientRegistration::<SverbSuite>::start(&mut Rng06(rng), password)
        .map_err(|_| CryptoError::InvalidParams("OPAQUE registration start"))?;
    Ok((
        ClientRegistrationState(res.state),
        res.message.serialize().to_vec(),
    ))
}

impl ClientRegistrationState {
    /// Finishes a registration with the server's `RegistrationResponse`,
    /// running the KSF (`ksf`, normally `&SverbKsf::default()`).
    ///
    /// # Errors
    /// [`CryptoError::Malformed`] for a malformed response,
    /// [`CryptoError::Auth`] if the server reflected the request.
    pub fn finish<R: CryptoRng + ?Sized>(
        self,
        rng: &mut R,
        password: &[u8],
        response: &[u8],
        ksf: &SverbKsf,
    ) -> Result<ClientRegistrationFinish> {
        let response =
            RegistrationResponse::<SverbSuite>::deserialize(response).map_err(|_| MALFORMED)?;
        let params = ClientRegistrationFinishParameters::new(Identifiers::default(), Some(ksf));
        let res = self
            .0
            .finish(&mut Rng06(rng), password, response, params)
            .map_err(|_| CryptoError::Auth)?;
        Ok(ClientRegistrationFinish {
            upload: res.message.serialize().to_vec(),
            export_key: export_key(&res.export_key)?,
        })
    }
}

/// Client state between login start and finish.
pub struct ClientLoginState(ClientLogin<SverbSuite>);

impl core::fmt::Debug for ClientLoginState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ClientLoginState([REDACTED])")
    }
}

/// Output of [`ClientLoginState::finish`].
pub struct ClientLoginFinish {
    /// `CredentialFinalization` (KE3), sent to the server.
    pub finalization: Vec<u8>,
    /// The export key (equal to the one from registration).
    pub export_key: Zeroizing<[u8; EXPORT_KEY_LEN]>,
    /// The shared session key.
    pub session_key: Zeroizing<[u8; SESSION_KEY_LEN]>,
}

impl core::fmt::Debug for ClientLoginFinish {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientLoginFinish")
            .field("finalization_len", &self.finalization.len())
            .field("export_key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Starts a login: returns the state and the `CredentialRequest` (KE1).
///
/// # Errors
/// [`CryptoError::InvalidParams`] if blinding fails (practically never).
pub fn client_login_start<R: CryptoRng + ?Sized>(
    rng: &mut R,
    password: &[u8],
) -> Result<(ClientLoginState, Vec<u8>)> {
    let res = ClientLogin::<SverbSuite>::start(&mut Rng06(rng), password)
        .map_err(|_| CryptoError::InvalidParams("OPAQUE login start"))?;
    Ok((
        ClientLoginState(res.state),
        res.message.serialize().to_vec(),
    ))
}

impl ClientLoginState {
    /// Finishes a login with the server's `CredentialResponse` (KE2).
    ///
    /// # Errors
    /// [`CryptoError::Auth`] for a wrong password, an unknown account (the
    /// server answered from a dummy record) or a tampered response;
    /// [`CryptoError::Malformed`] for an unparsable response.
    pub fn finish<R: CryptoRng + ?Sized>(
        self,
        rng: &mut R,
        password: &[u8],
        response: &[u8],
        ksf: &SverbKsf,
    ) -> Result<ClientLoginFinish> {
        let response =
            CredentialResponse::<SverbSuite>::deserialize(response).map_err(|_| MALFORMED)?;
        let params =
            ClientLoginFinishParameters::new(Some(CONTEXT), Identifiers::default(), Some(ksf));
        let res = self
            .0
            .finish(&mut Rng06(rng), password, response, params)
            .map_err(|_| CryptoError::Auth)?;
        let session: [u8; SESSION_KEY_LEN] = res
            .session_key
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::Malformed("OPAQUE session key length"))?;
        Ok(ClientLoginFinish {
            finalization: res.message.serialize().to_vec(),
            export_key: export_key(&res.export_key)?,
            session_key: Zeroizing::new(session),
        })
    }
}

// ---------------------------------------------------------------- server --

/// The server's long-term OPAQUE key material (OPRF seed and AKE keypair).
/// Generated once, stored encrypted in `server_secrets`.
pub struct ServerSetup(opaque_ke::ServerSetup<SverbSuite>);

impl core::fmt::Debug for ServerSetup {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ServerSetup([REDACTED])")
    }
}

/// Server state between login start and finish (KE2 state). It contains
/// secrets: store it only server-side and briefly.
pub struct ServerLoginState(ServerLogin<SverbSuite>);

impl core::fmt::Debug for ServerLoginState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ServerLoginState([REDACTED])")
    }
}

impl ServerSetup {
    /// Generates a fresh setup.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        Self(opaque_ke::ServerSetup::new(&mut Rng06(rng)))
    }

    /// Serialization (secret: encrypt before storing).
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.serialize().to_vec())
    }

    /// Parses [`Self::to_bytes`].
    ///
    /// # Errors
    /// [`CryptoError::Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        opaque_ke::ServerSetup::<SverbSuite>::deserialize(bytes)
            .map(Self)
            .map_err(|_| CryptoError::Malformed("OPAQUE server setup"))
    }

    /// Registration step 1: evaluates the client's `RegistrationRequest`
    /// under the per-user OPRF key and returns the `RegistrationResponse`.
    /// Stateless.
    ///
    /// # Errors
    /// [`CryptoError::Malformed`] for a malformed request.
    pub fn registration_start(&self, request: &[u8], credential_id: &[u8]) -> Result<Vec<u8>> {
        let request =
            RegistrationRequest::<SverbSuite>::deserialize(request).map_err(|_| MALFORMED)?;
        let res = ServerRegistration::<SverbSuite>::start(&self.0, request, credential_id)
            .map_err(|_| MALFORMED)?;
        Ok(res.message.serialize().to_vec())
    }

    /// Login step 1: computes KE2. `record` is the stored registration
    /// record, or `None` for an unknown account, in which case a dummy
    /// record is used and the response is indistinguishable from a real one
    /// (§10.4 enumeration resistance).
    ///
    /// Returns the `CredentialResponse` and the state for
    /// [`ServerLoginState::finish`].
    ///
    /// # Errors
    /// [`CryptoError::Malformed`] for a malformed request or record.
    pub fn login_start<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        record: Option<&[u8]>,
        request: &[u8],
        credential_id: &[u8],
    ) -> Result<(Vec<u8>, ServerLoginState)> {
        let request =
            CredentialRequest::<SverbSuite>::deserialize(request).map_err(|_| MALFORMED)?;
        let record = record
            .map(ServerRegistration::<SverbSuite>::deserialize)
            .transpose()
            .map_err(|_| CryptoError::Malformed("OPAQUE record"))?;
        let params = ServerLoginParameters {
            context: Some(CONTEXT),
            identifiers: Identifiers::default(),
        };
        let res = ServerLogin::start(
            &mut Rng06(rng),
            &self.0,
            record,
            request,
            credential_id,
            params,
        )
        .map_err(|_| MALFORMED)?;
        Ok((
            res.message.serialize().to_vec(),
            ServerLoginState(res.state),
        ))
    }
}

/// Registration step 2: validates the client's `RegistrationUpload` and
/// returns the record to store.
///
/// # Errors
/// [`CryptoError::Malformed`] for a malformed upload.
pub fn registration_finish(upload: &[u8]) -> Result<Vec<u8>> {
    let upload = RegistrationUpload::<SverbSuite>::deserialize(upload)
        .map_err(|_| CryptoError::Malformed("OPAQUE registration upload"))?;
    Ok(ServerRegistration::finish(upload).serialize().to_vec())
}

impl ServerLoginState {
    /// Serialization (secret: keep server-side, encrypted at rest).
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.serialize().to_vec())
    }

    /// Parses [`Self::to_bytes`].
    ///
    /// # Errors
    /// [`CryptoError::Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ServerLogin::<SverbSuite>::deserialize(bytes)
            .map(Self)
            .map_err(|_| CryptoError::Malformed("OPAQUE login state"))
    }

    /// Login step 2: checks the client's KE3. Success proves the client
    /// knows the password for the record used in [`ServerSetup::login_start`];
    /// with a dummy record it always fails.
    ///
    /// # Errors
    /// [`CryptoError::Auth`] when authentication fails,
    /// [`CryptoError::Malformed`] for an unparsable message.
    pub fn finish(self, finalization: &[u8]) -> Result<Zeroizing<[u8; SESSION_KEY_LEN]>> {
        let msg = CredentialFinalization::<SverbSuite>::deserialize(finalization)
            .map_err(|_| MALFORMED)?;
        let params = ServerLoginParameters {
            context: Some(CONTEXT),
            identifiers: Identifiers::default(),
        };
        let res = self.0.finish(msg, params).map_err(|_| CryptoError::Auth)?;
        let session: [u8; SESSION_KEY_LEN] = res
            .session_key
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::Malformed("OPAQUE session key length"))?;
        Ok(Zeroizing::new(session))
    }
}

// ------------------------------------------------------- recovery proof --

/// The message a client signs with its account Ed25519 key to prove, during
/// the recovery flow (§10.4 `POST /v1/account/recovery`), that it opened the
/// recovery bundle (sverb proposal; the spec leaves recovery authentication
/// open):
///
/// ```text
/// "sverb/recovery-proof/v1" || user_id(16) || new_version(u32 BE)
///   || u32 len || registration_upload || u32 len || private_bundle_enc
/// ```
#[must_use]
pub fn recovery_proof_message(
    user_id: &Id16,
    new_version: u32,
    registration_upload: &[u8],
    private_bundle_enc: &[u8],
) -> Vec<u8> {
    Canon::with_label("sverb/recovery-proof/v1")
        .id(user_id)
        .u32(new_version)
        .bytes(registration_upload)
        .bytes(private_bundle_enc)
        .finish()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn ksf_parameters_match_the_spec() {
        let ksf = SverbKsf::default();
        let p = ksf.0.params();
        assert_eq!((p.m_cost(), p.t_cost(), p.p_cost()), (65536, 3, 1));
    }

    #[test]
    fn credential_identifier_is_case_insensitive() {
        assert_eq!(
            credential_identifier(" Alice@Example.com "),
            credential_identifier("alice@example.COM")
        );
    }

    #[test]
    fn recovery_proof_is_length_prefixed() {
        let a = recovery_proof_message(&[1; 16], 2, b"ab", b"c");
        let b = recovery_proof_message(&[1; 16], 2, b"a", b"bc");
        assert_ne!(a, b);
    }
}
