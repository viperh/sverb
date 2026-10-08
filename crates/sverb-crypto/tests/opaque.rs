//! M4-02: the shared OPAQUE suite, client against server, in-process.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use sverb_crypto::account::derive_akek;
use sverb_crypto::opaque::{
    ServerLoginState, ServerSetup, SverbKsf, client_login_start, client_registration_start,
    credential_identifier, registration_finish,
};
use sverb_crypto::random::os_rng;

const EMAIL: &str = "Alice@Example.com";

/// Registers `password` and returns the stored record and the export key.
fn register(setup: &ServerSetup, password: &[u8], ksf: &SverbKsf) -> (Vec<u8>, [u8; 64]) {
    let mut rng = os_rng();
    let (state, request) = client_registration_start(&mut rng, password).unwrap();
    let response = setup
        .registration_start(&request, &credential_identifier(EMAIL))
        .unwrap();
    let fin = state.finish(&mut rng, password, &response, ksf).unwrap();
    let record = registration_finish(&fin.upload).unwrap();
    (record, *fin.export_key)
}

/// Runs a login; `Ok(export_key)` only if both sides accept.
fn login(
    setup: &ServerSetup,
    record: Option<&[u8]>,
    email: &str,
    password: &[u8],
    ksf: &SverbKsf,
) -> Result<[u8; 64], &'static str> {
    let mut rng = os_rng();
    let (client, ke1) = client_login_start(&mut rng, password).unwrap();
    let (ke2, server) = setup
        .login_start(&mut rng, record, &ke1, &credential_identifier(email))
        .unwrap();
    // The server keeps its state in Postgres between the two requests.
    let server = ServerLoginState::from_bytes(&server.to_bytes()).unwrap();
    let fin = client
        .finish(&mut rng, password, &ke2, ksf)
        .map_err(|_| "client rejected KE2")?;
    let server_key = server
        .finish(&fin.finalization)
        .map_err(|_| "server rejected KE3")?;
    assert_eq!(*server_key, *fin.session_key);
    Ok(*fin.export_key)
}

/// T-01 (crypto half): the real §10.4 suite, including the 64 MiB Argon2id
/// KSF. `export_key` is stable across registration and login.
#[test]
fn register_then_login_with_the_production_ksf() {
    let ksf = SverbKsf::default();
    let setup = ServerSetup::from_bytes(&ServerSetup::generate(&mut os_rng()).to_bytes()).unwrap();
    let (record, reg_export) = register(&setup, b"correct horse battery staple", &ksf);
    let login_export = login(
        &setup,
        Some(&record),
        "alice@example.com", // case-insensitive credential identifier
        b"correct horse battery staple",
        &ksf,
    )
    .unwrap();
    assert_eq!(reg_export, login_export);
    // AKEK derivation (M4-03) is therefore stable too.
    assert_eq!(
        derive_akek(&reg_export).expose_secret(),
        derive_akek(&login_export).expose_secret()
    );
    // Wrong password: the client cannot open the envelope.
    assert!(login(&setup, Some(&record), EMAIL, b"wrong", &ksf).is_err());
}

#[test]
fn unknown_account_gets_a_valid_looking_ke2_and_fails() {
    let setup = ServerSetup::generate(&mut os_rng());
    let ksf = SverbKsf::default();
    let mut rng = os_rng();
    let (_, ke1) = client_login_start(&mut rng, b"pw").unwrap();
    let (real_record, _) = register(&setup, b"pw", &ksf);
    let (ke2_dummy, _) = setup
        .login_start(
            &mut rng,
            None,
            &ke1,
            &credential_identifier("nobody@example.com"),
        )
        .unwrap();
    let (ke2_real, _) = setup
        .login_start(
            &mut rng,
            Some(&real_record),
            &ke1,
            &credential_identifier(EMAIL),
        )
        .unwrap();
    assert_eq!(ke2_dummy.len(), ke2_real.len());
    assert!(login(&setup, None, "nobody@example.com", b"pw", &ksf).is_err());
}

#[test]
fn malformed_inputs_are_errors_not_panics() {
    let setup = ServerSetup::generate(&mut os_rng());
    assert!(setup.registration_start(b"short", b"id").is_err());
    assert!(
        setup
            .login_start(&mut os_rng(), None, &[0; 3], b"id")
            .is_err()
    );
    assert!(registration_finish(&[0xff; 10]).is_err());
    assert!(ServerSetup::from_bytes(&[1, 2, 3]).is_err());
    assert!(ServerLoginState::from_bytes(&[]).is_err());
}

#[test]
fn setups_are_distinct() {
    let a = ServerSetup::generate(&mut os_rng()).to_bytes();
    let b = ServerSetup::generate(&mut os_rng()).to_bytes();
    assert_ne!(*a, *b);
}
