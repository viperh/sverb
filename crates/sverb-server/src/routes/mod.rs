//! Route modules. Each later task adds a module here and merges its router
//! into [`api_v1`] (`/v1/...`, SPEC §10.4).

// M4-02: authentication, account and device routes.
pub mod account;
pub mod auth;
pub mod devices;
pub mod ops;
// M4-04: vault list, pull and push.
pub mod vaults;
// M5-01: orgs, members, invites, the audit log, user public keys.
pub mod orgs;
// M5-02: shared vault members and org vault listings.
pub mod shared_vaults;
// M5-04: vault key rotation.
pub mod rotate;

use axum::Router;

use crate::state::AppState;

/// The versioned API, nested under `/v1` by [`crate::app::routes`].
///
/// M4-02 adds `auth`, `account` and `devices`; M4-04 `vaults`; M4-05 `ws`;
/// M5-01 `orgs`/`invites`; M6-01 `shares`.
pub fn api_v1() -> Router<AppState> {
    Router::new()
        // M4-02
        .merge(auth::router())
        .merge(account::router())
        .merge(devices::router())
        // M4-04
        .merge(vaults::router())
        // M4-05
        .merge(crate::ws::router())
        // M6-01
        .merge(crate::share::router())
        // M5-01
        .merge(orgs::router())
        // M5-02
        .merge(shared_vaults::router())
        // M5-04
        .merge(rotate::router())
}
