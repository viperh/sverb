//! Settings views (synced mode adds Sync and Team pages).

// M5-03: Settings → Team: safety numbers, ✓ verification, key-change warnings
// (§13.3). Sync builds only (team features need an account).
#[cfg(feature = "sync")]
pub mod team_verify;
