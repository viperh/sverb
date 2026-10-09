//! `.sverb-backup` files (header, KDF parameter checks, base64 fields) and the
//! authenticated plaintext (capped zstd + CBOR, then the import plan), without running
//! Argon2 (`sverb_core::importers::backup::fuzz_backup_decrypt`; property-tested in
//! `sverb-core` `importers::tests`).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    sverb_core::importers::backup::fuzz_backup_decrypt(data);
});
