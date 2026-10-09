#!/usr/bin/env python3
"""cargo-vet crypto policy (M0-02 §2.3, SPEC §17).

Crates in the SPEC Appendix A "Crypto" row should be vetted `safe-to-deploy`
through an imported or our own audit. Until those audits exist they are exempted
(decision of 2026-10-09), so this script reports every exempted crypto crate as a
CI warning instead of failing. Set VET_CRYPTO_STRICT=1 to make it fail again once
the audits are in. Run it after `cargo vet --locked`.

Usage: python3 scripts/check-vet-crypto.py [supply-chain/config.toml]
"""

from __future__ import annotations

import os
import sys
import tomllib

# SPEC Appendix A, "Crypto" row. Their RustCrypto building blocks (digest,
# hmac, aead, ...) may stay exempted for now; the list is reviewed each milestone.
CRYPTO = {
    "chacha20poly1305",
    "argon2",
    "hkdf",
    "sha2",
    "hpke",
    "opaque-ke",
    "x25519-dalek",
    "ed25519-dalek",
    "rand_core",
    "zeroize",
    "secrecy",
    "bip39",
    "zxcvbn",
}


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else "supply-chain/config.toml"
    with open(path, "rb") as fh:
        config = tomllib.load(fh)
    exempted = sorted(set(config.get("exemptions", {})) & CRYPTO)
    if exempted:
        message = (
            "crypto crates are exempted, not audited (SPEC §17): "
            f"{', '.join(exempted)}. Import an audit (cargo vet suggest) or certify one "
            "(cargo vet certify)."
        )
        if os.environ.get("VET_CRYPTO_STRICT") == "1":
            print(message, file=sys.stderr)
            return 1
        print(f"::warning::{message}")
        return 0
    print("cargo-vet crypto policy OK: no crypto crate is exempted")
    return 0


if __name__ == "__main__":
    sys.exit(main())
