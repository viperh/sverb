#!/usr/bin/env python3
"""cargo-vet crypto policy (M0-02 §2.3, SPEC §17).

Crates in the SPEC Appendix A "Crypto" row must be vetted `safe-to-deploy`
through an imported or our own audit. `cargo vet` accepts exemptions, so this
script fails when any of them appears in `[exemptions]`. Run it after
`cargo vet --locked`, which proves the remaining (audited) entries hold.

Usage: python3 scripts/check-vet-crypto.py [supply-chain/config.toml]
"""

from __future__ import annotations

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
        print(
            "crypto crates must be audited safe-to-deploy, not exempted "
            f"(SPEC §17): {', '.join(exempted)}\n"
            "Import an audit (cargo vet suggest) or certify one (cargo vet certify).",
            file=sys.stderr,
        )
        return 1
    print("cargo-vet crypto policy OK: no crypto crate is exempted")
    return 0


if __name__ == "__main__":
    sys.exit(main())
