#!/usr/bin/env python3
"""M7-03: writes the PuTTY `.ppk` fixtures of tests/fixtures/putty/keys/.

`puttygen` is not available on the machine the fixtures were made on, so this is an
independent PPK writer (Python's hashlib/hmac plus the `openssl` CLI for AES-256-CBC and
Argon2id) that follows PuTTY's `ppk_save_sb` (sshpubk.c):

- the public blob is the SSH wire public key; the private blobs are
  ed25519: string(seed, little-endian, high zero bytes stripped),
  ecdsa: mpint(d), rsa: mpint(d) mpint(p) mpint(q) mpint(iqmp);
- encrypted blobs are padded to 16 bytes with the SHA-1 of the unpadded blob;
- v2: AES key = SHA1(00000000 || pass) || SHA1(00000001 || pass) (first 32 bytes),
  IV = 0, MAC = HMAC-SHA1 keyed with SHA1("putty-private-key-file-mac-key" || pass);
- v3: Argon2id(pass, salt) -> 80 bytes = AES key (32) || IV (16) || MAC key (32), MAC =
  HMAC-SHA256 (empty MAC key when unencrypted);
- the MAC covers string(alg) string(encryption) string(comment) string(public)
  string(private, decrypted and padded).

The source keys (keys/src_*) are plain OpenSSH keys made with `ssh-keygen -N ""`; the
expected SHA256 fingerprints (fingerprints.txt) come from `ssh-keygen -lf` on them.

Usage (from the repository root): python3 -I tests/fixtures/putty/gen_ppk.py
Encrypted fixtures use the passphrase `fixture`. Salts are fixed so reruns are stable.
"""

import base64
import hashlib
import hmac
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
KEYS = os.path.join(HERE, "keys")
PASS = b"fixture"
ARGON2 = {"memory": 8192, "passes": 2, "parallelism": 1}


def u32(n):
    return struct.pack(">I", n)


def string(b):
    return u32(len(b)) + b


class Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def take(self, n):
        out = self.data[self.pos : self.pos + n]
        if len(out) != n:
            raise ValueError("truncated")
        self.pos += n
        return out

    def u32(self):
        return struct.unpack(">I", self.take(4))[0]

    def string(self):
        return self.take(self.u32())


def read_openssh(path):
    """(alg, public blob, private fields, comment) of an unencrypted OpenSSH key."""
    text = open(path).read()
    body = "".join(l for l in text.splitlines() if not l.startswith("-----"))
    data = base64.b64decode(body)
    magic = b"openssh-key-v1\0"
    assert data.startswith(magic)
    r = Reader(data[len(magic) :])
    assert r.string() == b"none" and r.string() == b"none"
    r.string()
    assert r.u32() == 1
    public = r.string()
    p = Reader(r.string())
    assert p.u32() == p.u32()
    alg = p.string()
    if alg == b"ssh-ed25519":
        p.string()
        seed = p.string()[:32]
        fields = {"seed": seed}
    elif alg.startswith(b"ecdsa-sha2-"):
        p.string()
        p.string()
        fields = {"d": p.string()}
    elif alg == b"ssh-rsa":
        fields = {}
        for name in ("n", "e", "d", "iqmp", "p", "q"):
            fields[name] = p.string()
    else:
        raise ValueError(alg)
    comment = p.string()
    return alg, public, fields, comment


def private_blob(alg, f):
    if alg == b"ssh-ed25519":
        le = f["seed"]  # PuTTY keeps the seed as a little-endian integer
        while le and le[-1] == 0:
            le = le[:-1]
        return string(le)
    if alg.startswith(b"ecdsa-sha2-"):
        return string(f["d"])
    return string(f["d"]) + string(f["p"]) + string(f["q"]) + string(f["iqmp"])


def openssl_aes(key, iv, data):
    out = subprocess.run(
        ["openssl", "enc", "-aes-256-cbc", "-nopad", "-nosalt", "-K", key.hex(), "-iv", iv.hex()],
        input=data,
        capture_output=True,
        check=True,
    )
    return out.stdout


def argon2id(password, salt, length):
    out = subprocess.run(
        [
            "openssl", "kdf", "-keylen", str(length),
            "-kdfopt", "hexpass:" + password.hex(),
            "-kdfopt", "hexsalt:" + salt.hex(),
            "-kdfopt", "memcost:%d" % ARGON2["memory"],
            "-kdfopt", "iter:%d" % ARGON2["passes"],
            "-kdfopt", "lanes:%d" % ARGON2["parallelism"],
            "ARGON2ID",
        ],
        capture_output=True,
        check=True,
        text=True,
    )
    return bytes.fromhex(out.stdout.strip().replace(":", ""))


def lines(b):
    s = base64.b64encode(b).decode()
    return [s[i : i + 64] for i in range(0, len(s), 64)]


def write_ppk(path, version, alg, public, priv, comment, encrypted, salt):
    enc = b"aes256-cbc" if encrypted else b"none"
    if encrypted:
        pad = (-len(priv)) % 16
        priv = priv + hashlib.sha1(priv).digest()[:pad]
    kdf_lines = []
    if version == 2:
        pw = PASS if encrypted else b""
        mac_key = hashlib.sha1(b"putty-private-key-file-mac-key" + pw).digest()
        if encrypted:
            aes_key = (hashlib.sha1(u32(0) + PASS).digest() + hashlib.sha1(u32(1) + PASS).digest())[:32]
            stored = openssl_aes(aes_key, b"\0" * 16, priv)
        else:
            stored = priv
        digest = hashlib.sha1
    else:
        if encrypted:
            k = argon2id(PASS, salt, 80)
            aes_key, iv, mac_key = k[:32], k[32:48], k[48:80]
            stored = openssl_aes(aes_key, iv, priv)
            kdf_lines = [
                "Key-Derivation: Argon2id",
                "Argon2-Memory: %d" % ARGON2["memory"],
                "Argon2-Passes: %d" % ARGON2["passes"],
                "Argon2-Parallelism: %d" % ARGON2["parallelism"],
                "Argon2-Salt: " + salt.hex(),
            ]
        else:
            mac_key = b""
            stored = priv
        digest = hashlib.sha256
    mac_data = string(alg) + string(enc) + string(comment) + string(public) + string(priv)
    mac = hmac.new(mac_key, mac_data, digest).hexdigest()
    pub_lines = lines(public)
    priv_lines = lines(stored)
    out = ["PuTTY-User-Key-File-%d: %s" % (version, alg.decode())]
    out.append("Encryption: " + enc.decode())
    out.append("Comment: " + comment.decode())
    out.append("Public-Lines: %d" % len(pub_lines))
    out += pub_lines
    out += kdf_lines
    out.append("Private-Lines: %d" % len(priv_lines))
    out += priv_lines
    out.append("Private-MAC: " + mac)
    with open(path, "w", newline="\n") as fh:
        fh.write("\n".join(out) + "\n")


def main():
    for i, name in enumerate(("ed25519", "ecdsa256", "rsa2048")):
        alg, public, fields, _ = read_openssh(os.path.join(KEYS, "src_" + name))
        priv = private_blob(alg, fields)
        for version in (2, 3):
            for encrypted in (False, True):
                suffix = "_enc" if encrypted else ""
                comment = ("fixture-%s-v%d%s" % (name, version, suffix)).encode()
                salt = hashlib.sha256(b"sverb-ppk-salt" + comment).digest()[:16]
                path = os.path.join(KEYS, "v%d_%s%s.ppk" % (version, name, suffix))
                write_ppk(path, version, alg, public, priv, comment, encrypted, salt)
                print("wrote", os.path.relpath(path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
