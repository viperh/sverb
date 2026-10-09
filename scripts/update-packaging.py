#!/usr/bin/env python3
"""M7-07: set the release version and checksums in the package-channel files.

    scripts/update-packaging.py <version> <SHA256SUMS> [--source-sha256 <hex>] [--out <dir>]

<SHA256SUMS> is the release's checksum file (`<sha256>  <archive name>` per line, as
written by scripts/release-package.sh and collected by cd.yml). `--source-sha256` is the
checksum of GitHub's source tarball for the tag (`archive/refs/tags/v<version>.tar.gz`),
used by the from-source AUR package; without it that package keeps its old checksum
and a warning is printed.

The files under packaging/ (AUR PKGBUILDs, Homebrew formula, Scoop manifest) are
rewritten in place, or copied to `--out <dir>` (same relative paths) and rewritten
there. Nothing is downloaded; run `--self-test` to check the rewriting offline.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILES = [
    "packaging/aur/sverb/PKGBUILD",
    "packaging/aur/sverb-bin/PKGBUILD",
    "packaging/homebrew/sverb.rb",
    "packaging/scoop/sverb.json",
]
SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")


def read_sums(path: Path) -> dict[str, str]:
    sums = {}
    for line in path.read_text().splitlines():
        parts = line.split()
        if len(parts) == 2 and re.fullmatch(r"[0-9a-f]{64}", parts[0]):
            sums[parts[1].lstrip("*")] = parts[0]
    return sums


def need(sums: dict[str, str], name: str) -> str:
    if name not in sums:
        raise SystemExit(f"error: {name} is missing from the checksum file")
    return sums[name]


def sub1(pattern: str, repl: str, text: str, what: str) -> str:
    new, n = re.subn(pattern, repl, text, flags=re.M)
    if n == 0:
        raise SystemExit(f"error: {what}: pattern not found: {pattern}")
    return new


def update(base: Path, version: str, sums: dict[str, str], source_sha: str | None) -> None:
    v = version
    linux_x64 = f"sverb-{v}-linux-x86_64.tar.gz"
    linux_arm = f"sverb-{v}-linux-aarch64.tar.gz"
    macos = f"sverb-{v}-macos-universal.tar.gz"
    windows = f"sverb-{v}-windows-x86_64.zip"

    # AUR, from source.
    p = base / "packaging/aur/sverb/PKGBUILD"
    t = p.read_text()
    t = sub1(r"^pkgver=.*$", f"pkgver={v}", t, p.name)
    t = sub1(r"^pkgrel=.*$", "pkgrel=1", t, p.name)
    if source_sha:
        t = sub1(r"^sha256sums=\('[0-9a-f]*'\)$", f"sha256sums=('{source_sha}')", t, p.name)
    else:
        print("warning: no --source-sha256; packaging/aur/sverb keeps its checksum", file=sys.stderr)
    p.write_text(t)

    # AUR, prebuilt.
    p = base / "packaging/aur/sverb-bin/PKGBUILD"
    t = p.read_text()
    t = sub1(r"^pkgver=.*$", f"pkgver={v}", t, p.name)
    t = sub1(r"^pkgrel=.*$", "pkgrel=1", t, p.name)
    t = sub1(r"^sha256sums_x86_64=\('[0-9a-f]*'\)$", f"sha256sums_x86_64=('{need(sums, linux_x64)}')", t, p.name)
    t = sub1(r"^sha256sums_aarch64=\('[0-9a-f]*'\)$", f"sha256sums_aarch64=('{need(sums, linux_arm)}')", t, p.name)
    p.write_text(t)

    # Homebrew: version, then each url line and the sha256 line after it.
    p = base / "packaging/homebrew/sverb.rb"
    t = p.read_text()
    t = sub1(r'^(\s*)version ".*"$', rf'\g<1>version "{v}"', t, p.name)
    for label, archive in (("macos-universal", macos), ("linux-x86_64", linux_x64), ("linux-aarch64", linux_arm)):
        t = sub1(
            rf'^(\s*)url "(.*?)/download/v[^/]+/sverb-[^"]*-{label}\.tar\.gz"\n(\s*)sha256 "[0-9a-f]*"$',
            rf'\g<1>url "\g<2>/download/v{v}/{archive}"\n\g<3>sha256 "{need(sums, archive)}"',
            t,
            f"{p.name} ({label})",
        )
    p.write_text(t)

    # Scoop.
    p = base / "packaging/scoop/sverb.json"
    data = json.loads(p.read_text())
    data["version"] = v
    arch = data["architecture"]["64bit"]
    arch["url"] = f"https://github.com/viperh/sverb/releases/download/v{v}/{windows}"
    arch["hash"] = need(sums, windows)
    arch["extract_dir"] = windows.removesuffix(".zip")
    p.write_text(json.dumps(data, indent=4) + "\n")


def self_test() -> int:
    with tempfile.TemporaryDirectory(dir=ROOT / "target" if (ROOT / "target").is_dir() else None) as tmp:
        base = Path(tmp)
        for f in FILES:
            (base / f).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT / f, base / f)
        v = "9.8.7"
        names = [
            f"sverb-{v}-linux-x86_64.tar.gz",
            f"sverb-{v}-linux-aarch64.tar.gz",
            f"sverb-{v}-macos-universal.tar.gz",
            f"sverb-{v}-windows-x86_64.zip",
        ]
        sums = {n: f"{i + 1:x}" * 64 for i, n in enumerate(names)}
        update(base, v, sums, "f" * 64)
        texts = {f: (base / f).read_text() for f in FILES}
        assert "pkgver=9.8.7" in texts[FILES[0]] and "f" * 64 in texts[FILES[0]]
        assert "1" * 64 in texts[FILES[1]] and "2" * 64 in texts[FILES[1]]
        rb = texts[FILES[2]]
        assert 'version "9.8.7"' in rb
        for n, s in sums.items():
            if n.endswith(".tar.gz"):
                assert f"/download/v{v}/{n}\"\n" in rb and s in rb, n
        scoop = json.loads(texts[FILES[3]])
        assert scoop["version"] == v and scoop["architecture"]["64bit"]["hash"] == "4" * 64
        assert scoop["architecture"]["64bit"]["extract_dir"] == f"sverb-{v}-windows-x86_64"
        # A second run with the same inputs changes nothing.
        update(base, v, sums, "f" * 64)
        assert texts == {f: (base / f).read_text() for f in FILES}
    print("update-packaging self-test: ok")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("version", nargs="?")
    ap.add_argument("sums", nargs="?", type=Path)
    ap.add_argument("--source-sha256")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    if not args.version or not args.sums:
        ap.error("version and SHA256SUMS are required")
    version = args.version.removeprefix("v")
    if not SEMVER.match(version):
        ap.error(f"not a version: {args.version}")
    if args.source_sha256 and not re.fullmatch(r"[0-9a-f]{64}", args.source_sha256):
        ap.error("--source-sha256 must be 64 hex digits")
    base = ROOT
    if args.out:
        base = args.out
        for f in FILES:
            (base / f).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT / f, base / f)
    update(base, version, read_sums(args.sums), args.source_sha256)
    for f in FILES:
        print(base / f)
    return 0


if __name__ == "__main__":
    sys.exit(main())
