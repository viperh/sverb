#!/usr/bin/env python3
"""`unsafe` confinement check (M7-05, SPEC §17).

The workspace lint is `unsafe_code = "deny"` (not `forbid`, which an inner `allow`
cannot lift). Exactly two modules may lift it, each with documented SAFETY comments:

* `crates/sverb-core/src/hardening/` (prctl, setrlimit, mlock, VirtualLock), and
* `crates/sverb-conn/src/agent/dacl_windows.rs` (the agent pipe's owner-only DACL).

This script fails when:

* an attribute lifts the `unsafe_code` lint (`allow`, `expect`, `warn`, or the same
  inside `cfg_attr`) in any `.rs` file outside those paths;
* a crate manifest overrides `unsafe_code` in its own `[lints]` table, or a crate
  does not inherit the workspace lints;
* the workspace level is not `deny` or `forbid`.

Only the Python standard library is used.

Usage: python3 scripts/check-unsafe.py [--root DIR]
Exit code 0 = clean, 1 = violations.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
import tomllib

# Repo-relative, forward slashes. A directory entry ends with "/".
ALLOWED = (
    "crates/sverb-core/src/hardening/",
    "crates/sverb-conn/src/agent/dacl_windows.rs",
)

# `allow(unsafe_code)`, `expect(unsafe_code)`, `warn(unsafe_code)`, also inside a
# list (`allow(dead_code, unsafe_code)`) or `cfg_attr(…, allow(unsafe_code))`.
LIFT = re.compile(r"\b(allow|expect|warn)\s*\(([^()]*\b)?unsafe_code\b")
# Strip string literals and line comments, so tests and documentation that *mention*
# the attribute are not flagged.
STRING = re.compile(r'"(?:[^"\\]|\\.)*"')
LINE_COMMENT = re.compile(r"//.*$")


def allowed(rel: str) -> bool:
    return any(rel.startswith(a) if a.endswith("/") else rel == a for a in ALLOWED)


def scan_sources(root: pathlib.Path) -> list[str]:
    problems = []
    crates = root / "crates"
    for path in sorted(crates.rglob("*.rs")):
        rel = path.relative_to(root).as_posix()
        if "/target/" in f"/{rel}":
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as err:
            problems.append(f"{rel}: unreadable ({err})")
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            code = LINE_COMMENT.sub("", STRING.sub('""', line))
            if LIFT.search(code) and not allowed(rel):
                problems.append(
                    f"{rel}:{lineno}: `unsafe_code` lifted outside the allowed modules: {line.strip()}"
                )
    return problems


def scan_manifests(root: pathlib.Path) -> list[str]:
    problems = []
    workspace = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    level = (
        workspace.get("workspace", {}).get("lints", {}).get("rust", {}).get("unsafe_code")
    )
    if isinstance(level, dict):
        level = level.get("level")
    if level not in ("deny", "forbid"):
        problems.append(f"Cargo.toml: [workspace.lints.rust] unsafe_code is {level!r}, expected \"deny\"")
    for manifest in sorted((root / "crates").glob("*/Cargo.toml")):
        rel = manifest.relative_to(root).as_posix()
        data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        lints = data.get("lints", {})
        if lints.get("workspace") is not True:
            problems.append(f"{rel}: does not inherit the workspace lints (`[lints] workspace = true`)")
        if "unsafe_code" in lints.get("rust", {}):
            problems.append(f"{rel}: overrides `unsafe_code` in its own [lints.rust]")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--root",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parent.parent,
        help="repository root (default: the parent of scripts/)",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    problems = scan_manifests(root) + scan_sources(root)
    if problems:
        print("unsafe confinement check FAILED:", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1
    print(f"unsafe confinement check passed (allowed: {', '.join(ALLOWED)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
