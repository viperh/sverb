#!/usr/bin/env python3
"""Crate layering check (M0-02, rules from M0-01 §2.3 / SPEC §3).

Reads `cargo metadata` and fails when a workspace crate breaks the dependency
direction:

* direct internal (`sverb-*`) dependencies must be in the crate's allow list;
* the transitive closure of *normal* dependencies (dev/build deps ignored, all
  target platforms included) must not contain a forbidden crate;
* the local-only build (`--no-default-features`, SPEC §1.1) of `sverb` and
  `sverb-tui` must not contain `sverb-sync`, and `sverb-sync` may only be an
  optional dependency of those two crates.

The graph is checked twice: with `--all-features` (worst case) and with
`--no-default-features` (local-only). Only the Python standard library is
used, so the script runs on any CI image with `cargo` and `python3`.

Usage: python3 scripts/check-layering.py [--manifest-path Cargo.toml]
Exit code 0 = clean, 1 = violations, 2 = could not run cargo metadata.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys

INTERNAL_PREFIX = "sverb"

# Crates that put a UI on the screen. Only the TUI layer may pull them in.
UI = {"ratatui", "crossterm"}

# crate -> (allowed direct internal deps or None for "any", forbidden transitive deps)
RULES: dict[str, tuple[set[str] | None, set[str]]] = {
    "sverb-crypto": (
        set(),
        UI | {"ratatui-core", "tokio", "rusqlite", "russh", "portable-pty", "mio"},
    ),
    "sverb-proto": ({"sverb-crypto"}, UI | {"rusqlite", "russh"}),
    "sverb-core": ({"sverb-crypto", "sverb-proto"}, UI | {"clap"}),
    "sverb-store": ({"sverb-core", "sverb-crypto"}, UI),
    "sverb-conn": ({"sverb-core", "sverb-term"}, UI),
    "sverb-term": ({"sverb-core", "sverb-crypto"}, {"crossterm"}),
    "sverb-sync": (
        {"sverb-core", "sverb-store", "sverb-proto", "sverb-crypto"},
        UI,
    ),
    # Everything client-side; sverb-sync only behind feature `sync` (checked below).
    "sverb-tui": (
        {
            "sverb-core",
            "sverb-crypto",
            "sverb-proto",
            "sverb-store",
            "sverb-conn",
            "sverb-term",
            "sverb-sync",
        },
        {"sverb-server"},
    ),
    "sverb-server": (
        {"sverb-proto", "sverb-crypto"},
        UI
        | {"russh", "rusqlite"}
        | {
            "sverb-core",
            "sverb-store",
            "sverb-conn",
            "sverb-term",
            "sverb-tui",
            "sverb-sync",
        },
    ),
    "sverb-e2e": (None, set()),
    "sverb": (None, set()),
}

# Crates that may depend on sverb-sync, and only optionally (feature `sync`).
SYNC_OPTIONAL_IN = {"sverb", "sverb-tui"}
LOCAL_ONLY_ROOTS = {"sverb", "sverb-tui"}


def metadata(manifest: str | None, features: str) -> dict:
    cmd = ["cargo", "metadata", "--format-version", "1", "--locked", features]
    if manifest:
        cmd += ["--manifest-path", manifest]
    try:
        out = subprocess.run(cmd, check=True, capture_output=True, text=True)
    except (OSError, subprocess.CalledProcessError) as err:
        stderr = getattr(err, "stderr", "") or ""
        print(f"error: `{' '.join(cmd)}` failed: {err}\n{stderr}", file=sys.stderr)
        sys.exit(2)
    return json.loads(out.stdout)


def normal_graph(meta: dict) -> tuple[dict[str, str], dict[str, set[str]]]:
    """Return (package id -> name, package id -> ids of normal deps)."""
    names = {p["id"]: p["name"] for p in meta["packages"]}
    edges: dict[str, set[str]] = {}
    for node in meta["resolve"]["nodes"]:
        deps = set()
        for dep in node.get("deps", []):
            kinds = dep.get("dep_kinds") or [{"kind": None}]
            if any(k.get("kind") is None for k in kinds):
                deps.add(dep["pkg"])
        edges[node["id"]] = deps
    return names, edges


def closure(root: str, edges: dict[str, set[str]]) -> set[str]:
    seen: set[str] = set()
    stack = list(edges.get(root, ()))
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        stack.extend(edges.get(cur, ()))
    return seen


def path_to(root: str, target: str, edges: dict[str, set[str]], names) -> str:
    """Shortest dependency path root -> target, for readable errors."""
    prev = {root: None}
    queue = [root]
    while queue:
        cur = queue.pop(0)
        if cur == target:
            break
        for nxt in sorted(edges.get(cur, ())):
            if nxt not in prev:
                prev[nxt] = cur
                queue.append(nxt)
    chain = []
    cur = target
    while cur is not None and cur in prev:
        chain.append(names[cur])
        cur = prev[cur]
    return " -> ".join(reversed(chain))


def check(meta: dict, label: str, local_only: bool) -> list[str]:
    errors: list[str] = []
    names, edges = normal_graph(meta)
    members = {pid: names[pid] for pid in meta["workspace_members"]}

    for pid, name in sorted(members.items(), key=lambda kv: kv[1]):
        if name not in RULES:
            errors.append(
                f"[{label}] {name}: workspace crate has no layering rule; "
                "add it to RULES in scripts/check-layering.py"
            )
            continue
        allowed, forbidden = RULES[name]
        direct = {names[d] for d in edges.get(pid, ())}

        if allowed is not None:
            for dep in sorted(direct):
                if dep.startswith(INTERNAL_PREFIX) and dep not in allowed:
                    errors.append(
                        f"[{label}] {name} must not depend on {dep} "
                        f"(allowed internal deps: {sorted(allowed) or 'none'})"
                    )

        reach = closure(pid, edges)
        for dep_id in sorted(reach, key=lambda i: names[i]):
            if names[dep_id] in forbidden:
                errors.append(
                    f"[{label}] {name} must not (transitively) depend on "
                    f"{names[dep_id]}: {path_to(pid, dep_id, edges, names)}"
                )

        if local_only and name in LOCAL_ONLY_ROOTS:
            for dep_id in reach:
                if names[dep_id] == "sverb-sync":
                    errors.append(
                        f"[{label}] local-only build of {name} links sverb-sync "
                        f"(SPEC §1.1): {path_to(pid, dep_id, edges, names)}"
                    )

    # sverb-sync may only be an *optional* dependency of sverb / sverb-tui.
    for pkg in meta["packages"]:
        if pkg["id"] not in members:
            continue
        for dep in pkg["dependencies"]:
            if dep["name"] != "sverb-sync" or dep.get("kind") is not None:
                continue
            if pkg["name"] in SYNC_OPTIONAL_IN and not dep.get("optional"):
                errors.append(
                    f"[{label}] {pkg['name']} depends on sverb-sync "
                    "unconditionally; it must be optional behind feature `sync`"
                )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest-path", default=None)
    args = parser.parse_args()

    errors: list[str] = []
    errors += check(metadata(args.manifest_path, "--all-features"), "all-features", False)
    errors += check(
        metadata(args.manifest_path, "--no-default-features"), "no-default-features", True
    )

    errors = list(dict.fromkeys(errors))  # two versions of one crate -> same message
    if errors:
        print("crate layering violations:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print("crate layering OK (all-features and no-default-features graphs)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
