#!/usr/bin/env python3
"""M7-06: benchmark gates and regression checks over criterion's results.

Criterion writes `target/criterion/<group>/<function>/<baseline>/estimates.json`
(times in ns) and `benchmark.json` (throughput). This script reads them; it needs
no extra tools.

    bench-gate.py gate [--local] [--dir target/criterion] [--baseline ci]
        Hard gates for the spec targets (`scripts/bench-gates.toml`). CI uses the
        CI-adjusted thresholds (2x the spec, runners are slower and noisy);
        `--local` uses the spec targets for the reference machine.

    bench-gate.py compare --old main --new ci [--threshold 15] [--dir ...]
        Every benchmark present in both baselines: fail when the new median is
        more than `threshold` percent slower (T-05: the regression alert).

    bench-gate.py self-test
        Checks the comparison logic on synthetic results: a 20% slowdown is
        flagged, a 5% one is not, and a missed gate fails.

Baselines are saved with `cargo bench -- --save-baseline <name>`; never name one
`new` or `base` (criterion's own working directories: saving to `new` leaves empty
files).

Exit status: 0 ok, 1 a gate or regression failed, 2 usage / missing data.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GATES = ROOT / "scripts" / "bench-gates.toml"


def median_ns(bench_dir: Path, baseline: str) -> float | None:
    est = bench_dir / baseline / "estimates.json"
    if not est.is_file():
        return None
    data = json.loads(est.read_text())
    return float(data["median"]["point_estimate"])


def throughput_bytes(bench_dir: Path, baseline: str) -> int | None:
    meta = bench_dir / baseline / "benchmark.json"
    if not meta.is_file():
        return None
    tp = json.loads(meta.read_text()).get("throughput") or {}
    return tp.get("Bytes") or tp.get("BytesDecimal")


def benches(root: Path, baseline: str) -> dict[str, Path]:
    """`group/function` -> its directory, for every bench with `baseline`."""
    out = {}
    for est in root.glob(f"**/{baseline}/estimates.json"):
        bench_dir = est.parent.parent
        name = bench_dir.relative_to(root).as_posix()
        if name.startswith("report") or "/report" in name:
            continue
        out[name] = bench_dir
    return out


def gate(root: Path, baseline: str, local: bool, gates_file: Path = GATES) -> int:
    spec = tomllib.loads(gates_file.read_text())
    failed = 0
    for g in spec.get("gate", []):
        bench_dir = root / g["bench"]
        ns = median_ns(bench_dir, baseline)
        if ns is None:
            print(f"MISSING  {g['bench']} (no {baseline} result; did the bench run?)")
            failed += 1
            continue
        if "min_mb_s" in g:
            limit = g["min_mb_s"] if local else g["ci_min_mb_s"]
            nbytes = throughput_bytes(bench_dir, baseline)
            if nbytes is None:
                print(f"MISSING  {g['bench']} has no throughput")
                failed += 1
                continue
            mb_s = nbytes / (ns / 1e9) / 1e6
            ok = mb_s >= limit
            print(f"{'ok  ' if ok else 'FAIL'}     {g['bench']}: {mb_s:.1f} MB/s (gate >= {limit})")
        else:
            limit = g["max_ms"] if local else g["ci_max_ms"]
            ms = ns / 1e6
            ok = ms <= limit
            print(f"{'ok  ' if ok else 'FAIL'}     {g['bench']}: {ms:.3f} ms (gate <= {limit})")
        failed += 0 if ok else 1
    return 1 if failed else 0


def compare(root: Path, old: str, new: str, threshold: float) -> int:
    olds, news = benches(root, old), benches(root, new)
    common = sorted(set(olds) & set(news))
    if not common:
        print(f"no benchmark has both {old!r} and {new!r} results")
        return 2
    regressed = 0
    for name in common:
        a, b = median_ns(olds[name], old), median_ns(news[name], new)
        if not a or b is None:
            continue
        change = (b - a) / a * 100
        flag = "REGRESSED" if change > threshold else "ok"
        regressed += change > threshold
        print(f"{flag:<10} {name}: {a / 1e6:.3f} ms -> {b / 1e6:.3f} ms ({change:+.1f}%)")
    if regressed:
        print(f"{regressed} benchmark(s) slower by more than {threshold}%")
    return 1 if regressed else 0


def _write(root: Path, name: str, baseline: str, ns: float, nbytes: int | None = None) -> None:
    d = root / name / baseline
    d.mkdir(parents=True, exist_ok=True)
    (d / "estimates.json").write_text(json.dumps({"median": {"point_estimate": ns}}))
    tp = {"Bytes": nbytes} if nbytes else None
    (d / "benchmark.json").write_text(json.dumps({"throughput": tp}))


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _write(root, "g/fast", "main", 1_000_000)
        _write(root, "g/fast", "ci", 1_050_000)  # +5%: fine
        assert compare(root, "main", "ci", 15) == 0, "5% must pass"
        _write(root, "g/slow", "main", 1_000_000)
        _write(root, "g/slow", "ci", 1_200_000)  # +20%: deliberately slowed
        assert compare(root, "main", "ci", 15) == 1, "20% must be flagged"

        gates = root / "gates.toml"
        gates.write_text(
            '[[gate]]\nbench = "emulator_parse/x"\nmin_mb_s = 100\nci_min_mb_s = 50\n'
            '[[gate]]\nbench = "render_300x100/x"\nmax_ms = 2\nci_max_ms = 4\n'
        )
        # 1 MiB in 10 ms = 105 MB/s; render 3 ms: CI passes, local fails.
        _write(root, "emulator_parse/x", "ci", 10_000_000, 1 << 20)
        _write(root, "render_300x100/x", "ci", 3_000_000)
        assert gate(root, "ci", local=False, gates_file=gates) == 0
        assert gate(root, "ci", local=True, gates_file=gates) == 1
        _write(root, "emulator_parse/x", "ci", 40_000_000, 1 << 20)  # 26 MB/s
        assert gate(root, "ci", local=False, gates_file=gates) == 1
    print("self-test ok")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gate")
    g.add_argument("--local", action="store_true")
    g.add_argument("--dir", type=Path, default=ROOT / "target" / "criterion")
    g.add_argument("--baseline", default="ci")
    c = sub.add_parser("compare")
    c.add_argument("--old", required=True)
    c.add_argument("--new", default="ci")
    c.add_argument("--threshold", type=float, default=15.0)
    c.add_argument("--dir", type=Path, default=ROOT / "target" / "criterion")
    sub.add_parser("self-test")
    a = p.parse_args()
    if a.cmd == "self-test":
        return self_test()
    if not a.dir.is_dir():
        print(f"{a.dir} does not exist; run `cargo bench` first")
        return 2
    if a.cmd == "gate":
        return gate(a.dir, a.baseline, a.local)
    return compare(a.dir, a.old, a.new, a.threshold)


if __name__ == "__main__":
    sys.exit(main())
