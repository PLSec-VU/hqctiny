#!/usr/bin/env python3
"""Bootstrap confidence intervals for the WAN sweep: 95% interval on the
median, n_boot=10000, seed=42. Reads one or more raw/<name>.json files
written by wan_sweep.py (the outputs of a split run merge) and prints one row
per system and cell: n, median, p95, max, n_fail, retries (HqcLethe only),
then the interval.

--metric picks the timing: session_s (default), process_s (whole client process,
HqcLethe and McTiny) or network_s (McTiny only). Rows without the metric are
skipped.

Usage: wan_bootstrap_ci.py [--metric session_s|process_s|network_s] <results_dir>/raw/wan_sweep.json [more.json ...]
"""
from __future__ import annotations

import json
import random
import statistics
import sys


def bootstrap_ci_median(values: list[float], n_boot: int = 10000, seed: int = 42) -> tuple[float, float]:
    rng = random.Random(seed)
    n = len(values)
    meds = []
    for _ in range(n_boot):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        meds.append(statistics.median(sample))
    meds.sort()
    lo = meds[int(0.025 * n_boot)]
    hi = meds[int(0.975 * n_boot) - 1]
    return lo, hi


def pct(values: list[float], p: float) -> float:
    if len(values) == 1:
        return values[0]
    k = (len(values) - 1) * p
    f = int(k)
    c = min(f + 1, len(values) - 1)
    sv = sorted(values)
    if f == c:
        return sv[f]
    return sv[f] + (sv[c] - sv[f]) * (k - f)


def main() -> None:
    args = sys.argv[1:]
    metric = "session_s"
    if args[:1] == ["--metric"]:
        metric, args = args[1], args[2:]
    paths = args
    data = {}
    for path in paths:
        data.update(json.load(open(path))["results"])
    print(f"# WAN bootstrap CIs (95%, n_boot=10000, seed=42), metric {metric}")
    print(f"# Generated from {', '.join(paths)}")
    print()
    header = (
        f"{'System':10} {'Cell':16} {'Dir':8} {'n_ok':>5} {'n_fail':>6} "
        f"{'median_s':>9} {'p95_s':>9} {'max_s':>9} {'CI_lo':>9} {'CI_hi':>9} "
        f"{'retries_tot':>11}"
    )
    print(header)
    for key, rows in sorted(data.items()):
        system, cell, direction = key.split("/")
        oks = [r[metric] for r in rows if r.get("ok") and r.get(metric) is not None]
        if not any(metric in r for r in rows):
            continue
        n_fail = sum(1 for r in rows if not r.get("ok"))
        retries_tot = sum(r.get("retries", 0) for r in rows if r.get("ok") and "retries" in r)
        if not oks:
            print(f"{system:10} {cell:16} {direction:8} {0:5d} {n_fail:6d}  (no successful sessions)")
            continue
        med = statistics.median(oks)
        p95 = pct(oks, 0.95)
        mx = max(oks)
        lo, hi = bootstrap_ci_median(oks)
        print(
            f"{system:10} {cell:16} {direction:8} {len(oks):5d} {n_fail:6d} "
            f"{med:9.4f} {p95:9.4f} {mx:9.4f} {lo:9.4f} {hi:9.4f} {retries_tot:11d}"
        )


if __name__ == "__main__":
    main()
