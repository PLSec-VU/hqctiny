#!/usr/bin/env python3
"""Orchestrates the full evaluation suite: builds the Docker
measurement environment, runs the requested categories, and renders one
report.md under results/<timestamp>/ combining every category's log.

Usage:
  eval/run.py [--categories 1,2,3,4,5] [--variant hqc1,hqc3,hqc5]
              [--wan-profile local|same_continent|transatlantic|transpacific|satellite]
              [--remote host:port] [--dos-reps N] [--wan-reps N]

Examples:
  eval/run.py                                   # everything, default (local) WAN profile
  eval/run.py --categories 1,2                  # just memory + bandwidth (fast)
  eval/run.py --categories 5 --wan-profile transatlantic
  eval/run.py --categories 5 --remote 203.0.113.4:12345
  eval/run.py --categories 4 --dos-reps 3        # fast DoS iteration while developing
  eval/run.py --dos-reps 20 --wan-reps 50        # tighter CIs for a paper-final run

Containers are left running afterwards (cached cargo builds speed up
repeat runs); tear down with:
  docker compose -f eval/docker-compose.yml down
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

EVAL_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(EVAL_DIR / "scripts" / "lib"))
from common import HOST_RESULTS_DIR, TS, capture_provenance, compose  # noqa: E402

CATEGORY_SCRIPTS = {
    "1": "memory_footprint.py",
    "2": "bandwidth.py",
    "3": "cpu_benchmarks.py",
    "4": "dos_flood.py",
    "5": "wan_latency.py",
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--categories", default="1,2,3,4,5")
    parser.add_argument("--variant", default="hqc1,hqc3,hqc5")
    parser.add_argument("--wan-profile", default="local")
    parser.add_argument("--remote")
    parser.add_argument(
        "--dos-reps", type=int, default=10,
        help="flood-window repetitions per variant for category 4 (default: 10)",
    )
    parser.add_argument(
        "--wan-reps", type=int, default=30,
        help="client-session repetitions per variant for category 5 (default: 30)",
    )
    args = parser.parse_args()

    categories = args.categories.split(",")
    for cat in categories:
        if cat not in CATEGORY_SCRIPTS:
            print(f"unknown category: {cat}", file=sys.stderr)
            sys.exit(1)
    variants = args.variant.replace(",", " ")

    print(f"== HQCLethe evaluation run: {TS} ==")
    print(f"Variants: {variants}")
    print(f"Categories: {','.join(categories)}")
    print(f"Results: {HOST_RESULTS_DIR}")
    print()

    env = os.environ.copy()
    env["TS"] = TS
    env["HOST_RESULTS_DIR"] = str(HOST_RESULTS_DIR)
    env["VARIANTS"] = variants
    env["DOS_REPS"] = str(args.dos_reps)
    env["WAN_REPS"] = str(args.wan_reps)

    print("Building the eval Docker image (cached after the first run)...")
    compose("build")

    print("Starting containers...")
    compose("up", "-d", "server")
    if "5" in categories:
        compose("up", "-d", "client")

    print("Recording provenance (git commit, toolchain, CPU)...")
    capture_provenance()

    for cat in categories:
        script = EVAL_DIR / "scripts" / CATEGORY_SCRIPTS[cat]
        cmd = [sys.executable, str(script)]
        if cat == "5":
            if args.remote:
                cmd += ["--remote", args.remote]
            else:
                cmd += ["--profile", args.wan_profile]
        subprocess.run(cmd, env=env, check=True)

    subprocess.run(
        [sys.executable, str(EVAL_DIR / "scripts" / "render_report.py"), str(HOST_RESULTS_DIR)],
        check=True,
    )
    print()
    print(f"Done. Report: {HOST_RESULTS_DIR / 'report.md'}")


if __name__ == "__main__":
    main()
