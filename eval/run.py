#!/usr/bin/env python3
"""Orchestrates the full evaluation suite: builds the Docker
measurement environment, runs the requested categories, and renders one
report.md under results/<timestamp>/ combining every category's log.

Usage:
  eval/run.py [--categories 1,2,3,4,5,6,7] [--variant hqc1,hqc3,hqc5] [--smoke]
              [--wan-profile local|same_continent|transatlantic|transpacific|satellite]
              [--remote host:port] [--remote-stateful host:port]
              [--dos-reps N] [--wan-reps N]

Categories: 1 memory, 2 bandwidth, 3 CPU microbenchmarks, 4 DoS floods
(stateless and stateful), 5 WAN latency (simple, both HqcLethe systems),
6 server CPU per session, 7 stack, 8 WAN sweep with loss sweep and McTiny
(not in the default list: it takes hours).
Most people want eval/run_all.sh, which wraps this script.

Examples:
  eval/run.py                                   # everything, default (local) WAN profile
  eval/run.py --categories 1,2                  # just memory + bandwidth (fast)
  eval/run.py --categories 5 --wan-profile transatlantic
  eval/run.py --categories 5 --remote 203.0.113.4:12345
  eval/run.py --categories 4 --dos-reps 3        # fast DoS iteration while developing
  eval/run.py --dos-reps 20 --wan-reps 50        # tighter CIs for a paper-final run
  eval/run.py --smoke                            # a few minutes, for checking the setup

Containers are left running afterwards (cached cargo builds speed up
repeat runs); tear down with:
  docker compose -f eval/docker-compose.yml down
"""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
from pathlib import Path

EVAL_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(EVAL_DIR / "scripts" / "lib"))
if "--smoke" in sys.argv:
    os.environ["EVAL_SMOKE"] = "1"
import knobs  # noqa: E402
from common import HOST_RESULTS_DIR, TS, capture_provenance, compose, setup_keys  # noqa: E402

CATEGORY_SCRIPTS = {
    "1": "memory_footprint.py",
    "2": "bandwidth.py",
    "3": "cpu_benchmarks.py",
    "4": "dos_flood.py",
    "5": "wan_latency.py",
    "6": "session_cpu.py",
    "7": "stack.py",
    "8": "wan_sweep.py",
    "9": "ct_check.py",
    "10": "rss.py",
}
EXTRA_ARGS_OPTIONS = {"4": "dos_args", "8": "wan_sweep_args"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--categories", default="1,2,3,4,5,6,7")
    parser.add_argument("--variant", help="default: the VARIANTS knob (all three, or hqc1 with --smoke)")
    parser.add_argument("--smoke", action="store_true", help="small counts, finishes in minutes; numbers are not for the paper")
    parser.add_argument("--wan-profile", default="local")
    parser.add_argument("--remote", help="host:port of a running stateless server")
    parser.add_argument("--remote-stateful", help="host:port of a running stateful server")
    parser.add_argument("--dos-reps", type=int, help="override the DOS_REPS knob")
    parser.add_argument("--wan-reps", type=int, help="override the WAN_REPS knob")
    parser.add_argument("--dos-args", default="", help="extra options for dos_flood.py (category 4), one string")
    parser.add_argument("--wan-sweep-args", default="", help="extra options for wan_sweep.py (category 8), one string")
    args = parser.parse_args()
    if args.variant:
        os.environ["VARIANTS"] = args.variant.replace(",", " ")
    if args.dos_reps is not None:
        os.environ["DOS_REPS"] = str(args.dos_reps)
    if args.wan_reps is not None:
        os.environ["WAN_REPS"] = str(args.wan_reps)

    categories = args.categories.split(",")
    for cat in categories:
        if cat not in CATEGORY_SCRIPTS:
            print(f"unknown category: {cat}", file=sys.stderr)
            sys.exit(1)
    variants = knobs.get("VARIANTS")

    print(f"== HQCLethe evaluation run: {TS} ==")
    print(f"Variants: {variants}")
    print(f"Categories: {','.join(categories)}")
    print(f"Smoke mode: {knobs.is_smoke()}")
    print(f"Knobs: {knobs.resolved()}")
    print(f"Results: {HOST_RESULTS_DIR}")
    print()

    env = os.environ.copy()
    env["TS"] = TS
    env["HOST_RESULTS_DIR"] = str(HOST_RESULTS_DIR)
    env.update(knobs.resolved())

    print("Building the eval Docker image (cached after the first run)...")
    compose("build")

    print("Starting containers...")
    compose("up", "-d", "server")
    if "5" in categories or "8" in categories:
        compose("up", "-d", "client")

    print("Recording provenance (git commit, toolchain, CPU)...")
    capture_provenance(categories)

    print("Generating ML-KEM server keys (kept if they exist)...")
    setup_keys()

    failed = []
    for cat in categories:
        script = EVAL_DIR / "scripts" / CATEGORY_SCRIPTS[cat]
        cmd = [sys.executable, str(script)]
        if cat == "5":
            if args.remote or args.remote_stateful:
                if args.remote:
                    cmd += ["--remote", args.remote]
                if args.remote_stateful:
                    cmd += ["--remote-stateful", args.remote_stateful]
            else:
                cmd += ["--profile", args.wan_profile]
        if cat in EXTRA_ARGS_OPTIONS:
            cmd += shlex.split(getattr(args, EXTRA_ARGS_OPTIONS[cat]))
        if subprocess.run(cmd, env=env, check=False).returncode != 0:
            failed.append(cat)
            print(f"!! category {cat} failed; continuing with the others", file=sys.stderr)

    subprocess.run(
        [sys.executable, str(EVAL_DIR / "scripts" / "render_report.py"), str(HOST_RESULTS_DIR)],
        check=True,
    )
    print()
    print(f"Done. Report: {HOST_RESULTS_DIR / 'report.md'}")
    if failed:
        print(f"FAILED categories: {','.join(failed)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
