#!/usr/bin/env python3
"""Category 6: server CPU time per session, one method for every system.

For each system and variant, container/session_cpu_run.py starts a fresh
server process, runs N sessions one after another, reads the server's CPU
time (schedstat, all threads) before and after, and divides by the
completed sessions. McTiny (host binary, mctiny_session_cpu.py) uses the
same method and the same core placement. The measurement runs CPU_REPS
repetitions. Inside each repetition every system and variant runs once, in
a shuffled order, so slow drift of the host does not favour one system.
The output keeps every repetition's row plus the between-repetition
statistics. This script then prints the per-phase Criterion numbers next to
the measured figure. If the measured figure is much higher
than the sum of the phases, the server spends CPU outside the protocol
code (system calls, scheduling, receive loop). The two must be reported
together.

Run it after category 3 (cpu_benchmarks.py) in the same results directory,
so that Criterion data from this host exists. Without Criterion data the
measured figure is still reported.

Env knobs: CPU_SESSIONS, CPU_REPS, MCTINY_SESSIONS (see lib/knobs.py).
McTiny is included when its binaries are found (MCTINY_DIR, MCTINY_STATE;
see mctiny_session_cpu.py). Options: --no-mctiny, --seed N, --systems a,b.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (  # noqa: E402
    EVAL_DIR, RAW_DIR, VARIANTS, cargo_build, dexec, ensure_up, hqc_features, knobs, log_section,
    measured_run, start_log,
)
from mctiny_session_cpu import DEFAULT_MCTINY_DIR, DEFAULT_STATE_DIR, McTiny, one_rep as mctiny_rep  # noqa: E402
from reps import describe_rows, new_seed, shuffled_for_rep  # noqa: E402

SYSTEMS = ("stateless", "stateful")
CRITERION_DIR = EVAL_DIR.parent / "target-linux" / "criterion"
NS_PER_MS = 1e6
MIN_RELIABLE_TICKS = 100


def criterion_mean_ms(*path_parts: str) -> float | None:
    estimates = CRITERION_DIR.joinpath(*path_parts, "new", "estimates.json")
    if not estimates.exists():
        return None
    return json.loads(estimates.read_text())["mean"]["point_estimate"] / NS_PER_MS


def request_counts_per_variant() -> dict[str, dict[str, int]]:
    """How many requests of each kind one stateless session sends, from the
    bandwidth report (category 2) of this results directory or the latest
    earlier one."""
    path = RAW_DIR / "bandwidth.json"
    if not path.exists():
        earlier = sorted(RAW_DIR.parent.parent.glob("*/raw/bandwidth.json"))
        if not earlier:
            return {}
        path = earlier[-1]
    return {
        v["variant"]: {packet["kind"]: packet["count"] for packet in v["packets"]}
        for v in json.loads(path.read_text())
    }


def phase_breakdown(system: str, variant: str, counts: dict[str, dict[str, int]]) -> dict[str, float] | None:
    """Criterion means in ms for the per-request work the server does in one
    session, or None when Criterion data is missing."""
    if system == "stateless":
        handshake = criterion_mean_ms(f"{variant}_server_handshake")
        uchunk = criterion_mean_ms(f"{variant}_server_uchunk_request")
        vresidue = criterion_mean_ms(f"{variant}_server_vresidue_request")
        decap = criterion_mean_ms(f"{variant}_server_mlkem_decap")
        if None in (handshake, uchunk, vresidue) or variant not in counts:
            return None
        parts = {
            "handshake_incl_mlkem_decap": handshake,
            "uchunk_requests": counts[variant]["uchunk"] * uchunk,
            "vresidue_requests": counts[variant]["vresidue"] * vresidue,
        }
        if decap is not None:
            parts["of_which_mlkem_decap"] = decap
        return parts
    group = f"stateful_{variant}"
    hello = criterion_mean_ms(group, "hello_to_cookie")
    upload = criterion_mean_ms(group, "full_key_upload_with_encaps")
    decap = criterion_mean_ms(group, "mlkem_decaps")
    if None in (hello, upload):
        return None
    parts = {"hello_incl_mlkem_decap": hello, "key_upload_incl_hqc_encaps": upload}
    if decap is not None:
        parts["of_which_mlkem_decap"] = decap
    return parts


def additive_total(parts: dict[str, float]) -> float:
    return sum(v for k, v in parts.items() if not k.startswith("of_which_"))


def run_container(system: str, variant: str, sessions: str, rep: int) -> dict | None:
    result = dexec(
        "server", "python3", "/work/eval/scripts/container/session_cpu_run.py",
        system, variant, sessions, "1", capture_output=True, check=False,
        extra_env={"REP_BASE": str(rep - 1)},
    )
    print(result.stdout, end="")
    print(result.stderr, end="", file=sys.stderr)
    for line in result.stdout.splitlines():
        if line.startswith("RESULT "):
            return json.loads(line[len("RESULT "):])["rows"][0]
    return None


def headline(rows: list[dict], key: str) -> float | None:
    stats = describe_rows(rows).get(key)
    return stats["median"] if stats else None


def find_mctiny() -> McTiny | None:
    mctiny_dir = Path(os.environ.get("MCTINY_DIR", DEFAULT_MCTINY_DIR))
    state_dir = Path(os.environ.get("MCTINY_STATE", DEFAULT_STATE_DIR))
    if not (mctiny_dir / "mctiny-server").exists() or not (state_dir / "public").exists():
        return None
    return McTiny(mctiny_dir, state_dir)


def build() -> None:
    quiet = hqc_features("quiet")
    cargo_build("--profile", "tiny-release", "-p", "hqclethe-server", features=quiet)
    cargo_build("--profile", "tiny-release", "-p", "hqclethe-stateful",
                "--bin", "hqclethe-server-stateful", features=quiet)
    cargo_build("--release", "-p", "hqclethe-client", features=quiet)
    cargo_build("--release", "-p", "hqclethe-stateful",
                "--bin", "hqclethe-client-stateful", features=quiet)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--reps", type=int, default=knobs.get_int("CPU_REPS"))
    parser.add_argument("--sessions", default=knobs.get("CPU_SESSIONS"))
    parser.add_argument("--mctiny-sessions", type=int, default=knobs.get_int("MCTINY_SESSIONS"))
    parser.add_argument("--variants", default=" ".join(VARIANTS))
    parser.add_argument("--systems", default=",".join(SYSTEMS))
    parser.add_argument("--no-mctiny", action="store_true")
    parser.add_argument("--seed", type=int, default=new_seed())
    return parser.parse_args()


def result_row(system: str, variant: str | None, rows: list[dict], parts: dict | None) -> dict:
    return {
        "system": system, "variant": variant, "reps": len(rows),
        "per_rep": rows, "between_rep_stats": describe_rows(rows),
        "completed_per_rep_median": headline(rows, "sessions_completed"),
        "measured_cpu_ms_per_session": headline(rows, "cpu_ms_per_session_schedstat")
        or headline(rows, "cpu_ms_per_session"),
        "measured_cpu_ms_per_session_ticks": headline(rows, "cpu_ms_per_session"),
        "tick_resolution_ms": headline(rows, "tick_resolution_ms_per_session"),
        "cpu_ticks_total": headline(rows, "cpu_ticks_total"),
        "idle_cpu_ms_same_wall": headline(rows, "idle_cpu_ms_same_wall_schedstat"),
        "criterion_phases_ms": parts,
        "criterion_sum_ms": additive_total(parts) if parts else None,
    }


def main() -> None:
    args = parse_args()
    systems = args.systems.split(",")
    variants = args.variants.replace(",", " ").split()
    mctiny = None if args.no_mctiny else find_mctiny()
    cells = [(system, variant) for variant in variants for system in systems]
    if mctiny:
        cells.append(("mctiny", None))
    ensure_up()
    with start_log("session_cpu.log"), measured_run("session_cpu"):
        log_section("6. Server CPU per session (one method for all systems)")
        print(f"cells={cells} reps={args.reps} seed={args.seed} mctiny={'yes' if mctiny else 'no'}")
        print("Building servers and clients...")
        build()

        collected: dict[tuple, list[dict]] = {cell: [] for cell in cells}
        orders = {}
        for rep in range(1, args.reps + 1):
            order = shuffled_for_rep(cells, args.seed, rep)
            orders[rep] = [f"{s}/{v}" for s, v in order]
            for system, variant in order:
                print(f"\n--- rep {rep}/{args.reps} {system} {variant}: "
                      f"{args.mctiny_sessions if mctiny and system == 'mctiny' else args.sessions} sessions ---",
                      flush=True)
                if system == "mctiny":
                    row = mctiny_rep(mctiny, args.mctiny_sessions, rep)
                else:
                    row = run_container(system, variant, args.sessions, rep)
                if row is None:
                    print(f"FAILED: no result for {system} {variant} rep {rep}")
                    continue
                collected[(system, variant)].append(row)

        counts = request_counts_per_variant()
        results = []
        for (system, variant), rows in collected.items():
            if not rows:
                continue
            parts = phase_breakdown(system, variant, counts) if variant else None
            result = result_row(system, variant, rows, parts)
            results.append(result)
            ticks = result["cpu_ticks_total"]
            if ticks is not None and ticks < MIN_RELIABLE_TICKS:
                print(f"WARNING: only {ticks:.0f} clock ticks were counted for {system} {variant} "
                      f"(fewer than {MIN_RELIABLE_TICKS}). The tick figure is unreliable; "
                      "schedstat is the primary figure.")
            per_rep = [r.get("cpu_ms_per_session_schedstat", r["cpu_ms_per_session"]) for r in rows]
            print(f"SUMMARY {system} {variant}: schedstat ms/session per rep "
                  f"{[round(v, 3) for v in per_rep]}; median {result['measured_cpu_ms_per_session']:.3f}"
                  + (f"; sum of Criterion phases {result['criterion_sum_ms']:.3f}" if parts else ""))
        output = {"seed": args.seed, "rep_orders": orders, "results": results}
        (RAW_DIR / "session_cpu.json").write_text(json.dumps(output, indent=2) + "\n")


if __name__ == "__main__":
    main()
