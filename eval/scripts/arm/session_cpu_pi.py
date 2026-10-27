#!/usr/bin/env python3
"""Server CPU per session on the Raspberry Pi, for stateless HqcLethe,
the stateful baseline and McTiny, by the method of session_cpu.py without
Docker. Each system and variant runs once per repetition, in a shuffled
order. Every row carries the SoC state before and after the run.

  session_cpu_pi.py --out FILE [--reps 5] [--sessions 50] [--mctiny-sessions 10]
      [--variants "hqc1 hqc3 hqc5"] [--no-mctiny] [--mctiny-dir D] [--mctiny-state D]

Environment: SERVER_BIN_DIR, CLIENT_BIN_DIR, KEY_DIR, SERVER_CORE, CLIENT_CORE,
ORCHESTRATOR_CORE (see container/placement.py and container/systems.py).
Run as root, so the SoC state can be read.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
os.environ.setdefault("HOST_RESULTS_DIR", "/tmp/session_cpu_pi_unused")
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "lib"))
sys.path.insert(0, str(HERE.parent))
from mctiny_session_cpu import McTiny, one_rep as mctiny_rep  # noqa: E402
from reps import describe_rows, new_seed, shuffled_for_rep  # noqa: E402
import pi_state  # noqa: E402

RUNNER = HERE.parent / "container" / "session_cpu_run.py"
ALL_VARIANTS = "hqc1 hqc3 hqc5"


def state_brief() -> dict:
    state = pi_state.snapshot()
    return {"temp_c": state["temp_c"], "arm_clock_hz": state["arm_clock_hz"],
            "throttled": state["throttled"]["raw"]}


def run_hqclethe(system: str, variant: str, sessions: int, rep: int) -> dict | None:
    result = subprocess.run(
        [sys.executable, str(RUNNER), system, variant, str(sessions), "1"],
        capture_output=True, text=True, env={**os.environ, "REP_BASE": str(rep - 1)},
    )
    print(result.stdout, end="")
    print(result.stderr, end="", file=sys.stderr)
    for line in result.stdout.splitlines():
        if line.startswith("RESULT "):
            return json.loads(line[len("RESULT "):])["rows"][0]
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--reps", type=int, default=5)
    parser.add_argument("--sessions", type=int, default=50)
    parser.add_argument("--mctiny-sessions", type=int, default=10)
    parser.add_argument("--variants", default=ALL_VARIANTS)
    parser.add_argument("--no-mctiny", action="store_true")
    parser.add_argument("--mctiny-dir", type=Path, default=Path("/mnt/arm/bin/mctiny"))
    parser.add_argument("--mctiny-state", type=Path, default=Path("/mnt/arm/mctiny_state"))
    parser.add_argument("--seed", type=int, default=new_seed())
    args = parser.parse_args()

    cells = [(system, variant) for variant in args.variants.split() for system in ("stateless", "stateful")]
    mctiny = None if args.no_mctiny else McTiny(args.mctiny_dir, args.mctiny_state)
    if mctiny:
        cells.append(("mctiny", None))
    collected: dict[tuple, list[dict]] = {cell: [] for cell in cells}
    orders = {}
    for rep in range(1, args.reps + 1):
        order = shuffled_for_rep(cells, args.seed, rep)
        orders[rep] = [f"{s}/{v}" for s, v in order]
        for system, variant in order:
            print(f"\n--- rep {rep}/{args.reps} {system} {variant} ---", flush=True)
            before = state_brief()
            if system == "mctiny":
                row = mctiny_rep(mctiny, args.mctiny_sessions, rep)
            else:
                row = run_hqclethe(system, variant, args.sessions, rep)
            if row is None:
                print(f"FAILED: {system} {variant} rep {rep}")
                continue
            collected[(system, variant)].append({**row, "state_before": before, "state_after": state_brief()})
    results = [
        {"system": system, "variant": variant, "per_rep": rows,
         "between_rep_stats": describe_rows([{k: v for k, v in r.items() if not isinstance(v, dict)} for r in rows])}
        for (system, variant), rows in collected.items() if rows
    ]
    args.out.write_text(json.dumps({"seed": args.seed, "rep_orders": orders, "results": results}, indent=2) + "\n")


if __name__ == "__main__":
    main()
