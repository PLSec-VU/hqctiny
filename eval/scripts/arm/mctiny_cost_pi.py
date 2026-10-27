#!/usr/bin/env python3
"""McTiny server cost per answered query on the Raspberry Pi, without a flood.

The stock McTiny server runs pinned to one core. Normal McTiny client
sessions arrive at a low steady rate (one session every --gap seconds). The
script reads the server's schedstat before and after the timed sessions and
parses the cycle counters that the server prints at the end of each session:
total cycles spent in the query handlers, and the cycles spent in the
phase-1 syndrome step. From these it derives the cost per session, per query,
and the largest session rate and query rate the core can answer (1 / cost).

  mctiny_cost_pi.py --out FILE [--reps 3] [--sessions 20] [--gap 1.0]
      [--mctiny-dir D] [--mctiny-state D]

Environment: SERVER_CORE, CLIENT_CORE, ORCHESTRATOR_CORE (container/placement.py).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "container"))
sys.path.insert(0, str(HERE.parent / "lib"))
from mctiny_session_cpu import McTiny, PORT, SERVER_STARTUP_SECS, WARMUP_SESSIONS, run_sessions  # noqa: E402
from placement import ORCHESTRATOR_CORE  # noqa: E402
from reps import describe_rows  # noqa: E402
from util import read_cpu_ns  # noqa: E402

PHASE0_QUERIES = 1
PHASE1_QUERIES = 119 * 8
PHASE2_QUERIES = 17
PHASE3_QUERIES = 1
QUERIES_PER_SESSION = PHASE0_QUERIES + PHASE1_QUERIES + PHASE2_QUERIES + PHASE3_QUERIES
SESSION_LINE = re.compile(r"server ksession \S+ cycles (\d+) (\d+)")
PI_MHZ = 1200.0


def session_cycles(log: Path, offset: int) -> list[tuple[int, int]]:
    text = log.read_text(errors="replace")[offset:]
    return [(int(a), int(b)) for a, b in SESSION_LINE.findall(text)]


def one_rep(mctiny: McTiny, sessions: int, gap: float, rep: int) -> dict:
    log = Path(tempfile.mkstemp(prefix="mctiny_cost_", suffix=".log")[1])
    with log.open("wb") as sink:
        server = subprocess.Popen(mctiny.server_command(), stdout=subprocess.DEVNULL, stderr=sink)
    try:
        time.sleep(SERVER_STARTUP_SECS)
        run_sessions(mctiny.client_command(), WARMUP_SESSIONS)
        offset = len(log.read_text(errors="replace"))
        ns0 = read_cpu_ns(server.pid)
        completed = 0
        for _ in range(sessions):
            completed += run_sessions(mctiny.client_command(), 1)
            time.sleep(gap)
        ns1 = read_cpu_ns(server.pid)
    finally:
        server.send_signal(signal.SIGTERM)
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()
    cycles = session_cycles(log, offset)
    row = {"rep": rep, "sessions_attempted": sessions, "sessions_completed": completed,
           "gap_s": gap, "logged_sessions": len(cycles)}
    if completed and None not in (ns0, ns1):
        row["schedstat_ms_per_session"] = (ns1 - ns0) / 1e6 / completed
    if cycles:
        total = [c[0] for c in cycles]
        phase1 = [c[1] for c in cycles]
        mean = lambda xs: sum(xs) / len(xs)  # noqa: E731
        row.update({
            "handler_cycles_per_session": mean(total),
            "phase1_cycles_per_session": mean(phase1),
            "other_cycles_per_session": mean(total) - mean(phase1),
            "handler_ms_per_session": mean(total) / (PI_MHZ * 1e3),
            "phase1_cycles_per_query": mean(phase1) / PHASE1_QUERIES,
            "other_cycles_per_query": (mean(total) - mean(phase1)) / QUERIES_PER_SESSION,
            "handler_cycles_per_query": mean(total) / QUERIES_PER_SESSION,
        })
    cost_ms = row.get("schedstat_ms_per_session")
    if cost_ms:
        row["max_sessions_per_s"] = 1000 / cost_ms
        row["max_queries_per_s"] = QUERIES_PER_SESSION * 1000 / cost_ms
        row["schedstat_ms_per_query"] = cost_ms / QUERIES_PER_SESSION
    print("RUN " + json.dumps(row), flush=True)
    return row


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--reps", type=int, default=3)
    parser.add_argument("--sessions", type=int, default=20)
    parser.add_argument("--gap", type=float, default=1.0)
    parser.add_argument("--mctiny-dir", type=Path, default=Path("/mnt/arm/bin/mctiny"))
    parser.add_argument("--mctiny-state", type=Path, default=Path("/mnt/arm/mctiny_state"))
    args = parser.parse_args()
    os.sched_setaffinity(0, {ORCHESTRATOR_CORE})
    mctiny = McTiny(args.mctiny_dir, args.mctiny_state)
    rows = [one_rep(mctiny, args.sessions, args.gap, rep) for rep in range(1, args.reps + 1)]
    args.out.write_text(json.dumps({
        "queries_per_session": QUERIES_PER_SESSION, "rows": rows,
        "between_rep_stats": describe_rows([{k: v for k, v in r.items()} for r in rows]),
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
