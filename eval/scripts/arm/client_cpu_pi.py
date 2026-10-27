#!/usr/bin/env python3
"""Client CPU per completed session on the Raspberry Pi: user plus system
time of the client processes (getrusage of the children, which have a
clock-tick resolution, summed over all sessions of one repetition), for
the stateless client, the stateful client and the McTiny client.

  client_cpu_pi.py --out FILE [--reps 5] [--sessions 30] [--mctiny-sessions 5]
      [--variants "hqc1 hqc3 hqc5"] [--no-mctiny]

The server runs on SERVER_CORE and the client on CLIENT_CORE.
"""

from __future__ import annotations

import argparse
import json
import os
import resource
import signal
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
os.environ.setdefault("HOST_RESULTS_DIR", "/tmp/client_cpu_pi_unused")
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "lib"))
sys.path.insert(0, str(HERE.parent / "container"))
from mctiny_session_cpu import McTiny  # noqa: E402
from placement import CLIENT_CORE, ORCHESTRATOR_CORE, SERVER_CORE  # noqa: E402
from reps import describe_rows  # noqa: E402
from systems import SYSTEMS  # noqa: E402
import pi_state  # noqa: E402

PORT = 24400
ADDR = f"127.0.0.1:{PORT}"
WARMUP_SESSIONS = 2
SESSION_TIMEOUT_S = 120
SERVER_STARTUP_S = 1.0


def children_cpu_s() -> float:
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_utime + usage.ru_stime


def run_sessions(command: list[str], count: int) -> int:
    completed = 0
    for _ in range(count):
        try:
            done = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  timeout=SESSION_TIMEOUT_S)
            completed += done.returncode == 0
        except subprocess.TimeoutExpired:
            pass
    return completed


def measure(server_command: list[str], client_command: list[str], sessions: int, rep: int) -> dict:
    server = subprocess.Popen(server_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(SERVER_STARTUP_S)
        run_sessions(client_command, WARMUP_SESSIONS)
        cpu0, wall0 = children_cpu_s(), time.monotonic()
        completed = run_sessions(client_command, sessions)
        cpu, wall = children_cpu_s() - cpu0, time.monotonic() - wall0
    finally:
        server.send_signal(signal.SIGTERM)
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()
    state = pi_state.snapshot()
    return {"rep": rep, "sessions_attempted": sessions, "sessions_completed": completed,
            "client_cpu_ms_per_session": 1000 * cpu / completed if completed else float("nan"),
            "wall_ms_per_session": 1000 * wall / completed if completed else float("nan"),
            "tick_resolution_ms_per_session": 1000 / os.sysconf("SC_CLK_TCK") / max(completed, 1),
            "temp_c_after": state["temp_c"], "arm_clock_hz_after": state["arm_clock_hz"],
            "throttled_after": state["throttled"]["raw"]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--reps", type=int, default=5)
    parser.add_argument("--sessions", type=int, default=30)
    parser.add_argument("--mctiny-sessions", type=int, default=5)
    parser.add_argument("--variants", default="hqc1 hqc3 hqc5")
    parser.add_argument("--no-mctiny", action="store_true")
    parser.add_argument("--mctiny-dir", type=Path, default=Path("/mnt/arm/bin/mctiny"))
    parser.add_argument("--mctiny-state", type=Path, default=Path("/mnt/arm/mctiny_state"))
    args = parser.parse_args()
    os.sched_setaffinity(0, {ORCHESTRATOR_CORE})

    cells = []
    for variant in args.variants.split():
        for name in ("stateless", "stateful"):
            system = SYSTEMS[name]
            cells.append((name, variant, args.sessions,
                          ["taskset", "-c", str(SERVER_CORE), *system.server_command(variant, PORT)],
                          ["taskset", "-c", str(CLIENT_CORE), *system.client_command(variant, ADDR)]))
    if not args.no_mctiny:
        mctiny = McTiny(args.mctiny_dir, args.mctiny_state)
        cells.append(("mctiny", None, args.mctiny_sessions, mctiny.server_command(), mctiny.client_command()))

    collected = {(name, variant): [] for name, variant, *_ in cells}
    for rep in range(1, args.reps + 1):
        for name, variant, sessions, server_command, client_command in cells:
            print(f"--- rep {rep} {name} {variant}", flush=True)
            row = measure(server_command, client_command, sessions, rep)
            print("RUN " + json.dumps({"system": name, "variant": variant, **row}), flush=True)
            collected[(name, variant)].append(row)
    results = [{"system": n, "variant": v, "per_rep": rows, "between_rep_stats": describe_rows(rows)}
               for (n, v), rows in collected.items()]
    args.out.write_text(json.dumps({"results": results}, indent=2) + "\n")


if __name__ == "__main__":
    main()
