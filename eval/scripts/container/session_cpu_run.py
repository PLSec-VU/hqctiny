#!/usr/bin/env python3
"""Runs inside the eval container (invoked by ../session_cpu.py).

Measures server CPU per completed session, the same way for every system:

  1. Start a fresh server process, pinned to the server core.
  2. Run WARMUP sessions. They are not counted.
  3. Read the server's CPU time (user + sys, all threads) from
     /proc/<pid>/stat. Also read /proc/<pid>/schedstat when present.
  4. Run N sessions one after another with the real client binary,
     pinned to the client core (placement.py). Count the sessions that exit with status 0.
  5. Read the CPU time again. Divide the difference by the completed
     sessions.
  6. Measure the same server for an idle period of the same wall time as a
     control. This shows how much of the number is background work.

/proc/<pid>/stat has a 10 ms tick (clock ticks per second is usually 100).
With N sessions the resolution is 10/N ms per session. The schedstat figure
has nanosecond resolution and is printed next to it as a cross-check.

Args: <mode> <variant> <sessions> <reps>
Env:  REP_BASE  repetitions are numbered from REP_BASE+1
Prints "RUN {json}" per repetition and "RESULT {json}" (with every row) at the end.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from placement import CLIENT_CORE, ORCHESTRATOR_CORE, SERVER_CORE  # noqa: E402
from systems import SYSTEMS  # noqa: E402
from util import (  # noqa: E402
    pin_to_core, popen_logged, read_cpu_ns, read_cpu_split_ticks, read_peak_rss_kb, read_rss_kb, run_logged,
)

PORT = 24300
ADDR = f"127.0.0.1:{PORT}"
WARMUP_SESSIONS = 5
SESSION_TIMEOUT_SECS = 30
SERVER_STARTUP_SECS = 1.0


def run_sessions(command: list[str], count: int, log_first: bool) -> int:
    completed = 0
    for index in range(count):
        kwargs = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL, "timeout": SESSION_TIMEOUT_SECS}
        try:
            if index == 0 and log_first:
                proc = run_logged("session", command, **kwargs)
            else:
                proc = subprocess.run(command, **kwargs)
            completed += proc.returncode == 0
        except subprocess.TimeoutExpired:
            pass
    return completed


def one_rep(mode: str, variant: str, sessions: int, rep: int) -> dict:
    system = SYSTEMS[mode]
    nproc = os.cpu_count() or 1
    client = [*pin_to_core(CLIENT_CORE, nproc, 2), *system.client_command(variant, ADDR)]
    server = popen_logged(
        "server", [*pin_to_core(SERVER_CORE, nproc, 2), *system.server_command(variant, PORT)]
    )
    try:
        time.sleep(SERVER_STARTUP_SECS)
        rss_idle_kb = read_rss_kb(server.pid)
        run_sessions(client, WARMUP_SESSIONS, log_first=False)
        user0, sys0 = read_cpu_split_ticks(server.pid)
        ns0 = read_cpu_ns(server.pid)
        t0 = time.monotonic()
        completed = run_sessions(client, sessions, log_first=True)
        wall = time.monotonic() - t0
        user1, sys1 = read_cpu_split_ticks(server.pid)
        ns1 = read_cpu_ns(server.pid)
        rss_after_kb = read_rss_kb(server.pid)
        rss_peak_kb = read_peak_rss_kb(server.pid)

        time.sleep(0.1)
        idle_user0, idle_sys0 = read_cpu_split_ticks(server.pid)
        idle_ns0 = read_cpu_ns(server.pid)
        time.sleep(wall)
        idle_user1, idle_sys1 = read_cpu_split_ticks(server.pid)
        idle_ns1 = read_cpu_ns(server.pid)
    finally:
        server.send_signal(signal.SIGTERM)
        server.wait(timeout=5)

    tick_ms = 1000 / os.sysconf("SC_CLK_TCK")
    per_session = lambda ticks: ticks * tick_ms / completed if completed else float("nan")  # noqa: E731
    row = {
        "rep": rep,
        "sessions_attempted": sessions,
        "sessions_completed": completed,
        "wall_s": wall,
        "cpu_ms_per_session": per_session((user1 - user0) + (sys1 - sys0)),
        "user_ms_per_session": per_session(user1 - user0),
        "sys_ms_per_session": per_session(sys1 - sys0),
        "tick_resolution_ms_per_session": per_session(1),
        "cpu_ticks_total": (user1 - user0) + (sys1 - sys0),
        "rss_idle_kb": rss_idle_kb,
        "rss_after_kb": rss_after_kb,
        "rss_peak_kb": rss_peak_kb,
        "idle_cpu_ms_same_wall": ((idle_user1 - idle_user0) + (idle_sys1 - idle_sys0)) * tick_ms,
    }
    if None not in (ns0, ns1) and completed:
        row["cpu_ms_per_session_schedstat"] = (ns1 - ns0) / 1e6 / completed
    if None not in (idle_ns0, idle_ns1):
        row["idle_cpu_ms_same_wall_schedstat"] = (idle_ns1 - idle_ns0) / 1e6
    print("RUN " + json.dumps(row), flush=True)
    return row


def main() -> None:
    mode, variant, sessions, reps = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
    if (os.cpu_count() or 1) > ORCHESTRATOR_CORE:
        os.sched_setaffinity(0, {ORCHESTRATOR_CORE})
    rep_base = int(os.environ.get("REP_BASE", "0"))
    print(f"mode={mode} variant={variant} sessions={sessions} reps={reps} nproc={os.cpu_count()}")
    rows = [one_rep(mode, variant, sessions, rep_base + rep) for rep in range(1, reps + 1)]
    summary = {"mode": mode, "variant": variant, "sessions": sessions, "reps": reps, "rows": rows}
    print("RESULT " + json.dumps(summary))


if __name__ == "__main__":
    main()
