#!/usr/bin/env python3
"""McTiny server CPU per completed session, by the same method as
container/session_cpu_run.py (HQCLethe): start a fresh server, run warm-up
sessions, read the server's schedstat (all threads, ns) and /proc/<pid>/stat
ticks before and after N timed sessions, divide by the sessions that
completed. Also measures an idle server for the same wall time.

McTiny is a bare host binary, so this runs on the host, not in a container.
The server runs on the server core and the client on the session client core
from container/placement.py: the same placement as every other driver.

  eval/scripts/mctiny_session_cpu.py --sessions 100 --reps 5
      [--mctiny-dir ~/mctiny_build/mctiny-20200804] [--state-dir ~/mctiny_state]
      [--out FILE.json]

Prints "RUN {json}" per repetition and "RESULT {json}" at the end.
`measure_reps` is also used by session_cpu.py to interleave McTiny with the
HQCLethe systems.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "container"))
sys.path.insert(0, str(HERE / "lib"))
from placement import CLIENT_CORE, SERVER_CORE  # noqa: E402
from common import measured_run  # noqa: E402
from reps import describe_rows  # noqa: E402
from util import read_cpu_ns, read_cpu_split_ticks, read_peak_rss_kb, read_rss_kb  # noqa: E402

DEFAULT_MCTINY_DIR = Path.home() / "mctiny_build" / "mctiny-20200804"
DEFAULT_STATE_DIR = Path.home() / "mctiny_state"
SERVER_ADDR = "127.0.0.1"
PORT = 24311
WARMUP_SESSIONS = 5
SESSION_TIMEOUT_SECS = 30
SERVER_STARTUP_SECS = 1.0
SERVER_STOP_SECS = 5


class McTiny:
    def __init__(self, mctiny_dir: Path, state_dir: Path):
        self.server_bin = str(mctiny_dir / "mctiny-server")
        self.client_bin = str(mctiny_dir / "mctiny-client")
        self.state_dir = str(state_dir)
        keys = list((state_dir / "public").iterdir())
        assert len(keys) == 1, f"expected one public key in {state_dir}/public, found {keys}"
        self.public_key = str(keys[0])

    def server_command(self) -> list[str]:
        return ["taskset", "-c", str(SERVER_CORE), self.server_bin, self.state_dir, SERVER_ADDR, str(PORT)]

    def client_command(self) -> list[str]:
        return ["taskset", "-c", str(CLIENT_CORE), self.client_bin, self.public_key, SERVER_ADDR, str(PORT)]


def run_sessions(command: list[str], count: int) -> int:
    completed = 0
    for _ in range(count):
        try:
            proc = subprocess.run(
                command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=SESSION_TIMEOUT_SECS,
            )
            completed += proc.returncode == 0
        except subprocess.TimeoutExpired:
            pass
    return completed


def one_rep(mctiny: McTiny, sessions: int, rep: int) -> dict:
    server = subprocess.Popen(mctiny.server_command(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(SERVER_STARTUP_SECS)
        rss_idle_kb = read_rss_kb(server.pid)
        run_sessions(mctiny.client_command(), WARMUP_SESSIONS)
        user0, sys0 = read_cpu_split_ticks(server.pid)
        ns0 = read_cpu_ns(server.pid)
        t0 = time.monotonic()
        completed = run_sessions(mctiny.client_command(), sessions)
        wall = time.monotonic() - t0
        user1, sys1 = read_cpu_split_ticks(server.pid)
        ns1 = read_cpu_ns(server.pid)
        rss_after_kb = read_rss_kb(server.pid)
        rss_peak_kb = read_peak_rss_kb(server.pid)

        time.sleep(0.1)
        idle_ns0 = read_cpu_ns(server.pid)
        time.sleep(wall)
        idle_ns1 = read_cpu_ns(server.pid)
    finally:
        server.send_signal(signal.SIGTERM)
        try:
            server.wait(timeout=SERVER_STOP_SECS)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()

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
    }
    if None not in (ns0, ns1) and completed:
        row["cpu_ms_per_session_schedstat"] = (ns1 - ns0) / 1e6 / completed
    if None not in (idle_ns0, idle_ns1):
        row["idle_cpu_ms_same_wall_schedstat"] = (idle_ns1 - idle_ns0) / 1e6
    print("RUN " + json.dumps({"system": "mctiny", **row}), flush=True)
    return row


def measure_reps(mctiny: McTiny, sessions: int, reps: int, rep_base: int = 0) -> list[dict]:
    return [one_rep(mctiny, sessions, rep_base + rep) for rep in range(1, reps + 1)]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sessions", type=int, default=100)
    parser.add_argument("--reps", type=int, default=5)
    parser.add_argument("--mctiny-dir", type=Path, default=Path(os.environ.get("MCTINY_DIR", DEFAULT_MCTINY_DIR)))
    parser.add_argument("--state-dir", type=Path, default=Path(os.environ.get("MCTINY_STATE", DEFAULT_STATE_DIR)))
    parser.add_argument("--out", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    mctiny = McTiny(args.mctiny_dir, args.state_dir)
    print(f"sessions={args.sessions} reps={args.reps} server_core={SERVER_CORE} client_core={CLIENT_CORE}")
    with measured_run("mctiny_session_cpu"):
        rows = measure_reps(mctiny, args.sessions, args.reps)
    summary = {"system": "mctiny", "sessions": args.sessions, "reps": args.reps,
               "rows": rows, "between_rep_stats": describe_rows(rows)}
    print("RESULT " + json.dumps(summary))
    if args.out:
        args.out.write_text(json.dumps(summary, indent=2) + "\n")


if __name__ == "__main__":
    main()
