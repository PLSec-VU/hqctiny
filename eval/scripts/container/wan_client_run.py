#!/usr/bin/env python3
"""Runs inside the eval container's "client" service. Runs several full
protocol sessions against a (possibly network-emulated or remote) server,
each wrapped in /usr/bin/time for real/user/sys accounting. This script
enforces the session timeout itself (REP_TIMEOUT_S, one process group kill),
because a `timeout` wrapper process would add its own polling delay to the
session. The client retransmits on loss with an RTT-adaptive
exponential-backoff RTO and gives up on its own after MAX_RETRIES
consecutive stalls (see hqclethe-client's run_client), so the timeout is
only a backstop against a hung rep. Reports
median/IQR RTTs across reps rather than a single session's numbers, which
under jitter+loss aren't representative of anything. RTTs are derived from the client's phase
timestamps, which it eprintln!s as `[phase] <name> t=<seconds>` at each
protocol transition.

With WAN_STATEFUL_STATS=1 and a system that has a statistics probe, every
row also has `server_stats_delta`: the change of the server counters during
that session. A failed row keeps the exit status and the end of the client's
stderr.

Args: <server_addr> <variant> [reps] [stateless|stateful]
Prints one "rep ..." line per repetition and "RESULT {json}" (every
repetition's numbers) at the end.
"""

from __future__ import annotations

import json
import os
import re
import signal
import statistics
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from placement import CLIENT_CORE  # noqa: E402
from systems import SYSTEMS, System  # noqa: E402
from util import log_command, pin_to_core  # noqa: E402

STATS_PROBE_ATTEMPTS = 10
STATS_PROBE_TIMEOUT_S = 5
FAILED_STDERR_TAIL_CHARS = 4000
REP_TIMEOUT_S = 300  # T8: brief specifies a uniform 300s per-session timeout across all WAN systems
DEFAULT_REPS = 15


def phase_time(stderr: str, name: str) -> float | None:
    m = re.search(rf"\[phase\] {name} t=([\d.]+)", stderr)
    return float(m.group(1)) if m else None


def run_with_timeout(command: list[str], timeout_s: float) -> subprocess.CompletedProcess | None:
    """Runs `command` in its own process group. Returns None after killing
    the whole group when `timeout_s` passes."""
    proc = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.communicate()
        return None
    return subprocess.CompletedProcess(command, proc.returncode, stdout, stderr)


def server_stats(system: System, addr: str) -> dict | None:
    for _ in range(STATS_PROBE_ATTEMPTS):
        done = run_with_timeout([system.client_bin, "stats", "--addr", addr], STATS_PROBE_TIMEOUT_S)
        if done is not None and done.returncode == 0:
            return json.loads(done.stdout.strip().splitlines()[-1])
    return None


def counter_delta(before: dict | None, after: dict | None) -> dict | None:
    if before is None or after is None:
        return None
    return {name: after[name] - before[name] for name in after}


def run_one(system: System, addr: str, variant: str, log: bool) -> dict:
    command = [
        "/usr/bin/time", "-v",
        *pin_to_core(CLIENT_CORE, os.cpu_count() or 1, 2), *system.client_command(variant, addr),
    ]
    if log:
        log_command("client", command)
    started = time.monotonic()
    result = run_with_timeout(command, REP_TIMEOUT_S)
    process_s = time.monotonic() - started
    if result is None:
        print(f"client killed after {REP_TIMEOUT_S}s")
        return {"ok": False, "reason": "killed_by_timeout", "process_s": process_s}
    if result.returncode != 0:
        print(f"client exit status {result.returncode}: {result.stderr[-300:]}")
        return {"ok": False, "reason": "client_error", "exit_status": result.returncode,
                "process_s": process_s, "stderr_tail": result.stderr[-FAILED_STDERR_TAIL_CHARS:]}

    phases = system.phases
    t_req = phase_time(result.stderr, phases.first_request_sent)
    t_res = phase_time(result.stderr, phases.first_response_received)
    t_pts = phase_time(result.stderr, phases.second_request_sent)
    t_done = phase_time(result.stderr, phases.session_done)
    if None in (t_req, t_res, t_pts, t_done):
        return {"ok": False, "reason": "missing_phase", "process_s": process_s,
                "stderr_tail": result.stderr[-FAILED_STDERR_TAIL_CHARS:]}

    return {
        "ok": True,
        "handshake_rtt_s": t_res - t_req,
        "request_phase_rtt_s": t_done - t_pts,
        "session_s": t_done - t_req,
        "process_s": process_s,
        "retries": len(re.findall(r"^\[retry\] ", result.stderr, flags=re.M)),
        "retry_lines": re.findall(r"^\[retry\].*$", result.stderr, flags=re.M),
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def summarize(values: list[float]) -> str:
    med = statistics.median(values)
    if len(values) >= 4:
        q1, q3 = statistics.quantiles(values, n=4, method="inclusive")[0::2]
    else:
        q1, q3 = min(values), max(values)
    return (
        f"median={med:.4f}s iqr=[{q1:.4f}, {q3:.4f}]s "
        f"min={min(values):.4f}s max={max(values):.4f}s (n={len(values)})"
    )


def main() -> None:
    addr, variant = sys.argv[1], sys.argv[2]
    reps = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_REPS
    system = SYSTEMS[sys.argv[4] if len(sys.argv) > 4 else "stateless"]
    print(f"system={system.name} variant={variant} addr={addr} reps={reps}")

    results = []
    rows = []
    failures = 0
    shown_full_output = False
    probe_stats = system.stats_probe and os.environ.get("WAN_STATEFUL_STATS") == "1"
    stats_before = server_stats(system, addr) if probe_stats else None
    for rep in range(1, reps + 1):
        r = run_one(system, addr, variant, log=rep == 1)
        stats_after = server_stats(system, addr) if probe_stats else None
        stats_delta = counter_delta(stats_before, stats_after) if probe_stats else None
        stats_before = stats_after
        stats_fields = {"server_stats_delta": stats_delta} if probe_stats else {}
        if not r["ok"]:
            failures += 1
            print(f"rep {rep}/{reps}: FAILED ({r['reason']}) server_stats_delta={stats_delta}")
            rows.append({"rep": rep, "ok": False, "session_s": None,
                         **{k: v for k, v in r.items() if k != "ok"}, **stats_fields})
            continue
        results.append(r)
        rows.append({
            "rep": rep, "ok": True, "session_s": r["session_s"], "process_s": r["process_s"], "handshake_rtt_s": r["handshake_rtt_s"],
            "request_phase_rtt_s": r["request_phase_rtt_s"], "retries": r["retries"],
            "retry_lines": r["retry_lines"], **stats_fields,
        })
        if not shown_full_output:
            shown_full_output = True
            print(f"--- rep {rep} client output (representative; later reps summarized to one line) ---")
            print(r["stdout"], end="")
            print()
            print(f"--- rep {rep} phase timestamps + /usr/bin/time accounting ---")
            print(r["stderr"], end="")
            print()
        print(
            f"rep {rep}/{reps}: handshake_rtt_s={r['handshake_rtt_s']:.4f} "
            f"request_phase_rtt_s={r['request_phase_rtt_s']:.4f} "
            f"session_s={r['session_s']:.4f} process_s={r['process_s']:.4f} retries={r['retries']}"
        )
        for line in r["retry_lines"]:  # T8: log actual RTO values for every rep, not just the first
            print(f"rep {rep}/{reps}: {line}")

    print()
    print(f"--- Aggregate across {len(results)}/{reps} successful reps ({failures} dropped/timed out) ---")
    if results:
        print(f"handshake_rtt_s: {summarize([r['handshake_rtt_s'] for r in results])}")
        print(f"request_phase_rtt_s: {summarize([r['request_phase_rtt_s'] for r in results])}")
        print(f"session_s: {summarize([r['session_s'] for r in results])}")
        print(f"process_s: {summarize([r['process_s'] for r in results])}")
        with_retries = [r for r in results if r["retries"] > 0]
        print(
            f"reps_with_retransmits: {len(with_retries)}/{len(results)} "
            f"(retry rounds per such rep: {sorted(r['retries'] for r in with_retries)})"
        )
        print("total_round_trips: 2 (first request/response, then the u-chunk and v-residue requests fired in parallel)")
    else:
        print("(all reps failed -- no RTT data)")
    print("RESULT " + json.dumps({"system": system.name, "variant": variant, "addr": addr, "rows": rows}))


if __name__ == "__main__":
    main()
