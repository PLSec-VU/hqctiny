#!/usr/bin/env python3
"""Runs inside the eval container's "client" service. Runs several full
protocol sessions against a (possibly network-emulated or remote) server,
each wrapped in /usr/bin/time for real/user/sys wall-clock accounting and
a `timeout` guard -- the protocol has no retry/timeout of its own (see
hqclethe-client's run_client, which blocks on socket.recv().await with no
deadline), so under a lossy netem profile a dropped response packet would
otherwise hang a rep forever instead of just failing it. Reports
median/IQR RTTs across reps rather than a single session's numbers, which
under jitter+loss aren't representative of anything (see eval/README.md's
reproducibility notes). RTTs are derived from the client's phase
timestamps, which it eprintln!s as `[phase] <name> t=<seconds>` at each
protocol transition.

Args: <server_addr> <variant> [reps]
"""

from __future__ import annotations

import re
import statistics
import subprocess
import sys

CLI = "/work/target-linux/release/hqclethe-client"
REP_TIMEOUT_S = 5
DEFAULT_REPS = 15


def phase_time(stderr: str, name: str) -> float | None:
    m = re.search(rf"\[phase\] {name} t=([\d.]+)", stderr)
    return float(m.group(1)) if m else None


def run_one(addr: str, variant: str) -> dict | None:
    result = subprocess.run(
        [
            "timeout", str(REP_TIMEOUT_S),
            "/usr/bin/time", "-v", CLI, "client", "--addr", addr, "--variant", variant,
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None

    t_req = phase_time(result.stderr, "handshake_request_sent")
    t_res = phase_time(result.stderr, "handshake_response_received")
    t_pts = phase_time(result.stderr, "point_requests_sent")
    t_done = phase_time(result.stderr, "session_key_derived")
    if None in (t_req, t_res, t_pts, t_done):
        return None

    return {
        "handshake_rtt_s": t_res - t_req,
        "point_request_rtt_s": t_done - t_pts,
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

    results = []
    failures = 0
    shown_full_output = False
    for rep in range(1, reps + 1):
        r = run_one(addr, variant)
        if r is None:
            failures += 1
            print(f"rep {rep}/{reps}: FAILED or timed out after {REP_TIMEOUT_S}s (skipped)")
            continue
        results.append(r)
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
            f"point_request_rtt_s={r['point_request_rtt_s']:.4f}"
        )

    print()
    print(f"--- Aggregate across {len(results)}/{reps} successful reps ({failures} dropped/timed out) ---")
    if results:
        print(f"handshake_rtt_s: {summarize([r['handshake_rtt_s'] for r in results])}")
        print(f"point_request_rtt_s: {summarize([r['point_request_rtt_s'] for r in results])}")
        print("total_round_trips: 2 (handshake, then all point requests fired in parallel)")
    else:
        print("(all reps failed -- no RTT data)")


if __name__ == "__main__":
    main()
