#!/usr/bin/env python3
"""Runs inside the eval container (invoked by ../dos_flood.py). Starts
the real hqctiny-server, then for `reps` repetitions samples its RSS/CPU
across an idle baseline and a flood window while `hqctiny-client
flood-client` blasts it, tracking two exact, kernel/server-reported
counters: the server socket's receive-buffer drop count (packets that
never reached recv_from) and the server's own successfully-sent-response
count (queried via a magic-byte UDP probe -- see FLOOD_STATS_QUERY and
--features flood-stats in hqctiny-server/src/main.rs). Together with the
client's self-reported sent count, that fully accounts for where flood
packets go: dropped at the kernel, answered by the server, or the small
residual (decode/handle failures, or still in flight at the sampling
boundary). Reports per-rep numbers plus median/IQR across reps (a single
flood window is not a distribution -- see eval/README.md's
reproducibility notes). Finishes with a short strace memory-syscall check.

Args: <variant> <flood_duration_secs> <num_sockets> [reps] [kind]
  kind: "handshake" (default) or "point" -- see hqctiny-client's FloodKind.
"""

from __future__ import annotations

import json
import os
import re
import signal
import socket as pysocket
import statistics
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from util import read_cpu_ticks, read_rss_kb, read_udp_socket_drops  # noqa: E402

SERVER_BIN = "/work/target-linux/tiny-release/hqctiny-server"
CLI = "/work/target-linux/release/hqctiny-client"
PORT = "24100"
PORT_INT = int(PORT)
DEFAULT_REPS = 5
DEFAULT_KIND = "handshake"

# Pin the server and the flood client to distinct cores: without this they
# compete for the same cores in the same container, which conflates "the
# server is overloaded" with "the server lost a scheduling fight against
# the thing attacking it" -- not the resource picture a remote attacker
# with their own machine would produce. Skipped (both lists empty) below
# 2 cores, where isolation isn't possible anyway.
def _taskset_prefix(core: int) -> list[str]:
    return ["taskset", "-c", str(core)]

# Must match FLOOD_STATS_QUERY in hqctiny-server/src/main.rs exactly.
FLOOD_STATS_QUERY = b"HQCTINY_FLOOD_STATS_QUERY_V1"

BRK_MMAP_RE = re.compile(r"\b(?:brk|mmap)\(")


def query_responses_sent(port: int) -> int | None:
    """Asks the server (built with --features flood-stats) for its
    successfully-sent-response counter. A plain request/response over the
    same socket the server already listens on -- no ptrace overhead, so
    unlike strace this is safe to call inside the timed flood window.
    Returns None if the server wasn't built with the feature (no reply
    within the timeout) rather than raising, so callers can fall back
    gracefully.
    """
    with pysocket.socket(pysocket.AF_INET, pysocket.SOCK_DGRAM) as s:
        s.settimeout(1.0)
        try:
            s.sendto(FLOOD_STATS_QUERY, ("127.0.0.1", port))
            data, _ = s.recvfrom(16)
        except OSError:
            return None
    if len(data) < 8:
        return None
    return int.from_bytes(data[:8], "little")


def sample_rss_for(pid: int, seconds: float, interval: float = 0.1) -> list[int]:
    samples = []
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        samples.append(read_rss_kb(pid))
        time.sleep(interval)
    return samples


def run_one_flood(
    server_pid: int,
    variant: str,
    duration: int,
    sockets: str,
    clk_tck: int,
    client_prefix: list[str],
    kind: str,
) -> dict:
    print("Sampling idle baseline RSS (2s)...")
    idle_samples = sample_rss_for(server_pid, 2.0)

    cpu_before = read_cpu_ticks(server_pid)
    drops_before = read_udp_socket_drops(PORT_INT) or 0
    resp_before = query_responses_sent(PORT_INT)
    t0 = time.monotonic()

    flood = subprocess.Popen(
        [
            *client_prefix,
            CLI,
            "flood-client",
            "--addr",
            f"127.0.0.1:{PORT}",
            "--variant",
            variant,
            "--duration",
            str(duration),
            "--sockets",
            sockets,
            "--kind",
            kind,
        ],
        stdout=subprocess.PIPE,
    )

    print(f"Sampling RSS during flood ({duration}s)...")
    # Sampling blocks for `duration` seconds while flood-client runs
    # concurrently in the background, same as the RSS window it's measuring.
    flood_samples = sample_rss_for(server_pid, float(duration))
    flood_stdout, _ = flood.communicate()
    t1 = time.monotonic()
    cpu_after = read_cpu_ticks(server_pid)
    drops_after = read_udp_socket_drops(PORT_INT)
    drops_delta = (drops_after - drops_before) if drops_after is not None else None
    resp_after = query_responses_sent(PORT_INT)
    resp_delta = (resp_after - resp_before) if resp_before is not None and resp_after is not None else None

    print(flood_stdout.decode(), end="")
    flood_json = json.loads(flood_stdout.decode().strip().splitlines()[-1])

    idle_mean = statistics.mean(idle_samples)
    idle_sd = statistics.pstdev(idle_samples)
    flood_mean = statistics.mean(flood_samples)
    flood_sd = statistics.pstdev(flood_samples)
    cpu_seconds = (cpu_after - cpu_before) / clk_tck
    wall = t1 - t0
    cpu_pct = 100 * cpu_seconds / wall if wall > 0 else 0.0

    client_sent = flood_json["packets_sent"]
    # Full accounting: sent = dropped-at-kernel + answered + residual.
    # The residual covers decode/handle failures (server silently discards
    # those, no response) and packets still in flight in the queue at the
    # instant we sampled "after" -- both expected to be small for this
    # flood's fixed, always-valid payload.
    unaccounted = None
    if drops_delta is not None and resp_delta is not None:
        unaccounted = client_sent - drops_delta - resp_delta

    print(f"idle_rss_kb: mean={idle_mean:.0f} stddev={idle_sd:.2f}")
    print(f"flood_rss_kb: mean={flood_mean:.0f} stddev={flood_sd:.2f}")
    print(f"rss_growth_kb: {flood_mean - idle_mean:.0f}")
    print(
        f"server_cpu_seconds_during_flood: {cpu_seconds:.2f}s / {wall:.2f}s wall "
        f"= {cpu_pct:.1f}% of one core"
    )
    print(f"client_packets_sent: {client_sent}")
    print(f"server_socket_kernel_drops (exact, rcvbuf full before recv_from): {drops_delta}")
    if resp_delta is not None:
        print(f"server_responses_sent (exact, from server's own counter): {resp_delta}")
        print(f"unaccounted (decode/handle failures + in-flight at sample boundary): {unaccounted}")
    else:
        print(
            "server_responses_sent: (unavailable -- server not built with "
            "--features flood-stats, or the probe timed out)"
        )

    return {
        "rss_growth_kb": flood_mean - idle_mean,
        "cpu_pct": cpu_pct,
        "client_packets_sent": client_sent,
        "kernel_drops": drops_delta if drops_delta is not None else 0,
        "responses_sent": resp_delta if resp_delta is not None else 0,
    }


def print_aggregate(reps_results: list[dict]) -> None:
    print(f"--- Aggregate across {len(reps_results)} reps ---")
    fields = [
        ("rss_growth_kb", "rss_growth_kb", "{:.1f}"),
        ("cpu_pct", "server_cpu_pct", "{:.1f}"),
        ("kernel_drops", "server_socket_kernel_drops", "{:.0f}"),
        ("responses_sent", "server_responses_sent", "{:.0f}"),
    ]
    for key, label, fmt in fields:
        values = [r[key] for r in reps_results]
        med = statistics.median(values)
        if len(values) >= 4:
            q1, q3 = statistics.quantiles(values, n=4, method="inclusive")[0::2]
        else:
            q1, q3 = min(values), max(values)
        print(f"{label}: median={fmt.format(med)} iqr=[{fmt.format(q1)}, {fmt.format(q3)}] (n={len(values)})")


def main() -> None:
    # Our own print() calls interleave with output from hqctiny-server,
    # flood-client, and strace below; without line buffering they'd sit in
    # Python's block buffer (the default once stdout isn't a tty, which it
    # isn't under `docker compose exec -T`) until process exit, landing
    # after all the subprocess output instead of in the right order.
    sys.stdout.reconfigure(line_buffering=True)

    variant, duration, sockets = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    reps = int(sys.argv[4]) if len(sys.argv) > 4 else DEFAULT_REPS
    kind = sys.argv[5] if len(sys.argv) > 5 else DEFAULT_KIND

    nproc = os.cpu_count() or 1
    if nproc >= 2:
        server_prefix, client_prefix = _taskset_prefix(0), _taskset_prefix(1)
        print(f"CPU isolation: server pinned to core 0, flood-client pinned to core 1 (nproc={nproc})")
    else:
        server_prefix, client_prefix = [], []
        print(f"CPU isolation: skipped (nproc={nproc} < 2, no core to isolate onto)")

    server = subprocess.Popen([*server_prefix, SERVER_BIN, "--port", PORT, "--variant", variant])
    time.sleep(1)

    clk_tck = os.sysconf("SC_CLK_TCK")

    reps_results = []
    for rep in range(1, reps + 1):
        print(f"--- Rep {rep}/{reps} ---")
        reps_results.append(
            run_one_flood(server.pid, variant, duration, sockets, clk_tck, client_prefix, kind)
        )
        print()

    print_aggregate(reps_results)

    print()
    print(
        "Post-flood strace memory-syscall snapshot (short burst, run after all flood reps "
        "above so it doesn't perturb those numbers)..."
    )
    # Line-by-line -e trace=memory (as in category 1's audit), not -c: strace's
    # -c summary is only flushed reliably when the *tracee* exits, not on a
    # detach signal, which doesn't fit an attach-to-a-still-running-server
    # check. Counting matching lines works regardless of how the trace ends.
    trace_path = Path("/tmp/flood.strace")
    trace_path.unlink(missing_ok=True)
    tracer = subprocess.Popen(
        ["strace", "-f", "-o", str(trace_path), "-e", "trace=memory", "-p", str(server.pid)]
    )
    time.sleep(0.3)
    subprocess.run(
        [
            *client_prefix,
            CLI,
            "flood-client",
            "--addr",
            f"127.0.0.1:{PORT}",
            "--variant",
            variant,
            "--duration",
            "1",
            "--sockets",
            "16",
            "--kind",
            kind,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.2)
    tracer.terminate()
    tracer.wait(timeout=5)

    text = trace_path.read_text() if trace_path.exists() else ""
    burst_calls = len(BRK_MMAP_RE.findall(text))
    print(f"brk_mmap_calls_during_1s_burst_after_main_flood: {burst_calls}")

    server.send_signal(signal.SIGTERM)
    server.wait(timeout=5)


if __name__ == "__main__":
    main()
