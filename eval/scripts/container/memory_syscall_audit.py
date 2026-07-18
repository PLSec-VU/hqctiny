#!/usr/bin/env python3
"""Runs inside the eval container. Straces hqclethe-server across N sequential
real client sessions and splits brk/mmap syscall counts into
"before the first request" (startup, expected) vs "after" (steady state).

Args: <variant> <num_client_sessions> <port>
"""

from __future__ import annotations

import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from util import find_tiny_server_pids  # noqa: E402

SERVER_BIN = "/work/target-linux/tiny-release/hqclethe-server"
CLI = "/work/target-linux/release/hqclethe-client"

# `strace -f` prefixes every line with the tracee's PID once more than one
# thread/process is being traced -- hqclethe-server spawns its key-rotation
# thread immediately at startup, so in practice *every* line here has that
# prefix, shifting the timestamp to the second field. Handle both forms.
TIMESTAMP_RE = re.compile(r"^(?:\d+\s+)?(\d+\.\d+)")
BRK_MMAP_RE = re.compile(r"\b(?:brk|mmap)\(")


def main() -> None:
    variant, num_sessions, port = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    trace_path = Path(f"/tmp/ts-{port}.strace")
    trace_path.unlink(missing_ok=True)

    server = subprocess.Popen(
        [
            "strace",
            "-f",
            "-ttt",
            "-o",
            str(trace_path),
            "-e",
            "trace=memory",
            SERVER_BIN,
            "--port",
            port,
            "--variant",
            variant,
        ]
    )
    time.sleep(1)
    boundary = time.time()

    for _ in range(num_sessions):
        subprocess.run(
            [CLI, "client", "--addr", f"127.0.0.1:{port}", "--variant", variant],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    time.sleep(0.3)
    # `strace -f prog` forks prog as strace's *child* and ptrace-attaches to
    # it; terminating the strace Popen handle we hold doesn't reliably kill
    # or reap that child within a short timeout. Find the actual hqclethe-server
    # process by its listening port (same helper dos_flood_variant.py uses)
    # and signal that directly; strace then notices its tracee exited and
    # exits on its own.
    for pid in find_tiny_server_pids(port):
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    server.wait(timeout=5)

    total = 0
    steady = 0
    for line in trace_path.read_text().splitlines():
        ts_match = TIMESTAMP_RE.match(line)
        if not ts_match or not BRK_MMAP_RE.search(line):
            continue
        total += 1
        if float(ts_match.group(1)) > boundary:
            steady += 1

    print(f"startup_brk_mmap_calls: {total - steady}")
    print(f"post_warmup_brk_mmap_calls_across_{num_sessions}_client_sessions: {steady}")


if __name__ == "__main__":
    main()
