#!/usr/bin/env python3
"""Runs inside the eval container's "server" service. Starts/stops
hqclethe-server for the WAN latency test (category 5), where each variant
needs a fresh server instance and the *next* invocation (a separate
process, run via a separate `docker compose exec`) has to find and stop
the previous one -- so unlike dos_flood_variant.py, which starts and stops
its own hqclethe-server within one process lifetime, this can't just hold a
Popen handle across calls and has to search for the process by argv (see
util.find_tiny_server_pids).

Usage:
  server_ctl.py start <port> <variant> [stateless|stateful]
  server_ctl.py stop <port>
"""

from __future__ import annotations

import os
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from placement import SERVER_CORE  # noqa: E402
from systems import SYSTEMS  # noqa: E402
from util import find_tiny_server_pids, log_command, pin_to_core  # noqa: E402


def stop(port: str) -> None:
    for pid in find_tiny_server_pids(port):
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass


def start(port: str, variant: str, mode: str) -> None:
    stop(port)
    time.sleep(0.2)
    log = open("/tmp/wan-server.log", "w")
    # start_new_session detaches the child from this process's session, so
    # it keeps running after this script (and the `docker compose exec`
    # session it's part of) exits -- the equivalent of bash's `nohup ... &`.
    system = SYSTEMS[mode]
    extra = shlex.split(os.environ.get(system.server_extra_args_env or "", ""))
    command = [*pin_to_core(SERVER_CORE, os.cpu_count() or 1, 2),
               *system.server_command(variant, int(port), extra)]
    log_command("server", command)
    subprocess.Popen(
        command,
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    time.sleep(1)
    print(f"server started (mode={mode}, variant={variant}, port={port})")


def main() -> None:
    command = sys.argv[1]
    if command == "start":
        start(sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else "stateless")
    elif command == "stop":
        stop(sys.argv[2])
    else:
        print(f"unknown command: {command}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
