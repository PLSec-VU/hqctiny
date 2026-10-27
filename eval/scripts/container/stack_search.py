#!/usr/bin/env python3
"""Smallest stack the real server binary needs to serve one full client
session. Runs inside the eval container (stack.py starts it), and stack.py
imports `find_minimum_stack` for the McTiny server on the host.

For a stack limit L the test starts the server with `ulimit -s L`, starts a
real client session, and passes when the client exits 0 and the server
process is still alive afterwards. The search halves the interval between
a failing and a passing limit until it is `RESOLUTION_KIB` wide. The server
runs without address-space randomization, so the result does not depend on
the random offset of the stack start. The result
is then confirmed with `CONFIRM_RUNS` sessions at the passing limit.

A server with one worker (`--workers 1`, the default) answers requests on its
main thread, so the limit applies to the request handlers. `ulimit -s` does
not limit worker threads. A search over several workers must start the server
with `--worker-stack-kib` instead.

Args: <stateless|stateful> <variant>
Prints "RESULT {json}".
"""

from __future__ import annotations

import ctypes
import json
import os
import resource
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))
from placement import CLIENT_CORE, SERVER_CORE  # noqa: E402
from systems import SYSTEMS  # noqa: E402
from util import pin_to_core  # noqa: E402

ADDR_NO_RANDOMIZE = 0x0040000
RESOLUTION_KIB = 4
START_KIB = 1024
CEILING_KIB = 65536
CONFIRM_RUNS = 5
SERVER_STARTUP_SECS = 1.0
CLIENT_TIMEOUT_SECS = 20.0
POLL_SECS = 0.01
CONTAINER_PORT = 24500


def disable_address_randomization() -> None:
    """The kernel moves the stack start by a random offset (ASLR), which
    makes the smallest passing limit vary between runs."""
    libc = ctypes.CDLL(None, use_errno=True)
    current = libc.personality(0xFFFFFFFF)
    libc.personality(current | ADDR_NO_RANDOMIZE)


def limit_stack_and_pin(stack_kib: int, core: int) -> Callable[[], None]:
    def prepare() -> None:
        disable_address_randomization()
        limit_bytes = stack_kib * 1024
        resource.setrlimit(resource.RLIMIT_STACK, (limit_bytes, limit_bytes))
        if (os.cpu_count() or 1) > core:
            os.sched_setaffinity(0, {core})

    return prepare


def session_succeeds(server_command: list[str], client_command: list[str], stack_kib: int) -> bool:
    server = subprocess.Popen(
        server_command, preexec_fn=limit_stack_and_pin(stack_kib, SERVER_CORE),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(SERVER_STARTUP_SECS)
        if server.poll() is not None:
            return False
        client = subprocess.Popen(client_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + CLIENT_TIMEOUT_SECS
        while client.poll() is None:
            if server.poll() is not None or time.monotonic() > deadline:
                client.kill()
                client.wait()
                return False
            time.sleep(POLL_SECS)
        return client.returncode == 0 and server.poll() is None
    finally:
        server.kill()
        server.wait()


def find_minimum_stack(server_command: list[str], client_command: list[str]) -> dict:
    probes: list[tuple[int, bool]] = []

    def survives(stack_kib: int) -> bool:
        ok = session_succeeds(server_command, client_command, stack_kib)
        probes.append((stack_kib, ok))
        print(f"  stack {stack_kib:5} KiB: {'ok' if ok else 'fail'}", flush=True)
        return ok

    high = START_KIB
    while not survives(high):
        high *= 2
        if high > CEILING_KIB:
            return {"min_stack_kib": None, "probes": probes}
    low = RESOLUTION_KIB
    while high - low > RESOLUTION_KIB:
        middle = (low + high) // 2 // RESOLUTION_KIB * RESOLUTION_KIB
        if survives(middle):
            high = middle
        else:
            low = middle
    while not all(survives(high) for _ in range(CONFIRM_RUNS)):
        high += RESOLUTION_KIB
    return {"min_stack_kib": high, "resolution_kib": RESOLUTION_KIB, "confirm_runs": CONFIRM_RUNS,
            "probes": probes}


def main() -> None:
    mode, variant = sys.argv[1], sys.argv[2]
    system = SYSTEMS[mode]
    nproc = os.cpu_count() or 1
    server = system.server_command(variant, CONTAINER_PORT)
    client = [*pin_to_core(CLIENT_CORE, nproc, 2), *system.client_command(variant, f"127.0.0.1:{CONTAINER_PORT}")]
    print(f"{mode} {variant}: server {' '.join(server)}", flush=True)
    result = find_minimum_stack(server, client)
    print("RESULT " + json.dumps({"system": mode, "variant": variant, **result}))


if __name__ == "__main__":
    main()
