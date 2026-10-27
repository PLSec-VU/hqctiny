#!/usr/bin/env python3
"""Memory of the three servers on the Raspberry Pi: `size` of the binaries,
smallest stack that serves one real session (container/stack_search.py),
and resident set sizes (VmRSS and VmHWM) idle and after warm-up sessions.

  memory_pi.py --out FILE [--variants "hqc1 hqc3 hqc5"] [--no-mctiny] [--rss-sessions 20]
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
os.environ.setdefault("HOST_RESULTS_DIR", "/tmp/memory_pi_unused")
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "lib"))
sys.path.insert(0, str(HERE.parent / "container"))
from mctiny_session_cpu import McTiny  # noqa: E402
import placement  # noqa: E402
import stack_search  # noqa: E402
from systems import SYSTEMS  # noqa: E402

PORT = 24500
STACK_CLIENT_TIMEOUT_S = 180.0
SESSION_TIMEOUT_S = 180
SERVER_STARTUP_S = 1.0
PROC_FIELDS = ("VmRSS", "VmHWM", "VmData", "VmStk", "VmSize")


def proc_status(pid: int) -> dict:
    fields = {}
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        name, _, value = line.partition(":")
        if name in PROC_FIELDS:
            fields[name + "_kb"] = int(value.split()[0])
    for line in Path(f"/proc/{pid}/smaps_rollup").read_text().splitlines():
        if line.startswith(("Pss:", "Private_Dirty:", "Private_Clean:")):
            fields[line.split(":")[0] + "_kb"] = int(line.split()[1])
    return fields


def size_rows(binaries: list[str]) -> list[dict]:
    text = subprocess.run(["size", *binaries], capture_output=True, text=True, check=True).stdout
    print(text, end="")
    rows = []
    for line in text.splitlines()[1:]:
        f = line.split()
        rows.append({"binary": f[5], "text": int(f[0]), "data": int(f[1]), "bss": int(f[2]), "total": int(f[3])})
    return rows


def rss_row(server_command: list[str], client_command: list[str], sessions: int) -> dict:
    server = subprocess.Popen(server_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(SERVER_STARTUP_S)
        idle = proc_status(server.pid)
        completed = 0
        for _ in range(sessions):
            done = subprocess.run(client_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  timeout=SESSION_TIMEOUT_S)
            completed += done.returncode == 0
        warm = proc_status(server.pid)
    finally:
        server.send_signal(signal.SIGTERM)
        server.wait(timeout=5)
    return {"sessions_completed": completed, "idle": idle, "after_sessions": warm}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--variants", default="hqc1 hqc3 hqc5")
    parser.add_argument("--no-mctiny", action="store_true")
    parser.add_argument("--rss-sessions", type=int, default=20)
    parser.add_argument("--mctiny-dir", type=Path, default=Path("/mnt/arm/bin/mctiny"))
    parser.add_argument("--mctiny-state", type=Path, default=Path("/mnt/arm/mctiny_state"))
    args = parser.parse_args()
    stack_search.CLIENT_TIMEOUT_SECS = STACK_CLIENT_TIMEOUT_S
    os.sched_setaffinity(0, {placement.ORCHESTRATOR_CORE})

    mctiny = None if args.no_mctiny else McTiny(args.mctiny_dir, args.mctiny_state)
    binaries = [SYSTEMS["stateless"].server_bin, SYSTEMS["stateful"].server_bin]
    if mctiny:
        binaries.append(mctiny.server_bin)
    out = {"sizes": size_rows(binaries), "stack": [], "rss": []}

    cells = [(name, variant, SYSTEMS[name].server_command(variant, PORT),
              ["taskset", "-c", str(placement.CLIENT_CORE),
               *SYSTEMS[name].client_command(variant, f"127.0.0.1:{PORT}")])
             for variant in args.variants.split() for name in ("stateless", "stateful")]
    if mctiny:
        cells.append(("mctiny", None, [mctiny.server_bin, mctiny.state_dir, "127.0.0.1", str(PORT)],
                      ["taskset", "-c", str(placement.CLIENT_CORE), mctiny.client_bin, mctiny.public_key,
                       "127.0.0.1", str(PORT)]))
    for name, variant, server_command, client_command in cells:
        print(f"--- rss {name} {variant}", flush=True)
        pinned = ["taskset", "-c", str(placement.SERVER_CORE), *server_command]
        row = {"system": name, "variant": variant, **rss_row(pinned, client_command, args.rss_sessions)}
        print("RSS " + json.dumps(row), flush=True)
        out["rss"].append(row)
        print(f"--- stack {name} {variant}", flush=True)
        result = {"system": name, "variant": variant, **stack_search.find_minimum_stack(server_command, client_command)}
        print(f"STACK {name} {variant} {result['min_stack_kib']} KiB", flush=True)
        out["stack"].append(result)
        args.out.write_text(json.dumps(out, indent=2) + "\n")


if __name__ == "__main__":
    main()
