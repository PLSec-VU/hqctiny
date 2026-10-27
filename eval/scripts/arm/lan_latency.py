#!/usr/bin/env python3
"""Session latency over the LAN with the server on the Raspberry Pi and the
client on this host (playground). No loss is emulated. For each system the
server is a fresh process on the Pi (pinned core) and the client runs
REPS sessions one after another, each pinned to LEGIT_CORE.

  lan_latency.py --out FILE [--reps 20] [--variants hqc1,hqc3,hqc5]
      [--mctiny-client PATH --mctiny-public-key PATH]

HqcLethe sessions use container/wan_client_run.py (phase times from the
client). McTiny sessions use mctiny_session_launcher.py (wall time of the
client process and the packet-to-packet time). Environment: CLIENT_BIN_DIR,
KEY_DIR (public keys), LEGIT_CORE.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "container"))
sys.path.insert(0, str(HERE.parent / "lib"))
from dos_flood_lan import PI_KEY_DIR, SERVER_BINARY, Agent  # noqa: E402
from placement import LEGIT_CORE  # noqa: E402
from systems import replay_rate_args  # noqa: E402

PI_SERVER_DIR = "/mnt/arm/bin/quiet"
PI_MCTINY_DIR = "/mnt/arm/bin/mctiny"
PI_MCTINY_STATE = "/mnt/arm/mctiny_state"
PI_SERVER_CORE = 2
PORT = 24200
STARTUP_S = 1.0
MCTINY_TIMEOUT_S = 600
LAUNCHER = HERE.parent / "mctiny_session_launcher.py"
WAN_CLIENT = HERE.parent / "container" / "wan_client_run.py"


def summarize(values: list[float]) -> dict:
    q = statistics.quantiles(values, n=4, method="inclusive") if len(values) >= 4 else [min(values), 0, max(values)]
    return {"n": len(values), "median": statistics.median(values), "q1": q[0], "q3": q[2],
            "min": min(values), "max": max(values), "mean": statistics.fmean(values)}


def hqclethe(agent: Agent, host: str, system: str, variant: str, reps: int) -> dict:
    argv = ["taskset", "-c", str(PI_SERVER_CORE), f"{PI_SERVER_DIR}/{SERVER_BINARY[system]}", "--port", str(PORT),
            "--variant", variant, "--key", f"{PI_KEY_DIR}/server-{variant}.sk",
            *(replay_rate_args(variant) if system == "stateless" else [])]
    pid = agent.call(cmd="start", argv=argv)["pid"]
    try:
        time.sleep(STARTUP_S)
        done = subprocess.run([sys.executable, str(WAN_CLIENT), f"{host}:{PORT}", variant, str(reps), system],
                              capture_output=True, text=True)
    finally:
        agent.call(cmd="stop", pid=pid)
    print(done.stdout[-1500:], flush=True)
    result = json.loads(next(l for l in done.stdout.splitlines() if l.startswith("RESULT "))[7:])
    rows = result["rows"]
    ok = [r for r in rows if r["ok"]]
    return {"system": system, "variant": variant, "rows": rows,
            "session_s": summarize([r["session_s"] for r in ok]) if ok else None,
            "process_s": summarize([r["process_s"] for r in ok]) if ok else None}


def mctiny(agent: Agent, host: str, client: str, public_key: str, reps: int) -> dict:
    argv = ["taskset", "-c", str(PI_SERVER_CORE), f"{PI_MCTINY_DIR}/mctiny-server", PI_MCTINY_STATE, host, str(PORT)]
    pid = agent.call(cmd="start", argv=argv)["pid"]
    rows = []
    try:
        time.sleep(STARTUP_S)
        for rep in range(1, reps + 1):
            done = subprocess.run([sys.executable, str(LAUNCHER), str(LEGIT_CORE), str(MCTINY_TIMEOUT_S), client,
                                   public_key, host, str(PORT)], capture_output=True, text=True)
            try:
                row = json.loads(done.stdout.strip().splitlines()[-1])
            except (IndexError, json.JSONDecodeError):
                row = {"ok": False, "session_s": None, "launcher_stderr": done.stderr[-400:]}
            row.pop("stderr_gz_b64", None)
            row["rep"] = rep
            print(f"mctiny rep {rep}: ok={row['ok']} session_s={row['session_s']}", flush=True)
            rows.append(row)
    finally:
        agent.call(cmd="stop", pid=pid)
    ok = [r for r in rows if r["ok"]]
    return {"system": "mctiny", "variant": None, "rows": rows,
            "session_s": summarize([r["session_s"] for r in ok]) if ok else None,
            "network_s": summarize([r["network_s"] for r in ok if r.get("network_s")]) if ok else None}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--pi", default="user@rpi")
    parser.add_argument("--pi-host", default="192.168.50.241")
    parser.add_argument("--reps", type=int, default=20)
    parser.add_argument("--variants", default="hqc1,hqc3,hqc5")
    parser.add_argument("--only-mctiny", action="store_true")
    parser.add_argument("--mctiny-client")
    parser.add_argument("--mctiny-public-key")
    args = parser.parse_args()
    agent = Agent(args.pi)
    results = []
    try:
        for variant in [] if args.only_mctiny else args.variants.split(","):
            for system in ("stateless", "stateful"):
                results.append(hqclethe(agent, args.pi_host, system, variant, args.reps))
                args.out.write_text(json.dumps({"results": results}, indent=1) + "\n")
        if args.mctiny_client:
            results.append(mctiny(agent, args.pi_host, args.mctiny_client, args.mctiny_public_key, args.reps))
            args.out.write_text(json.dumps({"results": results}, indent=1) + "\n")
    finally:
        agent.close()


if __name__ == "__main__":
    main()
