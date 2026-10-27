#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

HOME = Path.home()
TOOLS_DIR = Path(os.environ.get("MEMCAP_TOOLS_DIR", str(HOME / "memcap-build/tools")))
sys.path.insert(0, str(TOOLS_DIR / "container"))
from util import STATEFUL_STATS_FIELDS, STATEFUL_STATS_QUERY  # noqa: E402

DEFAULT_BIN_DIR = os.environ.get("MEMCAP_CLIENT_BIN_DIR", str(HOME / "memcap-build/out/x86"))
DEFAULT_KEY_DIR = os.environ.get("MEMCAP_KEY_DIR", str(HOME / "memcap-build/keys"))
DEFAULT_MCTINY_CLIENT = os.environ.get("MEMCAP_MCTINY_CLIENT", str(HOME / "mctiny_build/mctiny-20200804/mctiny-client"))
DEFAULT_MCTINY_STATE = os.environ.get("MEMCAP_MCTINY_STATE", str(HOME / "mctiny_state"))
CLIENT_BINARY = {"stateless": "hqclethe-client", "stateful": "hqclethe-client-stateful"}
STDERR_TAIL_CHARS = 300
HOLD_SCRIPT = 'kill -STOP $$; exec "$@"'
SOURCES_PER_NETWORK = 250
PROBE_TIMEOUT_S = 1.0
PROBE_ATTEMPTS = 5
PROBE_BYTES = 4096


def source_ip(base: str, index: int) -> str:
    return f"{base}.{index // SOURCES_PER_NETWORK}.{index % SOURCES_PER_NETWORK + 1}"


def stats_probe(addr: str) -> dict | None:
    host, _, port = addr.partition(":")
    for _ in range(PROBE_ATTEMPTS):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(PROBE_TIMEOUT_S)
            try:
                sock.sendto(STATEFUL_STATS_QUERY, (host, int(port)))
                data = sock.recvfrom(PROBE_BYTES)[0]
            except OSError:
                continue
            values = [int.from_bytes(data[i:i + 8], "little") for i in range(0, len(data), 8)]
            return dict(zip(STATEFUL_STATS_FIELDS, values))
    return None


def client_command(args: argparse.Namespace) -> list[str]:
    if args.system == "mctiny":
        public_key = next((Path(args.mctiny_state) / "public").iterdir())
        host, _, port = args.addr.partition(":")
        return [args.mctiny_client, str(public_key), host, port]
    return [f"{args.bin_dir}/{CLIENT_BINARY[args.system]}", "client", "--addr", args.addr, "--variant", args.variant,
            "--server-key", f"{args.key_dir}/server-{args.variant}.pk"]


def start_held(command: list[str]) -> subprocess.Popen:
    proc = subprocess.Popen(["sh", "-c", HOLD_SCRIPT, "sh", *command], stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE, start_new_session=True)
    os.waitid(os.P_PID, proc.pid, os.WSTOPPED | os.WNOWAIT)
    return proc


def finish_session(proc: subprocess.Popen, started: float, timeout_s: float, results: list, index: int) -> None:
    try:
        _, stderr = proc.communicate(timeout=timeout_s)
        returncode = proc.returncode
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        _, stderr = proc.communicate()
        returncode = "timeout"
    ended = time.monotonic()
    results[index] = {"rc": returncode, "start": started, "end": ended, "seconds": ended - started,
                      "stderr_tail": stderr.decode(errors="replace")[-STDERR_TAIL_CHARS:] if returncode != 0 else ""}


def peak_overlap(results: list[dict]) -> int:
    events = sorted([(r["start"], 1) for r in results] + [(r["end"], -1) for r in results])
    live = peak = 0
    for _, delta in events:
        live += delta
        peak = max(peak, live)
    return peak


def with_source(command: list[str], base: str | None, index: int) -> list[str]:
    return command if base is None else [*command, "--bind-ip", source_ip(base, index)]


def run_round(command: list[str], first_index: int, k: int, args: argparse.Namespace) -> list[dict]:
    held = [start_held(with_source(command, args.bind_base, first_index + index)) for index in range(k)]
    results: list = [None] * k
    threads = []
    for index, proc in enumerate(held):
        started = time.monotonic()
        os.kill(proc.pid, signal.SIGCONT)
        thread = threading.Thread(target=finish_session, args=(proc, started, args.timeout_s, results, index))
        thread.start()
        threads.append(thread)
        time.sleep(args.stagger_ms / 1000)
    for thread in threads:
        thread.join()
    return results


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--system", choices=("stateless", "stateful", "mctiny"), required=True)
    parser.add_argument("--variant", default="hqc1")
    parser.add_argument("--addr", required=True)
    parser.add_argument("--k", type=int, default=1)
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--stagger-ms", type=float, default=20)
    parser.add_argument("--timeout-s", type=float, default=60)
    parser.add_argument("--stop-on-failure", action="store_true")
    parser.add_argument("--bind-base")
    parser.add_argument("--stats-probe", action="store_true")
    parser.add_argument("--bin-dir", default=DEFAULT_BIN_DIR)
    parser.add_argument("--key-dir", default=DEFAULT_KEY_DIR)
    parser.add_argument("--mctiny-client", default=DEFAULT_MCTINY_CLIENT)
    parser.add_argument("--mctiny-state", default=DEFAULT_MCTINY_STATE)
    args = parser.parse_args()
    command = client_command(args)
    sessions: list[dict] = []
    for round_index in range(args.rounds):
        batch = run_round(command, round_index * args.k, args.k, args)
        sessions += batch
        if args.stop_on_failure and any(s["rc"] != 0 for s in batch):
            break
    failures = sum(s["rc"] != 0 for s in sessions)
    print(json.dumps({"k": args.k, "rounds": args.rounds, "completed": len(sessions) - failures, "failures": failures,
                      "attempted": len(sessions), "peak_overlap": peak_overlap(sessions),
                      "seconds": [round(s["seconds"], 3) for s in sessions],
                      "errors": [{"rc": s["rc"], "stderr_tail": s["stderr_tail"]} for s in sessions if s["rc"] != 0][:3],
                      "server_stats": stats_probe(args.addr) if args.stats_probe else None}))


if __name__ == "__main__":
    main()
