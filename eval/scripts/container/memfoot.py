#!/usr/bin/env python3
"""Idle and post-session RSS of the stateless and stateful servers, inside the server container.
memfoot.py OUT.json [--sessions N] [--repeats R]. Run through category 10 (rss.py)."""
import argparse, json, os, signal, subprocess, sys, time
from pathlib import Path

SCRIPTS = Path(os.environ.get("SCRIPTS", "/work/eval/scripts"))
os.environ.setdefault("HOST_RESULTS_DIR", "/tmp/memfoot_unused")
for sub in ("", "lib", "container"):
    sys.path.insert(0, str(SCRIPTS / sub))
from systems import SYSTEMS  # noqa: E402

PORT = 24600
STARTUP_S = 1.0
SESSION_TIMEOUT_S = 180
STATUS_FIELDS = ("VmRSS", "VmHWM", "RssAnon", "RssFile", "RssShmem", "VmData", "VmStk")
ROLLUP_FIELDS = ("Pss", "Private_Dirty", "Private_Clean", "Anonymous", "AnonHugePages")


def snapshot(pid):
    out = {}
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        name, _, value = line.partition(":")
        if name in STATUS_FIELDS:
            out[name] = int(value.split()[0])
        if name == "Threads":
            out[name] = int(value)
    for line in Path(f"/proc/{pid}/smaps_rollup").read_text().splitlines():
        name = line.split(":")[0]
        if name in ROLLUP_FIELDS:
            out[name] = int(line.split()[1])
    return out


def one_run(name, variant, sessions, log_path):
    system = SYSTEMS[name]
    core = os.environ.get("SERVER_CORE", "0")
    client_core = os.environ.get("CLIENT_CORE", "2")
    server_cmd = ["taskset", "-c", core, *system.server_command(variant, PORT)]
    client_cmd = ["taskset", "-c", client_core, *system.client_command(variant, f"127.0.0.1:{PORT}")]
    with open(log_path, "wb") as log:
        server = subprocess.Popen(server_cmd, stdout=log, stderr=log)
        try:
            time.sleep(STARTUP_S)
            idle = snapshot(server.pid)
            ok = 0
            for _ in range(sessions):
                ok += subprocess.run(client_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     timeout=SESSION_TIMEOUT_S).returncode == 0
            after = snapshot(server.pid)
        finally:
            server.send_signal(signal.SIGTERM)
            server.wait(timeout=5)
    return {"sessions_ok": ok, "idle": idle, "after": after}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("out", type=Path)
    p.add_argument("--sessions", type=int, default=20)
    p.add_argument("--repeats", type=int, default=3)
    a = p.parse_args()
    rows = []
    for variant in ("hqc1", "hqc3", "hqc5"):
        for name in ("stateless", "stateful"):
            for rep in range(a.repeats):
                log = a.out.with_suffix(f".{name}.{variant}.{rep}.log")
                row = {"system": name, "variant": variant, "rep": rep, **one_run(name, variant, a.sessions, log)}
                print(json.dumps(row), flush=True)
                rows.append(row)
    a.out.write_text(json.dumps(rows, indent=1))


main()
