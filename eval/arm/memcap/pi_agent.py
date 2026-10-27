#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, os.environ.get("PI_TOOLS", "/mnt/arm/scripts/arm"))
import pi_state  # noqa: E402

CGROUP_ROOT = Path(os.environ.get("MEMCAP_CGROUP_ROOT", "/sys/fs/cgroup"))
CGROUP_PREFIX = "memcap-"
SERVER_CORE = int(os.environ.get("PI_SERVER_CORE", "2"))
READY_TIMEOUT_S = 5.0
READY_POLL_S = 0.05
STOP_TIMEOUT_S = 10
MAX_START_C = float(os.environ.get("MAX_START_C", "65"))
STDERR_TAIL_BYTES = 400
STAT_KEYS = ("anon", "file", "kernel", "kernel_stack", "pagetables", "sec_pagetables", "percpu", "sock", "slab",
             "shmem", "file_mapped", "file_dirty", "anon_thp", "workingset_refault_file", "pgmajfault", "pgfault")
PROC_KEYS = ("VmRSS", "VmHWM", "VmData", "VmStk", "VmSize", "Threads")
UDP_TABLE = Path("/proc/net/udp")


def write(path: Path, value: str) -> None:
    path.write_text(value)


def keyed_values(path: Path) -> dict:
    return {line.split()[0]: int(line.split()[1]) for line in path.read_text().splitlines()}


def port_bound(port: int) -> bool:
    needle = f":{port:04X} "
    return any(needle in line for line in UDP_TABLE.read_text().splitlines()[1:])


def process_status(pid: int) -> dict:
    try:
        lines = Path(f"/proc/{pid}/status").read_text().splitlines()
        rollup = Path(f"/proc/{pid}/smaps_rollup").read_text().splitlines()
    except OSError:
        return {}
    fields = {}
    for line in lines:
        name, _, value = line.partition(":")
        if name in PROC_KEYS:
            fields[name + ("" if name == "Threads" else "_kb")] = int(value.split()[0])
    for line in rollup:
        if line.startswith(("Pss:", "Private_Dirty:", "Private_Clean:", "Anonymous:")):
            fields[line.split(":")[0] + "_kb"] = int(line.split()[1])
    return fields


def drop_caches() -> None:
    os.sync()
    write(Path("/proc/sys/vm/drop_caches"), "3")


class Trial:
    def __init__(self, name: str, argv: list[str], cap_bytes: int | None, port: int, stderr_path: str):
        self.dir = CGROUP_ROOT / (CGROUP_PREFIX + name)
        self.port = port
        self.dir.mkdir()
        write(self.dir / "memory.swap.max", "0")
        write(self.dir / "memory.max", "max" if cap_bytes is None else str(cap_bytes))
        write(self.dir / "memory.oom.group", "1")
        self.stderr_path = stderr_path
        self.stderr = open(stderr_path, "wb")
        self.proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=self.stderr, preexec_fn=self.enter)

    def enter(self) -> None:
        write(self.dir / "cgroup.procs", str(os.getpid()))
        os.sched_setaffinity(0, {SERVER_CORE})

    def wait_ready(self) -> bool:
        deadline = time.monotonic() + READY_TIMEOUT_S
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                return False
            if port_bound(self.port):
                return True
            time.sleep(READY_POLL_S)
        return False

    def stats(self) -> dict:
        exit_code = self.proc.poll()
        stat = keyed_values(self.dir / "memory.stat")
        return {
            "alive": exit_code is None, "exit_code": exit_code,
            "memory_current": int((self.dir / "memory.current").read_text()),
            "memory_peak": int((self.dir / "memory.peak").read_text()),
            "memory_max": (self.dir / "memory.max").read_text().strip(),
            "swap_max": (self.dir / "memory.swap.max").read_text().strip(),
            "events": keyed_values(self.dir / "memory.events"),
            "stat": {k: stat.get(k) for k in STAT_KEYS},
            "proc": process_status(self.proc.pid) if exit_code is None else {},
        }

    def stop(self) -> dict:
        final = self.stats()
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGKILL)
        self.proc.wait(timeout=STOP_TIMEOUT_S)
        self.stderr.close()
        final["stderr_tail"] = Path(self.stderr_path).read_bytes()[-STDERR_TAIL_BYTES:].decode(errors="replace")
        deadline = time.monotonic() + STOP_TIMEOUT_S
        while time.monotonic() < deadline:
            try:
                self.dir.rmdir()
                break
            except OSError:
                time.sleep(0.1)
        return final


LOSS_SOURCES = os.environ.get("MEMCAP_LOSS_SOURCES", "10.99.0.0/16")


def loss_rule(port: int, probability: float) -> list[str]:
    return ["INPUT", "-p", "udp", "-s", LOSS_SOURCES, "--dport", str(port), "-m", "statistic", "--mode", "random",
            "--probability", str(probability), "-j", "DROP"]


def set_loss(port: int, probability: float) -> None:
    clear_loss(port)
    if probability > 0:
        subprocess.run(["iptables", "-I", *loss_rule(port, probability)], check=True)


def clear_loss(port: int) -> None:
    listing = subprocess.run(["iptables", "-S", "INPUT"], capture_output=True, text=True, check=True).stdout
    for rule in listing.splitlines():
        if f"--dport {port}" in rule and "statistic" in rule:
            subprocess.run(["iptables", "-D", "INPUT", *shlex.split(rule)[2:]], check=True)


def environment() -> dict:
    uname = os.uname()
    return {
        "kernel": uname.release, "machine": uname.machine, "state": pi_state.snapshot(),
        "cgroup_controllers": (CGROUP_ROOT / "cgroup.controllers").read_text().split(),
        "cgroup_subtree_control": (CGROUP_ROOT / "cgroup.subtree_control").read_text().split(),
        "meminfo_kb": {k.rstrip(":"): v for k, v in keyed_values(Path("/proc/meminfo")).items()
                       if k in ("MemTotal:", "MemFree:", "MemAvailable:", "Cached:", "SwapTotal:")},
        "page_size": os.sysconf("SC_PAGE_SIZE"),
        "transparent_hugepage": Path("/sys/kernel/mm/transparent_hugepage/enabled").read_text().strip(),
    }


def main() -> None:
    trial: Trial | None = None
    loss_ports: set[int] = set()
    for line in sys.stdin:
        request = json.loads(line)
        cmd = request["cmd"]
        if cmd == "env":
            answer = environment()
        elif cmd == "start":
            pi_state.wait_cool(MAX_START_C)
            drop_caches()
            trial = Trial(request["name"], request["argv"], request.get("cap_bytes"), request["port"],
                          request["stderr_path"])
            answer = {"pid": trial.proc.pid, "ready": trial.wait_ready(), "state": pi_state.snapshot()}
        elif cmd == "loss":
            set_loss(request["port"], request["probability"])
            loss_ports.add(request["port"])
            answer = {"ok": True}
        elif cmd == "stats":
            answer = trial.stats()
        elif cmd == "stop":
            answer = trial.stop()
            trial = None
        elif cmd == "quit":
            answer = {"ok": True}
        else:
            answer = {"error": f"unknown cmd {cmd}"}
        sys.stdout.write(json.dumps(answer) + "\n")
        sys.stdout.flush()
        if cmd == "quit":
            break
    if trial:
        trial.stop()
    for port in loss_ports:
        clear_loss(port)


if __name__ == "__main__":
    main()
