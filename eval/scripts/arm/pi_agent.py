#!/usr/bin/env python3
"""Runs on the Raspberry Pi as root and serves JSON lines on stdin and stdout.
dos_flood_lan.py starts it over ssh. Every request is one JSON object with a
field "cmd"; every answer is one JSON line.

  start         argv                 start a server process, returns its pid
  snap          pid, port            server CPU (schedstat ns and ticks), RSS,
                                     socket drops, kernel UDP counters, NIC
                                     counters, per-core jiffies and soft
                                     interrupts, SoC state
  sample_start  pid, interval        sample server CPU and RSS in a thread
  sample_stop                        returns the samples
  stop          pid                  terminate the server process
  quit
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "container"))
import pi_state  # noqa: E402
from util import read_cpu_ns, read_cpu_ticks, read_rss_kb, read_udp_socket_drops  # noqa: E402

NIC = "eth0"
NIC_COUNTERS = ("rx_packets", "rx_bytes", "rx_dropped", "rx_errors", "rx_fifo_errors", "tx_packets",
                "tx_bytes", "tx_dropped", "tx_errors")
CPU_FIELDS = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal")
SOFTIRQ_ROWS = ("NET_RX", "NET_TX", "TIMER", "SCHED")


def snmp_udp() -> dict:
    lines = [line.split() for line in Path("/proc/net/snmp").read_text().splitlines() if line.startswith("Udp:")]
    return dict(zip(lines[0][1:], map(int, lines[1][1:])))


def nic_counters() -> dict:
    base = Path(f"/sys/class/net/{NIC}/statistics")
    return {name: int((base / name).read_text()) for name in NIC_COUNTERS}


def per_core_jiffies() -> dict:
    cores = {}
    for line in Path("/proc/stat").read_text().splitlines():
        fields = line.split()
        if fields[0].startswith("cpu") and fields[0] != "cpu":
            cores[fields[0]] = dict(zip(CPU_FIELDS, map(int, fields[1:1 + len(CPU_FIELDS)])))
    return cores


def softirqs() -> dict:
    rows = {}
    for line in Path("/proc/softirqs").read_text().splitlines()[1:]:
        name, _, rest = line.partition(":")
        if name.strip() in SOFTIRQ_ROWS:
            rows[name.strip()] = list(map(int, rest.split()))
    return rows


def nic_interrupts() -> dict:
    rows = {}
    for line in Path("/proc/interrupts").read_text().splitlines()[1:]:
        fields = line.split()
        if any(key in line for key in ("dwc", "usb", NIC)):
            counts = [int(f) for f in fields[1:5] if f.isdigit()]
            rows[fields[-1]] = counts
    return rows


def snap(pid: int, port: int) -> dict:
    return {
        "t": time.monotonic(), "cpu_ns": read_cpu_ns(pid), "cpu_ticks": read_cpu_ticks(pid),
        "rss_kb": read_rss_kb(pid), "socket_drops": read_udp_socket_drops(port),
        "snmp_udp": snmp_udp(), "nic": nic_counters(), "jiffies": per_core_jiffies(),
        "softirqs": softirqs(), "interrupts": nic_interrupts(), "state": pi_state.snapshot(),
        "clk_tck": os.sysconf("SC_CLK_TCK"),
    }


class Sampler:
    def __init__(self, pid: int, interval: float):
        self.pid, self.interval = pid, interval
        self.samples: list[list] = []
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self) -> None:
        while not self.stop.is_set():
            try:
                self.samples.append([time.monotonic(), read_cpu_ns(self.pid), read_rss_kb(self.pid)])
            except OSError:
                break
            self.stop.wait(self.interval)

    def finish(self) -> list[list]:
        self.stop.set()
        self.thread.join()
        return self.samples


def main() -> None:
    servers: dict[int, subprocess.Popen] = {}
    sampler: Sampler | None = None
    for line in sys.stdin:
        request = json.loads(line)
        cmd = request["cmd"]
        if cmd == "start":
            proc = subprocess.Popen(request["argv"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            servers[proc.pid] = proc
            answer = {"pid": proc.pid}
        elif cmd == "snap":
            answer = snap(request["pid"], request["port"])
        elif cmd == "sample_start":
            sampler = Sampler(request["pid"], request["interval"])
            answer = {"ok": True}
        elif cmd == "sample_stop":
            answer = {"samples": sampler.finish() if sampler else []}
            sampler = None
        elif cmd == "stop":
            proc = servers.pop(request["pid"])
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=5)
            answer = {"returncode": proc.returncode}
        elif cmd == "quit":
            sys.stdout.write(json.dumps({"ok": True}) + "\n")
            sys.stdout.flush()
            break
        else:
            answer = {"error": f"unknown cmd {cmd}"}
        sys.stdout.write(json.dumps(answer) + "\n")
        sys.stdout.flush()
    for proc in servers.values():
        proc.kill()


if __name__ == "__main__":
    main()
