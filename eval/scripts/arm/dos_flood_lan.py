#!/usr/bin/env python3
"""Real-network flood against a server on the Raspberry Pi. Runs on the
flood host (playground) and drives the Pi through pi_agent.py over ssh.

Per repetition and cell it starts a fresh server on the Pi, runs idle
probes, then the flood and the open-loop legitimate probes (see
container/legit_probes.py), then recovery probes. The row has the columns of
container/dos_flood_variant.py plus the link evidence from the Pi: NIC
and kernel UDP counters, per-core CPU split (user, system, irq, softirq) and
soft interrupts, SoC temperature and clock.

  dos_flood_lan.py --out FILE --pi user@rpi --pi-host 192.168.50.241
      --cells stateless:handshake:single,stateless:vresidue:single,stateful:hello:single,stateful:churn2:botnet
      --variants hqc1,hqc5 --reps 5 --duration 10

Cell syntax: system:kind:shape, shape single (SINGLE_SOCKETS sockets, one source
address) or botnet (BOTNET_SOCKETS sockets over BOTNET_IPS addresses
FLOOD_SOURCE_BASE.x.y). Kind `none` runs the probes only.

Environment (flood host): CLIENT_BIN_DIR and KEY_DIR (public keys), FLOOD_CORE,
LEGIT_CORE, ORCHESTRATOR_CORE, FLOOD_SOURCE_BASE.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import socket
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "container"))
sys.path.insert(0, str(HERE.parent / "lib"))
import dos_flood_variant as dfv  # noqa: E402
import legit_probes as lp  # noqa: E402
from placement import FLOOD_CORE, LEGIT_CORE, ORCHESTRATOR_CORE  # noqa: E402
from reps import describe_rows, new_seed, shuffled_for_rep  # noqa: E402
from systems import SYSTEMS  # noqa: E402
from util import STATEFUL_STATS_FIELDS, STATEFUL_STATS_QUERY  # noqa: E402

FLOOD_STATS_QUERY = b"HQCLETHE_FLOOD_STATS_QUERY_V1"
PI_SERVER_DIR = "/mnt/arm/bin/floodstats"
PI_KEY_DIR = "/mnt/arm/keys"
PI_SERVER_CORE = 2
PI_AGENT_CORE = 3
SERVER_STARTUP_S = 1.0
FLOOD_EXIT_TIMEOUT_S = 60
QUERY_ATTEMPTS = 5
QUERY_TIMEOUT_S = 1.0
IDLE_PROBES = 3
IDLE_RSS_S = 2.0
LEGIT_SOURCE_IP = "10.99.200.1"
SINGLE_SOCKETS = 128
BOTNET_SOCKETS = 4096
BOTNET_IPS = 1024
TABLE_CAP = 1024
SERVER_BINARY = {"stateless": "hqclethe-server", "stateful": "hqclethe-server-stateful"}


class Agent:
    def __init__(self, target: str):
        if target.startswith("tcp:"):
            link = socket.create_connection(("127.0.0.1", int(target[4:])))
            self.reader, self.writer, self.proc = link.makefile("r"), link.makefile("w", buffering=1), None
            return
        self.proc = subprocess.Popen(
            ["ssh", "-o", "BatchMode=yes", target, "sudo", "taskset", "-c", str(PI_AGENT_CORE), "python3",
             "/mnt/arm/scripts/arm/pi_agent.py"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
        self.reader, self.writer = self.proc.stdout, self.proc.stdin

    def call(self, **request) -> dict:
        self.writer.write(json.dumps(request) + "\n")
        self.writer.flush()
        return json.loads(self.reader.readline())

    def close(self) -> None:
        self.call(cmd="quit")
        if self.proc:
            self.proc.wait(timeout=10)


def udp_query(host: str, port: int, magic: bytes, size: int) -> bytes | None:
    for _ in range(QUERY_ATTEMPTS):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(QUERY_TIMEOUT_S)
            try:
                s.sendto(magic, (host, port))
                return s.recvfrom(size)[0]
            except OSError:
                continue
    return None


def responses_sent(host: str, port: int) -> int | None:
    data = udp_query(host, port, FLOOD_STATS_QUERY, 16)
    return int.from_bytes(data[:8], "little") if data and len(data) >= 8 else None


def stateful_stats(host: str, port: int) -> dict | None:
    data = udp_query(host, port, STATEFUL_STATS_QUERY, 4096)
    if not data:
        return None
    values = [int.from_bytes(data[i:i + 8], "little") for i in range(0, len(data), 8)]
    return dict(zip(STATEFUL_STATS_FIELDS, values))


def counters(ctx: dict) -> dict:
    return {
        "responses": responses_sent(ctx["host"], ctx["port"]),
        "stats": stateful_stats(ctx["host"], ctx["port"]) if ctx["system"].stats_probe else None,
    }


def link_columns(before: dict, after: dict) -> dict:
    seconds = after["t"] - before["t"]
    udp = {k: after["snmp_udp"][k] - before["snmp_udp"][k] for k in after["snmp_udp"]}
    nic = {k: after["nic"][k] - before["nic"][k] for k in after["nic"]}
    cores = {}
    for core, now in after["jiffies"].items():
        delta = {k: now[k] - before["jiffies"][core][k] for k in now}
        total = sum(delta.values()) or 1
        cores[core] = {k: round(100 * v / total, 2) for k, v in delta.items()}
    softirq = {name: [a - b for a, b in zip(after["softirqs"][name], before["softirqs"][name])]
               for name in after["softirqs"]}
    interrupts = {name: [a - b for a, b in zip(after["interrupts"][name], before["interrupts"][name])]
                  for name in after["interrupts"]}
    return {
        "pi_window_s": seconds, "pi_udp": udp, "pi_nic": nic,
        "pi_nic_rx_pps": nic["rx_packets"] / seconds, "pi_nic_rx_mbit": nic["rx_bytes"] * 8 / seconds / 1e6,
        "pi_nic_tx_mbit": nic["tx_bytes"] * 8 / seconds / 1e6,
        "pi_udp_in_per_s": udp["InDatagrams"] / seconds, "pi_udp_rcvbuf_errors": udp.get("RcvbufErrors", 0),
        "pi_core_pct": cores, "pi_softirq_delta": softirq, "pi_irq_delta": interrupts,
        "pi_temp_c_start": before["state"]["temp_c"], "pi_temp_c_end": after["state"]["temp_c"],
        "pi_clock_hz_start": before["state"]["arm_clock_hz"], "pi_clock_hz_end": after["state"]["arm_clock_hz"],
        "pi_throttled_end": after["state"]["throttled"]["raw"],
    }


def snapshot_for_window(agent_snap: dict, extra: dict) -> dict:
    return {"ns": agent_snap["cpu_ns"], "ticks": agent_snap["cpu_ticks"],
            "drops": agent_snap["socket_drops"], **extra}


def run_flood_window(ctx: dict, agent: Agent, runner: lp.ProbeRunner) -> dict:
    before_extra = counters(ctx)
    before_agent = agent.call(cmd="snap", pid=ctx["pid"], port=ctx["port"])
    agent.call(cmd="sample_start", pid=ctx["pid"], interval=dfv.RSS_SAMPLE_INTERVAL_S)
    flood = None
    runner.origin = time.monotonic()
    if ctx["kind"] != dfv.NO_FLOOD:
        flood = subprocess.Popen(
            [*ctx["flood_prefix"], *ctx["system"].flood_command(
                ctx["variant"], ctx["addr"], ctx["duration"], ctx["sockets"], ctx["source_ips"], ctx["kind"])],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("CMD[flood]: " + shlex.join(flood.args), flush=True)
    stop = threading.Event()
    scheduler = runner.start_open_loop(lp.PHASE_FLOOD, stop)
    flood_stdout = flood_stderr = b""
    if flood:
        try:
            flood_stdout, flood_stderr = flood.communicate(timeout=ctx["duration"] + FLOOD_EXIT_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            flood.kill()
            flood_stdout, flood_stderr = flood.communicate()
            print("WARNING: flood client killed after timeout", flush=True)
    else:
        time.sleep(ctx["duration"])
    end_offset = runner.offset()
    stop.set()
    after_agent = agent.call(cmd="snap", pid=ctx["pid"], port=ctx["port"])
    samples = agent.call(cmd="sample_stop")["samples"]
    after_extra = counters(ctx)
    scheduler.join()
    t0 = before_agent["t"]
    series = [(s[0] - t0, s[1]) for s in samples]
    series = [(0.0, before_agent["cpu_ns"]), *series, (after_agent["t"] - t0, after_agent["cpu_ns"])]
    return {
        "before": snapshot_for_window(before_agent, before_extra),
        "after": snapshot_for_window(after_agent, after_extra),
        "agent_before": before_agent, "agent_after": after_agent,
        "window_s": after_agent["t"] - t0, "end_offset_s": end_offset,
        "rss_samples": [s[2] for s in samples], "cpu_series": series,
        "flood_stdout": flood_stdout, "flood_stderr": flood_stderr,
        "exit_code": flood.returncode if flood else 0,
    }


def run_one(ctx: dict, agent: Agent) -> dict:
    system = ctx["system"]
    bind = LEGIT_SOURCE_IP if system.legit_bind_flag else None
    config = lp.ProbeConfig(
        command=[*ctx["legit_prefix"], *system.client_command(ctx["variant"], ctx["addr"], bind)],
        interval_s=ctx["probe_interval_s"], timeout_s=ctx["probe_timeout_s"], recovery_probes=3)
    idle = lp.ProbeRunner(config, time.monotonic())
    subprocess.run(config.command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    idle.run_sequential(lp.PHASE_IDLE, IDLE_PROBES, 0.0)
    idle_rss = statistics.mean(
        agent.call(cmd="snap", pid=ctx["pid"], port=ctx["port"])["rss_kb"] for _ in range(int(IDLE_RSS_S * 2)))

    runner = lp.ProbeRunner(config, time.monotonic())
    window = run_flood_window(ctx, agent, runner)
    flooding = ctx["kind"] != dfv.NO_FLOOD
    flood_json = dfv.parse_flood_json(window, flooding)
    runner.run_sequential(lp.PHASE_RECOVERY, config.recovery_probes, window["end_offset_s"] + lp.RECOVERY_DELAY_S)
    runner.join()
    probes = sorted(runner.records, key=lambda r: r["scheduled_offset_s"])
    lp.mark_during_flood(probes, window["end_offset_s"])
    samples = window["rss_samples"] or [idle_rss]
    row = {
        "rep": ctx["rep"], "idle_rss_kb": idle_rss,
        "rss_growth_kb": statistics.mean(samples) - idle_rss, "peak_rss_growth_kb": max(samples) - idle_rss,
        "peak_rss_abs_kb": max(samples),
        **dfv.cpu_columns(window, window["agent_after"]["clk_tck"]),
        **dfv.load_columns(window, flood_json),
        **dfv.attack_phase_columns(window, flood_json),
        **lp.summarize_flood_probes(probes), **dfv.attack_probe_columns(probes, flood_json),
        **lp.summarize_other_phase(probes, lp.PHASE_RECOVERY),
        "legit_idle_p50_s": lp.summarize_other_phase(idle.records, lp.PHASE_IDLE)["idle_p50_s"],
        **link_columns(window["agent_before"], window["agent_after"]),
        "flood_client_json": flood_json, "probes": probes,
    }
    print("RUN " + json.dumps({k: v for k, v in row.items() if k not in ("probes",)}), flush=True)
    return row


def parse_cells(text: str) -> list[tuple[str, str, str]]:
    return [tuple(item.split(":")) for item in text.split(",")]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--pi", default="user@rpi")
    parser.add_argument("--pi-host", default="192.168.50.241")
    parser.add_argument("--port", type=int, default=24100)
    parser.add_argument("--cells", required=True)
    parser.add_argument("--variants", default="hqc1,hqc5")
    parser.add_argument("--reps", type=int, default=5)
    parser.add_argument("--duration", type=int, default=10)
    parser.add_argument("--probe-interval", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=new_seed())
    parser.add_argument("--puzzle-difficulty", type=int, default=0,
                        help="--puzzle-difficulty for the stateless server (0 = off)")
    args = parser.parse_args()
    os.sched_setaffinity(0, {ORCHESTRATOR_CORE})

    cells = [(v, *cell) for v in args.variants.split(",") for cell in parse_cells(args.cells)]
    agent = Agent(args.pi)
    rows: dict[str, list[dict]] = {":".join(c): [] for c in cells}
    orders = {}
    try:
        for rep in range(1, args.reps + 1):
            order = shuffled_for_rep(cells, args.seed, rep)
            orders[rep] = [":".join(c) for c in order]
            for variant, name, kind, shape in order:
                system = SYSTEMS[name]
                botnet = shape == "botnet"
                extra = []
                if name == "stateful":
                    extra = ["--max-entries", str(TABLE_CAP), "--watch-source", LEGIT_SOURCE_IP]
                elif args.puzzle_difficulty:
                    extra = ["--puzzle-difficulty", str(args.puzzle_difficulty)]
                server_argv = ["taskset", "-c", str(PI_SERVER_CORE), f"{PI_SERVER_DIR}/{SERVER_BINARY[name]}",
                               "--port", str(args.port), "--variant", variant, "--key",
                               f"{PI_KEY_DIR}/server-{variant}.sk", *extra]
                print(f"\n--- rep {rep}/{args.reps} {variant} {name} {kind} {shape} ---", flush=True)
                print("CMD[server on Pi]: " + shlex.join(server_argv), flush=True)
                pid = agent.call(cmd="start", argv=server_argv)["pid"]
                try:
                    time.sleep(SERVER_STARTUP_S)
                    ctx = {
                        "system": system, "variant": variant, "kind": kind, "host": args.pi_host,
                        "port": args.port, "addr": f"{args.pi_host}:{args.port}", "pid": pid, "rep": rep,
                        "duration": args.duration, "sockets": BOTNET_SOCKETS if botnet else SINGLE_SOCKETS,
                        "source_ips": BOTNET_IPS if botnet else 1,
                        "flood_prefix": ["taskset", "-c", str(FLOOD_CORE)],
                        "legit_prefix": ["taskset", "-c", str(LEGIT_CORE)],
                        "probe_interval_s": args.probe_interval, "probe_timeout_s": 10.0,
                    }
                    rows[":".join((variant, name, kind, shape))].append(run_one(ctx, agent))
                finally:
                    agent.call(cmd="stop", pid=pid)
            args.out.write_text(json.dumps({"seed": args.seed, "rep_orders": orders, "cells": {
                key: {"reps": value, "between_rep_stats": describe_rows(
                    [{k: v for k, v in r.items() if isinstance(v, (int, float))} for r in value])}
                for key, value in rows.items() if value}}, indent=1) + "\n")
    finally:
        agent.close()


if __name__ == "__main__":
    main()
